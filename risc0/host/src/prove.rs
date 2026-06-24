use std::collections::BTreeMap;

use anyhow::{anyhow, Context, Result};
use clap::ValueEnum;
use frost_core::{storage, FrostPayload, ProofOutputs};
use methods::{FROST_GUEST_ELF, FROST_GUEST_ID};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, Prover, ProverOpts};
use tiny_keccak::{Hasher, Keccak};

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum ProofType {
    Core,
    Compressed,
    Groth16,
}

impl ProofType {
    fn prover_opts(self) -> ProverOpts {
        match self {
            ProofType::Core => ProverOpts::default(),
            ProofType::Compressed => ProverOpts::succinct(),
            ProofType::Groth16 => ProverOpts::groth16(),
        }
    }
}

pub fn run(message: String, proof_type: ProofType, execute_only: bool) -> Result<()> {
    let pubkey_package = storage::load_pubkey_package()
        .context("loading group public-key package; run `setup` first")?;

    let collected =
        storage::collect_signers().context("scanning state directory for signature shares")?;
    if collected.is_empty() {
        return Err(anyhow!(
            "no signature shares found on disk; run `commit` and `sign` for each participant first"
        ));
    }

    let signer_ids: Vec<u16> = collected.iter().map(|(id, ..)| *id).collect();
    let (commitments, signature_shares): (BTreeMap<_, _>, BTreeMap<_, _>) = collected
        .into_iter()
        .map(|(_, ident, c, s)| ((ident, c), (ident, s)))
        .unzip();
    let payload = FrostPayload {
        message: message.as_bytes().to_vec(),
        pubkey_package,
        commitments,
        signature_shares,
    };

    println!("payload: {} signers {signer_ids:?}", signer_ids.len(),);

    let env = ExecutorEnv::builder()
        .write(&payload)?
        .build()
        .context("building RISC Zero executor environment")?;

    if execute_only {
        let session = default_executor()
            .execute(env, FROST_GUEST_ELF)
            .context("RISC Zero execute() failed: guest panicked or input was malformed")?;
        println!("cycles: {}", session.cycles());
        return Ok(());
    }

    let prove_info = default_prover()
        .prove_with_opts(env, FROST_GUEST_ELF, &proof_type.prover_opts())
        .with_context(|| format!("RISC Zero prove_with_opts({proof_type:?}) failed"))?;
    let receipt = prove_info.receipt;

    receipt
        .verify(FROST_GUEST_ID)
        .context("RISC Zero receipt verification failed")?;

    let outputs = ProofOutputs::from_bytes(receipt.journal.as_ref())
        .map_err(|e| anyhow!("invalid journal blob in receipt: {e}"))?;

    let msg_hash = {
        let mut h = Keccak::v256();
        h.update(message.as_bytes());
        let mut out = [0u8; 32];
        h.finalize(&mut out);
        out
    };

    if outputs.message_hash != msg_hash {
        return Err(anyhow!(
            "message hash in receipt does not match expected hash of `{message}`"
        ));
    }

    println!(
        "\nproof_type {proof_type:?}\nimage_id   {FROST_GUEST_ID:?}\nmessage    {message:?}\nmsg_hash   0x{}\ngroup_pk   0x{}\nsignature  0x{}",
        hex::encode(outputs.message_hash),
        hex::encode(outputs.group_pubkey),
        hex::encode(outputs.signature),
    );
    Ok(())
}
