//! `prove`: assemble the final FROST payload, execute the SP1 circuit,
//! generate a proof, verify it, and check public outputs.

use std::collections::BTreeMap;

use anyhow::{anyhow, Context, Result};
use clap::ValueEnum;
use shared::{FrostPayload, ProofOutputs};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Stdin,
};
use tiny_keccak::{Hasher, Keccak};

use crate::storage;

const GUEST_ELF: Elf = include_elf!("guest");

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum ProofType {
    Core,
    Compressed,
    Groth16,
}

pub fn run(message: String, proof_type: ProofType) -> Result<()> {
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

    let payload_bytes = bincode::serde::encode_to_vec(&payload, bincode::config::standard())
        .context("bincode-encoding FrostPayload for SP1Stdin")?;
    println!(
        "payload: {} signers {signer_ids:?}, {} bytes",
        signer_ids.len(),
        payload_bytes.len()
    );

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(payload_bytes);
    let client = ProverClient::from_env();

    let (_, report) = client
        .execute(GUEST_ELF, stdin.clone())
        .run()
        .context("SP1 execute() failed: circuit panicked or input was malformed")?;
    println!("cycles: {}", report.total_instruction_count());

    let pk = client.setup(GUEST_ELF).context("SP1 setup failed")?;

    let proof = match proof_type {
        ProofType::Core => client.prove(&pk, stdin).run(),
        ProofType::Compressed => client.prove(&pk, stdin).compressed().run(),
        ProofType::Groth16 => client.prove(&pk, stdin).groth16().run(),
    }
    .context("SP1 prove() failed")?;

    client
        .verify(&proof, pk.verifying_key(), None)
        .context("SP1 verify() rejected the freshly generated proof")?;

    let outputs = ProofOutputs::from_bytes(proof.public_values.as_slice())
        .map_err(|e| anyhow!("invalid public-values blob in proof: {e}"))?;

    let msg_hash = {
        let mut h = Keccak::v256();
        h.update(message.as_bytes());
        let mut out = [0u8; 32];
        h.finalize(&mut out);
        out
    };

    if outputs.message_hash != msg_hash {
        return Err(anyhow!(
            "message hash in proof does not match expected hash of `{message}`"
        ));
    }

    println!(
        "\nvk         {}\nmessage    {message:?}\nmsg_hash   0x{}\ngroup_pk   0x{}\nsignature  0x{}",
        pk.verifying_key().bytes32(),
        hex::encode(outputs.message_hash),
        hex::encode(outputs.group_pubkey),
        hex::encode(outputs.signature),
    );
    Ok(())
}
