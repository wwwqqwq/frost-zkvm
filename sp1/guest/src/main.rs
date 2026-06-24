#![no_main]

use frost_core::{FrostPayload, ProofOutputs, SIGNATURE_LEN, VERIFYING_KEY_LEN};
use frost_ed25519 as frost;
use tiny_keccak::{Hasher, Keccak};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let raw: Vec<u8> = sp1_zkvm::io::read_vec();
    let FrostPayload {
        message,
        pubkey_package,
        commitments,
        signature_shares,
    } = bincode::serde::decode_from_slice(&raw, bincode::config::standard())
        .expect("guest: failed to deserialize FrostPayload")
        .0;

    let signing_package = frost::SigningPackage::new(commitments, &message);
    let signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_package)
        .unwrap_or_else(|e| {
            panic!(
                "guest: FROST aggregate failed: {e} (culprits: {:?})",
                e.culprits()
            )
        });
    let verifying_key = pubkey_package.verifying_key();

    let message_hash = {
        let mut h = Keccak::v256();
        h.update(&message);
        let mut out = [0u8; 32];
        h.finalize(&mut out);
        out
    };

    let group_pubkey: [u8; VERIFYING_KEY_LEN] = verifying_key
        .serialize()
        .expect("guest: serialize verifying key")
        .try_into()
        .expect("guest: verifying key wrong length");

    let signature_bytes: [u8; SIGNATURE_LEN] = signature
        .serialize()
        .expect("guest: serialize aggregated signature")
        .try_into()
        .expect("guest: signature wrong length");

    let outputs = ProofOutputs {
        message_hash,
        group_pubkey,
        signature: signature_bytes,
    };

    sp1_zkvm::io::commit_slice(&outputs.to_bytes());
}
