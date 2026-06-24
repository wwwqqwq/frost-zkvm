#![cfg_attr(not(feature = "host"), no_std)]

extern crate alloc;

pub mod wire;

pub use wire::{
    FrostPayload, ProofOutputs, ProofOutputsError, MESSAGE_HASH_LEN, PROOF_OUTPUTS_LEN,
    SIGNATURE_LEN, VERIFYING_KEY_LEN,
};

#[cfg(feature = "host")]
pub mod commit;
#[cfg(feature = "host")]
pub mod setup;
#[cfg(feature = "host")]
pub mod sign;
#[cfg(feature = "host")]
pub mod storage;
