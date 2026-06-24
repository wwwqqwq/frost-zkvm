use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use frost_ed25519::{
    keys::PublicKeyPackage, round1::SigningCommitments, round2::SignatureShare, Identifier,
};
use serde::{Deserialize, Serialize};

pub const VERIFYING_KEY_LEN: usize = 32;

pub const MESSAGE_HASH_LEN: usize = 32;

pub const SIGNATURE_LEN: usize = 64;

pub const PROOF_OUTPUTS_LEN: usize = MESSAGE_HASH_LEN + VERIFYING_KEY_LEN + SIGNATURE_LEN;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrostPayload {
    pub message: Vec<u8>,
    pub pubkey_package: PublicKeyPackage,
    pub commitments: BTreeMap<Identifier, SigningCommitments>,
    pub signature_shares: BTreeMap<Identifier, SignatureShare>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofOutputs {
    pub message_hash: [u8; MESSAGE_HASH_LEN],
    pub group_pubkey: [u8; VERIFYING_KEY_LEN],
    pub signature: [u8; SIGNATURE_LEN],
}

impl ProofOutputs {
    pub fn to_bytes(&self) -> [u8; PROOF_OUTPUTS_LEN] {
        let mut out = [0u8; PROOF_OUTPUTS_LEN];
        out[..MESSAGE_HASH_LEN].copy_from_slice(&self.message_hash);
        out[MESSAGE_HASH_LEN..MESSAGE_HASH_LEN + VERIFYING_KEY_LEN]
            .copy_from_slice(&self.group_pubkey);
        out[MESSAGE_HASH_LEN + VERIFYING_KEY_LEN..].copy_from_slice(&self.signature);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProofOutputsError> {
        if bytes.len() != PROOF_OUTPUTS_LEN {
            return Err(ProofOutputsError::WrongLength {
                expected: PROOF_OUTPUTS_LEN,
                actual: bytes.len(),
            });
        }
        let mut message_hash = [0u8; MESSAGE_HASH_LEN];
        let mut group_pubkey = [0u8; VERIFYING_KEY_LEN];
        let mut signature = [0u8; SIGNATURE_LEN];

        message_hash.copy_from_slice(&bytes[..MESSAGE_HASH_LEN]);
        group_pubkey
            .copy_from_slice(&bytes[MESSAGE_HASH_LEN..MESSAGE_HASH_LEN + VERIFYING_KEY_LEN]);
        signature.copy_from_slice(&bytes[MESSAGE_HASH_LEN + VERIFYING_KEY_LEN..]);

        Ok(Self {
            message_hash,
            group_pubkey,
            signature,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ProofOutputsError {
    WrongLength { expected: usize, actual: usize },
}

impl core::fmt::Display for ProofOutputsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProofOutputsError::WrongLength { expected, actual } => core::write!(
                f,
                "invalid public-values length: expected {expected}, got {actual}"
            ),
        }
    }
}
