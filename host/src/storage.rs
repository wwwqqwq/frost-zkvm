use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use frost_ed25519::{
    keys::{KeyPackage, PublicKeyPackage},
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
    Identifier,
};
use serde::{de::DeserializeOwned, Serialize};

const STATE_DIR: &str = "state";
const PUBKEY_PACKAGE_FILE: &str = "pubkey_package.bin";
const THRESHOLD_FILE: &str = "threshold.txt";

const KEY_PACKAGE_FILE: &str = "key_package.bin";
const NONCES_FILE: &str = "nonces.bin";
const COMMITMENTS_FILE: &str = "commitments.bin";
const SIGNATURE_SHARE_FILE: &str = "signature_share.bin";

pub fn state_dir() -> PathBuf {
    PathBuf::from(STATE_DIR)
}

pub fn participant_dir(id: u16) -> PathBuf {
    state_dir().join(format!("participant_{id}"))
}

fn pubkey_package_path() -> PathBuf {
    state_dir().join(PUBKEY_PACKAGE_FILE)
}

fn threshold_path() -> PathBuf {
    state_dir().join(THRESHOLD_FILE)
}

fn write_bin<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let bytes = bincode::serde::encode_to_vec(value, bincode::config::standard())
        .with_context(|| format!("encoding {}", path.display()))?;
    fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn read_bin<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let (value, _) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
        .with_context(|| format!("decoding {}", path.display()))?;
    Ok(value)
}

pub fn save_pubkey_package(pkg: &PublicKeyPackage) -> Result<()> {
    write_bin(&pubkey_package_path(), pkg)
}

pub fn load_pubkey_package() -> Result<PublicKeyPackage> {
    read_bin(&pubkey_package_path())
}

pub fn save_threshold(min_signers: u16, max_signers: u16) -> Result<()> {
    let dir = state_dir();
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = threshold_path();
    fs::write(&path, format!("{min_signers}/{max_signers}\n"))
        .with_context(|| format!("writing {}", path.display()))
}

pub fn save_key_package(id: u16, pkg: &KeyPackage) -> Result<()> {
    write_bin(&participant_dir(id).join(KEY_PACKAGE_FILE), pkg)
}

pub fn load_key_package(id: u16) -> Result<KeyPackage> {
    read_bin(&participant_dir(id).join(KEY_PACKAGE_FILE))
}

pub fn save_nonces(id: u16, nonces: &SigningNonces) -> Result<()> {
    write_bin(&participant_dir(id).join(NONCES_FILE), nonces)
}

pub fn load_nonces(id: u16) -> Result<SigningNonces> {
    read_bin(&participant_dir(id).join(NONCES_FILE))
}

/// Deletes the secret nonces file after producing the signing share.
/// FROST nonces must never be reused, so we delete on first use.
/// No zero-fill: on CoW/SSD filesystems sectors are not rewritten.
pub fn delete_nonces(id: u16) -> Result<()> {
    let path = participant_dir(id).join(NONCES_FILE);
    if !path.exists() {
        return Ok(());
    }
    fs::remove_file(&path).with_context(|| format!("deleting nonces file {}", path.display()))
}

pub fn save_commitments(id: u16, commitments: &SigningCommitments) -> Result<()> {
    write_bin(&participant_dir(id).join(COMMITMENTS_FILE), commitments)
}

pub fn load_commitments(id: u16) -> Result<SigningCommitments> {
    read_bin(&participant_dir(id).join(COMMITMENTS_FILE))
}

pub fn save_signature_share(id: u16, share: &SignatureShare) -> Result<()> {
    write_bin(&participant_dir(id).join(SIGNATURE_SHARE_FILE), share)
}

pub fn load_signature_share(id: u16) -> Result<SignatureShare> {
    read_bin(&participant_dir(id).join(SIGNATURE_SHARE_FILE))
}

fn participant_ids() -> Result<Vec<u16>> {
    let dir = state_dir();
    if !dir.exists() {
        return Err(anyhow!(
            "state directory `{}` does not exist; run `setup` first",
            dir.display()
        ));
    }
    let mut ids: Vec<u16> = fs::read_dir(&dir)
        .with_context(|| format!("listing {}", dir.display()))?
        .filter_map(|entry| {
            entry
                .ok()?
                .file_name()
                .to_str()?
                .strip_prefix("participant_")?
                .parse::<u16>()
                .ok()
                .filter(|&id| id != 0)
        })
        .collect();
    ids.sort_unstable();
    Ok(ids)
}

/// Loads all round-1 commitments from disk, keyed by `Identifier`.
/// Used by `sign` to build the FROST `SigningPackage`.
pub fn collect_commitments() -> Result<BTreeMap<Identifier, SigningCommitments>> {
    participant_ids()?
        .into_iter()
        .filter(|&id| participant_dir(id).join(COMMITMENTS_FILE).exists())
        .map(|id| {
            Ok((
                Identifier::try_from(id).expect("nonzero"),
                load_commitments(id)?,
            ))
        })
        .collect()
}

/// Loads all (commitment, signature share) pairs currently on disk.
/// Only participants who completed both `commit` and `sign` are included.
/// Used by `prove` to assemble the `FrostPayload`.
pub fn collect_signers() -> Result<Vec<(u16, Identifier, SigningCommitments, SignatureShare)>> {
    participant_ids()?
        .into_iter()
        .filter(|&id| {
            let dir = participant_dir(id);
            dir.join(COMMITMENTS_FILE).exists() && dir.join(SIGNATURE_SHARE_FILE).exists()
        })
        .map(|id| {
            let ident = Identifier::try_from(id).expect("nonzero");
            Ok((id, ident, load_commitments(id)?, load_signature_share(id)?))
        })
        .collect()
}
