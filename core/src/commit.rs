//! `commit {id}`: FROST signing round 1.
//!
//! Loads the participant's KeyPackage, generates fresh nonces and
//! commitments, and stores both to disk for the subsequent `sign`.

use anyhow::{Context, Result};
use frost_ed25519 as frost;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::storage;

pub fn run(id: u16) -> Result<()> {
    let key_package = storage::load_key_package(id)
        .with_context(|| format!("participant {id}: missing key package; run `setup` first"))?;

    let mut rng = ChaCha20Rng::from_entropy();
    let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);

    storage::save_nonces(id, &nonces)?;
    storage::save_commitments(id, &commitments)?;

    println!(
        "commit: participant {id} -> {}",
        storage::participant_dir(id).display()
    );
    Ok(())
}
