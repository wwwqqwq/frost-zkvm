//! `sign {id} {message}`: round-2 of FROST signing.
//!
//! Collects the round-1 commitments of *every* participant who has already
//! committed, builds a `SigningPackage`, and produces this participant's
//! signature share.
//!

use anyhow::{anyhow, Context, Result};
use frost_ed25519 as frost;

use crate::storage;

pub fn run(id: u16, message: String) -> Result<()> {
    let key_package = storage::load_key_package(id)
        .with_context(|| format!("participant {id}: missing key package"))?;
    let nonces = storage::load_nonces(id)
        .with_context(|| format!("participant {id}: missing nonces; run `commit {id}` first"))?;

    let commitments = storage::collect_commitments()?;
    if commitments.is_empty() {
        return Err(anyhow!(
            "no round-1 commitments found on disk; every signer must run `commit` first"
        ));
    }

    let signing_package = frost::SigningPackage::new(commitments, message.as_bytes());
    let signature_share = frost::round2::sign(&signing_package, &nonces, &key_package)
        .with_context(|| format!("participant {id}: round-2 sign"))?;

    storage::save_signature_share(id, &signature_share)?;
    storage::delete_nonces(id)
        .with_context(|| format!("participant {id}: failed to delete nonces"))?;

    println!("sign: participant {id}, message {message:?} (nonces wiped)");
    Ok(())
}
