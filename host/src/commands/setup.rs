//! `setup`: run a Pedersen-VSS distributed key generation (DKG).
//!
//! Drives all 3 rounds of `frost::keys::dkg` for every participant in-process.
//! Output: per-participant `KeyPackage`s + a shared `PublicKeyPackage` (the
//! group verifying key).
//!
//! Simulated ceremony: in production each participant runs their own instance
//! and exchanges round-1 commitments and round-2 shares over secure channels.

use std::collections::BTreeMap;

use anyhow::{anyhow, Context, Result};
use frost_ed25519::{
    keys::{dkg, PublicKeyPackage},
    Identifier,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::storage;

pub fn run(min_signers: u16, max_signers: u16) -> Result<()> {
    if min_signers < 2 {
        return Err(anyhow!("threshold must be >= 2"));
    }
    if min_signers > max_signers {
        return Err(anyhow!(
            "threshold ({min_signers}) cannot exceed total participants ({max_signers})"
        ));
    }

    let mut rng = ChaCha20Rng::from_entropy();

    // Pair numeric ids 1..=N with their frost Identifier; try_from only fails for 0.
    let participants: Vec<(u16, Identifier)> = (1..=max_signers)
        .map(|id| (id, Identifier::try_from(id).expect("id >= 1")))
        .collect();

    // Round 1: pick a random polynomial; broadcast its commitment vector +
    // Schnorr PoK, keep the secret polynomial local.
    let mut round1_secrets: BTreeMap<Identifier, dkg::round1::SecretPackage> = BTreeMap::new();
    let mut round1_packages: BTreeMap<Identifier, dkg::round1::Package> = BTreeMap::new();
    for &(_, ident) in &participants {
        let (secret, package) = dkg::part1(ident, max_signers, min_signers, &mut rng)
            .with_context(|| format!("DKG round 1 for {ident:?}"))?;
        round1_secrets.insert(ident, secret);
        round1_packages.insert(ident, package);
    }

    // Round 2: verify other participants' PoKs and produce one secret packet
    // per recipient, to be delivered privately.
    let mut round2_secrets: BTreeMap<Identifier, dkg::round2::SecretPackage> = BTreeMap::new();
    // For each recipient j: { sender_i -> packet_for_j_from_i }
    let mut round2_inbox: BTreeMap<Identifier, BTreeMap<Identifier, dkg::round2::Package>> =
        BTreeMap::new();

    for &(_, sender) in &participants {
        let secret = round1_secrets
            .remove(&sender)
            .expect("every participant ran round 1");
        let own_pkg = round1_packages
            .remove(&sender)
            .expect("every participant ran round 1");
        let result = dkg::part2(secret, &round1_packages)
            .with_context(|| format!("DKG round 2 for {sender:?}"));
        round1_packages.insert(sender, own_pkg);
        let (round2_secret, packages_to_send) = result?;

        round2_secrets.insert(sender, round2_secret);
        for (recipient, pkg) in packages_to_send {
            round2_inbox
                .entry(recipient)
                .or_default()
                .insert(sender, pkg);
        }
    }

    // Round 3: verify received shares against broadcast commitments, output
    // our final KeyPackage and the (shared) PublicKeyPackage.
    let mut public_key_package_out: Option<PublicKeyPackage> = None;
    for &(numeric_id, ident) in &participants {
        let secret = round2_secrets
            .get(&ident)
            .expect("every participant ran round 2");
        let own_pkg = round1_packages
            .remove(&ident)
            .expect("every participant ran round 1");
        let received_round2 = round2_inbox.remove(&ident).unwrap_or_default();
        let result = dkg::part3(secret, &round1_packages, &received_round2)
            .with_context(|| format!("DKG round 3 for {ident:?}"));
        round1_packages.insert(ident, own_pkg);
        let (key_package, public_key_package) = result?;

        storage::save_key_package(numeric_id, &key_package)?;
        public_key_package_out.get_or_insert(public_key_package);
    }

    let pubkey_package =
        public_key_package_out.ok_or_else(|| anyhow!("DKG completed with zero participants"))?;
    storage::save_pubkey_package(&pubkey_package)?;
    storage::save_threshold(min_signers, max_signers)?;

    let group_vk_bytes = pubkey_package
        .verifying_key()
        .serialize()
        .context("serializing group verifying key")?;
    println!(
        "dkg ok: {min_signers}-of-{max_signers}, group_key=0x{}",
        hex::encode(group_vk_bytes)
    );
    println!("state -> {}", storage::state_dir().display());
    Ok(())
}
