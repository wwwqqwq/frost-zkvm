# FROST-Ed25519 Threshold Signatures, Aggregated Inside SP1

End-to-end Rust workspace that implements FROST-Ed25519 threshold signing and
proves the aggregation step inside the [SP1](https://github.com/succinctlabs/sp1)
zkVM. The result is a 128-byte public-output blob — `msg_hash || group_pubkey ||
signature` — together with a SNARK that convinces any verifier the aggregate
was computed honestly, without ever revealing the per-signer secret shares.

## Architecture

```
┌────────────┐  bincode(FrostPayload)   ┌───────────────────────┐
│   host     │ ────────────────────────►│       guest (SP1)     │
│ coordinator│                          │  frost::aggregate +   │
│  + prover  │ ◄────────────────────────│  vk.verify + commit   │
└────────────┘   128 B public values    └───────────────────────┘
```

| Crate    | Role                                                                |
|----------|---------------------------------------------------------------------|
| `shared` | `FrostPayload` (input) + `ProofOutputs` (output) wire formats.      |
| `guest`  | SP1 RISC-V circuit. Aggregates shares, asserts the verify, commits. |
| `host`   | clap CLI: drives the 3-round Pedersen-VSS DKG, both signing rounds, and the prover. |

State is persisted to `state/` between commands so the demo is trivially
scriptable from `bash`. The secret nonces file is **deleted** the moment a
share is produced — re-using a FROST nonce across two messages leaks the
private signing share.

## Requirements

- [Rust](https://rustup.rs/) (stable, see `rust-toolchain`)
- [SP1 toolchain](https://docs.succinct.xyz/docs/sp1/getting-started/install) — `sp1up` + `cargo prove`

## Build

The host crate's `build.rs` invokes `cargo prove build` on the guest
automatically the first time you compile, but you can also build the guest
ELF by hand:

```sh
# Build the SP1 guest ELF (RISC-V, optimized).
cargo prove build --manifest-path guest/Cargo.toml

# Build the host CLI (release recommended for proving).
cargo build --release -p host
```

## End-to-End Walkthrough (3-of-5 demo)

```sh
# 0. Optional: copy environment defaults (cpu | cuda | network).
cp .env.example .env

# 1. Pedersen-VSS DKG: 5 participants run the 3-round protocol, threshold = 3.
cargo run --release -p host -- setup 3 5

# 2. Round-1 commitments. Three signers is enough; the threshold is 3.
cargo run --release -p host -- commit 1
cargo run --release -p host -- commit 2
cargo run --release -p host -- commit 4

# 3. Round-2 signature shares. Each `sign` call destroys the secret nonces.
cargo run --release -p host -- sign 1 "hello, frost"
cargo run --release -p host -- sign 2 "hello, frost"
cargo run --release -p host -- sign 4 "hello, frost"

# 4. Aggregate + prove inside SP1. Pick the proof type you want:
cargo run --release -p host -- prove "hello, frost" --proof-type core
cargo run --release -p host -- prove "hello, frost" --proof-type compressed
cargo run --release -p host -- prove "hello, frost" --proof-type groth16
```

The `prove` command first calls `client.execute(...)` and prints
`report.total_instruction_count()` — that's your circuit's RISC-V cycle
budget. It then generates the proof, verifies it locally, decodes the
128-byte public-values blob and confirms that the committed message hash
matches the one you asked it to sign.

## Using the Prover Network

```sh
SP1_PROVER=network NETWORK_PRIVATE_KEY=0x... \
  cargo run --release -p host -- prove "hello, frost" --proof-type groth16
```

See the [Succinct quickstart](https://docs.succinct.xyz/docs/sp1/prover-network/quickstart)
for key setup.
