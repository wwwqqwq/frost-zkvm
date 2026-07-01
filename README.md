# frost-zkvm

FROST-Ed25519 threshold signing, proved in a zkVM. Backends: **sp1**, **risc0**, **jolt**.

Guest aggregates signature shares. Public output: `msg_hash || group_pubkey || signature`.

## Layout

```
core/     wire types + ceremony (setup/commit/sign/storage)
sp1/      guest + host
risc0/    guest + host
jolt/     guest + host
state/    shared ceremony data 
```

## Commands

```sh
just build sp1
just demo sp1                  # setup → commit → sign → prove
just execute sp1               # guest only, print cycles
just prove sp1 groth16         # proof type: core | compressed | groth16

just demo risc0
just demo jolt
```

Same ceremony for all backends. Swap `sp1` for `risc0` or `jolt`.

Outer gnark circuit aggregates inner Groth16 proofs (2-of-3: SP1 + RISC0 + dummy(Jolt in the future) slot).

```sh
just dump-aggregator

just aggregator-setup
just aggregator-prove
just aggregator-verify
```