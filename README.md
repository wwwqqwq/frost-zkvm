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

Manual steps: `just setup`, `just commit`, `just sign`, `just prove`.

