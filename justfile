# FROST-Ed25519 ⨉ SP1 — task runner.
#
#   $ just            # list every recipe
#   $ just demo       # full 3-of-5 walkthrough end-to-end
#
# Anything in UPPER_CASE is a positional / env override:
#   $ just commit ID=2
#   $ just sign   ID=2 MSG="hello, frost"
#   $ just prove  MSG="hello, frost" PROOF=groth16
#
# Pick a real prover backend in `.env` or per-recipe (cpu | cuda | network):
#   $ SP1_PROVER=cpu     just prove
#   $ SP1_PROVER=network NETWORK_PRIVATE_KEY=0x... just prove

set shell := ["bash", "-cu"]
set dotenv-load := true

# --- knobs you might want to override on the command line --------------------
THRESHOLD  := "3"
TOTAL      := "5"
ID         := "1"
MSG        := "hello, frost"
PROOF      := "core"          # core | compressed | groth16
HOST       := "./target/release/host"

default:
    @just --list

build:
    cargo build --release -p host

check:
    cargo check --workspace

lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Pedersen-VSS DKG (THRESHOLD-of-TOTAL).
setup THRESHOLD=THRESHOLD TOTAL=TOTAL: build
    {{HOST}} setup {{THRESHOLD}} {{TOTAL}}

# Round-1: participant ID generates and stores a fresh nonce/commitment pair.
commit ID=ID: build
    {{HOST}} commit {{ID}}

# Round-2: participant ID produces a signature share over MSG.
# Secret nonces file is destroyed afterwards.
sign ID=ID MSG=MSG: build
    {{HOST}} sign {{ID}} "{{MSG}}"

# Aggregate every share on disk and prove inside SP1.
prove MSG=MSG PROOF=PROOF: build
    {{HOST}} prove "{{MSG}}" --proof-type {{PROOF}}

# 3-of-5 demo: setup → commit (1, 2, 4) → sign (1, 2, 4) → prove.
demo MSG=MSG PROOF=PROOF: build
    rm -rf state
    {{HOST}} setup 3 5
    {{HOST}} commit 1
    {{HOST}} commit 2
    {{HOST}} commit 4
    {{HOST}} sign 1 "{{MSG}}"
    {{HOST}} sign 2 "{{MSG}}"
    {{HOST}} sign 4 "{{MSG}}"
    {{HOST}} prove "{{MSG}}" --proof-type {{PROOF}}

# Wipe coordinator state (secret shares, nonces, commitments).
clean-state:
    rm -rf state

# Wipe everything: state + cargo target.
clean: clean-state
    cargo clean
