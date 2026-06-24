set shell := ["bash", "-cu"]

export FROST_REPO_ROOT := justfile_directory()

THRESHOLD := "3"
TOTAL     := "5"
ID        := "1"
MSG       := "hello, frost"
PROOF     := "core"

default:
    @just --list

# --- commands ------

clean-state:
    rm -rf {{FROST_REPO_ROOT}}/state

clean: clean-state
    cd sp1 && cargo clean
    cd risc0 && cargo clean
    cd jolt && cargo clean

build backend:
    cd {{backend}} && cargo build --release -p host

setup backend THRESHOLD=THRESHOLD TOTAL=TOTAL: (build backend)
    cd {{backend}} && ./target/release/host setup {{THRESHOLD}} {{TOTAL}}

commit backend ID=ID: (build backend)
    cd {{backend}} && ./target/release/host commit {{ID}}

sign backend ID=ID MSG=MSG: (build backend)
    cd {{backend}} && ./target/release/host sign {{ID}} "{{MSG}}"

execute backend MSG=MSG: (build backend)
    cd {{backend}} && ./target/release/host prove "{{MSG}}" --execute-only

prove backend PROOF=PROOF MSG=MSG: (build backend)
    cd {{backend}} && ./target/release/host prove "{{MSG}}" --proof-type {{PROOF}}

demo backend MSG=MSG PROOF=PROOF: (build backend)
    just clean-state
    just setup {{backend}} 3 5
    just commit {{backend}} 1
    just commit {{backend}} 2
    just commit {{backend}} 4
    just sign {{backend}} 1 "{{MSG}}"
    just sign {{backend}} 2 "{{MSG}}"
    just sign {{backend}} 4 "{{MSG}}"
    just prove {{backend}} {{PROOF}} "{{MSG}}"
