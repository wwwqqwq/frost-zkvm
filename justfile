set shell := ["bash", "-cu"]

export FROST_REPO_ROOT := justfile_directory()

INNER_SP1    := "aggregator/inner/sp1"
INNER_RISC0  := "aggregator/inner/risc0"
OUTER_SETUP  := "aggregator/outer/setup"
OUTER_PROOF  := "aggregator/outer/proof"
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

dump-aggregator MSG=MSG: (build "sp1") (build "risc0")
    just clean-state
    just setup sp1 2 3
    just commit sp1 1
    just commit sp1 2
    just sign sp1 1 "{{MSG}}"
    just sign sp1 2 "{{MSG}}"
    cd sp1 && ./target/release/host prove "{{MSG}}" --proof-type groth16 --dump-dir {{FROST_REPO_ROOT}}/{{INNER_SP1}}
    cd risc0 && ./target/release/host prove "{{MSG}}" --proof-type groth16 --dump-dir {{FROST_REPO_ROOT}}/{{INNER_RISC0}}

aggregator-setup sp1=INNER_SP1 risc0=INNER_RISC0 setup=OUTER_SETUP:
    cd aggregator && go run . setup-outer \
      --sp1-dir {{FROST_REPO_ROOT}}/{{sp1}} \
      --risc0-dir {{FROST_REPO_ROOT}}/{{risc0}} \
      --outer-setup {{FROST_REPO_ROOT}}/{{setup}}

aggregator-prove sp1=INNER_SP1 risc0=INNER_RISC0 setup=OUTER_SETUP proof=OUTER_PROOF:
    cd aggregator && go run . prove \
      --sp1-dir {{FROST_REPO_ROOT}}/{{sp1}} \
      --risc0-dir {{FROST_REPO_ROOT}}/{{risc0}} \
      --outer-setup {{FROST_REPO_ROOT}}/{{setup}} \
      --outer-proof {{FROST_REPO_ROOT}}/{{proof}}

aggregator-verify proof=OUTER_PROOF:
    cd aggregator && go run . verify --outer-proof {{FROST_REPO_ROOT}}/{{proof}}
