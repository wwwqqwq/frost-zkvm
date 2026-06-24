use anyhow::Result;
use clap::{Parser, Subcommand};
use frost_core::{commit, setup, sign};

mod prove;

use prove::ProofType;

#[derive(Parser, Debug)]
#[command(
    name = "host",
    author,
    version,
    about = "FROST-Ed25519 threshold-signature aggregation, proven inside RISC Zero.",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Setup {
        threshold: u16,
        total: u16,
    },
    /// Round-1: generate this participant's nonce/commitment pair.
    Commit {
        id: u16,
    },
    /// Round-2: produce this participant's signature share over `message`.
    Sign {
        id: u16,
        message: String,
    },
    /// Aggregate every signature share on disk and prove the result inside RISC Zero.
    Prove {
        message: String,
        #[arg(long, value_enum, default_value_t = ProofType::Core)]
        proof_type: ProofType,
        #[arg(long)]
        execute_only: bool,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    match Cli::parse().command {
        Command::Setup { threshold, total } => setup::run(threshold, total),
        Command::Commit { id } => commit::run(id),
        Command::Sign { id, message } => sign::run(id, message),
        Command::Prove {
            message,
            proof_type,
            execute_only,
        } => prove::run(message, proof_type, execute_only),
    }
}
