use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    pub fn get_cli() -> Self {
        Self::parse()
    }
}

#[derive(Subcommand)]
pub enum Command {
    /// Generate an ed25519 keypair
    Keygen,
    /// Generate the static site
    Build(BuildArgs),
}

#[derive(Args)]
pub struct BuildArgs {
    /// Output directory
    #[arg(long, default_value = "dist/v1")]
    pub out: PathBuf,

    /// How many calendar years of future transitions to include
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u16).range(1..=100))]
    pub years: u16,

    /// Sign every file with ed25519 (needs a signing key). Without it the
    /// trailer carries the hash only and "sig" is null
    #[arg(long)]
    pub sign: bool,

    /// Base64 ed25519 private key (32 bytes). Prefer the environment variable
    /// or --signing-key-file so the key stays out of the process list.
    #[arg(
        long,
        env = "TZ_SIGNING_KEY",
        hide_env_values = true,
        conflicts_with = "signing_key_file"
    )]
    pub signing_key: Option<String>,

    /// File containing the base64 ed25519 private key (surrounding whitespace is ignored)
    #[arg(long, env = "TZ_SIGNING_KEY_FILE")]
    pub signing_key_file: Option<PathBuf>,

    /// Use this directory of compiled TZif files instead of downloading
    #[arg(long)]
    pub tzdata_dir: Option<PathBuf>,

    /// Use the database compiled into this binary (build with `--features tzdata-bundled`)
    #[arg(long, conflicts_with = "tzdata_dir")]
    pub tzdata_bundled: bool,

    /// Where downloaded databases are cached
    #[arg(long, default_value = ".tzdata-cache")]
    pub cache_dir: PathBuf,
}
