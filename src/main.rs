use clap::Parser;
use std::io::Write;

use crate::config::{ConfigCliOverride, Environment};

mod config;
mod state;
mod oidc;
mod ssh;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, global = true, help = "Enable verbose output")]
    verbose: bool,
    #[command(subcommand)]
    command: ssh::Commands,
    #[arg(long, global = true, value_enum, hide = true)]
    pub env: Option<Environment>,
    #[command(flatten)]
    pub config_overrides: ConfigCliOverride,
}

fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .format(|buf, record| {
            writeln!(buf, "{}", record.args())
        })
        .init();

    let cli = Cli::parse();

    let config = config::Config::load(cli.env, &cli.config_overrides)?;

    if cli.verbose {
        println!("Verbose output ...");
    }

    ssh::run(&cli.command, &config)?;

    Ok(())
}
