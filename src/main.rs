use clap::Parser;
use clap_verbosity_flag::{Verbosity, InfoLevel};
use std::io::Write;

use crate::config::{ConfigCliOverride, Environment};

mod config;
mod state;
mod oidc;
mod ssh;
mod completion;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,
    #[command(subcommand)]
    command: ssh::Commands,
    #[arg(long, global = true, value_enum, hide = true)]
    pub env: Option<Environment>,
    #[command(flatten)]
    pub config_overrides: ConfigCliOverride,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    env_logger::Builder::new()
        .filter_level(cli.verbose.log_level_filter())
        .filter_module("reqwest", log::LevelFilter::Warn) // Keep reqwest quiet
        .filter_module("openidconnect", log::LevelFilter::Warn) // Keep auth quiet
        .format(|buf, record| {
            writeln!(buf, "{}", record.args())
        })
        .init();

    let config = config::Config::load(cli.env, &cli.config_overrides)?;

    ssh::run(&cli.command, &config)?;

    Ok(())
}
