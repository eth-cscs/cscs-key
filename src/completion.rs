use clap::{Args, CommandFactory};
use clap_complete::{generate, Shell};
use log::{info, trace};

#[derive(Args, Debug)]
pub struct CompletionArgs {
    #[arg(value_enum)]
    pub shell: Shell,
}

pub fn generate_completion(args: &CompletionArgs) -> anyhow::Result<()> {
    trace!("completion subcommand");
    trace!("{:?}", args);

    let shell = args.shell;
    let mut cmd = crate::Cli::command();
    let bin_name = cmd.get_name().to_string();

    info!("Generating {} completion script.", shell);
    generate(shell, &mut cmd, bin_name, &mut std::io::stdout());

    Ok(())
}
