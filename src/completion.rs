use clap::{Args, CommandFactory};
use clap_complete::{Shell, generate};
use log::{debug, trace};

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

    debug!("Generating {} completion script.", shell);
    generate(shell, &mut cmd, bin_name, &mut std::io::stdout());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bash_completion_includes_browser_option_and_values() {
        let mut cmd = crate::Cli::command();
        let bin_name = cmd.get_name().to_string();
        let mut output = Vec::new();

        generate(Shell::Bash, &mut cmd, bin_name, &mut output);

        let completion = String::from_utf8(output).expect("completion output should be UTF-8");
        assert!(completion.contains("--browser"));
        assert!(completion.contains("firefox chrome safari edge opera"));
    }
}
