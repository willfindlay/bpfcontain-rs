use anyhow::{bail, Result};
use clap::{App, AppSettings, Arg, SubCommand};

mod subcommands;
use subcommands::daemon;

fn main() -> Result<()> {
    let app = App::new("BPFContain")
        .version("0.0.1")
        .about("TODO: description here")
        .author("William Findlay <william@williamfindlay.com>")
        .setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp)
        .subcommand(SubCommand::with_name("daemon").about("Control the BPFContain daemon."));

    let args = app.get_matches();

    if let Some(subargs) = args.subcommand_matches("daemon") {
        return daemon::main(subargs);
    }

    Ok(())
}
