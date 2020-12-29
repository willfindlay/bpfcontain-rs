use anyhow::Result;
use clap::ArgMatches;

pub fn main(args: &ArgMatches) -> Result<()> {
    println!("Hello daemon world! My args are: {:?}", args);

    Ok(())
}
