use std::path::Path;

use anyhow::{Context as _, Result};
use clap::ArgMatches;

use crate::{bindings, config::Settings, policy::Policy};

/// Main entrypoint into launching a container.
pub fn main(args: &ArgMatches, config: &Settings) -> Result<()> {
    // Initialize the logger
    // We don't want to log to any file, just stderr
    crate::log::configure(config.daemon.verbosity, None)?;

    // Pretty print current config
    log::debug!("{:#?}", config);

    // Configure policy path
    let policy_dir = Path::new(&config.policy.dir);
    let policy_file = Path::new(
        args.value_of("policy")
            .context("Failed to get path to policy file")?,
    );
    let path = policy_dir.join(policy_file);

    let policy_name = args.value_of("policy").unwrap();
    let pid = args
        .value_of("pid")
        .unwrap()
        .parse::<u32>()
        .context("Failed to parse pid")?;

    // Parse policy
    let policy = Policy::from_path(path).context("Failed to parse policy")?;

    log::info!("Applying policy {}({})...", policy_name, policy.policy_id());
    bindings::ioctl::confine(policy.policy_id(), Some(pid))

    // match ret {
    //    0 => Ok(()),
    //    n if n == -libc::EAGAIN => bail!("Failed to call into uprobe. Is BPFContain running?"),
    //    n if n == -libc::ENOENT => bail!(
    //        "No such policy {}:{}. Has your policy been loaded?",
    //        policy_name,
    //        policy.policy_id()
    //    ),
    //    n if n == -libc::ESRCH => bail!("No containers found for that pid, are you sure the container is running and the daemon is started?"),
    //    n if n == -libc::EINVAL => bail!("Something went wrong when updating the container policy in the map. Please report an issue to the maintainers."),
    //    n => bail!("Unknown error: {}", n),
    // }
}
