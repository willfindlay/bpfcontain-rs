use std::path::Path;

use anyhow::{bail, Context as _, Result};
use clap::ArgMatches;

use crate::config::Settings;
use crate::policy::Policy;

use bpfcontain_uprobes::do_apply_policy_to_container;

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
    let pid = args.value_of("pid").unwrap();

    // Parse policy
    let policy = Policy::from_path(path).context("Failed to parse policy")?;

    println!("Applying policy now {:#?} {:#?}", pid, policy_name);

    println!("Policy Id {:#?}", policy.policy_id());
   // call into a function which provies the policy id and pid

   let mut ret: i32 = -libc::EAGAIN;

   // Call into uprobe
   do_apply_policy_to_container(&mut ret as *mut i32, pid.parse::<u64>()?, policy.policy_id());

   match ret {
       0 => Ok(()),
       n if n == -libc::EAGAIN => bail!("Failed to call into uprobe. Is BPFContain running?"),
       n if n == -libc::ENOENT => bail!(
           "No such policy {}:{}. Has your policy been loaded?",
           policy_name,
           policy.policy_id()
       ),
       n if n == -libc::ESRCH => bail!("No containers found for that pid, are you sure the container is running and the daemon is started?"),
       n if n == -libc::EINVAL => bail!("Something went wrong when updating the container policy in the map. Please report an issue to the maintainers."),
       n => bail!("Unknown error: {}", n),
   }
}