use anyhow::{Context as _, Result};

use crate::{bindings, policy::Policy};

/// Main entrypoint into launching a container.
pub fn main(policy_file: &str, pid: u32) -> Result<()> {
    // Parse policy
    let policy = Policy::from_path(policy_file).context("Failed to parse policy")?;

    log::info!("Applying policy {}({})...", policy.name, policy.policy_id());
    bindings::ioctl::confine(policy.policy_id(), Some(pid))
}
