// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! The `daemon` subcommand.

use std::fs::{create_dir_all, metadata, set_permissions, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;

use anyhow::{bail, Context, Result};
use clap::ArgMatches;
use daemonize::Daemonize;
use fs2::FileExt as _;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

use crate::bpf_program::work_loop;
use crate::config::Settings;

/// Main entrypoint into the daemon.
pub fn main(args: &ArgMatches, config: &Settings) -> Result<()> {
    // Initialize the logger
    crate::log::configure(
        config.daemon.verbosity,
        Some(config.daemon.log_file.as_str()),
    )?;

    // Pretty print current config
    log::debug!("{:#?}", config);

    // Run the correct subcommand
    let result = match args.subcommand() {
        ("start", _) => start_daemon(config),
        ("restart", _) => restart_daemon(config),
        ("stop", _) => stop_daemon(config),
        ("foreground", _) => run_in_foreground(config),
        (unknown, _) => bail!("Unknown subcommand {}", unknown),
    };

    // Log results and exit with error code
    if let Err(e) = result {
        log::error!("{:?}", e);
        std::process::exit(1);
    }

    Ok(())
}

/// Run in the foreground.
fn run_in_foreground(config: &Settings) -> Result<()> {
    log::info!("Running in the foreground...");

    work_loop(config)
}

/// Starts the daemon.
fn start_daemon(config: &Settings) -> Result<()> {
    let workdir = &config.daemon.work_dir;
    let pidfile = &config.daemon.pid_file;

    // Create workdir and set permissions to rwxr-xr-t
    create_dir_all(workdir).context("Failed creating policy directory")?;
    let mut perms = metadata(workdir)
        .context("Failed getting policy directory permissions")?
        .permissions();
    perms.set_mode(0o1755);
    set_permissions(workdir, perms).context("Failed setting policy directory permissions")?;

    // Make sure the file is unlocked
    log::info!("Waiting for lock on {}...", pidfile);
    let f = OpenOptions::new()
        .write(true)
        .read(true)
        .create(true)
        .open(pidfile)
        .context("Failed to open pid file")?;
    f.lock_exclusive().context("Failed to acquire file lock")?;
    f.unlock().context("Failed to release lock")?;

    // Set up the daemon
    let daemonize = Daemonize::new()
        .pid_file(pidfile)
        .working_directory(workdir)
        .exit_action(|| log::info!("Started the daemon!"));

    // Try to start the daemon
    log::info!("Starting daemon...");
    daemonize.start().context("Failed to start the daemon")?;

    work_loop(config)
}

/// Stops the daemon by parsing the daemon's [`PIDFILE`] and sending a `SIGTERM`
/// using kill(2).
fn stop_daemon(config: &Settings) -> Result<()> {
    log::info!("Stopping daemon...");

    let pidfile = &config.daemon.pid_file;

    // Parse pid from pidfile
    let pid: i32 = {
        // Open pidfile for reading
        let mut pidfile = match File::open(pidfile) {
            Ok(file) => file,
            Err(e) => bail!("Failed to open pidfile: {}", e),
        };

        // Read contents of pidfile
        let mut contents = String::new();
        match pidfile.read_to_string(&mut contents) {
            Ok(_) => {}
            Err(e) => bail!("Unable to read pidfile: {}", e),
        };

        // Parse contents into a pid
        match contents.parse() {
            Ok(pid) => pid,
            Err(e) => bail!("Failed to parse pid: {}", e),
        }
    };

    // Invoke kill(2) to send a SIGTERM to the process running under pid
    kill(Pid::from_raw(pid), Signal::SIGINT).context("Failed to kill the daemon")?;

    Ok(())
}

/// Restarts the daemon by invoking [`stop_daemon`] followed by
/// [`start_daemon`]. [`stop_daemon`] is allowed to fail with a warning.
fn restart_daemon(config: &Settings) -> Result<()> {
    log::info!("Restarting daemon...");

    // Try to stop the daemon
    if let Err(e) = stop_daemon(config) {
        log::warn!(
            "Unable to stop the daemon while restarting (daemon may not be running): {}",
            e
        );
    }

    // Start the daemon
    start_daemon(config)
}
