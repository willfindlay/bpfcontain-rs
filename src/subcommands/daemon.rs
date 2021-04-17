// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use std::fs::{create_dir_all, metadata, set_permissions, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::thread::sleep;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::ArgMatches;
use daemonize::Daemonize;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

use crate::bpf_program::work_loop;
use crate::config::Settings;

pub fn main(args: &ArgMatches, config: &Settings) -> Result<()> {
    // Initialize the logger
    crate::log::configure(
        config.daemon.verbosity,
        Some(config.daemon.log_file.as_str()),
    )?;

    // Run the correct subcommand
    let result = match args.subcommand() {
        ("start", Some(args)) => start_daemon(args, config),
        ("restart", Some(args)) => restart_daemon(args, config),
        ("stop", Some(_)) => stop_daemon(config),
        ("foreground", Some(args)) => run_in_foreground(args, config),
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
fn run_in_foreground(args: &ArgMatches, config: &Settings) -> Result<()> {
    log::info!("Running in the foreground...");

    work_loop(args, config)
}

/// Starts the daemon.
fn start_daemon(args: &ArgMatches, config: &Settings) -> Result<()> {
    log::info!("Starting daemon...");

    let workdir = &config.daemon.work_dir;
    let pidfile = &config.daemon.pid_file;

    // Create workdir and set permissions to rwxr-xr-t
    create_dir_all(workdir).context("Failed creating policy directory")?;
    let mut perms = metadata(workdir)
        .context("Failed getting policy directory permissions")?
        .permissions();
    perms.set_mode(0o1755);
    set_permissions(workdir, perms).context("Failed setting policy directory permissions")?;

    // Set up the daemon
    let daemonize = Daemonize::new()
        .pid_file(pidfile)
        .working_directory(workdir)
        .exit_action(|| log::info!("Started the daemon!"));

    // Try to start the daemon
    match daemonize.start() {
        Ok(_) => log::info!("Started the daemon!"),
        Err(e) => {
            bail!("Failed to start the daemon: {}", e);
        }
    }

    work_loop(args, config)
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
    if let Err(e) = kill(Pid::from_raw(pid), Signal::SIGINT) {
        bail!("Failed to kill daemon: {}", e);
    }

    Ok(())
}

/// Restarts the daemon by invoking [`stop_daemon`] followed by
/// [`start_daemon`]. [`stop_daemon`] is allowed to fail with a warning.
///
/// FIXME: This is racy because we need to wait for the pidfile to be unlocked
/// before we can start the daemon. As a crude workaround, we currently
/// sleep for a few seconds after a successful call to [`stop_daemon`].
///
/// This behaviour should be changed in future versions to wait for the file to
/// be unlocked.
fn restart_daemon(args: &ArgMatches, config: &Settings) -> Result<()> {
    log::info!("Restarting daemon...");

    // Try to stop the daemon
    match stop_daemon(config) {
        Ok(_) => {
            // FIXME: Should poll to see if the process has actually stopped
            sleep(Duration::new(3, 0));
        }
        Err(e) => {
            log::warn!(
                "Unable to stop the daemon while restarting (daemon may not be running): {}",
                e
            );
        }
    }

    // Start the daemon
    start_daemon(args, config)
}
