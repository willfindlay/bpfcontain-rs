use anyhow::{bail, Result};
use clap::ArgMatches;
use daemonize::Daemonize;
use std::fs::{create_dir_all, metadata, set_permissions, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;

static PIDFILE: &str = "/run/bpfcontain.pid";
static LOGFILE: &str = "/var/log/bpfcontain.log";
static WORKDIR: &str = "/var/lib/bpfcontain";

pub fn main(args: &ArgMatches) -> Result<()> {
    let result = match args.subcommand() {
        ("start", Some(_args)) => start_daemon(),
        ("restart", Some(_args)) => restart_daemon(),
        ("stop", Some(_args)) => stop_daemon(),
        _ => bail!("Bad subcommand name"),
    };

    result
}

/// Starts the daemon.
fn start_daemon() -> Result<()> {
    log::info!("Starting daemon...");

    // Open the log file
    let stdout = OpenOptions::new().create(true).append(true).open(LOGFILE)?;
    let stderr = OpenOptions::new().create(true).append(true).open(LOGFILE)?;

    // Create workdir and set permissions to rwxr-xr-t
    create_dir_all(WORKDIR)?;
    let mut perms = metadata(WORKDIR)?.permissions();
    perms.set_mode(0o1755);
    set_permissions(WORKDIR, perms)?;

    // Set up the daemon
    let daemonize = Daemonize::new()
        .pid_file(PIDFILE)
        .user("nobody")
        .stdout(stdout)
        .stderr(stderr)
        .working_directory(WORKDIR)
        .exit_action(|| log::info!("Started the daemon!"));

    // Try to start the daemon
    match daemonize.start() {
        Ok(_) => log::info!("Started the daemon!"),
        Err(e) => {
            bail!("Failed to start the daemon: {}", e);
        }
    }

    // FIXME: replace this with the actual BPF program work loop
    std::thread::sleep(std::time::Duration::new(10, 0));

    Ok(())
}

/// Stops the daemon by parsing the daemon's [`PIDFILE`] and sending a `SIGTERM`
/// using kill(2).
fn stop_daemon() -> Result<()> {
    log::info!("Stopping daemon...");

    // Parse pid from pidfile
    let pid: i32 = {
        // Open pidfile for reading
        let mut pidfile = match File::open(PIDFILE) {
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
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        let err = std::io::Error::last_os_error();
        bail!("Failed to kill the daemon ({}): {}", pid, err);
    };

    Ok(())
}

/// Restarts the daemon by invoking [`stop_daemon`] followed by
/// [`start_daemon`]. [`stop_daemon`] is allowed to fail with a warning.
///
/// FIXME: This is racy because we need to wait for the pidfile to be unlocked
/// before we can start the daemon. As a crude workaround, we currently
/// sleep for 1 second after a successful call to [`stop_daemon`].
///
/// This behaviour should be changed in future versions to wait for the file to
/// be unlocked.
fn restart_daemon() -> Result<()> {
    log::info!("Restarting daemon...");

    // Try to stop the daemon
    match stop_daemon() {
        Ok(_) => {
            // FIXME: Should poll to see if the process has actually stopped
            std::thread::sleep(std::time::Duration::new(1, 0));
        }
        Err(e) => {
            log::warn!(
                "Unable to stop the daemon while restarting (daemon may not \
                be running): {}",
                e
            );
        }
    }

    // Start the daemon
    start_daemon()
}
