use anyhow::{Context, Result};
use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub dir: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Daemon {
    pub logfile: String,
    pub pidfile: String,
    pub workdir: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub daemon: Daemon,
    pub policy: Policy,
}

impl Settings {
    pub fn new(path: Option<&str>) -> Result<Self, ConfigError> {
        let mut s = Config::new();

        // Set defaults
        Self::set_defaults(&mut s)?;

        // User-supplied config file
        if let Some(path) = path {
            s.merge(File::with_name(path))?;
        }
        // Ordinary config hierarchy
        else {
            // Ignore results
            let _ = s.merge(File::with_name("/etc/bpfcontain"));
        }

        // Read in from environment variables starting with `BPFCONTAIN_`
        s.merge(Environment::with_prefix("bpfcontain"))?;

        s.try_into()
    }

    fn set_defaults(s: &mut Config) -> Result<(), ConfigError> {
        // Daemon defaults
        s.set_default("daemon.logfile", "/var/log/bpfcontain.log")?;
        s.set_default("daemon.pidfile", "/run/bpfcontain.pid")?;
        s.set_default("daemon.workdir", "/var/lib/bpfcontain")?;

        // Policy defaults
        s.set_default("policy.dir", "/var/lib/bpfcontain/policy")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_smoke() -> Result<(), ConfigError> {
        let mut s = Config::new();

        Settings::set_defaults(&mut s).expect("Failed to set defaults");

        s.try_into::<Settings>().expect("Deserialization failed");

        Ok(())
    }
}
