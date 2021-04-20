use anyhow::{Context as _, Result};
use config::{Config, Environment, File, FileFormat};
use serde::Deserialize;

//! Configuration settings.

/// Configuration related to policy language
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    #[serde(alias = "policyDir")]
    #[serde(alias = "policy_dir")]
    pub dir: String,
}

/// Configuration related to the daemon
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct Daemon {
    pub log_file: String,
    pub pid_file: String,
    pub work_dir: String,
    pub verbosity: log::LevelFilter, // TODO: figure out why only INFO works and not Info, info, etc.
}

/// Configuration struct
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub daemon: Daemon,
    pub policy: Policy,
}

impl Settings {
    pub fn new(path: Option<&str>) -> Result<Self> {
        let mut s = Config::new();

        // Set defaults
        s.merge(File::from_str(
            include_str!("../config/default.yml"),
            FileFormat::Yaml,
        ))
        .context("Failed to apply default settings")?;

        // Merge in config files
        match path {
            // User-supplied config file
            Some(path) => s.merge(File::with_name(path).required(true)),
            // Global config file
            None => s.merge(File::with_name("/etc/bpfcontain.yml").required(false)),
        }
        .context("Error reading config file")?;

        // Read in from environment variables starting with prefix
        for prefix in &["BPFCON", "BPFCONTAIN"] {
            s.merge(Environment::with_prefix(prefix).separator("_"))
                .context("Error reading settings from environment")?;
        }

        // Lock the configuration
        Ok(s.try_into()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_smoke_test() {
        Settings::new(None).expect("Failed to set default settings");
    }
}
