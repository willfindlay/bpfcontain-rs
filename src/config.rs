use anyhow::{Context, Result};
use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    dir: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Daemon {
    logfile: String,
    pidfile: String,
    workdir: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    daemon: Daemon,
    policy: Policy,
}

impl Settings {
    pub fn new(path: Option<&str>) -> Result<Self, ConfigError> {
        let mut s = Config::new();

        // Default configuration TODO change this to s.default()
        s.merge(File::with_name("config/default.yaml"))?;

        // User-supplied config file
        if let Some(path) = path {
            s.merge(File::with_name(path))?;
        }
        // Ordinary config hierarchy
        else {
            // TODO
        }

        // Read in from environment variables starting with `BPFCONTAIN_`
        s.merge(Environment::with_prefix("bpfcontain"))?;

        s.try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_smoke() -> Result<(), ConfigError> {
        let mut s = Config::new();

        s.merge(File::with_name("config/default.yaml"))?;

        s.try_into::<Settings>().expect("Deserialization failed");

        Ok(())
    }
}
