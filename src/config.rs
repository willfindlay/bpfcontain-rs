use anyhow::Result;
use config::{Config, ConfigError, Environment, File, FileFormat};
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
            s.merge(File::with_name("/etc/bpfcontain").required(false))?;
        }

        // Read in from environment variables starting with `BPFCON_`
        s.merge(Environment::with_prefix("BPFCON").separator("_"))?;

        s.try_into()
    }

    fn set_defaults(s: &mut Config) -> Result<(), ConfigError> {
        s.merge(File::from_str(
            include_str!("../config/default.yml"),
            FileFormat::Yaml,
        ))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_smoke_test() -> Result<(), ConfigError> {
        let mut s = Config::new();

        Settings::set_defaults(&mut s).expect("Failed to set defaults");

        s.try_into::<Settings>().expect("Deserialization failed");

        Ok(())
    }
}
