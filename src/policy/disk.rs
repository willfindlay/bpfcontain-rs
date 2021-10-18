use super::Policy;
use anyhow::{Context, Result};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

/// Possible formats for saving and loading a policy to/from disk
pub enum PolicyFormat {
    Bin,
    Yaml,
    Json,
    Toml,
}

/// A trait for saving and loading policies to/from disk.
pub trait PolicyDiskExt {
    fn from_disk<P: AsRef<Path>>(path: P, format: Option<PolicyFormat>) -> Result<Policy>;
    fn to_disk<P: AsRef<Path>>(&self, path: P, format: Option<PolicyFormat>) -> Result<()>;
}

impl PolicyDiskExt for Policy {
    fn from_disk<P: AsRef<Path>>(path: P, format: Option<PolicyFormat>) -> Result<Policy> {
        let mut reader = File::open(path).context("Failed to open policy file for reading")?;
        match format {
            Some(PolicyFormat::Bin) => todo!("Binary policy format is not yet supported"),
            Some(PolicyFormat::Yaml) | None => {
                serde_yaml::from_reader(reader).context("Failed to parse policy file as YAML")
            }
            Some(PolicyFormat::Json) => {
                serde_json::from_reader(reader).context("Failed to parse policy file as JSON")
            }
            Some(PolicyFormat::Toml) => {
                let mut s = String::new();
                reader
                    .read_to_string(&mut s)
                    .context("Failed to read TOML file")?;
                toml::from_str(&s).context("Failed to parse policy file as TOML")
            }
        }
    }

    fn to_disk<P: AsRef<Path>>(&self, path: P, format: Option<PolicyFormat>) -> Result<()> {
        let mut writer = File::create(path).context("Failed to open policy file for writing")?;
        match format {
            Some(PolicyFormat::Bin) => todo!("Binary policy format is not yet supported"),
            Some(PolicyFormat::Yaml) | None => {
                serde_yaml::to_writer(writer, &self).context("Failed to write policy file as YAML")
            }
            Some(PolicyFormat::Json) => {
                serde_json::to_writer(writer, &self).context("Failed to write policy file as JSON")
            }
            Some(PolicyFormat::Toml) => {
                // let mut s = String::new();
                // reader
                //     .read_to_string(&mut s)
                //     .context("Failed to read TOML file")?;
                // toml::from_str(&s).context("Failed to parse policy file as TOML")
                let s = toml::to_string_pretty(&self).context("Failed to serialize as TOML")?;
                writer
                    .write_all(s.as_bytes())
                    .context("Failed to write policy file as TOML")
            }
        }
    }
}
