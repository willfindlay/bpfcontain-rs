// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! Configuration settings.

use std::path::Path;

use anyhow::{Context as _, Result};
use config::{Config, Environment, File, FileFormat};
use serde::Deserialize;

use crate::bindings::audit::AuditLevel;

/// Configuration struct
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub daemon: Daemon,
    pub policy: Policy,
    pub bpf: Bpf,
    pub verbosity: log::LevelFilter, // TODO: figure out why only INFO works and not Info, info, etc.
}

impl Settings {
    pub fn new(path: &Path) -> Result<Self> {
        let mut s = Config::new();

        // Set defaults
        s.merge(File::from_str(
            include_str!("../config/default.yml"),
            FileFormat::Yaml,
        ))
        .context("Failed to apply default settings")?;

        // Merge in config files
        s.merge(File::with_name(&path.to_string_lossy()).required(false))
            .context("Error reading config file")?;

        // Read in from environment variables starting with prefix
        for prefix in &["BC", "BPFCON", "BPFCONTAIN"] {
            s.merge(Environment::with_prefix(prefix).separator("_"))
                .context("Error reading settings from environment")?;
        }

        // Lock the configuration
        Ok(s.try_into()?)
    }
}

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
}

/// Configuration related to BPF settings
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct Bpf {
    pub audit_level: Vec<AuditLevelSettings>,
}

/// Possible audit levels that can be passed to `Bpf::audit_level`
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum AuditLevelSettings {
    Allow,
    Deny,
    Taint,
    Info,
    Warn,
}

impl From<AuditLevelSettings> for AuditLevel {
    fn from(level: AuditLevelSettings) -> Self {
        use AuditLevelSettings::*;
        match level {
            Allow => Self::AUDIT_ALLOW,
            Deny => Self::AUDIT_DENY,
            Taint => Self::AUDIT_TAINT,
            Info => Self::AUDIT_INFO,
            Warn => Self::AUDIT_WARN,
        }
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
