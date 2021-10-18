// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (c) 2021  William Findlay
//
// September 23, 2021  William Findlay  Created this.

use std::{
    collections::{hash_map::DefaultHasher, BTreeSet},
    convert::{TryFrom, TryInto},
    fs::File,
    hash::{Hash, Hasher},
    io::{Read, Write},
    path::Path,
};

use anyhow::{bail, Context, Result};
use bit_iter::BitIter;
use plain::as_bytes;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::utils::{default_false, default_true};
use crate::{
    bindings::policy::bitflags::PolicyDecision as PolicyDecisionBitflag, bpf::BpfcontainSkel,
};

#[derive(Hash, Debug, Serialize, Deserialize, Clone)]
pub struct Rule();

/// A serializable and deserializable BPFContain policy
#[derive(Hash, Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The policy's ID (usually just a string name), which should be globally unique.
    #[serde(alias = "name")]
    pub id: PolicyIdentifier,
    /// The default command associated with the policy, if any.
    pub cmd: Option<String>,
    /// Whether the container should spawn in a tainted state. Otherwise, taint rules will
    /// specify when the container should become tainted. Defaults to true.
    /// Defaults to true.
    #[serde(default = "default_true")]
    default_taint: bool,
    /// Whether the policy should complain (log) instead of deny.
    /// Defaults to false.
    #[serde(default = "default_false")]
    complain: bool,
    /// Whether the policy should be in privileged mode,
    /// granting extra capabilities when untainted.
    /// Defaults to false.
    #[serde(default = "default_false")]
    privileged: bool,
    /// The allow rules associated with the policy. Accesses covered by these rules are
    /// always allowed, unless the access also matches a deny rule.
    #[serde(default)]
    #[serde(alias = "rights")]
    allow: Vec<Rule>,
    /// The deny rules associated with the policy. Accesses covered by these rules are
    /// always denied.
    #[serde(default)]
    #[serde(alias = "restrictions")]
    deny: Vec<Rule>,
    /// The taint rules associated with the policy. Accesses covered by these rules always
    /// taint the container, placing it into a more restrictive enforcement mode. If the
    /// container is `default_taint`, these rules do nothing.
    #[serde(default)]
    #[serde(alias = "taints")]
    taint: Vec<Rule>,
}

impl Policy {
    /// Load a policy from disk, located at `path` and in `format`. The `format` defaults to
    /// [`PolicyFormat::Yaml`] if `None` is provided.
    pub fn from_disk<P: AsRef<Path>>(path: P, format: Option<PolicyFormat>) -> Result<Self> {
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

    /// Save a policy to disk in a given `format`, at the location specified by `path`.
    /// The `format` defaults to [`PolicyFormat::Yaml`] if `None` is provided.
    pub fn to_disk<P: AsRef<Path>>(&self, path: P, format: Option<PolicyFormat>) -> Result<()> {
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

    // Load the policy into the kernel.
    // pub fn load_kernel(&self, skel: &mut BpfcontainSkel) -> Result<()> {
    //     let mut maps = skel.maps_mut();
    //     let policy_common = maps.policy_common();

    //     let key = unsafe { as_bytes(&self.id.get_id()) };
    //     let value
    //     Ok(())
    // }
}

/// Possible formats for saving and loading a policy to/from disk
pub enum PolicyFormat {
    Bin,
    Yaml,
    Json,
    Toml,
}

/// Uniquely identifies a policy.
#[derive(Debug, Serialize, Deserialize, Eq, Clone)]
#[serde(untagged)]
pub enum PolicyIdentifier {
    PolicyName(String),
    PolicyId(u64),
}

impl PolicyIdentifier {
    /// Get the underlying policy id as a u64
    pub fn get_id(&self) -> u64 {
        match self {
            PolicyIdentifier::PolicyName(name) => Self::name_to_id(name),
            PolicyIdentifier::PolicyId(id) => id.to_owned(),
        }
    }

    /// Convert the policy name to the BPF identifier by taking its hash as a u64
    fn name_to_id(name: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);
        hasher.finish()
    }
}

impl Hash for PolicyIdentifier {
    /// An equivalent `PolicyName` and `PolicyId` should hash to each other
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.get_id().hash(state);
    }
}

impl PartialEq for PolicyIdentifier {
    /// `PolicyIdentifier`s are considered equal if they resolve to the same underlying id
    fn eq(&self, other: &Self) -> bool {
        self.get_id() == other.get_id()
    }
}

/// Represents a policy decision.
#[derive(Hash, Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum PolicyDecision {
    #[serde(skip)]
    NoDecision,
    Allow,
    Deny,
    Taint,
}

impl TryFrom<PolicyDecisionBitflag> for PolicyDecision {
    type Error = anyhow::Error;

    fn try_from(value: PolicyDecisionBitflag) -> Result<Self, Self::Error> {
        Ok(match value {
            PolicyDecisionBitflag::NO_DECISION => Self::NoDecision,
            PolicyDecisionBitflag::ALLOW => Self::Allow,
            PolicyDecisionBitflag::DENY => Self::Deny,
            PolicyDecisionBitflag::TAINT => Self::Taint,
            v => bail!("Invalid value for `PolicyDecision` {}", v.bits()),
        })
    }
}

impl From<PolicyDecision> for PolicyDecisionBitflag {
    fn from(value: PolicyDecision) -> Self {
        match value {
            PolicyDecision::NoDecision => Self::NO_DECISION,
            PolicyDecision::Deny => Self::DENY,
            PolicyDecision::Allow => Self::ALLOW,
            PolicyDecision::Taint => Self::TAINT,
        }
    }
}

/// A wrapper around a `BTreeSet` of [`PolicyDecision`]s.
#[derive(Hash, Debug, Clone, PartialEq)]
pub struct PolicyDecisionSet(BTreeSet<PolicyDecision>);

impl TryFrom<PolicyDecisionBitflag> for PolicyDecisionSet {
    type Error = anyhow::Error;

    fn try_from(value: PolicyDecisionBitflag) -> Result<Self, Self::Error> {
        let mut set = BTreeSet::default();

        for b in BitIter::from(value.bits()).map(|b| b as u32) {
            let bit = 1 << b;
            let bitflag = PolicyDecisionBitflag::from_bits(bit).unwrap();
            set.insert(bitflag.try_into()?);
        }

        Ok(PolicyDecisionSet(set))
    }
}

impl<'de> Deserialize<'de> for PolicyDecisionSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum BTreeSetOrSingle {
            BTreeSet(BTreeSet<PolicyDecision>),
            Single(PolicyDecision),
        }

        // Allows a set to be deserialized from a single item or a sequence of items.
        let hash_set = match BTreeSetOrSingle::deserialize(deserializer)? {
            BTreeSetOrSingle::BTreeSet(set) => set,
            BTreeSetOrSingle::Single(decision) => {
                let mut s = BTreeSet::new();
                s.insert(decision);
                s
            }
        };

        Ok(PolicyDecisionSet(hash_set))
    }
}

impl Serialize for PolicyDecisionSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(self.0.iter())
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use super::*;
    use proptest::{collection::btree_set, prelude::*};
    use serde::de::DeserializeOwned;

    fn hash<H: Hash>(v: &H) -> u64 {
        let mut hasher = DefaultHasher::new();
        v.hash(&mut hasher);
        hasher.finish()
    }

    fn policy_decision_strategy() -> impl Strategy<Value = PolicyDecision> {
        prop_oneof![
            Just(PolicyDecision::Allow),
            Just(PolicyDecision::Deny),
            Just(PolicyDecision::Taint),
        ]
    }

    fn policy_decision_strategy_with_nd() -> impl Strategy<Value = PolicyDecision> {
        prop_oneof![
            Just(PolicyDecision::NoDecision),
            Just(PolicyDecision::Allow),
            Just(PolicyDecision::Deny),
            Just(PolicyDecision::Taint),
        ]
    }

    fn assert_serde<S: AsRef<str>, T: DeserializeOwned + Serialize + PartialEq + Debug>(s: S) -> T {
        let t1: T = serde_yaml::from_str(s.as_ref()).expect("Failed to deserialize");
        let t2: T = serde_yaml::from_str(
            &serde_yaml::to_string(
                &serde_yaml::from_str::<T>(s.as_ref()).expect("Failed to deserialize inner"),
            )
            .expect("Failed to serialize"),
        )
        .expect("Failed to deserialize outer");
        assert_eq!(t1, t2);
        t1
    }

    proptest! {
        #[test]
        fn policy_id_equivalent_test(s in String::arbitrary()) {
            // Create a policy idenfitier wrapping a string
            let a = PolicyIdentifier::PolicyName(s);
            // Create a policy idenfitier wrapping the equivalent id
            let b = PolicyIdentifier::PolicyId(a.get_id());

            // Make sure they are truly equal
            assert_eq!(a, b);
            assert_eq!(a.get_id(), b.get_id());
            assert_eq!(hash(&a), hash(&b));
        }

        #[test]
        fn policy_id_serde_test(s in "[a-zA-Z0-9]+") {
            // Deserialize a policy identifier from a string
            let policy_str_a = s.to_owned();
            let a: PolicyIdentifier = assert_serde(&policy_str_a);

            // Deserialize a policy identifier from the equivalent id
            let policy_str_b = format!("{}", a.get_id());
            let b: PolicyIdentifier = assert_serde(&policy_str_b);

            // Make sure they are truly equal
            assert_eq!(a, b);
            assert_eq!(a.get_id(), b.get_id());
            assert_eq!(hash(&a), hash(&b));
        }

        #[test]
        fn policy_decision_set_hash_test(b in btree_set(policy_decision_strategy_with_nd(), 4)) {
            // The hash of the underlying BTreeSet should be the same as the
            // PolicyDecisionSet.
            let a = PolicyDecisionSet(b.clone());
            assert_eq!(hash(&a), hash(&b));
        }

        #[test]
        fn policy_decision_set_serde_test(b in btree_set(policy_decision_strategy(), 3)) {
            let a = PolicyDecisionSet(b.clone());
            let s = serde_yaml::to_string(&a).expect("Failed to serialize");
            assert_serde::<_, PolicyDecisionSet>(&s);
        }
    }
}
