// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (c) 2021  William Findlay
//
// September 23, 2021  William Findlay  Created this.

use std::{
    collections::{hash_map::DefaultHasher, BTreeSet},
    convert::{TryFrom, TryInto},
    hash::{Hash, Hasher},
};

use anyhow::bail;
use bit_iter::BitIter;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::bindings::policy::bitflags::PolicyDecision as PolicyDecisionBitflag;

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
