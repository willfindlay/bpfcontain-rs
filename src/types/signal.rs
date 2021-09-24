// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (c) 2021  William Findlay
//
// September 23, 2021  William Findlay  Created this.

use std::collections::HashSet;
use std::convert::{TryFrom, TryInto};
use std::fmt::{Debug, Display};

use anyhow::bail;
use bit_iter::BitIter;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::PolicyIdentifier;
use crate::bindings::policy::bitflags::Signal as SignalBitflag;

/// Access to signal another process.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignalAccess {
    pub other: PolicyIdentifier,
    #[serde(alias = "signals")]
    pub signal: SignalSet,
}

/// Represents a Linux signal.
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub enum Signal {
    SigChk,
    SigHup,
    SigInt,
    SigQuit,
    SigIll,
    SigTrap,
    SigAbrt,
    SigBus,
    SigFpe,
    SigKill,
    SigUsr1,
    SigSegv,
    SigUsr2,
    SigPipe,
    SigAlrm,
    SigTerm,
    SigStkFlt,
    SigChld,
    SigCont,
    SigStop,
    SigTstp,
    SigTtin,
    SigTtou,
    SigUrg,
    SigXcpu,
    SigXfsz,
    SigVtalrm,
    SigProf,
    SigWinch,
    SigIo,
    SigPwr,
    SigSys,
    // Convenience aliases below this line
    Check,
    Fatal,
    SuperFatal,
    Stop,
    SuperStop,
    Any,
}

impl Display for Signal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self, f)
    }
}

impl TryFrom<SignalBitflag> for Signal {
    type Error = anyhow::Error;

    fn try_from(value: SignalBitflag) -> Result<Self, Self::Error> {
        Ok(match value {
            SignalBitflag::SIGCHK => Self::SigChk,
            SignalBitflag::SIGHUP => Self::SigHup,
            SignalBitflag::SIGINT => Self::SigInt,
            SignalBitflag::SIGQUIT => Self::SigQuit,
            SignalBitflag::SIGILL => Self::SigIll,
            SignalBitflag::SIGTRAP => Self::SigTrap,
            SignalBitflag::SIGABRT => Self::SigAbrt,
            SignalBitflag::SIGBUS => Self::SigBus,
            SignalBitflag::SIGFPE => Self::SigFpe,
            SignalBitflag::SIGKILL => Self::SigKill,
            SignalBitflag::SIGUSR1 => Self::SigUsr1,
            SignalBitflag::SIGSEGV => Self::SigSegv,
            SignalBitflag::SIGUSR2 => Self::SigUsr2,
            SignalBitflag::SIGPIPE => Self::SigPipe,
            SignalBitflag::SIGALRM => Self::SigAlrm,
            SignalBitflag::SIGTERM => Self::SigTerm,
            SignalBitflag::SIGSTKFLT => Self::SigStkFlt,
            SignalBitflag::SIGCHLD => Self::SigChld,
            SignalBitflag::SIGCONT => Self::SigCont,
            SignalBitflag::SIGSTOP => Self::SigStop,
            SignalBitflag::SIGTSTP => Self::SigTstp,
            SignalBitflag::SIGTTIN => Self::SigTtin,
            SignalBitflag::SIGTTOU => Self::SigTtou,
            SignalBitflag::SIGURG => Self::SigUrg,
            SignalBitflag::SIGXCPU => Self::SigXcpu,
            SignalBitflag::SIGXFSZ => Self::SigXfsz,
            SignalBitflag::SIGVTALRM => Self::SigVtalrm,
            SignalBitflag::SIGPROF => Self::SigProf,
            SignalBitflag::SIGWINCH => Self::SigWinch,
            SignalBitflag::SIGIO => Self::SigIo,
            SignalBitflag::SIGPWR => Self::SigPwr,
            SignalBitflag::SIGSYS => Self::SigSys,
            v => bail!("Invalid value for `Signal` {}", v.bits()),
        })
    }
}

impl From<Signal> for SignalBitflag {
    fn from(sig: Signal) -> Self {
        match sig {
            Signal::SigChk => SignalBitflag::SIGCHK,
            Signal::SigHup => SignalBitflag::SIGHUP,
            Signal::SigInt => SignalBitflag::SIGINT,
            Signal::SigQuit => SignalBitflag::SIGQUIT,
            Signal::SigIll => SignalBitflag::SIGILL,
            Signal::SigTrap => SignalBitflag::SIGTRAP,
            Signal::SigAbrt => SignalBitflag::SIGABRT,
            Signal::SigBus => SignalBitflag::SIGBUS,
            Signal::SigFpe => SignalBitflag::SIGFPE,
            Signal::SigKill => SignalBitflag::SIGKILL,
            Signal::SigUsr1 => SignalBitflag::SIGUSR1,
            Signal::SigSegv => SignalBitflag::SIGSEGV,
            Signal::SigUsr2 => SignalBitflag::SIGUSR2,
            Signal::SigPipe => SignalBitflag::SIGPIPE,
            Signal::SigAlrm => SignalBitflag::SIGALRM,
            Signal::SigTerm => SignalBitflag::SIGTERM,
            Signal::SigStkFlt => SignalBitflag::SIGSTKFLT,
            Signal::SigChld => SignalBitflag::SIGCHLD,
            Signal::SigCont => SignalBitflag::SIGCONT,
            Signal::SigStop => SignalBitflag::SIGSTOP,
            Signal::SigTstp => SignalBitflag::SIGTSTP,
            Signal::SigTtin => SignalBitflag::SIGTTIN,
            Signal::SigTtou => SignalBitflag::SIGTTOU,
            Signal::SigUrg => SignalBitflag::SIGURG,
            Signal::SigXcpu => SignalBitflag::SIGXCPU,
            Signal::SigXfsz => SignalBitflag::SIGXFSZ,
            Signal::SigVtalrm => SignalBitflag::SIGVTALRM,
            Signal::SigProf => SignalBitflag::SIGPROF,
            Signal::SigWinch => SignalBitflag::SIGWINCH,
            Signal::SigIo => SignalBitflag::SIGIO,
            Signal::SigPwr => SignalBitflag::SIGPWR,
            Signal::SigSys => SignalBitflag::SIGSYS,
            Signal::Check => SignalBitflag::SIGCHK,
            Signal::Fatal => SignalBitflag::SIGTERM | SignalBitflag::SIGINT,
            Signal::SuperFatal => {
                SignalBitflag::SIGTERM | SignalBitflag::SIGINT | SignalBitflag::SIGKILL
            }
            Signal::Stop => SignalBitflag::SIGSTOP,
            Signal::SuperStop => SignalBitflag::SIGSTOP | SignalBitflag::SIGTSTP,
            Signal::Any => SignalBitflag::all(),
        }
    }
}

/// A wrapper around a hashset of [`Signal`]s.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct SignalSet(pub HashSet<Signal>);

impl Display for SignalSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl TryFrom<SignalBitflag> for SignalSet {
    type Error = anyhow::Error;

    fn try_from(value: SignalBitflag) -> Result<Self, Self::Error> {
        let mut set = HashSet::default();

        for b in BitIter::from(value.bits()).map(|b| b as u64) {
            let bit = 1 << b;
            let bitflag = SignalBitflag::from_bits(bit).unwrap();
            set.insert(bitflag.try_into()?);
        }

        Ok(SignalSet(set))
    }
}

impl From<SignalSet> for SignalBitflag {
    fn from(sigs: SignalSet) -> Self {
        let mut bits = SignalBitflag::default();

        for sig in sigs.0 {
            let bit = SignalBitflag::from(sig);
            bits |= bit;
        }

        bits
    }
}

impl<'de> Deserialize<'de> for SignalSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum HashSetOrSingle {
            HashSet(HashSet<Signal>),
            Single(Signal),
        }

        // Allows a signal set to be deserialized from either a single signal or
        // a sequence of signals.
        let hash_set = match HashSetOrSingle::deserialize(deserializer)? {
            HashSetOrSingle::HashSet(set) => set,
            HashSetOrSingle::Single(cap) => {
                let mut s = HashSet::with_capacity(1);
                s.insert(cap);
                s
            }
        };

        Ok(SignalSet(hash_set))
    }
}

impl Serialize for SignalSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(self.0.iter())
    }
}
