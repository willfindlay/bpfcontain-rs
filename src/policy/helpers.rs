// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

use serde::Deserialize;
use std::convert::From;

/// Allow a single or vector value
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum SingleOrVec<T> {
    Single(T),
    Vec(Vec<T>),
}

/// Provide an into() conversion to convert into a vector over T
impl<T> From<SingleOrVec<T>> for Vec<T> {
    fn from(value: SingleOrVec<T>) -> Self {
        match value {
            SingleOrVec::Single(v) => vec![v],
            SingleOrVec::Vec(v) => v,
        }
    }
}

impl<T> IntoIterator for SingleOrVec<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::Single(item) => vec![item].into_iter(),
            Self::Vec(items) => items.into_iter(),
        }
    }
}
