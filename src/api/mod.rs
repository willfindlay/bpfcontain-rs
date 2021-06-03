// SPDX-License-Identifier: GPL-2.0-or-later
//
// BPFContain - Container security with eBPF
// Copyright (C) 2020  William Findlay
//
// Dec. 29, 2020  William Findlay  Created this.

//! The BPFContain API.

use std::collections::HashMap;
use std::sync::atomic;
use std::sync::Arc;
use std::sync::RwLock;

use jsonrpc_core::{Error, ErrorCode, Result};
use jsonrpc_derive::rpc;
use jsonrpc_ipc_server::{RequestContext, Server, ServerBuilder};
use jsonrpc_pubsub::{typed, PubSubHandler, Session, SubscriptionId};
use serde::{Deserialize, Serialize};

use crate::bindings::policy::keys::PolicyId;

pub type Subscriptions<T: serde::Serialize> = Arc<RwLock<HashMap<SubscriptionId, typed::Sink<T>>>>;

#[rpc(server)]
pub trait Rpc {
    type Metadata;

    #[rpc(name = "echo")]
    fn echo(&self) -> Result<String>;

    #[pubsub(
        subscription = "security",
        subscribe,
        name = "security_subscribe",
        alias("security_sub")
    )]
    fn security_subscribe(
        &self,
        meta: Self::Metadata,
        subscriber: typed::Subscriber<ApiResponse>,
        filter: SecurityEventFilter,
    );

    #[pubsub(
        subscription = "security",
        unsubscribe,
        name = "security_unsubscribe",
        alias("security_unsub")
    )]
    fn security_unsubscribe(&self, meta: Option<Self::Metadata>, id: SubscriptionId) -> Result<()>;
}

#[derive(Deserialize)]
pub struct SecurityEventFilter {
    policy_id: Option<PolicyId>,
}

#[derive(Serialize)]
pub enum ApiResponse {
    String(String),
}

#[derive(Default)]
struct Api {
    uid: atomic::AtomicUsize,
    security_subscribers: Subscriptions<ApiResponse>,
}

impl Rpc for Api {
    type Metadata = Arc<Session>;

    fn echo(&self) -> Result<String> {
        Ok("It works!".into())
    }

    fn security_subscribe(
        &self,
        meta: Self::Metadata,
        subscriber: typed::Subscriber<ApiResponse>,
        filter: SecurityEventFilter,
    ) {
        // Add the subscriber
        let id = self.uid.fetch_add(1, atomic::Ordering::SeqCst);
        let sub_id = SubscriptionId::Number(id as u64);
        let sink = subscriber.assign_id(sub_id.clone()).unwrap();
        self.security_subscribers
            .write()
            .unwrap()
            .insert(sub_id, sink);
    }

    fn security_unsubscribe(
        &self,
        _meta: Option<Self::Metadata>,
        id: SubscriptionId,
    ) -> Result<()> {
        let removed = self.security_subscribers.write().unwrap().remove(&id);
        if removed.is_some() {
            Ok(())
        } else {
            Err(Error {
                code: ErrorCode::InvalidParams,
                message: format!("Invalid subscription id {:?}", id),
                data: None,
            })
        }
    }
}

pub fn spawn_api_server<'a>() -> (Server, ActiveSubscriptions) {
    let mut io = PubSubHandler::default();
    let api = Api::default();
    let active_subscriptions = api.active.clone();
    io.extend_with(api.to_delegate());

    let server = ServerBuilder::with_meta_extractor(io, |context: &RequestContext| {
        Arc::new(Session::new(context.sender.clone()))
    })
    .start("/var/run/bpfcontain.sock")
    .expect("Failed to start API server");

    (server, active_subscriptions)
}
