use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
};

use jsonrpc_core::*;
use jsonrpc_derive::rpc;
use jsonrpc_pubsub::{typed::Sink, typed::Subscriber, Session, SubscriptionId};
use serde::{Deserialize, Serialize};

use super::ApiContext;

/// An active subscription expecting responses of type `T`.
pub type Subscriptions<T> = Arc<RwLock<HashMap<SubscriptionId, Sink<T>>>>;

/// A trait defining the publish/subscribe portions of BPFContain's API.
#[rpc(server)]
pub trait PubSub {
    type Metadata;

    /// Subscribe to a security audit event using a filter selector.
    #[pubsub(subscription = "audit", subscribe, name = "audit_subscribe")]
    fn audit_subscribe(
        &self,
        meta: Self::Metadata,
        subscriber: Subscriber<AuditEvent>,
        filter: AuditFilter,
    );

    /// Unsubscribe from a security audit event.
    #[pubsub(subscription = "audit", unsubscribe, name = "audit_unsubscribe")]
    fn audit_unsubscribe(&self, meta: Option<Self::Metadata>, id: SubscriptionId) -> Result<()>;
}

/// Implements BPFContain's publish/subscribe API.
#[derive(Default)]
pub struct PubSubImpl {
    uid: AtomicUsize,
    pub(crate) audit_subscribers: Subscriptions<AuditEvent>,
}

impl PubSub for PubSubImpl {
    type Metadata = Arc<Session>;

    fn audit_subscribe(
        &self,
        meta: Self::Metadata,
        subscriber: Subscriber<AuditEvent>,
        filter: AuditFilter,
    ) {
        let id = SubscriptionId::Number(self.uid.fetch_add(1, Ordering::SeqCst) as u64);
        let sink = subscriber.assign_id(id.clone()).unwrap();
        // TODO: use `filter` to discriminate based on
        log::debug!("Hello pubsub!");
    }

    fn audit_unsubscribe(&self, meta: Option<Self::Metadata>, id: SubscriptionId) -> Result<()> {
        log::debug!("Goodbye pubsub!");
        Ok(())
    }
}

// #[derive(Serialize, Deserialize)]
// pub enum ApiResponse {
//     String(String),
//     SecurityEvent {
//         policy_id: u64,
//         container_id: u64,
//         comm: String,
//         msg: Option<String>,
//     },
// }

#[derive(Serialize, Deserialize)]
pub struct AuditFilter {
    policy_name: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct AuditEvent {/* TODO */}
