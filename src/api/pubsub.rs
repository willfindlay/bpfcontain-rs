use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use jsonrpc_core::*;
use jsonrpc_derive::rpc;
use jsonrpc_pubsub::{typed::Sink, typed::Subscriber, Session, SubscriptionId};

/// An active subscription expecting responses of type `T`.
pub type Subscriptions<T: serde::Serialize> = Arc<RwLock<HashMap<SubscriptionId, Sink<T>>>>;

/// A trait defining the publish/subscribe portions of BPFContain's API.
#[rpc(server)]
pub trait PubSub {
    type Metadata;

    /// Subscribe to a security audit event using a filter selector.
    #[pubsub(subscription = "audit", subscribe, name = "audit_subscribe")]
    fn audit_subscribe(&self, meta: Self::Metadata, subscriber: Subscriber<AuditEvent>);

    /// Unsubscribe from a security audit event.
    #[pubsub(subscription = "audit", unsubscribe, name = "audit_unsubscribe")]
    fn audit_unsubscribe(&self, meta: Option<Self::Metadata>, id: SubscriptionId) -> Result<()>;
}

/// Implements BPFContain's publish/subscribe API.
pub struct PubSubImpl;
impl PubSub for PubSubImpl {
    type Metadata = Arc<Session>;

    fn audit_subscribe(&self, meta: Self::Metadata, subscriber: Subscriber<AuditEvent>) {
        todo!()
    }

    fn audit_unsubscribe(&self, meta: Option<Self::Metadata>, id: SubscriptionId) -> Result<()> {
        todo!()
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

pub struct AuditEvent {/* TODO */}
