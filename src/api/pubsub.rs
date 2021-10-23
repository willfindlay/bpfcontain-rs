use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
};

use jsonrpc_core::*;
use jsonrpc_derive::rpc;
use jsonrpc_pubsub::{
    typed::{Sink, Subscriber},
    Session, SubscriptionId,
};
use serde::{Deserialize, Serialize};

use crate::policy::types::AuditEvent;

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
        filter: Option<AuditFilter>,
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

    #[allow(unused_variables)]
    fn audit_subscribe(
        &self,
        meta: Self::Metadata,
        subscriber: Subscriber<AuditEvent>,
        filter: Option<AuditFilter>,
    ) {
        // Assign subscriber to a sink associated with a unique ID
        let id = SubscriptionId::Number(self.uid.fetch_add(1, Ordering::SeqCst) as u64);
        let sink = subscriber.assign_id(id.clone()).unwrap();

        // Register a handler for dropped connections
        let audit_subscribers_clone = self.audit_subscribers.clone();
        let id_clone = id.clone();
        meta.on_drop(move || {
            audit_subscribers_clone.write().unwrap().remove(&id_clone);
            log::warn!(
                "Lost connection with subscriber {}, dropping subscription!",
                id_clone.number()
            )
        });

        log::debug!("Registering a subscriber with id {:?}", id);

        // TODO: use `filter` to discriminate based on policy name, etc
        // Map the subscriber's ID to the sink
        self.audit_subscribers.write().unwrap().insert(id, sink);
    }

    fn audit_unsubscribe(&self, _meta: Option<Self::Metadata>, id: SubscriptionId) -> Result<()> {
        self.audit_subscribers.write().unwrap().remove(&id);
        log::debug!("Unsubscribing the subscriber with id {:?}", id);
        Ok(())
    }
}

/// Used to filter over security events when calling `audit_subscribe`.
/// TODO: This currently does nothing.
#[derive(Serialize, Deserialize)]
pub struct AuditFilter {
    policy_name: Option<String>,
    container_id: Option<u64>,
}

/// An extension trait enabling us to coerce the inner values out of a
/// `SubscriptionId`, provided that the variant is known at compile-time.
pub trait SubscriptionIdInnerNumberExt {
    fn number(&self) -> u64;
    fn string(&self) -> &String;
}

impl SubscriptionIdInnerNumberExt for SubscriptionId {
    /// Convert a `SubscriptionId` to the inner number.
    /// Panics if `SubscriptionId` is not `SubscriptionId::Number` variant.
    fn number(&self) -> u64 {
        match self {
            SubscriptionId::Number(n) => n.to_owned(),
            _ => panic!("SubscriptionId is not a number!?"),
        }
    }

    /// Convert a `SubscriptionId` to the inner string.
    /// Panics if `SubscriptionId` is not `SubscriptionId::String` variant.
    fn string(&self) -> &String {
        match self {
            SubscriptionId::String(s) => s,
            _ => panic!("SubscriptionId is not a string!?"),
        }
    }
}
