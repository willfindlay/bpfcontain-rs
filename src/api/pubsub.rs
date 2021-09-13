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

use crate::bindings::audit::{AuditData, AuditType};

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

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditEvent {
    policy_id: u64,
    container_id: u64,
    pid: u32,
    ns_pid: u32,
    decision: String, // TODO: make this a decision enum
    data: AuditEventData,
}

impl From<AuditData> for AuditEvent {
    fn from(data: AuditData) -> Self {
        AuditEvent {
            policy_id: data.policy_id,
            container_id: 0, // TODO: data.container_id
            pid: data.pid,
            ns_pid: 0, // TODO: data.ns_pid
            decision: data.level.to_string(),
            data: match data.type_ {
                AuditType::AUDIT_TYPE_FILE => {
                    todo!()
                }
                AuditType::AUDIT_TYPE_CAP => {
                    todo!()
                }
                AuditType::AUDIT_TYPE_NET => {
                    todo!()
                }
                AuditType::AUDIT_TYPE_IPC => {
                    todo!()
                }
                AuditType::AUDIT_TYPE_SIGNAL => {
                    todo!()
                }
                AuditType::AUDIT_TYPE__UNKOWN => {
                    AuditEventData::String("Unknown audit event".into())
                }
            },
        }
    }
}

/// A security event that can be forwarded to audit subscribers.
#[derive(Serialize, Deserialize, Clone)]
pub enum AuditEventData {
    String(String),
    FileEvent {
        st_ino: u64,
        st_dev: u64,
    },
    DeviceEvent {
        major: u64,
        minor: u64,
    },
    IpcEvent {
        other_policy_id: u64,
        other_container_id: u64,
        operation: String, // TODO: make this a send/recv enum
    },
    SignalEvent {
        other_policy_id: u64,
        other_container_id: u64,
    },
    SocketEvent {
        // TODO
        operation: String, // TODO: make this an operation enum
    },
    CapabilityEvent {
        // TODO
        capability: String, // TODO: make this a capability enum
    },
    ImplicitPolicyEvent {
        // TODO
        kind: String, // TODO: Make this an implicit policy enum
    },
    NewContainerEvent,
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
