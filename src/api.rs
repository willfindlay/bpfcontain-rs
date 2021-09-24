pub mod pubsub;
pub mod rpc;

use std::sync::Arc;

use jsonrpc_pubsub::{PubSubHandler, Session};
use jsonrpc_ws_server::RequestContext;
use jsonrpc_ws_server::{Server, ServerBuilder};
use log::{debug, warn};
use pubsub::{PubSub, PubSubImpl, SubscriptionIdInnerNumberExt as _, Subscriptions};

use crate::config::Settings;
use crate::types::AuditEvent;

/// Represents a running API server along with all the context
/// it needs to operate normally.
pub struct ApiContext {
    #[allow(dead_code)]
    // TODO: We may need to read this at some point in the future. If not, we can prefix with an underscore
    server: Server,
    audit_subscribers: Subscriptions<AuditEvent>,
}

impl ApiContext {
    pub fn new(config: &Settings) -> Self {
        // Create a new event handler using the pubub extensions
        let mut io = PubSubHandler::default();

        // Register publish/subscribe API
        let pubsub = PubSubImpl::default();
        let audit_subscribers = pubsub.audit_subscribers.clone();
        io.extend_with(pubsub.to_delegate());

        // Set websocket server address
        let addr = &config
            .daemon
            .websocket_ip
            .parse()
            .expect("Failed to parse websocket server IP");

        // Spawn the websocket server
        let server = ServerBuilder::with_meta_extractor(io, |context: &RequestContext| {
            Arc::new(Session::new(context.sender()))
        })
        .start(addr)
        .expect("Server must start with no issues");

        Self {
            server,
            audit_subscribers,
        }
    }

    pub fn notify_audit_subscribers(&self, event: AuditEvent) {
        for (id, subscriber) in self.audit_subscribers.read().unwrap().iter() {
            debug!("Notifying subscription id {}", id.number());
            if let Err(e) = subscriber.notify(Ok(event.clone())) {
                warn!("Failed to notify subscription id {}: {:?}", id.number(), e);
            }
        }
    }
}
