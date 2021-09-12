use std::sync::Arc;

use jsonrpc_pubsub::{PubSubHandler, Session};
use jsonrpc_ws_server::RequestContext;
use jsonrpc_ws_server::{Server, ServerBuilder};

use self::pubsub::{AuditEvent, PubSub, PubSubImpl, Subscriptions};
use crate::config::Settings;

mod pubsub;
mod rpc;

/// Represents a running API server along with all the context
/// it needs to operate normally.
pub struct ApiContext {
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
            Arc::new(Session::new(context.sender().clone()))
        })
        .start(addr)
        .expect("Server must start with no issues");

        Self {
            server,
            audit_subscribers,
        }
    }
}
