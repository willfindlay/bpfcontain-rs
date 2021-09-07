use std::cell::RefCell;
use std::sync::{Arc, RwLock};

use jsonrpc_core::serde::{Deserialize, Serialize};
use jsonrpc_ws_server::jsonrpc_core::*;
use jsonrpc_ws_server::{Server, ServerBuilder};

use crate::config::Settings;

mod pubsub;
mod rpc;

#[derive(Default, Serialize, Deserialize)]
pub struct ApiRequest {/* TODO */}

#[derive(Serialize, Deserialize)]
pub enum ApiResponse {
    String(String),
    SecurityEvent {
        policy_id: u64,
        container_id: u64,
        comm: String,
        msg: Option<String>,
    },
}

/// Represents a running API server along with all the context
/// it needs to operate normally.
pub struct ApiContext {
    server: Server,
}

impl ApiContext {
    pub fn new(config: &Settings) -> Self {
        let mut io = IoHandler::default();
        // TODO: Register API endpoints here

        // Spawn the websocket server
        let server = ServerBuilder::new(io)
            .start(
                &config
                    .daemon
                    .websocket_ip
                    .parse()
                    .expect("Failed to parse websocket server IP"),
            )
            .expect("Server must start with no issues");

        Self { server }
    }
}
