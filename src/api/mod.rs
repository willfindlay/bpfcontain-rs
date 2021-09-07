use std::cell::RefCell;
use std::sync::{Arc, RwLock};

use jsonrpc_ws_server::jsonrpc_core::*;
use jsonrpc_ws_server::{Server, ServerBuilder};

use crate::bpf_program::BpfcontainContext;
use crate::config::Settings;

mod pubsub;
mod rpc;

/// Represents a running API server along with all the context
/// it needs to operate normally.
pub struct ApiContext<'bpf> {
    /// A `RefCell` wrapping a reference to the `BpfcontainContext`.
    /// TODO: Figure out if Arc/RwLock are strictly necessary here
    bpfcontain: Arc<RwLock<RefCell<BpfcontainContext<'bpf>>>>,
    server: Server,
}

impl<'bpf> ApiContext<'bpf> {
    pub fn new(config: &Settings, bpfcontain: RefCell<BpfcontainContext<'bpf>>) -> Self {
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

        Self {
            bpfcontain: Arc::new(RwLock::new(bpfcontain)),
            server,
        }
    }
}
