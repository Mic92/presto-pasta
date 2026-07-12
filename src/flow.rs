//! Flow table: guest 5-tuple to host socket.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};

use crate::buf;

/// Guest-visible identity of a flow. `dst` is what the guest addressed
/// (before any DNS redirect), so replies can be sourced from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub proto: u8,
    pub guest_port: u16,
    pub dst: SocketAddr,
}

/// A UDP flow: connected host socket plus the buffer its pending recv
/// targets.
pub struct UdpFlow {
    pub key: FlowKey,
    pub sock: UdpSocket,
    pub buf: buf::BufId,
}

/// Flows indexed by a stable id (used as `io_uring` `user_data`) and by key.
#[derive(Default)]
pub struct FlowTable {
    flows: Vec<UdpFlow>,
    by_key: HashMap<FlowKey, usize, foldhash::fast::RandomState>,
}

impl FlowTable {
    #[must_use]
    pub fn get(&self, key: &FlowKey) -> Option<usize> {
        self.by_key.get(key).copied()
    }

    #[must_use]
    pub fn get_by_id(&self, id: usize) -> Option<&UdpFlow> {
        self.flows.get(id)
    }

    pub fn insert(&mut self, flow: UdpFlow) -> usize {
        let id = self.flows.len();
        self.by_key.insert(flow.key, id);
        self.flows.push(flow);
        id
    }
}
