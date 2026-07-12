//! Flow table: guest 5-tuple to host socket.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::Instant;

use crate::buf;

/// Guest-visible identity of a flow. `dst` is what the guest addressed
/// (before any DNS redirect), so replies can be sourced from it. For
/// ICMP echo flows `guest_port` carries the guest's echo identifier
/// and the port in `dst` is zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub proto: u8,
    pub guest_port: u16,
    pub dst: SocketAddr,
}

/// How replies from the host socket are framed back to the guest.
#[derive(Debug, Clone, Copy)]
pub enum FlowKind {
    Udp,
    /// ICMP/ICMPv6 echo over a ping socket; the kernel rewrites the
    /// echo identifier, so replies are patched back to the guest's.
    Ping,
}

/// A flow: connected host socket plus the buffer its pending recv
/// targets.
pub struct Flow {
    pub key: FlowKey,
    pub kind: FlowKind,
    pub sock: UdpSocket,
    pub buf: buf::BufId,
    pub last_active: Instant,
    /// Set once expiry has cancelled the pending recv; the slot is
    /// freed when that recv completes.
    pub closing: bool,
}

/// Flows indexed by a stable id (used as `io_uring` `user_data`) and by key.
/// Slots of removed flows are reused only after their pending recv
/// completed, so in-flight completions never hit a different flow.
#[derive(Default)]
pub struct FlowTable {
    flows: Vec<Option<Flow>>,
    free: Vec<usize>,
    by_key: HashMap<FlowKey, usize, foldhash::fast::RandomState>,
}

impl FlowTable {
    #[must_use]
    pub fn get(&self, key: &FlowKey) -> Option<usize> {
        self.by_key.get(key).copied()
    }

    #[must_use]
    pub fn get_by_id(&self, id: usize) -> Option<&Flow> {
        self.flows.get(id)?.as_ref()
    }

    pub fn get_mut(&mut self, id: usize) -> Option<&mut Flow> {
        self.flows.get_mut(id)?.as_mut()
    }

    pub fn insert(&mut self, flow: Flow) -> usize {
        let key = flow.key;
        let id = if let Some(id) = self.free.pop() {
            self.flows[id] = Some(flow);
            id
        } else {
            self.flows.push(Some(flow));
            self.flows.len() - 1
        };
        self.by_key.insert(key, id);
        id
    }

    /// Drop the flow, closing its socket, and hand back its buffer id.
    pub fn remove(&mut self, id: usize) -> Option<buf::BufId> {
        let flow = self.flows.get_mut(id)?.take()?;
        self.by_key.remove(&flow.key);
        self.free.push(id);
        Some(flow.buf)
    }

    /// Ids of flows idle since before `cutoff` and not yet closing.
    #[must_use]
    pub fn expired(&self, cutoff: Instant) -> Vec<usize> {
        self.flows
            .iter()
            .enumerate()
            .filter_map(|(id, slot)| slot.as_ref().map(|f| (id, f)))
            .filter(|(_, f)| !f.closing && f.last_active < cutoff)
            .map(|(id, _)| id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(port: u16) -> Flow {
        Flow {
            key: FlowKey {
                proto: 17,
                guest_port: port,
                dst: "10.0.0.1:53".parse().unwrap(),
            },
            kind: FlowKind::Udp,
            sock: UdpSocket::bind("127.0.0.1:0").unwrap(),
            buf: 0,
            last_active: Instant::now(),
            closing: false,
        }
    }

    #[test]
    fn slots_are_reused_after_removal() {
        let mut t = FlowTable::default();
        let a = t.insert(flow(1000));
        let b = t.insert(flow(1001));
        assert_ne!(a, b);
        t.remove(a);
        assert!(t.get_by_id(a).is_none());
        assert!(t.get(&flow(1000).key).is_none());
        let c = t.insert(flow(1002));
        assert_eq!(c, a);
        assert!(t.get_by_id(b).is_some());
    }

    #[test]
    fn expired_skips_active_and_closing() {
        let mut t = FlowTable::default();
        let a = t.insert(flow(1));
        let b = t.insert(flow(2));
        t.get_mut(b).unwrap().closing = true;
        let later = Instant::now() + std::time::Duration::from_secs(1);
        assert_eq!(t.expired(later), vec![a]);
        let earlier = Instant::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .unwrap();
        assert!(t.expired(earlier).is_empty());
    }
}
