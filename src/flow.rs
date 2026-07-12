//! Flow table: guest 5-tuple to host socket.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::OwnedFd;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowKind {
    Udp,
    /// ICMP/ICMPv6 echo over a ping socket; the kernel rewrites the
    /// echo identifier, so replies are patched back to the guest's.
    Ping,
    Tcp,
}

/// State of the FIN we send towards the guest when the host socket
/// hits EOF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinState {
    NotSent,
    Sent,
    Acked,
}

/// Connection state of a TCP flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// `connect()` to the host target is in progress; SYN-ACK is sent
    /// once the socket reports writability without error.
    Connecting,
    Established,
}

/// Per-flow TCP sequence bookkeeping.
///
/// Bytes towards the guest are read from the host socket into the
/// flow's buffer and dropped from it only once the guest acknowledges
/// them, so retransmission just rewinds `sent_unacked` and resends
/// from the buffer.
#[derive(Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent protocol conditions, not a state machine"
)]
pub struct Tcp {
    pub state: TcpState,
    /// Sequence of the next byte expected from the guest.
    pub seq_from_guest: u32,
    /// Sequence of the oldest byte sent to the guest and not yet acked
    /// (snapshots the guest's highest ack).
    pub seq_una: u32,
    /// Payload bytes past `seq_una` currently in flight to the guest.
    pub sent_unacked: u32,
    /// Bytes read from the host socket and held in the flow's buffer,
    /// starting at `seq_una`; the first `sent_unacked` of them are in
    /// flight, the rest not yet sent.
    pub buffered: u32,
    /// The host closed its sending side; a FIN is forwarded to the
    /// guest once all buffered data has been sent and acknowledged.
    pub host_eof: bool,
    /// Guest receive window in bytes (already scaled).
    pub guest_window: u32,
    /// Consecutive duplicate acks from the guest; three trigger a
    /// fast retransmit of everything in flight.
    pub dup_acks: u8,
    /// Window scale shift the guest offered, if any; scaling is only
    /// in effect (in both directions) when this is `Some`.
    pub guest_wscale: Option<u8>,
    /// MSS the guest announced; used as GSO segment size towards it.
    pub guest_mss: u16,
    /// Host socket send buffer size, for clamping the window we
    /// advertise to the guest.
    pub sndbuf: u32,
    pub host_fin: FinState,
    pub guest_fin_received: bool,
    /// An ack owed to the guest was withheld for one in-order data
    /// frame; the next data frame acks unconditionally.
    pub ack_deferred: bool,
    /// A poll for readability of the host socket is pending.
    pub poll_armed: bool,
}

/// A flow: connected host socket plus the buffer its pending recv or
/// poll targets.
pub struct Flow {
    pub key: FlowKey,
    pub kind: FlowKind,
    pub sock: OwnedFd,
    pub buf: buf::BufId,
    pub last_active: Instant,
    /// TCP bookkeeping; `None` for UDP and ping flows.
    pub tcp: Option<Tcp>,
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
            sock: std::net::UdpSocket::bind("127.0.0.1:0").unwrap().into(),
            buf: 0,
            last_active: Instant::now(),
            tcp: None,
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
