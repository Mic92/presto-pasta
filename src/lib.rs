//! presto-pasta: user-mode NAT datapath for sandboxes.
//!
//! Translates L2 frames on a caller-provided tap fd to native host
//! sockets (outbound TCP/UDP, ICMP echo, DNS forwarding). The host
//! kernel runs the real TCP stack; presto-pasta only rewrites headers and
//! moves payload. The caller owns the network namespace and the tap
//! device configuration. See DESIGN.md.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::OwnedFd;
use std::sync::Arc;

pub mod buf;
pub mod dns;
pub mod flow;
pub mod proto;
#[cfg(feature = "seccomp")]
mod seccomp;
mod stats;
pub mod tap;
pub mod uring;

/// Destination of a new guest flow, presented to [`Config::allow_flow`]
/// before the host socket is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowDst {
    /// IP protocol number (`IPPROTO_TCP`, `IPPROTO_UDP`, ICMP/ICMPv6).
    pub proto: u8,
    pub ip: IpAddr,
    pub port: u16,
}

impl FlowDst {
    /// True for globally routable unicast destinations: loopback,
    /// private (RFC 1918), link-local, ULA, shared (CGNAT), multicast,
    /// broadcast and unspecified addresses are all non-public. Useful
    /// for an "internet only" policy that keeps the sandbox away from
    /// host-local services, LANs and VPN subnets.
    #[must_use]
    pub fn is_public(&self) -> bool {
        match self.ip {
            IpAddr::V4(ip) => {
                !(ip.is_loopback()
                    || ip.is_private()
                    || ip.is_link_local()
                    || ip.is_multicast()
                    || ip.is_broadcast()
                    || ip.is_unspecified()
                    // 100.64.0.0/10, RFC 6598 shared address space.
                    || (ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64))
            }
            IpAddr::V6(ip) => {
                let seg0 = ip.segments()[0];
                !(ip.is_loopback()
                    || ip.is_multicast()
                    || ip.is_unspecified()
                    // fc00::/7 unique local, fe80::/10 link-local.
                    || seg0 & 0xfe00 == 0xfc00
                    || seg0 & 0xffc0 == 0xfe80)
            }
        }
    }
}

/// Per-flow policy callback: return `false` to refuse the flow.
pub type FlowFilter = Arc<dyn Fn(&FlowDst) -> bool + Send + Sync>;

/// Addresses presto-pasta uses to synthesize headers and to recognize
/// gateway-addressed traffic (DNS). Must match what the caller
/// configured on the tap interface.
#[derive(Clone)]
pub struct Config {
    pub guest4: Ipv4Addr,
    pub gateway4: Ipv4Addr,
    pub guest6: Ipv6Addr,
    pub gateway6: Ipv6Addr,
    /// MAC the caller assigned to the gateway neighbor entry.
    pub gateway_mac: [u8; 6],
    /// Forward DNS queries addressed to the gateway to the host resolver.
    pub dns_forward: bool,
    /// Number of 64k buffers in the pool. The pool is registered with
    /// `io_uring` and pinned, so it is charged against `RLIMIT_MEMLOCK`
    /// (commonly 8 MiB); raise the limit before raising this.
    pub buffers: usize,
    /// Called once per new guest flow with its destination; a `false`
    /// return refuses the flow (the guest sees an unreachable host).
    /// `None` applies the default policy: refuse loopback destinations,
    /// allow everything else. DNS to the gateway address is forwarded
    /// by presto-pasta itself and is filtered on the gateway address,
    /// not on the host resolver's.
    pub allow_flow: Option<FlowFilter>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            guest4: Ipv4Addr::new(169, 254, 1, 2),
            gateway4: Ipv4Addr::new(169, 254, 1, 1),
            guest6: Ipv6Addr::new(0x64, 0xff9b, 0x1, 0x4b8e, 0x472e, 0xa5c8, 0xa9fe, 0x0102),
            gateway6: Ipv6Addr::new(0x64, 0xff9b, 0x1, 0x4b8e, 0x472e, 0xa5c8, 0xa9fe, 0x0101),
            gateway_mac: [0x9a, 0x55, 0x9a, 0x55, 0x9a, 0x55],
            dns_forward: true,
            buffers: 64,
            allow_flow: None,
        }
    }
}

/// A configured datapath over a tap fd.
pub struct Presto {
    cfg: Config,
    tap: tap::Tap,
    /// Write ends of liveness pipes; dropped (closing the read ends'
    /// peers) when the event loop exits.
    liveness: Vec<OwnedFd>,
}

impl Presto {
    /// Take ownership of a tap fd (opened by the caller inside the
    /// sandbox netns with `IFF_TAP | IFF_NO_PI | IFF_VNET_HDR`) and
    /// negotiate its offloads.
    #[must_use]
    pub fn new(cfg: Config, tap_fd: OwnedFd) -> Self {
        Self {
            cfg,
            tap: tap::Tap::new(tap_fd),
            liveness: Vec::new(),
        }
    }

    /// A liveness fd for a supervisor: it signals `POLLHUP`/EOF when
    /// the event loop exits (or the datapath process dies), so the
    /// supervisor can fail the sandboxed job instead of letting it
    /// hang without network.
    ///
    /// # Errors
    ///
    /// Returns an error if the pipe cannot be created.
    pub fn liveness_fd(&mut self) -> io::Result<OwnedFd> {
        let (read, write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)?;
        self.liveness.push(write);
        Ok(read)
    }

    /// Run the event loop until the tap fd is torn down or an
    /// unrecoverable error occurs.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from the ring or the tap fd.
    pub fn run(self) -> io::Result<()> {
        let event_loop = uring::EventLoop::new(&self.cfg, self.tap)?;
        // After setup so ring and tap initialization stay unrestricted.
        #[cfg(feature = "seccomp")]
        seccomp::apply()?;
        event_loop.run()
    }
}

#[cfg(test)]
mod tests {
    use super::FlowDst;

    fn dst(ip: &str) -> FlowDst {
        FlowDst {
            proto: 6,
            ip: ip.parse().unwrap(),
            port: 443,
        }
    }

    #[test]
    fn public_destinations() {
        for ip in ["1.1.1.1", "93.184.216.34", "2606:4700::1111"] {
            assert!(dst(ip).is_public(), "{ip} should be public");
        }
    }

    #[test]
    fn non_public_destinations() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "ff02::1",
            "::",
        ] {
            assert!(!dst(ip).is_public(), "{ip} should not be public");
        }
    }
}
