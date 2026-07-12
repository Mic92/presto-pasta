//! presto: user-mode NAT datapath for sandboxes.
//!
//! Translates L2 frames on a caller-provided tap fd to native host
//! sockets (outbound TCP/UDP, ICMP echo, DNS forwarding). The host
//! kernel runs the real TCP stack; presto only rewrites headers and
//! moves payload. The caller owns the network namespace and the tap
//! device configuration. See DESIGN.md.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::OwnedFd;

pub mod buf;
pub mod proto;
pub mod tap;
pub mod uring;

/// Addresses presto uses to synthesize headers and to recognize
/// gateway-addressed traffic (DNS). Must match what the caller
/// configured on the tap interface.
#[derive(Debug, Clone)]
pub struct Config {
    pub guest4: Ipv4Addr,
    pub gateway4: Ipv4Addr,
    pub guest6: Ipv6Addr,
    pub gateway6: Ipv6Addr,
    /// MAC the caller assigned to the gateway neighbor entry.
    pub gateway_mac: [u8; 6],
    /// Forward DNS queries addressed to the gateway to the host resolver.
    pub dns_forward: bool,
    /// Number of 64k buffers in the pool.
    pub buffers: usize,
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
            buffers: 256,
        }
    }
}

/// A configured datapath over a tap fd.
pub struct Presto {
    cfg: Config,
    tap: tap::Tap,
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
        }
    }

    /// Run the event loop until the tap fd is torn down or an
    /// unrecoverable error occurs.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from the ring or the tap fd.
    pub fn run(self) -> io::Result<()> {
        uring::EventLoop::new(&self.cfg, self.tap)?.run()
    }
}
