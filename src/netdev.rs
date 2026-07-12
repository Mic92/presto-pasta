//! Guest-side interface configuration.
//!
//! presto-pasta has no ARP/NDP responder and no DHCP: the tap
//! interface inside the sandbox namespace must carry the addresses
//! from [`Config`], default routes via the gateway addresses and
//! permanent neighbor entries for [`Config::gateway_mac`].
//! [`configure`] sets all of that up via ioctl and rtnetlink so
//! callers do not need an `ip` binary in the sandbox.

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, OwnedFd};

use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType, socket};

use crate::Config;

/// MTU set on the tap interface: large frames let the guest emit GSO
/// aggregates that presto-pasta forwards as single writes.
pub const MTU: u32 = 65520;

#[expect(clippy::cast_possible_truncation, reason = "NLM_F_* fit in u16")]
const NLM_F_FLAGS: u16 =
    (libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_REPLACE) as u16;
/// `RTNH_F_ONLINK`: the gateway is reachable on the interface even
/// though it is outside the (host-width) address prefix.
const ONLINK: u32 = 0x4;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;
const NDA_DST: u16 = 1;

// Fixed-layout rtnetlink payload headers (linux/if_addr.h,
// linux/rtnetlink.h, linux/neighbour.h).
#[repr(C)]
struct IfAddrMsg {
    family: u8,
    prefixlen: u8,
    flags: u8,
    scope: u8,
    index: u32,
}

#[repr(C)]
struct RtMsg {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table: u8,
    protocol: u8,
    scope: u8,
    rtype: u8,
    flags: u32,
}

#[repr(C)]
struct NdMsg {
    family: u8,
    pad1: u8,
    pad2: u16,
    ifindex: i32,
    state: u16,
    flags: u8,
    ntype: u8,
}

/// One rtnetlink request: a payload header followed by attributes,
/// serialized with the kernel's 4-byte alignment rules.
struct Request {
    buf: Vec<u8>,
}

impl Request {
    fn new<T>(msg_type: u16, header: &T) -> Self {
        let hdr_len = std::mem::size_of::<libc::nlmsghdr>();
        let mut buf = vec![0u8; hdr_len];
        // Written as bytes; nlmsg_len is fixed up in finish().
        let nl = libc::nlmsghdr {
            nlmsg_len: 0,
            nlmsg_type: msg_type,
            nlmsg_flags: NLM_F_FLAGS,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        };
        buf[..hdr_len].copy_from_slice(unsafe {
            std::slice::from_raw_parts(std::ptr::from_ref(&nl).cast::<u8>(), hdr_len)
        });
        buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(std::ptr::from_ref(header).cast::<u8>(), size_of::<T>())
        });
        Self { buf }
    }

    fn attr(mut self, kind: u16, data: &[u8]) -> Self {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
        #[expect(clippy::cast_possible_truncation, reason = "attributes are tiny")]
        let len = (4 + data.len()) as u16;
        self.buf.extend_from_slice(&len.to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self
    }

    fn finish(mut self) -> Vec<u8> {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
        #[expect(clippy::cast_possible_truncation, reason = "requests are tiny")]
        let len = self.buf.len() as u32;
        self.buf[..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

fn family(ip: IpAddr) -> u8 {
    #[expect(clippy::cast_possible_truncation, reason = "AF_INET(6) fit in u8")]
    match ip {
        IpAddr::V4(_) => libc::AF_INET as u8,
        IpAddr::V6(_) => libc::AF_INET6 as u8,
    }
}

/// Send one rtnetlink request and wait for its acknowledgement.
fn rtnetlink(sock: &OwnedFd, req: &[u8]) -> io::Result<()> {
    nix::sys::socket::send(sock.as_raw_fd(), req, nix::sys::socket::MsgFlags::empty())?;
    let mut buf = [0u8; 512];
    let n = nix::sys::socket::recv(
        sock.as_raw_fd(),
        &mut buf,
        nix::sys::socket::MsgFlags::empty(),
    )?;
    let hdr_len = std::mem::size_of::<libc::nlmsghdr>();
    if n < hdr_len + 4 {
        return Err(io::Error::other("short netlink reply"));
    }
    let msg_type = u16::from_ne_bytes([buf[4], buf[5]]);
    if i32::from(msg_type) != libc::NLMSG_ERROR {
        return Err(io::Error::other("unexpected netlink reply type"));
    }
    let errno = i32::from_ne_bytes([
        buf[hdr_len],
        buf[hdr_len + 1],
        buf[hdr_len + 2],
        buf[hdr_len + 3],
    ]);
    if errno == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(-errno))
    }
}

/// Set `IFF_UP` and the MTU via `SIOCSIFFLAGS`/`SIOCSIFMTU`.
fn link_up(ifname: &str) -> io::Result<()> {
    let sock = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?;
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    if ifname.len() >= ifr.ifr_name.len() {
        return Err(io::Error::other("interface name too long"));
    }
    unsafe {
        std::ptr::copy_nonoverlapping(
            ifname.as_ptr(),
            ifr.ifr_name.as_mut_ptr().cast::<u8>(),
            ifname.len(),
        );
    }
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFFLAGS, &mut ifr) } < 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "IFF_UP|IFF_RUNNING fit in c_short"
        )]
        {
            ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        }
        if libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS, &ifr) < 0 {
            return Err(io::Error::last_os_error());
        }
        ifr.ifr_ifru.ifru_mtu = MTU.cast_signed();
        if libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFMTU, &ifr) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn add_addr(sock: &OwnedFd, ifindex: u32, ip: IpAddr) -> io::Result<()> {
    let hdr = IfAddrMsg {
        family: family(ip),
        prefixlen: if ip.is_ipv4() { 32 } else { 128 },
        #[expect(clippy::cast_possible_truncation, reason = "IFA_F_NODAD fits in u8")]
        flags: if ip.is_ipv4() {
            0
        } else {
            libc::IFA_F_NODAD as u8
        },
        scope: RT_SCOPE_UNIVERSE,
        index: ifindex,
    };
    let req = Request::new(libc::RTM_NEWADDR, &hdr)
        .attr(libc::IFA_LOCAL, &ip_bytes(ip))
        .attr(libc::IFA_ADDRESS, &ip_bytes(ip))
        .finish();
    rtnetlink(sock, &req)
}

fn add_default_route(sock: &OwnedFd, ifindex: u32, gateway: IpAddr) -> io::Result<()> {
    let hdr = RtMsg {
        family: family(gateway),
        dst_len: 0,
        src_len: 0,
        tos: 0,
        table: RT_TABLE_MAIN,
        protocol: RTPROT_BOOT,
        scope: RT_SCOPE_UNIVERSE,
        rtype: RTN_UNICAST,
        flags: ONLINK,
    };
    let req = Request::new(libc::RTM_NEWROUTE, &hdr)
        .attr(libc::RTA_GATEWAY, &ip_bytes(gateway))
        .attr(libc::RTA_OIF, &ifindex.to_ne_bytes())
        .finish();
    rtnetlink(sock, &req)
}

fn add_neighbor(sock: &OwnedFd, ifindex: u32, gateway: IpAddr, mac: [u8; 6]) -> io::Result<()> {
    let hdr = NdMsg {
        family: family(gateway),
        pad1: 0,
        pad2: 0,
        #[expect(clippy::cast_possible_wrap, reason = "kernel ifindexes are small")]
        ifindex: ifindex as i32,
        state: libc::NUD_PERMANENT,
        flags: 0,
        ntype: 0,
    };
    let req = Request::new(libc::RTM_NEWNEIGH, &hdr)
        .attr(NDA_DST, &ip_bytes(gateway))
        .attr(libc::NDA_LLADDR, &mac)
        .finish();
    rtnetlink(sock, &req)
}

/// Configure the tap interface inside the sandbox namespace to match
/// `cfg`: link up with a large MTU, the guest addresses (host-width
/// prefixes), onlink default routes via the gateway addresses and
/// permanent neighbor entries for the gateway MAC. Must run in the
/// namespace that owns the interface, with `CAP_NET_ADMIN` there.
///
/// # Errors
///
/// Any ioctl or rtnetlink failure, e.g. when the interface does not
/// exist or the caller lacks `CAP_NET_ADMIN`.
pub fn configure(ifname: &str, cfg: &Config) -> io::Result<()> {
    link_up(ifname)?;
    let ifindex = nix::net::if_::if_nametoindex(ifname)?;

    let sock = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkRoute,
    )?;
    for (guest, gateway) in [
        (IpAddr::V4(cfg.guest4), IpAddr::V4(cfg.gateway4)),
        (IpAddr::V6(cfg.guest6), IpAddr::V6(cfg.gateway6)),
    ] {
        add_addr(&sock, ifindex, guest)?;
        add_neighbor(&sock, ifindex, gateway, cfg.gateway_mac)?;
        add_default_route(&sock, ifindex, gateway)?;
    }
    Ok(())
}
