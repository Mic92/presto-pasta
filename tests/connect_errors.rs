//! A guest TCP connection the host cannot make is answered at once
//! instead of dropped: ICMP/ICMPv6 destination unreachable for routing
//! errors and prohibit routes, RST for a refused connect and for an
//! error no ICMP code gives. Otherwise the guest keeps retransmitting
//! its SYN for minutes before its connect gives up. A SYN or datagram
//! to a multicast or broadcast address, IPv4-mapped ones included,
//! gets no answer (RFC 1122 3.2.2, 4.2.3.10).
//!
//! The tap is faked with a unix datagram pair. Each test re-executes
//! itself as root in a fresh user and network namespace (`own_netns`:
//! it needs iproute2's `ip`, and skips without unprivileged user
//! namespaces) whose routes it sets up, which makes every case
//! independent of the host's routing:
//! no route (ENETUNREACH), an unreachable route (EHOSTUNREACH), a
//! prohibit route (EACCES), a closed loopback port (ECONNREFUSED), an
//! on-link address nobody answers for (EHOSTUNREACH once neighbor
//! discovery gives up), a link-local address without a scope (EINVAL),
//! no free ephemeral port and IPv6 disabled (both EADDRNOTAVAIL).
//!
//! The datapath's host sockets live in that namespace too, so a native
//! connect from the test tells which error they meet. The answer is
//! checked against it, not against presto-pasta's own mapping: the ICMP
//! code must make a Linux guest's socket fail with the native errno
//! (see [`guest_errno`] and [`owed`]), and ECONNREFUSED, or an error no
//! ICMP code gives, must be an RST.
//! A case whose native connect does not fail as the setup intends fails
//! the test.

mod own_netns;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixDatagram;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use own_netns::{Ran, in_own_netns, ip};
use presto_pasta::{Config, FlowDst, Presto, proto, tap};
use rustix::io::Errno;
use rustix::net::{AddressFamily, SocketFlags, SocketType, connect, socket_with, sockopt};

const GUEST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
const SYN_SEQ: u32 = 0x1234_5678;
/// The fake guest never retransmits, so a dropped packet gets no answer
/// at all; the bound only keeps that failure from hanging the test. It
/// covers neighbor discovery giving up (about 3 s).
const ANSWER_WITHIN: Duration = Duration::from_secs(10);

/// RFC 5737 / RFC 3849 documentation addresses: no route to them.
const UNROUTED_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const UNROUTED_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
/// Behind an unreachable route (`ip route add unreachable`).
const UNREACHABLE_V4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const UNREACHABLE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1);
/// Behind a prohibit route (`ip route add prohibit`).
const PROHIBITED_V4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const PROHIBITED_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 1);
/// Link-local without a scope: a host connect fails with EINVAL, which
/// no ICMP code gives a guest.
const UNSCOPED_LINK_LOCAL_V6: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
/// On-link on a bridge without ports, so without carrier: neighbor
/// discovery for them fails. (A dummy interface is NOARP: it never
/// looks a neighbor up, and the connect just times out.)
const ON_LINK_V4: Ipv4Addr = Ipv4Addr::new(10, 9, 9, 77);
const ON_LINK_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 9, 0, 0, 0, 0, 0x77);

/// The routes every case relies on.
const NETNS_SETUP: &[&str] = &[
    "link set lo up",
    "route add unreachable 198.51.100.0/24",
    "-6 route add unreachable 2001:db8:1::/48",
    "route add prohibit 203.0.113.0/24",
    "-6 route add prohibit 2001:db8:2::/48",
];
/// The on-link prefixes, on a bridge without ports.
const BRIDGE_SETUP: &[&str] = &[
    "link add br0 type bridge",
    "addr add 10.9.9.1/24 dev br0",
    "-6 addr add 2001:db8:9::1/64 dev br0 nodad",
    "link set br0 up",
];

struct Datapath {
    guest: UnixDatagram,
    cfg: Config,
    stop: Option<std::io::PipeWriter>,
    thread: Option<std::thread::JoinHandle<std::io::Result<()>>>,
}

impl Datapath {
    fn start() -> Self {
        // Allow every destination: the refused-port cases target
        // loopback, which the default policy rejects.
        Self::with_policy(Arc::new(|_: &FlowDst| true))
    }

    fn with_policy(allow_flow: presto_pasta::FlowFilter) -> Self {
        Self::with_config(Config {
            allow_flow: Some(allow_flow),
            ..Config::default()
        })
    }

    fn with_config(cfg: Config) -> Self {
        let (guest, tap_end) = UnixDatagram::pair().expect("socketpair");
        guest
            .set_read_timeout(Some(ANSWER_WITHIN))
            .expect("read timeout");
        let mut presto = Presto::new(cfg.clone(), OwnedFd::from(tap_end));
        let (stop_r, stop_w) = std::io::pipe().expect("pipe");
        presto.stop_on(OwnedFd::from(stop_r));
        let thread = std::thread::spawn(move || presto.run());
        Self {
            guest,
            cfg,
            stop: Some(stop_w),
            thread: Some(thread),
        }
    }

    fn guest_ip(&self, dst: IpAddr) -> IpAddr {
        match dst {
            IpAddr::V4(_) => self.cfg.guest4.into(),
            IpAddr::V6(_) => self.cfg.guest6.into(),
        }
    }

    /// Send one guest IP packet, behind vnet and ethernet headers.
    fn send(&self, ip_packet: &[u8]) {
        let mut frame = vec![0u8; tap::VNET_HDR_LEN + proto::ETH_LEN];
        proto::EthHdr {
            dst: self.cfg.gateway_mac,
            src: GUEST_MAC,
            ethertype: ethertype(ip_packet),
        }
        .write(&mut frame[tap::VNET_HDR_LEN..]);
        frame.extend_from_slice(ip_packet);
        self.guest.send(&frame).expect("send guest frame");
    }

    /// The IP packet of the next frame the datapath writes to the guest,
    /// which must be an answer to `sent`'s family.
    fn recv(&self, sent: &[u8], what: &str) -> Vec<u8> {
        let mut answer = vec![0u8; 65536];
        let n = self.guest.recv(&mut answer).unwrap_or_else(|e| {
            let exited = self
                .thread
                .as_ref()
                .is_some_and(std::thread::JoinHandle::is_finished);
            panic!("{what}: no answer within {ANSWER_WITHIN:?} (datapath exited: {exited}): {e}")
        });
        let eth = proto::EthHdr::parse(&answer[tap::VNET_HDR_LEN..n]).expect("ethernet header");
        assert_eq!(eth.dst, GUEST_MAC, "{what}: not addressed to the guest");
        assert_eq!(
            eth.ethertype,
            ethertype(sent),
            "{what}: answer of another family"
        );
        answer[tap::VNET_HDR_LEN + proto::ETH_LEN..n].to_vec()
    }

    fn exchange(&self, ip_packet: &[u8], what: &str) -> Vec<u8> {
        self.send(ip_packet);
        self.recv(ip_packet, what)
    }
}

impl Drop for Datapath {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(t) = self.thread.take() {
            let run = t.join();
            if !std::thread::panicking() {
                run.expect("join").expect("datapath run");
            }
        }
    }
}

fn ethertype(ip_packet: &[u8]) -> u16 {
    if ip_packet[0] >> 4 == 4 {
        proto::ETHERTYPE_IPV4
    } else {
        proto::ETHERTYPE_IPV6
    }
}

/// How a native nonblocking connect from this namespace ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Native {
    /// `connect` itself fails with this errno.
    Fails(i32),
    /// `connect` starts, and the socket reports this error within
    /// [`ANSWER_WITHIN`].
    FailsLater(i32),
}

/// What a native connect of `kind` from this namespace to `dst` meets:
/// the error the datapath's host socket meets too. Panics if it
/// connects or does not fail in time.
fn native_connect(kind: SocketType, dst: SocketAddr) -> Native {
    let family = if dst.is_ipv4() {
        AddressFamily::INET
    } else {
        AddressFamily::INET6
    };
    let flags = SocketFlags::NONBLOCK | SocketFlags::CLOEXEC;
    let sock = socket_with(family, kind, flags, None).expect("native socket");
    match connect(&sock, &dst) {
        Err(Errno::INPROGRESS) => {}
        Err(e) => return Native::Fails(e.raw_os_error()),
        Ok(()) => panic!("{dst}: native connect succeeded"),
    }
    let mut pfd = libc::pollfd {
        fd: sock.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    let ms = i32::try_from(ANSWER_WITHIN.as_millis()).expect("timeout");
    // SAFETY: one valid pollfd for the call.
    let ready = unsafe { libc::poll(&raw mut pfd, 1, ms) };
    assert_eq!(ready, 1, "{dst}: native connect still pending");
    match sockopt::socket_error(&sock).expect("SO_ERROR") {
        Ok(()) => panic!("{dst}: native connect succeeded"),
        Err(e) => Native::FailsLater(e.raw_os_error()),
    }
}

/// The errno a Linux guest's socket gets from an ICMP/ICMPv6
/// destination unreachable with `code`: `icmp_err_convert` in
/// net/ipv4/icmp.c and `tab_unreach` in net/ipv6/icmp.c (Linux 6.12),
/// which `tcp_v4_err`/`tcp_v6_err` apply to a connecting socket and
/// `__udp4_lib_err`/`__udp6_lib_err` to a UDP one. Independent of
/// presto-pasta's errno-to-code mapping.
fn guest_errno(v4: bool, code: u8) -> Option<i32> {
    use libc::{
        EACCES, ECONNREFUSED, EHOSTDOWN, EHOSTUNREACH, EMSGSIZE, ENETUNREACH, ENONET, ENOPROTOOPT,
        EOPNOTSUPP,
    };
    let table: &[i32] = if v4 {
        &[
            ENETUNREACH,  // 0 net unreachable
            EHOSTUNREACH, // 1 host unreachable
            ENOPROTOOPT,  // 2 protocol unreachable
            ECONNREFUSED, // 3 port unreachable
            EMSGSIZE,     // 4 fragmentation needed
            EOPNOTSUPP,   // 5 source route failed
            ENETUNREACH,  // 6 net unknown
            EHOSTDOWN,    // 7 host unknown
            ENONET,       // 8 host isolated
            ENETUNREACH,  // 9 net administratively prohibited
            EHOSTUNREACH, // 10 host administratively prohibited
            ENETUNREACH,  // 11 net unreachable for TOS
            EHOSTUNREACH, // 12 host unreachable for TOS
            EHOSTUNREACH, // 13 communication administratively prohibited
            EHOSTUNREACH, // 14 host precedence violation
            EHOSTUNREACH, // 15 precedence cutoff
        ]
    } else {
        &[
            ENETUNREACH,  // 0 no route to destination
            EACCES,       // 1 administratively prohibited
            EHOSTUNREACH, // 2 beyond scope of source address
            EHOSTUNREACH, // 3 address unreachable
            ECONNREFUSED, // 4 port unreachable
            EACCES,       // 5 source address failed policy
            EACCES,       // 6 reject route to destination
        ]
    };
    table.get(usize::from(code)).copied()
}

/// The errno a guest's socket should fail with when its host
/// counterpart failed with `native`: the same, except where no ICMP
/// code gives it. No IPv4 code gives EACCES or EPERM on Linux (a
/// firewall or LSM refusing the connect); communication
/// administratively prohibited (code 13, RFC 1812 5.2.7.1) gives
/// EHOSTUNREACH, and [`assert_answer`] requires that code. No IPv6 code
/// gives EPERM; administratively prohibited (code 1) gives EACCES.
fn owed(v4: bool, native: i32) -> i32 {
    match native {
        libc::EACCES | libc::EPERM if v4 => libc::EHOSTUNREACH,
        libc::EPERM => libc::EACCES,
        e => e,
    }
}

/// A guest packet from `src` to `dst` carrying `l4`, whose header
/// `fill` writes given the pseudo-header sum.
fn ip_packet(
    src: IpAddr,
    dst: IpAddr,
    ip_proto: u8,
    l4: &mut [u8],
    fill: impl Fn(&mut [u8], u32),
) -> Vec<u8> {
    let len = u16::try_from(l4.len()).expect("l4 length");
    let (mut packet, pseudo) = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut h = vec![0u8; proto::IPV4_HDR_LEN];
            proto::Ipv4Hdr::write(&mut h, s, d, ip_proto, len);
            (h, proto::pseudo_v4(s, d, ip_proto, len))
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut h = vec![0u8; proto::IPV6_HDR_LEN];
            proto::Ipv6Hdr::write(&mut h, s, d, ip_proto, len);
            (h, proto::pseudo_v6(s, d, ip_proto, len))
        }
        _ => unreachable!("mixed families"),
    };
    fill(l4, pseudo);
    packet.extend_from_slice(l4);
    packet
}

fn tcp_syn(src: IpAddr, dst: SocketAddr, sport: u16) -> Vec<u8> {
    let mut l4 = [0u8; proto::TCP_HDR_LEN + 4];
    // MSS option, as every real SYN carries
    let mss = [2, 4, 0x05, 0xb4];
    ip_packet(src, dst.ip(), proto::IPPROTO_TCP, &mut l4, |b, pseudo| {
        let ports = (sport, dst.port());
        proto::TcpHdr::write(
            b,
            ports,
            SYN_SEQ,
            0,
            proto::TCP_SYN,
            65535,
            &mss,
            pseudo,
            false,
        );
    })
}

fn udp_datagram(src: IpAddr, dst: SocketAddr, sport: u16) -> Vec<u8> {
    let mut l4 = [0u8; proto::UDP_HDR_LEN + 4];
    l4[proto::UDP_HDR_LEN..].copy_from_slice(b"ping");
    ip_packet(src, dst.ip(), proto::IPPROTO_UDP, &mut l4, |b, pseudo| {
        proto::UdpHdr::write(b, sport, dst.port(), pseudo, false);
    })
}

/// Parse the answer's IP header, check it runs from the destination of
/// `sent` back to its source with protocol `ip_proto`, and return the
/// header length and the pseudo-header sum of its payload.
fn answer_ip(answer: &[u8], sent: &[u8], ip_proto: u8, what: &str) -> (usize, u32) {
    let len = |hdr: usize| u16::try_from(answer.len() - hdr).expect("length");
    if sent[0] >> 4 == 4 {
        let ip = proto::Ipv4Hdr::parse(answer).expect("IPv4 answer");
        let guest = proto::Ipv4Hdr::parse(sent).expect("IPv4 packet");
        assert_eq!(
            (ip.src, ip.dst),
            (guest.dst, guest.src),
            "{what}: addresses"
        );
        assert_eq!(ip.proto, ip_proto, "{what}: protocol");
        assert_eq!(usize::from(ip.total_len), answer.len(), "{what}: length");
        let header = &answer[..proto::IPV4_HDR_LEN];
        assert_eq!(proto::checksum(header, 0), 0, "{what}: IPv4 checksum");
        let n = len(proto::IPV4_HDR_LEN);
        (
            proto::IPV4_HDR_LEN,
            proto::pseudo_v4(ip.src, ip.dst, ip_proto, n),
        )
    } else {
        let ip = proto::Ipv6Hdr::parse(answer).expect("IPv6 answer");
        let guest = proto::Ipv6Hdr::parse(sent).expect("IPv6 packet");
        assert_eq!(
            (ip.src, ip.dst),
            (guest.dst, guest.src),
            "{what}: addresses"
        );
        assert_eq!(ip.next_header, ip_proto, "{what}: next header");
        let n = len(proto::IPV6_HDR_LEN);
        assert_eq!(ip.payload_len, n, "{what}: payload length");
        (
            proto::IPV6_HDR_LEN,
            proto::pseudo_v6(ip.src, ip.dst, ip_proto, n),
        )
    }
}

/// Check an ICMP/ICMPv6 destination unreachable towards the guest,
/// quoting the IP header of `sent` and the first `l4_match` bytes of
/// its L4 header (ports and, for TCP, the SYN's sequence number): what
/// the guest kernel needs to match it to its socket. Returns its code.
fn assert_unreachable(answer: &[u8], sent: &[u8], l4_match: usize, what: &str) -> u8 {
    let v4 = sent[0] >> 4 == 4;
    let (icmp_proto, icmp_type) = if v4 {
        (proto::IPPROTO_ICMP, proto::ICMP_DEST_UNREACH)
    } else {
        (proto::IPPROTO_ICMPV6, proto::ICMPV6_DEST_UNREACH)
    };
    let (ip_len, pseudo) = answer_ip(answer, sent, icmp_proto, what);
    // ICMPv4 checksums have no pseudo-header.
    let pseudo = if v4 { 0 } else { pseudo };
    let icmp = &answer[ip_len..];
    assert_eq!(icmp[0], icmp_type, "{what}: ICMP type");
    assert_eq!(proto::checksum(icmp, pseudo), 0, "{what}: ICMP checksum");
    let quoted = &icmp[proto::ICMP_HDR_LEN..];
    // Same addresses and protocol as the guest's packet; the lengths
    // differ, only headers are quoted.
    let (proto_at, addrs) = if v4 { (9, 12..20) } else { (6, 8..40) };
    assert_eq!(quoted[proto_at], sent[proto_at], "{what}: quoted protocol");
    assert_eq!(
        quoted[addrs.clone()],
        sent[addrs],
        "{what}: quoted addresses"
    );
    let l4 = ip_len..ip_len + l4_match;
    assert_eq!(quoted[l4.clone()], sent[l4], "{what}: quoted L4 header");
    icmp[1]
}

/// Check an RST|ACK towards the guest that acknowledges its SYN.
fn assert_rst(answer: &[u8], syn: &[u8], what: &str) {
    let (ip_len, pseudo) = answer_ip(answer, syn, proto::IPPROTO_TCP, what);
    let segment = &answer[ip_len..];
    assert_eq!(proto::checksum(segment, pseudo), 0, "{what}: TCP checksum");
    let tcp = proto::TcpHdr::parse(segment).expect("TCP header");
    let sent = proto::TcpHdr::parse(&syn[ip_len..]).expect("SYN header");
    let ports = (tcp.src_port, tcp.dst_port);
    assert_eq!(ports, (sent.dst_port, sent.src_port), "{what}: ports");
    let rst_ack = proto::TCP_RST | proto::TCP_ACK;
    assert_eq!(
        tcp.flags & rst_ack,
        rst_ack,
        "{what}: flags {:#x}",
        tcp.flags
    );
    assert_eq!(tcp.ack, SYN_SEQ.wrapping_add(1), "{what}: must ack the SYN");
}

/// Check that `answer` to `sent` makes the guest's socket fail with
/// `errno`, the error its native counterpart met: for TCP, an RST for a
/// refused connect and for an error no ICMP code gives a guest, else an
/// ICMP unreachable whose code the guest kernel turns into `errno`.
fn assert_answer(answer: &[u8], sent: &[u8], errno: i32, what: &str) {
    let v4 = sent[0] >> 4 == 4;
    let tcp = sent[if v4 { 9 } else { 6 }] == proto::IPPROTO_TCP;
    let want = owed(v4, errno);
    let no_code = (0..=u8::MAX).all(|code| guest_errno(v4, code) != Some(want));
    if tcp && (errno == libc::ECONNREFUSED || no_code) {
        assert_rst(answer, sent, what);
        return;
    }
    // TCP: ports and sequence number; UDP: ports (its length and
    // checksum are reconstructed).
    let code = assert_unreachable(answer, sent, if tcp { 8 } else { 4 }, what);
    assert_eq!(
        guest_errno(v4, code),
        Some(want),
        "{what}: ICMP code {code} gives the guest {:?}, not errno {want}",
        guest_errno(v4, code)
    );
    if v4 && want != errno {
        assert_eq!(code, 13, "{what}: administratively prohibited");
    }
}

/// Check that the datapath leaves `packet` unanswered: a witness SYN
/// sent after it, which the datapath answers at once (no route), must
/// get the first answer.
fn check_silent(dp: &Datapath, packet: &[u8], witness_port: u16, what: &str) {
    dp.send(packet);
    let dst = if packet[0] >> 4 == 4 {
        IpAddr::from(UNROUTED_V4)
    } else {
        IpAddr::from(UNROUTED_V6)
    };
    let dst = SocketAddr::new(dst, 443);
    let witness = tcp_syn(dp.guest_ip(dst.ip()), dst, witness_port);
    let what = format!("{what}: must get no answer, so the witness gets the first");
    let answer = dp.exchange(&witness, &what);
    assert_answer(&answer, &witness, libc::ENETUNREACH, &what);
}

/// A closed port on `ip`: bind one, then close it.
fn closed_port(ip: IpAddr) -> SocketAddr {
    TcpListener::bind((ip, 0))
        .and_then(|l| l.local_addr())
        .expect("ephemeral port")
}

/// Send a guest SYN to `dst` and check the answer against a native
/// connect, which must end as `intended`.
fn check_tcp(dp: &Datapath, dst: SocketAddr, sport: u16, intended: Native) {
    let native = native_connect(SocketType::STREAM, dst);
    assert_eq!(native, intended, "{dst}: native TCP connect");
    let (Native::Fails(errno) | Native::FailsLater(errno)) = native;
    let what = format!("TCP SYN to {dst} (native {native:?})");
    let syn = tcp_syn(dp.guest_ip(dst.ip()), dst, sport);
    let answer = dp.exchange(&syn, &what);
    assert_answer(&answer, &syn, errno, &what);
    eprintln!("checked {what}");
}

#[test]
fn failed_tcp_connect_is_answered() {
    in_own_netns("failed_tcp_connect_is_answered", NETNS_SETUP, || {
        let dp = Datapath::start();
        let at = |ip: IpAddr| SocketAddr::new(ip, 443);
        for (i, (dst, errno)) in [
            (at(UNROUTED_V4.into()), libc::ENETUNREACH),
            (at(UNROUTED_V6.into()), libc::ENETUNREACH),
            (at(UNREACHABLE_V4.into()), libc::EHOSTUNREACH),
            (at(UNREACHABLE_V6.into()), libc::EHOSTUNREACH),
            (at(PROHIBITED_V4.into()), libc::EACCES),
            (at(PROHIBITED_V6.into()), libc::EACCES),
            (at(UNSCOPED_LINK_LOCAL_V6.into()), libc::EINVAL),
        ]
        .into_iter()
        .enumerate()
        {
            let sport = 40000 + u16::try_from(i).expect("port");
            check_tcp(&dp, dst, sport, Native::Fails(errno));
        }
    });
}

#[test]
fn refused_tcp_connect_is_answered_with_rst() {
    in_own_netns(
        "refused_tcp_connect_is_answered_with_rst",
        NETNS_SETUP,
        || {
            let dp = Datapath::start();
            let v4 = closed_port(Ipv4Addr::LOCALHOST.into());
            let v6 = closed_port(Ipv6Addr::LOCALHOST.into());
            let refused = Native::FailsLater(libc::ECONNREFUSED);
            check_tcp(&dp, v4, 40100, refused);
            check_tcp(&dp, v6, 40101, refused);
        },
    );
}

#[test]
fn tcp_connect_failing_later_is_answered() {
    in_own_netns("tcp_connect_failing_later_is_answered", NETNS_SETUP, || {
        for args in BRIDGE_SETUP {
            ip(args).unwrap_or_else(|e| panic!("setting up the bridge: {e}"));
        }
        let dp = Datapath::start();
        let unreachable = Native::FailsLater(libc::EHOSTUNREACH);
        check_tcp(
            &dp,
            SocketAddr::new(ON_LINK_V4.into(), 443),
            40200,
            unreachable,
        );
        check_tcp(
            &dp,
            SocketAddr::new(ON_LINK_V6.into(), 443),
            40201,
            unreachable,
        );
    });
}

/// A host out of local ports fails a connect with EADDRNOTAVAIL, the
/// error an IPv6 host without a source address meets too (below), so
/// it is reset like any other error no ICMP code gives.
#[test]
fn tcp_connect_short_of_ports_is_reset() {
    in_own_netns("tcp_connect_short_of_ports_is_reset", NETNS_SETUP, || {
        // A single ephemeral port, reserved: a connect that needs one
        // fails with EADDRNOTAVAIL.
        for (knob, value) in [
            ("ip_local_port_range", "40000 40000"),
            ("ip_local_reserved_ports", "40000"),
        ] {
            std::fs::write(format!("/proc/sys/net/ipv4/{knob}"), value)
                .unwrap_or_else(|e| panic!("net.ipv4.{knob}: {e}"));
        }
        let dp = Datapath::start();
        for (i, ip) in [
            IpAddr::from(Ipv4Addr::LOCALHOST),
            Ipv6Addr::LOCALHOST.into(),
        ]
        .into_iter()
        .enumerate()
        {
            let sport = 40400 + u16::try_from(i).expect("port");
            let dst = SocketAddr::new(ip, 9);
            check_tcp(&dp, dst, sport, Native::Fails(libc::EADDRNOTAVAIL));
        }
    });
}

/// Disable IPv6 in this namespace as NixOS's `networking.enableIPv6 =
/// false` does: `disable_ipv6` on all, default and lo.
fn disable_ipv6() {
    for conf in ["all", "default", "lo"] {
        std::fs::write(format!("/proc/sys/net/ipv6/conf/{conf}/disable_ipv6"), "1")
            .unwrap_or_else(|e| panic!("net.ipv6.conf.{conf}.disable_ipv6: {e}"));
    }
}

/// A host with IPv6 disabled (`disable_ipv6` on all, default and lo,
/// as NixOS's `networking.enableIPv6 = false` sets it) has no IPv6
/// source address: an IPv6 connect fails with EADDRNOTAVAIL, and the
/// guest's SYN is reset rather than left to retransmit.
#[test]
fn tcp_connect_from_a_host_without_ipv6_is_reset() {
    in_own_netns(
        "tcp_connect_from_a_host_without_ipv6_is_reset",
        NETNS_SETUP,
        || {
            disable_ipv6();
            let dp = Datapath::start();
            let dst = SocketAddr::new(UNROUTED_V6.into(), 443);
            check_tcp(&dp, dst, 40450, Native::Fails(libc::EADDRNOTAVAIL));
        },
    );
}

/// The answer needs no buffer from the pool: with every buffer held,
/// the tap's and one per open TCP flow (which is never evicted), a SYN
/// whose host connect fails is still answered.
#[test]
fn failed_tcp_connect_is_answered_with_the_pool_dry() {
    in_own_netns(
        "failed_tcp_connect_is_answered_with_the_pool_dry",
        NETNS_SETUP,
        || {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener");
            let open = listener.local_addr().expect("listener address");
            let flows = 2;
            let dp = Datapath::with_config(Config {
                buffers: 1 + flows,
                allow_flow: Some(Arc::new(|_: &FlowDst| true)),
                ..Config::default()
            });
            for i in 0..flows {
                let what = format!("SYN {i} to the open port {open}");
                let sport = 40500 + u16::try_from(i).expect("port");
                let answer = dp.exchange(&tcp_syn(dp.guest_ip(open.ip()), open, sport), &what);
                assert_eq!(answer[9], proto::IPPROTO_TCP, "{what}: protocol");
                assert_eq!(
                    answer[proto::IPV4_HDR_LEN + 13],
                    proto::TCP_SYN | proto::TCP_ACK,
                    "{what}: a SYN-ACK"
                );
            }
            let unrouted = SocketAddr::new(UNROUTED_V4.into(), 443);
            check_tcp(&dp, unrouted, 40510, Native::Fails(libc::ENETUNREACH));
        },
    );
}

/// The name the control below re-runs, which no test has.
const NO_SUCH_TEST: &str = "control_rerun_of_no_test";

/// The guard in [`in_own_netns`]: a re-run that runs no test fails, so
/// a test renamed without its name string cannot pass by running
/// nothing. Skipped, like the tests it guards, without user namespaces.
#[test]
fn a_namespace_re_run_that_runs_no_test_fails() {
    match std::panic::catch_unwind(|| in_own_netns(NO_SUCH_TEST, &[], || {})) {
        Ok(Ran::Skipped) => {}
        Ok(Ran::InOwnNetns) => panic!("a re-run of no test passed"),
        Err(panic) => {
            let msg = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or_default();
            assert!(
                msg.contains(&format!("ran no test named {NO_SUCH_TEST}")),
                "{msg}"
            );
        }
    }
}

#[test]
fn no_answer_to_multicast_or_broadcast() {
    in_own_netns("no_answer_to_multicast_or_broadcast", NETNS_SETUP, || {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let dp = Datapath::with_policy({
            let asked = Arc::clone(&asked);
            Arc::new(move |dst: &FlowDst| {
                asked.lock().expect("policy log").push(*dst);
                true
            })
        });
        let mut port = 40600;
        let ips = [
            IpAddr::from(Ipv4Addr::new(224, 0, 0, 1)),
            Ipv4Addr::BROADCAST.into(),
            Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 1).into(),
            Ipv4Addr::new(224, 0, 0, 1).to_ipv6_mapped().into(),
        ];
        for ip in ips {
            for (kind, dst) in [
                (SocketType::STREAM, SocketAddr::new(ip, 443)),
                (SocketType::DGRAM, SocketAddr::new(ip, 53)),
            ] {
                // The host's connect fails at once, so anything but the
                // rule would answer it.
                let native = native_connect(kind, dst);
                assert!(
                    matches!(native, Native::Fails(_)),
                    "{dst}: native connect must fail at once: {native:?}"
                );
                let (what, packet) = if kind == SocketType::STREAM {
                    ("TCP SYN", tcp_syn(dp.guest_ip(ip), dst, port))
                } else {
                    ("UDP datagram", udp_datagram(dp.guest_ip(ip), dst, port))
                };
                let what = format!("{what} to {dst} (native {native:?})");
                check_silent(&dp, &packet, port + 1, &what);
                eprintln!("checked {what}: no answer");
                port += 2;
            }
        }
        // Such a SYN is dropped before the flow policy is asked or a host
        // socket made; the witnesses' SYNs are asked about.
        let asked = asked.lock().expect("policy log");
        let tcp = |d: &&FlowDst| d.proto == proto::IPPROTO_TCP;
        assert!(asked.iter().any(|d| tcp(&d)), "no SYN reached the policy");
        let mc: Vec<_> = asked
            .iter()
            .filter(tcp)
            .filter(|d| ips.contains(&d.ip))
            .collect();
        assert!(mc.is_empty(), "the policy was asked about {mc:?}");
    });
}
