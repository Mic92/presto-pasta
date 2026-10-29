//! A guest flow to an unspecified address (`0.0.0.0`, `::` or
//! `::ffff:0.0.0.0`) is refused before any flow policy is asked: a host
//! `connect()` to one reaches loopback, which the default policy refuses.
//! The tap is faked with a unix datagram pair, and the listeners are on
//! this process's loopback, where the datapath's host sockets would
//! reach them.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::time::Duration;

use presto_pasta::{Config, FlowDst, FlowFilter, Presto, proto, tap};

const L3: usize = tap::VNET_HDR_LEN + proto::ETH_LEN;

/// A guest SYN from `sport` to `dst` as the tap delivers it, or with
/// `udp` a datagram.
fn frame(cfg: &Config, dst: SocketAddr, sport: u16, udp: bool) -> Vec<u8> {
    let (ip_proto, l4_len) = if udp {
        (proto::IPPROTO_UDP, proto::UDP_HDR_LEN + 4)
    } else {
        (proto::IPPROTO_TCP, proto::TCP_HDR_LEN)
    };
    let len = u16::try_from(l4_len).expect("length");
    let mut f = vec![0u8; L3 + proto::IPV6_HDR_LEN + l4_len];
    let (ethertype, l4, pseudo) = match dst.ip() {
        IpAddr::V4(d) => {
            proto::Ipv4Hdr::write(&mut f[L3..], cfg.guest4, d, ip_proto, len);
            let pseudo = proto::pseudo_v4(cfg.guest4, d, ip_proto, len);
            (proto::ETHERTYPE_IPV4, L3 + proto::IPV4_HDR_LEN, pseudo)
        }
        IpAddr::V6(d) => {
            proto::Ipv6Hdr::write(&mut f[L3..], cfg.guest6, d, ip_proto, len);
            let pseudo = proto::pseudo_v6(cfg.guest6, d, ip_proto, len);
            (proto::ETHERTYPE_IPV6, L3 + proto::IPV6_HDR_LEN, pseudo)
        }
    };
    proto::EthHdr {
        dst: cfg.gateway_mac,
        src: [2, 0, 0, 0, 0, 1],
        ethertype,
    }
    .write(&mut f[tap::VNET_HDR_LEN..]);
    f.truncate(l4 + l4_len);
    let l4 = &mut f[l4..];
    if udp {
        l4[proto::UDP_HDR_LEN..].copy_from_slice(b"ping");
        proto::UdpHdr::write(l4, sport, dst.port(), pseudo, false);
    } else {
        let ports = (sport, dst.port());
        proto::TcpHdr::write(l4, ports, 1, 0, proto::TCP_SYN, 65535, &[], pseudo, false);
    }
    f
}

/// Under `cfg`, send a SYN to each unspecified address, at the port of a
/// listener on the loopback address a host connect would reach, and a
/// datagram to `0.0.0.0`, at a UDP socket's on `127.0.0.1`: none may get
/// through.
fn check(what: &str, cfg: &Config) {
    let (guest, tap_end) = UnixDatagram::pair().expect("socketpair");
    guest
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("read timeout");
    let mut presto = Presto::new(cfg.clone(), OwnedFd::from(tap_end));
    let (stop_r, stop_w) = std::io::pipe().expect("pipe");
    presto.stop_on(OwnedFd::from(stop_r));
    let datapath = std::thread::spawn(move || presto.run());

    let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listen on 127.0.0.1");
    let v6 = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).expect("listen on ::1");
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind 127.0.0.1");
    let port = |l: &TcpListener| l.local_addr().expect("listener").port();
    let syns = [
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, port(&v4))),
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, port(&v6))),
        SocketAddr::from((Ipv4Addr::UNSPECIFIED.to_ipv6_mapped(), port(&v4))),
    ];
    for (sport, dst) in (40000..).zip(syns) {
        guest.send(&frame(cfg, dst, sport, false)).expect("send");
    }
    let udp_port = udp.local_addr().expect("socket").port();
    let dst = SocketAddr::from((Ipv4Addr::UNSPECIFIED, udp_port));
    guest.send(&frame(cfg, dst, 40003, true)).expect("send");

    let mut answer = [0u8; 2048];
    if let Ok(n) = guest.recv(&mut answer) {
        let ip_len = if answer[L3] >> 4 == 4 {
            proto::IPV4_HDR_LEN
        } else {
            proto::IPV6_HDR_LEN
        };
        let tcp = proto::TcpHdr::parse(&answer[L3 + ip_len..n]);
        panic!("{what}: answered the guest: {tcp:?}");
    }
    for listener in [&v4, &v6] {
        listener.set_nonblocking(true).expect("nonblocking");
        let accepted = listener.accept();
        assert!(accepted.is_err(), "{what}: accepted {accepted:?}");
    }
    udp.set_nonblocking(true).expect("nonblocking");
    let got = udp.recv_from(&mut answer);
    assert!(got.is_err(), "{what}: 127.0.0.1 got a datagram: {got:?}");

    drop(stop_w);
    datapath.join().expect("join").expect("datapath run");
}

#[test]
fn unspecified_destinations_do_not_reach_host_loopback() {
    check("default policy", &Config::default());
    // Refused before the policy is asked, not by the default one.
    let allow_all: FlowFilter = Arc::new(|_: &FlowDst| true);
    let cfg = Config {
        allow_flow: Some(allow_all),
        ..Config::default()
    };
    check("allow-all policy", &cfg);
}
