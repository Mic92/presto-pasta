//! A guest SYN whose host `connect()` fails at once is reset instead of
//! left to retransmit for minutes; one to a multicast or broadcast
//! address gets no answer (RFC 1122 4.2.3.10). Every destination here
//! fails `connect()` the same way on any host, so the tap is faked with
//! a unix datagram pair and no namespace is needed.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use presto_pasta::{Config, Presto, proto, tap};

const SEQ: u32 = 0x1234_5678;
const L3: usize = tap::VNET_HDR_LEN + proto::ETH_LEN;

/// A guest SYN from `sport` to `dst`, as the tap delivers it.
fn syn(cfg: &Config, dst: SocketAddr, sport: u16) -> Vec<u8> {
    let len = u16::try_from(proto::TCP_HDR_LEN).expect("length");
    let tcp = proto::IPPROTO_TCP;
    let mut f = vec![0u8; L3 + proto::IPV6_HDR_LEN + proto::TCP_HDR_LEN];
    let (ethertype, l4, pseudo) = match dst.ip() {
        IpAddr::V4(d) => {
            proto::Ipv4Hdr::write(&mut f[L3..], cfg.guest4, d, tcp, len);
            let pseudo = proto::pseudo_v4(cfg.guest4, d, tcp, len);
            (proto::ETHERTYPE_IPV4, L3 + proto::IPV4_HDR_LEN, pseudo)
        }
        IpAddr::V6(d) => {
            proto::Ipv6Hdr::write(&mut f[L3..], cfg.guest6, d, tcp, len);
            let pseudo = proto::pseudo_v6(cfg.guest6, d, tcp, len);
            (proto::ETHERTYPE_IPV6, L3 + proto::IPV6_HDR_LEN, pseudo)
        }
    };
    proto::EthHdr {
        dst: cfg.gateway_mac,
        src: [2, 0, 0, 0, 0, 1],
        ethertype,
    }
    .write(&mut f[tap::VNET_HDR_LEN..]);
    let end = l4 + proto::TCP_HDR_LEN;
    let ports = (sport, dst.port());
    proto::TcpHdr::write(
        &mut f[l4..end],
        ports,
        SEQ,
        0,
        proto::TCP_SYN,
        65535,
        &[],
        pseudo,
        false,
    );
    f.truncate(end);
    f
}

#[test]
fn failed_connect_is_reset_and_multicast_gets_no_answer() {
    let cfg = Config::default();
    let (guest, tap_end) = UnixDatagram::pair().expect("socketpair");
    guest
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut presto = Presto::new(cfg.clone(), OwnedFd::from(tap_end));
    let (stop_r, stop_w) = std::io::pipe().expect("pipe");
    presto.stop_on(OwnedFd::from(stop_r));
    let datapath = std::thread::spawn(move || presto.run());

    // Host connects to these fail at once (ENETUNREACH), yet they get no
    // answer, so the RST below must be the first one.
    let mc = Ipv4Addr::new(224, 0, 0, 1);
    let quiet: [IpAddr; 4] = [
        mc.into(),
        Ipv4Addr::BROADCAST.into(),
        mc.to_ipv6_mapped().into(),
        Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 1).into(),
    ];
    for (sport, ip) in (40000..).zip(quiet) {
        let frame = syn(&cfg, SocketAddr::new(ip, 443), sport);
        guest.send(&frame).expect("send SYN");
    }
    // connect() to a link-local address without a scope fails with EINVAL.
    let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let frame = syn(&cfg, SocketAddr::new(link_local.into(), 443), 40100);
    guest.send(&frame).expect("send SYN");

    let mut answer = [0u8; 2048];
    let n = guest.recv(&mut answer).expect("no answer to the SYN");
    let eth = proto::EthHdr::parse(&answer[tap::VNET_HDR_LEN..n]).expect("ethernet");
    assert_eq!(eth.ethertype, proto::ETHERTYPE_IPV6, "answered an IPv4 SYN");
    let rst = proto::TcpHdr::parse(&answer[L3 + proto::IPV6_HDR_LEN..n]).expect("TCP");
    assert_eq!(
        (rst.src_port, rst.dst_port),
        (443, 40100),
        "answered another SYN"
    );
    assert_eq!(rst.flags, proto::TCP_RST | proto::TCP_ACK);
    assert_eq!(rst.ack, SEQ.wrapping_add(1), "must acknowledge the SYN");

    drop(stop_w);
    datapath.join().expect("join").expect("datapath run");
}
