//! Differential fuzzing of the datapath against the kernel network
//! stack, plus raw tap frame fuzzing.
//!
//! The sandbox namespace has two paths to the host services: the tap
//! driven by presto-pasta (10.0.0.1 / `fd00::1`) and a veth pair handled
//! entirely by the kernel (10.0.1.1 / `fd00:1::1`). `differential_traffic`
//! runs seeded random socket scenarios through both paths and asserts
//! the observable outcomes match. `frame_fuzz` injects mutated L2
//! frames into the tap and asserts the datapath survives and keeps
//! forwarding.
//!
//! Both tests are `#[ignore]`d:
//!
//! ```console
//! cargo test --release --test differential -- --ignored --nocapture
//! ```
//!
//! `PRESTO_FUZZ_SEED` fixes the RNG seed, `PRESTO_FUZZ_ITERS` scales
//! the number of scenarios / frames.

mod common;

use std::io;
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::exit;
use std::time::{Duration, Instant};

use common::{
    ROLE, allow_ping_sockets, connect_with_retry, ip, ping, run_in_userns, setup_and_pass_tap,
    spawn_sandbox_and_recv_tap,
};
use presto_pasta::proto;

/// Presto path targets: host loopback addresses reached through the tap.
const PRESTO_V4: &str = "10.0.0.1";
const PRESTO_V6: &str = "fd00::1";
/// Kernel path targets: host end of the veth pair.
const VETH_V4: &str = "10.0.1.1";
const VETH_V6: &str = "fd00:1::1";

const TCP_PORT: u16 = 7878;
const UDP_PORT: u16 = 7777;
/// No listener on this port; used to compare error behaviour.
const CLOSED_PORT: u16 = 7000;

/// Fuzz configuration forwarded into the re-executed roles.
fn fuzz_env() -> Vec<(&'static str, String)> {
    let mut env = vec![("PRESTO_FUZZ_SEED", seed().to_string())];
    if let Ok(iters) = std::env::var("PRESTO_FUZZ_ITERS") {
        env.push(("PRESTO_FUZZ_ITERS", iters));
    }
    env
}

/// RNG seed: from the environment for reproduction, otherwise random.
fn seed() -> u64 {
    if let Ok(s) = std::env::var("PRESTO_FUZZ_SEED") {
        return s.parse().expect("PRESTO_FUZZ_SEED must be a u64");
    }
    let mut buf = [0u8; 8];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .expect("read /dev/urandom");
    u64::from_le_bytes(buf).max(1)
}

fn iterations(default: usize) -> usize {
    std::env::var("PRESTO_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// xorshift64*: deterministic, no external dependency.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).expect("fits usize")
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// Interface index of `ifname`, 0 when it does not exist. sysfs still
/// shows the original namespace after `unshare --net`, so ask the
/// kernel directly.
fn ifindex(ifname: &str) -> u32 {
    let name = std::ffi::CString::new(ifname).expect("interface name");
    unsafe { libc::if_nametoindex(name.as_ptr()) }
}

/// Wait for the host side to move `veth0` into this namespace, then
/// address the kernel-stack reference path.
fn setup_veth_guest() {
    let deadline = Instant::now() + Duration::from_secs(10);
    while ifindex("veth0") == 0 {
        assert!(Instant::now() < deadline, "veth0 never appeared in sandbox");
        std::thread::sleep(Duration::from_millis(50));
    }
    ip("addr add 10.0.1.2/24 dev veth0");
    ip("addr add fd00:1::2/64 dev veth0 nodad");
    ip("link set veth0 up");
}

/// Host namespace: create the veth pair and address the host end. The
/// peer stays here until the sandbox pid is known.
fn setup_veth_host() {
    ip("link add veth0 type veth peer name veth-host");
    ip(&format!("addr add {VETH_V4}/24 dev veth-host"));
    ip(&format!("addr add {VETH_V6}/64 dev veth-host nodad"));
    ip("link set veth-host up");
}

/// Every address one of the echo services listens on.
fn service_addrs(port: u16) -> [String; 4] {
    [
        format!("{PRESTO_V4}:{port}"),
        format!("{VETH_V4}:{port}"),
        format!("[{PRESTO_V6}]:{port}"),
        format!("[{VETH_V6}]:{port}"),
    ]
}

/// Bind the echo services on all addresses so both paths reach them.
fn start_echo_services() {
    for addr in service_addrs(UDP_PORT) {
        let echo = UdpSocket::bind(&addr).unwrap_or_else(|e| panic!("bind udp echo {addr}: {e}"));
        std::thread::spawn(move || {
            let mut b = vec![0u8; 65536];
            while let Ok((n, peer)) = echo.recv_from(&mut b) {
                let _ = echo.send_to(&b[..n], peer);
            }
        });
    }
    for addr in service_addrs(TCP_PORT) {
        let listener =
            TcpListener::bind(&addr).unwrap_or_else(|e| panic!("bind tcp echo {addr}: {e}"));
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut rx = conn;
                    let mut tx = rx.try_clone().expect("clone conn");
                    let mut b = vec![0u8; 64 * 1024];
                    while let Ok(n) = rx.read(&mut b) {
                        if n == 0 || tx.write_all(&b[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
    }
}

/// Whether the datapath thread is still alive (liveness fd not HUP'd).
fn datapath_alive(liveness: &OwnedFd) -> bool {
    let mut pfd = libc::pollfd {
        fd: liveness.as_raw_fd(),
        events: 0,
        revents: 0,
    };
    let n = unsafe { libc::poll(&raw mut pfd, 1, 0) };
    n == 0 || (pfd.revents & libc::POLLHUP) == 0
}

/// Host side shared by both fuzz tests: echo services on the presto
/// addresses, presto-pasta on the tap, veth pair to the sandbox.
fn fuzz_host(sandbox_role: &str, test: &str) -> ! {
    allow_ping_sockets();
    ip("link set lo up");
    ip(&format!("addr add {PRESTO_V4}/32 dev lo"));
    ip(&format!("addr add {PRESTO_V6}/128 dev lo nodad"));
    setup_veth_host();
    start_echo_services();

    let (mut child, tap_fd) = spawn_sandbox_and_recv_tap(sandbox_role, test, &fuzz_env());
    let mut presto = presto_pasta::Presto::new(presto_pasta::Config::default(), tap_fd);
    let liveness = presto.liveness_fd().expect("liveness fd");
    std::thread::spawn(move || presto.run().expect("presto-pasta run"));
    // Hand the sandbox its end of the veth pair.
    ip(&format!("link set veth0 netns {}", child.id()));

    let status = child.wait().expect("wait sandbox");
    assert!(datapath_alive(&liveness), "datapath thread died");
    exit(i32::from(!status.success()));
}

/// One randomized scenario, executed identically against both paths.
#[derive(Debug, Clone)]
enum Scenario {
    /// Stream `size` bytes to the echo server in `chunk`-byte writes;
    /// `half_close` shuts the write side down before draining.
    TcpEcho {
        v6: bool,
        size: usize,
        chunk: usize,
        half_close: bool,
    },
    /// Connect to a port with no listener.
    TcpClosedPort { v6: bool },
    /// Send `pkts` datagrams of `size` bytes and count echoes.
    UdpEcho { v6: bool, pkts: usize, size: usize },
    /// Send a datagram to a port with no listener and observe the error
    /// surfaced on the connected socket.
    UdpClosedPort { v6: bool },
    /// One ICMP / `ICMPv6` echo request.
    Ping { v6: bool },
}

impl Scenario {
    fn random(rng: &mut Rng) -> Self {
        let v6 = rng.below(2) == 1;
        match rng.below(8) {
            0..=2 => Scenario::TcpEcho {
                v6,
                size: 1 + rng.below(512 * 1024),
                chunk: 1 + rng.below(64 * 1024),
                half_close: rng.below(2) == 1,
            },
            3 => Scenario::TcpClosedPort { v6 },
            4 | 5 => Scenario::UdpEcho {
                v6,
                pkts: 1 + rng.below(16),
                size: 1 + rng.below(1400),
            },
            6 => Scenario::UdpClosedPort { v6 },
            _ => Scenario::Ping { v6 },
        }
    }
}

/// Address of one path/family/port combination.
fn target(v4: &str, v6_addr: &str, v6: bool, port: u16) -> String {
    if v6 {
        format!("[{v6_addr}]:{port}")
    } else {
        format!("{v4}:{port}")
    }
}

/// Coarse error class: enough to compare behaviour without depending on
/// exact error strings or timing.
fn error_class(e: &io::Error) -> &'static str {
    use io::ErrorKind::{
        BrokenPipe, ConnectionRefused, ConnectionReset, HostUnreachable, NetworkUnreachable,
        TimedOut, WouldBlock,
    };
    match e.kind() {
        ConnectionRefused => "refused",
        ConnectionReset | BrokenPipe => "reset",
        TimedOut | WouldBlock => "timeout",
        HostUnreachable | NetworkUnreachable => "unreachable",
        _ => "other",
    }
}

/// Run one scenario against one path and describe the observable
/// outcome; identical strings on both paths mean identical behaviour as
/// far as a socket user can tell.
fn run_scenario(scenario: &Scenario, payload_seed: u64, v4: &str, v6_addr: &str) -> String {
    let mut rng = Rng::new(payload_seed);
    match scenario {
        Scenario::TcpEcho {
            v6,
            size,
            chunk,
            half_close,
        } => {
            let addr = target(v4, v6_addr, *v6, TCP_PORT);
            let mut stream = match connect_with_retry(&addr) {
                Ok(s) => s,
                Err(e) => return format!("tcp-connect-{}", error_class(&e)),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .unwrap();
            let mut payload = vec![0u8; *size];
            rng.fill(&mut payload);
            let writer = {
                let mut tx = stream.try_clone().expect("clone stream");
                let payload = payload.clone();
                let (chunk, half_close) = (*chunk, *half_close);
                std::thread::spawn(move || -> Result<(), &'static str> {
                    for part in payload.chunks(chunk) {
                        tx.write_all(part).map_err(|e| error_class(&e))?;
                    }
                    if half_close {
                        tx.shutdown(std::net::Shutdown::Write)
                            .map_err(|e| error_class(&e))?;
                    }
                    Ok(())
                })
            };
            // With a half-close read to EOF, otherwise read exactly the
            // payload back.
            let mut echoed = Vec::with_capacity(payload.len());
            let read = if *half_close {
                stream.read_to_end(&mut echoed).map(|_| ())
            } else {
                echoed.resize(payload.len(), 0);
                stream.read_exact(&mut echoed)
            };
            match (writer.join().expect("writer thread"), read) {
                (Ok(()), Ok(())) if echoed == payload => "tcp-echo-ok".to_string(),
                (Ok(()), Ok(())) => "tcp-echo-corrupt".to_string(),
                (Err(w), _) => format!("tcp-write-{w}"),
                (_, Err(r)) => format!("tcp-read-{}", error_class(&r)),
            }
        }
        Scenario::TcpClosedPort { v6 } => {
            match connect_with_retry(&target(v4, v6_addr, *v6, CLOSED_PORT)) {
                Ok(_) => "tcp-closed-connected".to_string(),
                Err(e) => format!("tcp-closed-{}", error_class(&e)),
            }
        }
        Scenario::UdpEcho { v6, pkts, size } => {
            let sock = udp_connected(v4, v6_addr, *v6, UDP_PORT);
            let mut payload = vec![0u8; *size];
            let mut echoed = 0usize;
            for i in 0..*pkts {
                rng.fill(&mut payload);
                payload[0] = u8::try_from(i).expect("pkts fits u8");
                let mut reply = vec![0u8; *size + 1];
                // Retry: UDP is lossy on both paths; the comparison is
                // about reachability and payload fidelity, not loss rate.
                for _ in 0..20 {
                    if sock.send(&payload).is_err() {
                        break;
                    }
                    if let Ok(n) = sock.recv(&mut reply)
                        && reply[..n] == payload[..]
                    {
                        echoed += 1;
                        break;
                    }
                }
            }
            format!("udp-echo-{echoed}/{pkts}")
        }
        Scenario::UdpClosedPort { v6 } => {
            let sock = udp_connected(v4, v6_addr, *v6, CLOSED_PORT);
            // The ICMP error may surface on the send or the recv; retry
            // so both paths get the chance to deliver it.
            for _ in 0..10 {
                if let Err(e) = sock.send(b"nobody-home") {
                    return format!("udp-closed-send-{}", error_class(&e));
                }
                let mut reply = [0u8; 64];
                match sock.recv(&mut reply) {
                    Ok(_) => return "udp-closed-reply".to_string(),
                    Err(e) if error_class(&e) == "timeout" => {}
                    Err(e) => return format!("udp-closed-recv-{}", error_class(&e)),
                }
            }
            "udp-closed-timeout".to_string()
        }
        Scenario::Ping { v6 } => {
            let dst = if *v6 { v6_addr } else { v4 };
            format!("ping-{}", if ping(dst) { "reply" } else { "silent" })
        }
    }
}

fn udp_connected(v4: &str, v6_addr: &str, v6: bool, port: u16) -> UdpSocket {
    let sock = UdpSocket::bind(if v6 { "[::]:0" } else { "0.0.0.0:0" }).expect("bind udp");
    sock.connect(target(v4, v6_addr, v6, port))
        .expect("connect udp");
    sock.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    sock
}

/// Sandbox side of the differential traffic test: run every scenario
/// through both paths and compare.
fn traffic_sandbox() -> ! {
    allow_ping_sockets();
    let _tap_fd = setup_and_pass_tap();
    setup_veth_guest();

    let seed = seed();
    let iters = iterations(40);
    println!("differential_traffic: seed={seed} iterations={iters}");
    let mut rng = Rng::new(seed);
    let mut mismatches = Vec::new();
    for i in 0..iters {
        let scenario = Scenario::random(&mut rng);
        let payload_seed = rng.next();
        let presto = run_scenario(&scenario, payload_seed, PRESTO_V4, PRESTO_V6);
        let kernel = run_scenario(&scenario, payload_seed, VETH_V4, VETH_V6);
        println!("[{i:03}] {scenario:?}: presto={presto} kernel={kernel}");
        if presto != kernel {
            mismatches.push(format!(
                "scenario {i} ({scenario:?}): presto={presto} kernel={kernel}"
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "behaviour differs from kernel stack (seed {seed}):\n{}",
        mismatches.join("\n")
    );
    exit(0);
}

/// Randomized socket traffic through presto-pasta and through a veth
/// pair, asserting both paths behave identically.
#[test]
#[ignore = "differential fuzz, run explicitly"]
fn differential_traffic() {
    match std::env::var(ROLE).as_deref() {
        Ok("diff-host") => fuzz_host("diff-sandbox", "differential_traffic"),
        Ok("diff-sandbox") => traffic_sandbox(),
        _ => {}
    }
    run_in_userns("diff-host", "differential_traffic", &fuzz_env());
}

/// Raw `AF_PACKET` socket bound to `ifname` for injecting arbitrary L2
/// frames into the guest side of the tap.
fn packet_socket(ifname: &str) -> OwnedFd {
    let eth_p_all = u16::try_from(libc::ETH_P_ALL).expect("ETH_P_ALL fits u16");
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            i32::from(eth_p_all.to_be()),
        )
    };
    assert!(fd >= 0, "packet socket: {}", io::Error::last_os_error());
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = u16::try_from(libc::AF_PACKET).unwrap();
    sll.sll_protocol = eth_p_all.to_be();
    sll.sll_ifindex = i32::try_from(ifindex(ifname)).expect("ifindex fits i32");
    assert!(sll.sll_ifindex != 0, "interface {ifname} not found");
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            std::ptr::from_ref(&sll).cast(),
            u32::try_from(std::mem::size_of::<libc::sockaddr_ll>()).unwrap(),
        )
    };
    assert!(
        rc == 0,
        "bind packet socket: {}",
        io::Error::last_os_error()
    );
    fd
}

/// MAC address of a local interface (SIOCGIFHWADDR; sysfs shows the
/// original namespace after `unshare --net`).
fn mac_of(ifname: &str) -> [u8; 6] {
    let sock = UdpSocket::bind("0.0.0.0:0").expect("mac probe socket");
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    #[expect(clippy::cast_possible_wrap, reason = "c_char is i8 on some targets")]
    for (dst, src) in ifr.ifr_name.iter_mut().zip(ifname.bytes()) {
        *dst = src as libc::c_char;
    }
    let rc = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFHWADDR, &raw mut ifr) };
    assert!(
        rc == 0,
        "SIOCGIFHWADDR {ifname}: {}",
        io::Error::last_os_error()
    );
    let raw = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data };
    let mut mac = [0u8; 6];
    #[expect(clippy::cast_sign_loss, reason = "c_char is i8 on some targets")]
    for (dst, src) in mac.iter_mut().zip(raw) {
        *dst = src as u8;
    }
    mac
}

/// A well-formed IPv4/UDP frame from the guest to the gateway, used as
/// the mutation template so fuzzed frames reach deep into the parser.
fn udp_template(cfg: &presto_pasta::Config, guest_mac: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let udp_len = u16::try_from(proto::UDP_HDR_LEN + payload.len()).expect("payload fits u16");
    let mut frame = vec![0u8; proto::ETH_LEN + proto::IPV4_HDR_LEN + usize::from(udp_len)];
    let (eth, rest) = frame.split_at_mut(proto::ETH_LEN);
    let (ipv4, udp) = rest.split_at_mut(proto::IPV4_HDR_LEN);

    proto::EthHdr {
        dst: cfg.gateway_mac,
        src: guest_mac,
        ethertype: proto::ETHERTYPE_IPV4,
    }
    .write(eth);
    proto::Ipv4Hdr::write(ipv4, cfg.guest4, cfg.gateway4, proto::IPPROTO_UDP, udp_len);
    udp[proto::UDP_HDR_LEN..].copy_from_slice(payload);
    let pseudo = proto::pseudo_v4(cfg.guest4, cfg.gateway4, proto::IPPROTO_UDP, udp_len);
    proto::UdpHdr::write(udp, 12345, UDP_PORT, pseudo, false);
    frame
}

/// One fuzzed frame: either mutated from the valid template or random
/// bytes behind a plausible ethernet header.
fn fuzz_frame(rng: &mut Rng, cfg: &presto_pasta::Config, guest_mac: [u8; 6]) -> Vec<u8> {
    if rng.below(4) == 0 {
        let mut frame = vec![0u8; 14 + rng.below(1500)];
        rng.fill(&mut frame);
        frame[..6].copy_from_slice(&cfg.gateway_mac);
        frame[6..12].copy_from_slice(&guest_mac);
        return frame;
    }
    let mut payload = vec![0u8; rng.below(256)];
    rng.fill(&mut payload);
    let mut frame = udp_template(cfg, guest_mac, &payload);
    // Corrupt a handful of bytes anywhere: truncated headers, bad
    // versions, wrong lengths, broken checksums, flipped protocol
    // numbers all fall out of this.
    for _ in 0..=rng.below(8) {
        let idx = rng.below(frame.len());
        frame[idx] = u8::try_from(rng.next() & 0xff).expect("byte");
    }
    match rng.below(4) {
        0 => frame.truncate(1 + rng.below(frame.len())),
        1 => frame.extend_from_slice(&vec![0xa5u8; rng.below(512)]),
        _ => {}
    }
    frame
}

/// Sandbox side of the frame fuzz test: blast mutated frames at the
/// tap, then prove the datapath still forwards well-formed traffic.
fn frame_fuzz_sandbox() -> ! {
    let _tap_fd = setup_and_pass_tap();
    setup_veth_guest();

    let seed = seed();
    let iters = iterations(2000);
    println!("frame_fuzz: seed={seed} frames={iters}");
    let mut rng = Rng::new(seed);
    let cfg = presto_pasta::Config::default();
    let guest_mac = mac_of("eth0");
    let sock = packet_socket("eth0");

    for _ in 0..iters {
        let frame = fuzz_frame(&mut rng, &cfg, guest_mac);
        let rc = unsafe { libc::send(sock.as_raw_fd(), frame.as_ptr().cast(), frame.len(), 0) };
        // Frames the kernel itself refuses (e.g. shorter than an
        // ethernet header) are fine to skip; everything else must reach
        // the tap.
        assert!(
            rc >= 0
                || matches!(
                    io::Error::last_os_error().raw_os_error(),
                    Some(libc::EINVAL | libc::EMSGSIZE)
                ),
            "send fuzz frame: {}",
            io::Error::last_os_error()
        );
    }

    // The datapath must survive the fuzzed frames and keep forwarding.
    let checks = [
        (
            Scenario::TcpEcho {
                v6: false,
                size: 64 * 1024,
                chunk: 4096,
                half_close: true,
            },
            "tcp-echo-ok",
        ),
        (
            Scenario::UdpEcho {
                v6: true,
                pkts: 4,
                size: 512,
            },
            "udp-echo-4/4",
        ),
    ];
    for (scenario, expected) in checks {
        let outcome = run_scenario(&scenario, seed, PRESTO_V4, PRESTO_V6);
        assert_eq!(outcome, expected, "broken after frame fuzz (seed {seed})");
    }
    exit(0);
}

/// Mutated raw L2 frames must not kill or wedge the datapath.
#[test]
#[ignore = "differential fuzz, run explicitly"]
fn frame_fuzz() {
    match std::env::var(ROLE).as_deref() {
        Ok("frame-host") => fuzz_host("frame-sandbox", "frame_fuzz"),
        Ok("frame-sandbox") => frame_fuzz_sandbox(),
        _ => {}
    }
    run_in_userns("frame-host", "frame_fuzz", &fuzz_env());
}
