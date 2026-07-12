//! End-to-end harness with two namespaces, mirroring real deployment:
//! a "host" user+net namespace where presto-pasta and the reachable services
//! live, and a nested "sandbox" namespace that owns the tap device and
//! generates guest traffic.
//!
//! The test re-executes itself under `unshare --user --map-root-user
//! --net` twice (roles selected via `PRESTO_ROLE`); the sandbox child
//! opens and configures the tap the way a sandbox runner would and
//! passes the fd to the host side over a unix socketpair. This doubles
//! as the reference for integrating presto-pasta into a sandbox runner.

use std::io;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::process::{Command, exit};
use std::time::Duration;

use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockProtocol, SockType,
    recvmsg, sendmsg, socket, socketpair,
};

const ROLE: &str = "PRESTO_ROLE";
const PASS_FD: &str = "PRESTO_PASS_FD";

// linux/if_tun.h
const IFF_TAP: i16 = 0x0002;
const IFF_NO_PI: i16 = 0x1000;
const IFF_VNET_HDR: i16 = 0x4000;

nix::ioctl_write_ptr_bad!(
    tun_set_iff,
    nix::request_code_write!(b'T', 202, std::mem::size_of::<libc::c_int>()),
    libc::ifreq
);

fn open_tap(name: &str) -> io::Result<OwnedFd> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    #[allow(clippy::cast_possible_wrap, reason = "c_char is i8 on some targets")]
    for (dst, src) in ifr.ifr_name.iter_mut().zip(name.bytes()) {
        *dst = src as libc::c_char;
    }
    ifr.ifr_ifru.ifru_flags = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR;
    unsafe { tun_set_iff(file.as_raw_fd(), &raw const ifr) }.map_err(io::Error::from)?;
    Ok(OwnedFd::from(file))
}

fn allow_ping_sockets() {
    // Only gid 0 is mapped in the user namespace; wider ranges are
    // rejected with EINVAL.
    std::fs::write("/proc/sys/net/ipv4/ping_group_range", "0 0").expect("enable ping sockets");
}

/// Bulk TCP echo through presto-pasta: connect, stream 1 MiB, read it back.
fn tcp_echo(target: &str) {
    let mut stream = connect_with_retry(target);
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    let payload: Vec<u8> = (0..1024u32 * 1024)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    let writer = {
        let mut tx = stream.try_clone().expect("clone stream");
        let payload = payload.clone();
        std::thread::spawn(move || {
            tx.write_all(&payload).expect("write payload");
            tx.shutdown(std::net::Shutdown::Write).expect("shutdown");
        })
    };
    let mut echoed = Vec::with_capacity(payload.len());
    stream
        .read_to_end(&mut echoed)
        .unwrap_or_else(|e| panic!("read echo from {target}: {e}"));
    writer.join().expect("writer thread");
    assert_eq!(echoed.len(), payload.len(), "echo length from {target}");
    assert_eq!(echoed, payload, "echo content from {target}");
}

/// Connect through presto-pasta, retrying while it is still starting up.
fn connect_with_retry(target: &str) -> TcpStream {
    for _ in 0..20 {
        if let Ok(s) = TcpStream::connect(target) {
            return s;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    panic!("connect to {target}");
}

/// Send one ICMP echo request over an unprivileged ping socket and wait
/// for the reply.
fn ping(dst: &str) -> bool {
    let v4 = !dst.contains(':');
    let (family, proto) = if v4 {
        (AddressFamily::Inet, SockProtocol::Icmp)
    } else {
        (AddressFamily::Inet6, SockProtocol::IcmpV6)
    };
    let fd =
        socket(family, SockType::Datagram, SockFlag::SOCK_CLOEXEC, proto).expect("ping socket");
    let sock = UdpSocket::from(fd);
    sock.connect((dst, 0)).expect("connect ping socket");
    sock.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let echo_request = if v4 { 8u8 } else { 128 };
    // type, code, checksum (kernel), id (kernel), seq 1, payload
    let req = [echo_request, 0, 0, 0, 0, 0, 0, 1, 0xaa, 0xbb];
    let mut reply = [0u8; 64];
    for _ in 0..20 {
        sock.send(&req).expect("send echo request");
        if let Ok(n) = sock.recv(&mut reply) {
            return n == req.len() && reply[8..10] == [0xaa, 0xbb];
        }
    }
    false
}

/// Run `nft`, returning whether it succeeded (the binary or the
/// netfilter modules may be unavailable).
fn nft(args: &[&str]) -> bool {
    Command::new("nft")
        .args(args)
        .status()
        .is_ok_and(|s| s.success())
}

/// Byte pattern streamed and verified by the frame-loss test.
fn pattern(i: usize) -> u8 {
    u8::try_from(i % 251).expect("remainder fits u8")
}

fn ip(args: &str) {
    let status = Command::new("ip")
        .args(args.split_whitespace())
        .status()
        .expect("run ip");
    assert!(status.success(), "ip {args} failed");
}

fn reexec_unshared(role: &str, test: &str, extra_env: &[(&str, String)]) -> Command {
    let exe = std::env::current_exe().unwrap();
    let mut cmd = Command::new("unshare");
    cmd.args(["--user", "--map-root-user", "--net", "--"])
        .arg(exe)
        .args(["--exact", test, "--include-ignored", "--nocapture"])
        .env(ROLE, role);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd
}

/// Configure the tap the way a sandbox runner would before handing the
/// fd to presto-pasta, and pass it to the host side over the unix socket.
fn setup_and_pass_tap() -> OwnedFd {
    let tap_fd = open_tap("eth0").expect("open tap");

    ip("link set lo up");
    // Same MTU pasta configures on its tap: with the default 1500 the
    // guest's MSS is 1460 and its GSO frames stay well below the 64 KiB
    // a frame could carry.
    ip("link set eth0 mtu 65520");
    ip("link set eth0 up");
    ip("addr add 169.254.1.2/16 dev eth0");
    ip("addr add 64:ff9b:1:4b8e:472e:a5c8:a9fe:102/112 dev eth0 nodad");
    ip("route add default via 169.254.1.1 dev eth0");
    ip("route add default via 64:ff9b:1:4b8e:472e:a5c8:a9fe:101 dev eth0");
    ip("neigh add 169.254.1.1 lladdr 9a:55:9a:55:9a:55 dev eth0 nud permanent");
    ip(
        "neigh add 64:ff9b:1:4b8e:472e:a5c8:a9fe:101 lladdr 9a:55:9a:55:9a:55 dev eth0 nud permanent",
    );

    let pass_fd: RawFd = std::env::var(PASS_FD).unwrap().parse().unwrap();
    let pass = unsafe { BorrowedFd::borrow_raw(pass_fd) };
    let fds = [tap_fd.as_raw_fd()];
    sendmsg::<()>(
        pass.as_raw_fd(),
        &[io::IoSlice::new(b"tap")],
        &[ControlMessage::ScmRights(&fds)],
        MsgFlags::empty(),
        None,
    )
    .expect("send tap fd");
    // Keep tap_fd open: closing the last attached queue would drop the
    // interface carrier and with it the routes.
    tap_fd
}

/// Spawn the sandbox role, receive the tap fd it configured, and start
/// presto-pasta on it. Returns the sandbox child to wait on.
fn spawn_sandbox_with_presto(role: &str, test: &str) -> std::process::Child {
    let (ours, theirs) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None,
        SockFlag::empty(),
    )
    .expect("socketpair");
    let child = reexec_unshared(role, test, &[(PASS_FD, theirs.as_raw_fd().to_string())])
        .spawn()
        .expect("spawn sandbox");

    let mut cmsg = nix::cmsg_space!([RawFd; 1]);
    let mut data = [0u8; 8];
    let mut iov = [io::IoSliceMut::new(&mut data)];
    let msg = recvmsg::<()>(
        ours.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg),
        MsgFlags::empty(),
    )
    .expect("recv tap fd");
    let tap_fd = match msg.cmsgs().expect("cmsgs").next() {
        Some(ControlMessageOwned::ScmRights(fds)) => unsafe { OwnedFd::from_raw_fd(fds[0]) },
        other => panic!("expected SCM_RIGHTS, got {other:?}"),
    };

    let presto = presto_pasta::Presto::new(presto_pasta::Config::default(), tap_fd);
    let datapath_cpu = bench_cpus().map(|c| c[1].clone());
    std::thread::spawn(move || {
        if let Some(cpu) = datapath_cpu
            && let Ok(cpu) = cpu.parse()
        {
            let mut set = nix::sched::CpuSet::new();
            set.set(cpu).expect("cpu id in range");
            nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(0), &set)
                .expect("pin datapath thread");
        }
        presto.run().expect("presto-pasta run");
    });
    child
}

/// Sandbox namespace: open + configure the tap, hand the fd to the host
/// side, then exercise UDP through presto-pasta.
fn sandbox() -> ! {
    allow_ping_sockets();
    let _tap_fd = setup_and_pass_tap();

    for target in ["10.0.0.1:7777", "[fd00::1]:7777"] {
        let bind = if target.starts_with('[') {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let sock = UdpSocket::bind(bind).expect("bind in sandbox");
        sock.connect(target).expect("connect");
        sock.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let mut reply = [0u8; 16];
        let mut ok = false;
        for _ in 0..20 {
            sock.send(b"hello").expect("send");
            if let Ok(n) = sock.recv(&mut reply) {
                assert_eq!(&reply[..n], b"hello", "echo mismatch from {target}");
                ok = true;
                break;
            }
        }
        assert!(ok, "no echo reply from {target}");
    }

    for dst in ["10.0.0.1", "fd00::1"] {
        assert!(ping(dst), "no ICMP echo reply from {dst}");
    }

    for target in ["10.0.0.1:7878", "[fd00::1]:7878"] {
        tcp_echo(target);
    }
    exit(0);
}

/// Host namespace: run the echo services and presto-pasta, spawn the sandbox.
fn host() -> ! {
    allow_ping_sockets();
    ip("link set lo up");
    ip("addr add 10.0.0.1/32 dev lo");
    ip("addr add fd00::1/128 dev lo nodad");

    for addr in ["10.0.0.1:7777", "[fd00::1]:7777"] {
        let echo = UdpSocket::bind(addr).expect("bind echo");
        std::thread::spawn(move || {
            let mut b = [0u8; 2048];
            while let Ok((n, peer)) = echo.recv_from(&mut b) {
                let _ = echo.send_to(&b[..n], peer);
            }
        });
    }

    for addr in ["10.0.0.1:7878", "[fd00::1]:7878"] {
        let listener = TcpListener::bind(addr).expect("bind tcp echo");
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

    let mut child = spawn_sandbox_with_presto("sandbox", "datapath");
    let status = child.wait().expect("wait sandbox");
    exit(i32::from(!status.success()));
}

/// CPUs to pin the benchmark onto, from `PRESTO_BENCH_CPUS` as
/// "server,datapath,client". Pinning the three busiest actors to fixed
/// cores removes most of the run-to-run variance the scheduler causes
/// on large machines.
fn bench_cpus() -> Option<[String; 3]> {
    let val = std::env::var("PRESTO_BENCH_CPUS").ok()?;
    let mut parts = val.split(',').map(str::to_owned);
    let cpus = [parts.next()?, parts.next()?, parts.next()?];
    Some(cpus)
}

/// Command wrapped in `taskset -c cpu` when a CPU is given.
fn pinned(cpu: Option<&str>, program: &str) -> Command {
    match cpu {
        Some(cpu) => {
            let mut cmd = Command::new("taskset");
            cmd.args(["-c", cpu, program]);
            cmd
        }
        None => Command::new(program),
    }
}

/// Run the iperf3 client against the host-side server, once in each
/// direction, labelling the output.
fn iperf3_client(label: &str) {
    let cpus = bench_cpus();
    for (dir, extra) in [("upload", &[][..]), ("download", &["-R"][..])] {
        println!("=== {label} {dir} ===");
        let status = pinned(cpus.as_ref().map(|c| c[2].as_str()), "iperf3")
            .args(["-c", "10.0.0.1", "-t", "5", "-f", "g"])
            .args(extra)
            .status()
            .expect("run iperf3 client");
        assert!(status.success(), "iperf3 {label} {dir} failed");
    }
}

/// Run the iperf3 UDP client against the host-side server, once in
/// each direction. 1400-byte datagrams and no rate limit: each
/// datagram is one frame through the datapath (plain UDP sockets get
/// no GSO batching), so this measures per-packet cost.
fn iperf3_udp_client(label: &str) {
    let cpus = bench_cpus();
    for (dir, extra) in [("upload", &[][..]), ("download", &["-R"][..])] {
        println!("=== {label} udp {dir} ===");
        let status = pinned(cpus.as_ref().map(|c| c[2].as_str()), "iperf3")
            .args([
                "-c", "10.0.0.1", "-u", "-b", "0", "-l", "1400", "-t", "5", "-f", "g",
            ])
            .args(extra)
            .status()
            .expect("run iperf3 udp client");
        assert!(status.success(), "iperf3 udp {label} {dir} failed");
    }
}

/// UDP bench sandbox namespace: configure the tap, then measure with
/// iperf3 in UDP mode.
fn udp_sandbox() -> ! {
    let _tap_fd = setup_and_pass_tap();
    iperf3_udp_client("presto-pasta");
    exit(0);
}

/// UDP throughput comparison against pasta; needs iperf3 and pasta in
/// PATH. Run with `cargo test --release -- --ignored --nocapture
/// bench_udp`.
#[test]
#[ignore = "benchmark, run explicitly"]
fn bench_udp() {
    match std::env::var(ROLE).as_deref() {
        Ok("udp-host") => iperf3_bench_host("udp-sandbox", "bench_udp", "udp-pasta"),
        Ok("udp-sandbox") => udp_sandbox(),
        Ok("udp-pasta") => {
            iperf3_udp_client("pasta");
            exit(0);
        }
        _ => {}
    }
    let status = reexec_unshared("udp-host", "bench_udp", &[])
        .status()
        .expect("unshare");
    assert!(status.success(), "bench_udp run failed");
}

/// Bench sandbox namespace: configure the tap, then measure with iperf3.
fn bench_sandbox() -> ! {
    let _tap_fd = setup_and_pass_tap();
    // Optional debug capture of the guest side of the tap (headers
    // only), enabled by pointing PRESTO_BENCH_PCAP at the output file.
    let mut tcpdump = std::env::var("PRESTO_BENCH_PCAP").ok().and_then(|path| {
        Command::new("tcpdump")
            .args(["-i", "eth0", "-s", "96", "-w", &path])
            .spawn()
            .ok()
    });
    iperf3_client("presto-pasta");
    if let Some(child) = tcpdump.as_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
    exit(0);
}

/// Re-run this test binary as `role` inside a namespace attached to
/// pasta, invoked the way sandbox runners do (private netns, no port
/// forwarding), so the same client measures pasta's datapath.
fn client_via_pasta(test: &str, role: &str) -> bool {
    pinned(bench_cpus().as_ref().map(|c| c[1].as_str()), "pasta")
        .args([
            "--config-net",
            "--quiet",
            "-t",
            "none",
            "-u",
            "none",
            "-T",
            "none",
            "-U",
            "none",
            "--",
        ])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", test, "--include-ignored", "--nocapture"])
        .env(ROLE, role)
        .status()
        .expect("run pasta")
        .success()
}

/// Bench host namespace shared by the TCP and UDP iperf3 benchmarks:
/// iperf3 server plus presto-pasta, then the same measurement through pasta
/// attached to its own namespace.
fn iperf3_bench_host(sandbox_role: &str, test: &str, pasta_role: &str) -> ! {
    ip("link set lo up");
    ip("addr add 10.0.0.1/32 dev lo");

    let cpus = bench_cpus();
    let mut server = pinned(cpus.as_ref().map(|c| c[0].as_str()), "iperf3")
        .args(["-s", "-B", "10.0.0.1"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("start iperf3 server");

    let mut child = spawn_sandbox_with_presto(sandbox_role, test);
    let presto_ok = child.wait().expect("wait bench sandbox").success();

    let pasta_ok = client_via_pasta(test, pasta_role);

    let _ = server.kill();
    let _ = server.wait();
    exit(i32::from(!(presto_ok && pasta_ok)));
}

/// Run the qperf client against the host-side server. qperf only
/// measures server-to-client bulk transfer, i.e. downloads.
fn qperf_client(label: &str) {
    let cpus = bench_cpus();
    println!("=== {label} quic download ===");
    let status = pinned(cpus.as_ref().map(|c| c[2].as_str()), "qperf")
        .args(["-c", "10.0.0.1", "-p", "18000", "-t", "5", "-g", "-i", "1"])
        .status()
        .expect("run qperf client");
    assert!(status.success(), "qperf {label} failed");
}

/// QUIC bench sandbox namespace: configure the tap, then measure with
/// qperf.
fn quic_sandbox() -> ! {
    let _tap_fd = setup_and_pass_tap();
    qperf_client("presto-pasta");
    exit(0);
}

/// QUIC bench host namespace: qperf server plus presto-pasta, then the same
/// measurement through pasta.
fn quic_host() -> ! {
    ip("link set lo up");
    ip("addr add 10.0.0.1/32 dev lo");

    // qperf expects server.crt/server.key in its working directory;
    // the client does not validate them.
    let dir = std::env::temp_dir().join(format!("presto-pasta-qperf-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create qperf dir");
    let status = Command::new("openssl")
        .current_dir(&dir)
        .args("req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 1 -subj /CN=presto-pasta-bench".split_whitespace())
        .status()
        .expect("run openssl");
    assert!(status.success(), "generate qperf certificate");

    let cpus = bench_cpus();
    let mut server = pinned(cpus.as_ref().map(|c| c[0].as_str()), "qperf")
        .current_dir(&dir)
        .args(["-s", "10.0.0.1", "-p", "18000", "-i", "1", "-g"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("start qperf server");

    let mut child = spawn_sandbox_with_presto("quic-sandbox", "bench_quic");
    let presto_ok = child.wait().expect("wait quic sandbox").success();

    let pasta_ok = client_via_pasta("bench_quic", "quic-pasta");

    let _ = server.kill();
    let _ = server.wait();
    let _ = std::fs::remove_dir_all(&dir);
    exit(i32::from(!(presto_ok && pasta_ok)));
}

/// QUIC throughput comparison against pasta; needs qperf, openssl and
/// pasta in PATH. Run with `cargo test --release -- --ignored
/// --nocapture bench_quic`.
#[test]
#[ignore = "benchmark, run explicitly"]
fn bench_quic() {
    match std::env::var(ROLE).as_deref() {
        Ok("quic-host") => quic_host(),
        Ok("quic-sandbox") => quic_sandbox(),
        Ok("quic-pasta") => {
            qperf_client("pasta");
            exit(0);
        }
        _ => {}
    }
    let status = reexec_unshared("quic-host", "bench_quic", &[])
        .status()
        .expect("unshare");
    assert!(status.success(), "bench_quic run failed");
}

/// Size of the stream used by the frame-loss test.
const LOSSY_LEN: usize = 8 * 1024 * 1024;

/// Sandbox namespace for the frame-loss test: drop 10% of the packets
/// presto-pasta sends towards the guest and check a bulk download still
/// completes; only the retransmission timeout recovers a loss at the
/// tail of a burst.
fn loss_sandbox() -> ! {
    let _tap_fd = setup_and_pass_tap();
    if !(nft(&["add", "table", "inet", "loss"])
        && nft(&[
            "add",
            "chain",
            "inet",
            "loss",
            "input",
            "{ type filter hook input priority 0; }",
        ])
        && nft(&[
            "add", "rule", "inet", "loss", "input", "numgen", "random", "mod", "10", "0", "drop",
        ]))
    {
        eprintln!("skipping: nftables unavailable");
        exit(0);
    }
    let mut stream = connect_with_retry("10.0.0.1:7979");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut data = Vec::with_capacity(LOSSY_LEN);
    stream
        .read_to_end(&mut data)
        .expect("download despite frame loss");
    assert_eq!(data.len(), LOSSY_LEN, "short download under frame loss");
    assert!(
        data.iter().enumerate().all(|(i, b)| *b == pattern(i)),
        "corrupted download under frame loss"
    );
    exit(0);
}

/// Host namespace for the frame-loss test: stream a fixed pattern to
/// the first connection, then wait for the sandbox verdict.
fn loss_host() -> ! {
    ip("link set lo up");
    ip("addr add 10.0.0.1/32 dev lo");
    let listener = TcpListener::bind("10.0.0.1:7979").expect("bind loss stream");
    std::thread::spawn(move || {
        let payload: Vec<u8> = (0..LOSSY_LEN).map(pattern).collect();
        for mut conn in listener.incoming().flatten() {
            let _ = conn.write_all(&payload);
        }
    });
    let mut child = spawn_sandbox_with_presto("loss-sandbox", "lossy_download");
    let status = child.wait().expect("wait sandbox");
    exit(i32::from(!status.success()));
}

/// Regression test for the retransmission timeout: without it a
/// dropped tail frame deadlocks the flow and the download never
/// finishes.
#[test]
fn lossy_download() {
    match std::env::var(ROLE).as_deref() {
        Ok("loss-host") => loss_host(),
        Ok("loss-sandbox") => loss_sandbox(),
        _ => {}
    }
    run_in_userns("loss-host", "lossy_download");
}

/// Throughput comparison against pasta; needs iperf3 and pasta in
/// PATH. Run with `cargo test --release -- --ignored --nocapture bench`.
#[test]
#[ignore = "benchmark, run explicitly"]
fn bench() {
    match std::env::var(ROLE).as_deref() {
        Ok("bench-host") => iperf3_bench_host("bench-sandbox", "bench", "bench-pasta"),
        Ok("bench-sandbox") => bench_sandbox(),
        Ok("bench-pasta") => {
            iperf3_client("pasta");
            exit(0);
        }
        _ => {}
    }
    let status = reexec_unshared("bench-host", "bench", &[])
        .status()
        .expect("unshare");
    assert!(status.success(), "bench run failed");
}

/// Re-run this test binary as `role` in a fresh user+net namespace and
/// fail on any child error; skipped where user namespaces are not
/// available.
fn run_in_userns(role: &str, test: &str) {
    let output = match reexec_unshared(role, test, &[]).output() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("skipping: unshare unavailable: {e}");
            return;
        }
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("Operation not permitted") {
            eprintln!("skipping: user namespaces not permitted");
            return;
        }
        panic!(
            "netns child failed: {}\nstdout: {}\nstderr: {stderr}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
        );
    }
}

#[test]
fn datapath() {
    match std::env::var(ROLE).as_deref() {
        Ok("host") => host(),
        Ok("sandbox") => sandbox(),
        _ => {}
    }
    run_in_userns("host", "datapath");
}
