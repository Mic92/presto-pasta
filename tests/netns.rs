//! End-to-end harness with two namespaces, mirroring real deployment:
//! a "host" user+net namespace where presto and the reachable services
//! live, and a nested "sandbox" namespace that owns the tap device and
//! generates guest traffic.
//!
//! The test re-executes itself under `unshare --user --map-root-user
//! --net` twice (roles selected via `PRESTO_ROLE`); the sandbox child
//! opens and configures the tap the way a sandbox runner would and
//! passes the fd to the host side over a unix socketpair. This doubles
//! as the reference for integrating presto into a sandbox runner.

use std::io;
use std::net::UdpSocket;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::process::{Command, exit};
use std::time::Duration;

use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, recvmsg,
    sendmsg, socketpair,
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

fn ip(args: &str) {
    let status = Command::new("ip")
        .args(args.split_whitespace())
        .status()
        .expect("run ip");
    assert!(status.success(), "ip {args} failed");
}

fn reexec_unshared(role: &str, extra_env: &[(&str, String)]) -> Command {
    let exe = std::env::current_exe().unwrap();
    let mut cmd = Command::new("unshare");
    cmd.args(["--user", "--map-root-user", "--net", "--"])
        .arg(exe)
        .args(["--exact", "udp_datapath"])
        .env(ROLE, role);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd
}

/// Sandbox namespace: open + configure the tap, hand the fd to the host
/// side, then exercise UDP through presto.
fn sandbox() -> ! {
    let tap_fd = open_tap("eth0").expect("open tap");

    // Same setup a sandbox runner performs before handing the fd to presto.
    ip("link set lo up");
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
    exit(0);
}

/// Host namespace: run the echo services and presto, spawn the sandbox.
fn host() -> ! {
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

    let (ours, theirs) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None,
        SockFlag::empty(),
    )
    .expect("socketpair");
    let mut child = reexec_unshared("sandbox", &[(PASS_FD, theirs.as_raw_fd().to_string())])
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

    let presto = presto::Presto::new(presto::Config::default(), tap_fd);
    std::thread::spawn(move || presto.run().expect("presto run"));

    let status = child.wait().expect("wait sandbox");
    exit(i32::from(!status.success()));
}

#[test]
fn udp_datapath() {
    match std::env::var(ROLE).as_deref() {
        Ok("host") => host(),
        Ok("sandbox") => sandbox(),
        _ => {}
    }
    let output = match reexec_unshared("host", &[]).output() {
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
