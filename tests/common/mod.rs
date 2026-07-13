//! Namespace and tap plumbing shared by the netns and differential
//! test binaries: role re-execution under `unshare`, tap setup in the
//! sandbox, tap fd handoff over a unix socketpair, and small traffic
//! helpers.

use std::io;
use std::net::{TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::process::Command;
use std::time::Duration;

use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockProtocol, SockType,
    recvmsg, sendmsg, socket, socketpair,
};

/// Environment variable selecting which namespace role a re-executed
/// test process plays.
pub const ROLE: &str = "PRESTO_ROLE";
/// Environment variable carrying the fd number of the unix socket used
/// to pass the tap fd from the sandbox to the host role.
pub const PASS_FD: &str = "PRESTO_PASS_FD";

// linux/if_tun.h
const IFF_TAP: i16 = 0x0002;
const IFF_NO_PI: i16 = 0x1000;
const IFF_VNET_HDR: i16 = 0x4000;

nix::ioctl_write_ptr_bad!(
    tun_set_iff,
    nix::request_code_write!(b'T', 202, std::mem::size_of::<libc::c_int>()),
    libc::ifreq
);

/// Copy `name` into an ifreq name field. `c_char` signedness differs
/// across targets, so convert per byte instead of casting.
pub fn set_ifr_name(ifr: &mut libc::ifreq, name: &str) {
    for (dst, src) in ifr.ifr_name.iter_mut().zip(name.bytes()) {
        *dst = libc::c_char::from_ne_bytes([src]);
    }
}

pub fn open_tap(name: &str) -> io::Result<OwnedFd> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    set_ifr_name(&mut ifr, name);
    ifr.ifr_ifru.ifru_flags = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR;
    unsafe { tun_set_iff(file.as_raw_fd(), &raw const ifr) }.map_err(io::Error::from)?;
    Ok(OwnedFd::from(file))
}

pub fn allow_ping_sockets() {
    // Only gid 0 is mapped in the user namespace; wider ranges are
    // rejected with EINVAL.
    std::fs::write("/proc/sys/net/ipv4/ping_group_range", "0 0").expect("enable ping sockets");
}

pub fn ip(args: &str) {
    let status = Command::new("ip")
        .args(args.split_whitespace())
        .status()
        .expect("run ip");
    assert!(status.success(), "ip {args} failed");
}

pub fn reexec_unshared(role: &str, test: &str, extra_env: &[(&str, String)]) -> Command {
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

/// Re-run this test binary as `role` in a fresh user+net namespace and
/// fail on any child error; skipped where user namespaces are not
/// available.
pub fn run_in_userns(role: &str, test: &str, extra_env: &[(&str, String)]) {
    let output = match reexec_unshared(role, test, extra_env).output() {
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

/// Configure the tap the way a sandbox runner would before handing the
/// fd to presto-pasta, and pass it to the host side over the unix socket.
/// Keep the returned fd open: closing the last attached queue would drop
/// the interface carrier and with it the routes.
pub fn setup_and_pass_tap() -> OwnedFd {
    let tap_fd = open_tap("eth0").expect("open tap");

    ip("link set lo up");
    presto_pasta::netdev::configure("eth0", &presto_pasta::Config::default())
        .expect("configure eth0");

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
    tap_fd
}

/// Spawn the sandbox role in its own user+net namespace and receive the
/// tap fd it configured over a unix socketpair.
pub fn spawn_sandbox_and_recv_tap(
    role: &str,
    test: &str,
    extra_env: &[(&str, String)],
) -> (std::process::Child, OwnedFd) {
    let (ours, theirs) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None,
        SockFlag::empty(),
    )
    .expect("socketpair");
    let mut env = extra_env.to_vec();
    env.push((PASS_FD, theirs.as_raw_fd().to_string()));
    let child = reexec_unshared(role, test, &env)
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
    (child, tap_fd)
}

/// Connect through the datapath, retrying while it is still starting
/// up. A refused connection is returned immediately: the services are
/// listening before the sandbox starts, so a refusal is a real verdict.
pub fn connect_with_retry(target: &str) -> io::Result<TcpStream> {
    let mut last = None;
    for _ in 0..20 {
        match TcpStream::connect(target) {
            Ok(s) => return Ok(s),
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => return Err(e),
            Err(e) => last = Some(e),
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    Err(last.unwrap())
}

/// Send one ICMP echo request over an unprivileged ping socket and wait
/// for the reply.
pub fn ping(dst: &str) -> bool {
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
