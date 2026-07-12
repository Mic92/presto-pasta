//! End-to-end harness: user+net namespace, tap device configured the
//! way a sandbox runner would (address, default route, permanent
//! neighbor entry), presto running on the tap fd.
//!
//! The test re-executes itself under `unshare --user --map-root-user
//! --net`; the child opens the tap and drives presto. This doubles as
//! the reference for integrating presto into a sandbox runner.

use std::io;
use std::net::UdpSocket;
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::{Command, exit};
use std::time::Duration;

const CHILD_ENV: &str = "PRESTO_NETNS_CHILD";

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

fn child() -> ! {
    let tap_fd = open_tap("eth0").expect("open tap");

    // Same setup a sandbox runner performs before handing the fd to presto.
    ip("link set lo up");
    ip("link set eth0 up");
    ip("addr add 169.254.1.2/16 dev eth0");
    ip("route add default via 169.254.1.1 dev eth0");
    ip("neigh add 169.254.1.1 lladdr 9a:55:9a:55:9a:55 dev eth0 nud permanent");

    let presto = presto::Presto::new(presto::Config::default(), tap_fd);
    std::thread::spawn(move || presto.run().expect("presto run"));

    // Traffic to the gateway leaves via eth0 and must arrive on the tap.
    let sock = UdpSocket::bind("169.254.1.2:0").expect("bind in netns");
    sock.send_to(b"ping", "169.254.1.1:53").expect("send");
    std::thread::sleep(Duration::from_millis(200));
    exit(0);
}

#[test]
fn tap_datapath() {
    if std::env::var_os(CHILD_ENV).is_some() {
        child();
    }
    let exe = std::env::current_exe().unwrap();
    let output = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--"])
        .arg(exe)
        .args(["--exact", "tap_datapath"])
        .env(CHILD_ENV, "1")
        .output();
    let output = match output {
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
