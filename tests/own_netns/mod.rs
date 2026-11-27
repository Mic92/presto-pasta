//! Running a test as root in a fresh user and network namespace of its
//! own, whose routes and interfaces it sets up with iproute2's `ip`:
//! nothing then depends on the host's network.
//!
//! `common::run_in_userns` does this with util-linux's unshare, which the
//! flake's check does not have, so its tests skip there; giving them
//! util-linux would not help, since they also need /dev/net/tun. This
//! makes the namespaces itself, needs neither, and so runs in the check.
//! It also fails a re-run that ran no test, so a test renamed without its
//! name string here cannot pass by running nothing.
//!
//! Where unprivileged user namespaces are not available a test skips: it
//! passes and writes "skipping" straight to stderr, past the harness's
//! output capture, so the skip shows in every log. With
//! `PRESTO_TEST_REQUIRE_USERNS` set it fails instead.

use std::ffi::CStr;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Output};

/// Marks the re-executed test process inside its own namespaces.
const IN_NETNS: &str = "PRESTO_TEST_IN_OWN_NETNS";
/// Turns a skip into a failure, for builders known to allow user
/// namespaces.
const REQUIRE_USERNS: &str = "PRESTO_TEST_REQUIRE_USERNS";

/// Whether [`in_own_netns`] ran the test or skipped it.
#[derive(Debug, PartialEq, Eq)]
pub enum Ran {
    InOwnNetns,
    Skipped,
}

/// Run `body` as root in a fresh user and network namespace, after
/// `ip` with each of `setup`: the test binary re-executes itself there,
/// running only `test` ([`rerun`]), and the parent passes on its output
/// and panics unless [`check`] accepts it.
pub fn in_own_netns(test: &str, setup: &[&str], body: fn()) -> Ran {
    if std::env::var_os(IN_NETNS).is_some() {
        for args in setup {
            ip(args).unwrap_or_else(|e| panic!("setting up the namespace: {e}"));
        }
        body();
        return Ran::InOwnNetns;
    }
    let Some(out) = rerun(test) else {
        return Ran::Skipped;
    };
    print!("{}", String::from_utf8_lossy(&out.stdout));
    eprint!("{}", String::from_utf8_lossy(&out.stderr));
    if let Err(e) = check(test, &out) {
        panic!("{e}");
    }
    Ran::InOwnNetns
}

/// Re-execute this test binary as root in a fresh user and network
/// namespace, running only `test`. `None`, after saying so, where
/// unprivileged user namespaces are not available.
fn rerun(test: &str) -> Option<Output> {
    // SAFETY: getuid and getgid cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let uid_map = format!("0 {uid} 1");
    let gid_map = format!("0 {gid} 1");
    let mut cmd = Command::new(std::env::current_exe().expect("test binary"));
    cmd.args(["--exact", test, "--nocapture"])
        .env(IN_NETNS, "1");
    // SAFETY: between fork and exec the closure only makes system calls
    // on data prepared before the fork.
    unsafe {
        cmd.pre_exec(move || {
            if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) != 0 {
                return Err(io::Error::last_os_error());
            }
            write_proc(c"/proc/self/setgroups", b"deny")?;
            write_proc(c"/proc/self/uid_map", uid_map.as_bytes())?;
            write_proc(c"/proc/self/gid_map", gid_map.as_bytes())
        });
    }
    match cmd.output() {
        Ok(out) => Some(out),
        // unshare(2) fails with EINVAL without user namespace support,
        // ENOSPC at the namespace limit and EPERM where they are
        // forbidden; the id maps cannot be written (EPERM, or EACCES
        // under Ubuntu's AppArmor restriction) where a security module
        // leaves the new namespace without capabilities.
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::EPERM | libc::EACCES | libc::ENOSPC | libc::EINVAL)
            ) =>
        {
            let why = format!("{test}: unprivileged user namespaces unavailable: {e}");
            assert!(
                std::env::var_os(REQUIRE_USERNS).is_none(),
                "{why}, and {REQUIRE_USERNS} is set"
            );
            // Past the harness's capture of eprintln!, which hides the
            // output of passing tests; one write, on a line of its own
            // even after the harness's "test ... " progress.
            let _ = io::stderr().write_all(format!("\nskipping: {why}\n").as_bytes());
            None
        }
        Err(e) => panic!("{test}: cannot re-run in a new user and network namespace: {e}"),
    }
}

/// The parent's verdict on a re-run of `test`: it must succeed and
/// report one passed test, which with --exact is the one named `test`.
fn check(test: &str, out: &Output) -> Result<(), String> {
    if !out.status.success() {
        return Err(format!("{test}: {} in its namespace", out.status));
    }
    if !String::from_utf8_lossy(&out.stdout).contains("\ntest result: ok. 1 passed;") {
        return Err(format!(
            "{test}: the re-run in its namespace ran no test named {test}"
        ));
    }
    Ok(())
}

/// Write `data` to the procfs file `path` with plain system calls, as
/// is safe between fork and exec.
fn write_proc(path: &CStr, data: &[u8]) -> io::Result<()> {
    // SAFETY: `path` is NUL-terminated and `data` outlives the calls.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = libc::write(fd, data.as_ptr().cast(), data.len());
        let err = io::Error::last_os_error();
        libc::close(fd);
        if usize::try_from(n).ok() == Some(data.len()) {
            Ok(())
        } else {
            Err(err)
        }
    }
}

/// Run `ip` with `args`, split at whitespace.
pub fn ip(args: &str) -> Result<(), String> {
    let status = Command::new("ip")
        .args(args.split_whitespace())
        .status()
        .map_err(|e| format!("ip {args}: {e} (iproute2's ip must be on PATH)"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("ip {args}: {status}"))
    }
}
