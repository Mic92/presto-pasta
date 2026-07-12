//! Optional seccomp allowlist for the datapath thread.
//!
//! Applied per-thread from [`crate::Presto::run`] once the ring and
//! tap are set up, so only syscalls needed by steady-state operation
//! remain: ring submission, per-flow socket setup and I/O, resolv.conf
//! reads, allocator and unwinding support. `io_uring` itself bypasses
//! seccomp; ring restrictions (registered before enabling the ring)
//! cover that side.

use std::io;

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};

/// Install the allowlist on the calling thread.
pub fn apply() -> io::Result<()> {
    let allowed = [
        // io_uring submission and the tap/socket fast path
        libc::SYS_io_uring_enter,
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_writev, // TCP segments to the tap: headers + payload
        libc::SYS_recvfrom,
        libc::SYS_sendto,
        // per-flow host sockets (DNS forwarding binds an ephemeral port)
        libc::SYS_socket,
        libc::SYS_bind,
        libc::SYS_connect,
        libc::SYS_fcntl, // std sets O_NONBLOCK on new UDP sockets
        libc::SYS_getsockopt,
        libc::SYS_setsockopt, // SO_SNDBUF on new TCP flows
        libc::SYS_shutdown,
        libc::SYS_ioctl, // SIOCOUTQ
        libc::SYS_close,
        // resolv.conf re-read on new DNS flows (stat flavour depends
        // on the libc version)
        libc::SYS_openat,
        libc::SYS_statx,
        libc::SYS_newfstatat,
        // allocator, panic/unwind, misc runtime
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_futex,
        libc::SYS_clock_gettime,
        libc::SYS_sigaltstack,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigprocmask,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ];
    let arch = TargetArch::try_from(std::env::consts::ARCH).map_err(io::Error::other)?;
    let filter = SeccompFilter::new(
        allowed.into_iter().map(|s| (s, vec![])).collect(),
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        arch,
    )
    .map_err(io::Error::other)?;
    let prog: BpfProgram = filter.try_into().map_err(io::Error::other)?;
    seccompiler::apply_filter(&prog).map_err(io::Error::other)
}
