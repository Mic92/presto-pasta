//! `io_uring` event loop.
//!
//! The ring starts disabled, registers an operation allowlist
//! (`io_uring` submissions bypass seccomp, so the kernel-side
//! restriction is the only enforcement point), the tap fd and the
//! buffer pool, and only then is enabled.

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use io_uring::{IoUring, opcode, register::Restriction, squeue, types};
use nix::sys::socket::{
    AddressFamily, MsgFlags, Shutdown, SockFlag, SockProtocol, SockType, SockaddrStorage, connect,
    getsockopt, recv, send, setsockopt, shutdown, socket, sockopt,
};

use crate::{Config, buf, dns, flow, proto, tap};

/// Registered-file index of the tap fd.
const TAP: types::Fixed = types::Fixed(0);
/// `user_data` of the tap read; flow ids use their table index.
const TAP_UD: u64 = u64::MAX;
/// `user_data` of the periodic expiry timer.
const TIMER_UD: u64 = u64::MAX - 1;
/// `user_data` of cancel requests issued by flow expiry.
const CANCEL_UD: u64 = u64::MAX - 2;

/// Idle time after which a flow's socket and buffer are reclaimed.
const FLOW_EXPIRY: Duration = Duration::from_mins(3);
/// Period of the expiry sweep.
const TIMER_INTERVAL: Duration = Duration::from_secs(30);

/// Initial sequence number towards the guest. The tap is a private
/// point-to-point link, so ISN randomization buys nothing.
const TCP_ISN: u32 = 0x0001_0000;
/// Window scale we announce when the guest offers scaling.
const WINDOW_SHIFT: u8 = 7;
/// MSS we announce; the guest clamps it to its own MTU.
const TCP_MSS: u16 = 65_495;
/// Fallback MSS when the guest's SYN carries no MSS option (RFC 9293).
const TCP_DEFAULT_MSS: u16 = 536;
/// Largest TCP payload per super-frame: the IP total length field is
/// 16 bits and must also cover IP and TCP headers.
const TCP_MAX_PAYLOAD: usize = 65_535 - 60;

const POLL_OUT: u32 = libc::POLLOUT as u32;
const POLL_RECV: u32 = (libc::POLLIN | libc::POLLRDHUP) as u32;
const POLL_ERR: u32 = (libc::POLLERR | libc::POLLNVAL) as u32;
const POLL_HUP: u32 = libc::POLLHUP as u32;

// SIOCOUTQ: bytes queued in a socket's send buffer (linux/sockios.h);
// numerically TIOCOUTQ, which is what libc exposes.
nix::ioctl_read_bad!(siocoutq, libc::TIOCOUTQ, libc::c_int);

/// Operations the datapath needs; everything else is rejected by the
/// kernel. Restrictions can only be registered while the ring is
/// disabled, so ops for handlers that are not implemented yet are
/// already listed.
const ALLOWED_OPS: &[u8] = &[
    opcode::ReadFixed::CODE,
    opcode::WriteFixed::CODE,
    opcode::Recv::CODE,
    opcode::RecvMulti::CODE,
    opcode::Send::CODE,
    opcode::SendZc::CODE,
    opcode::Connect::CODE,
    opcode::PollAdd::CODE,
    opcode::Timeout::CODE,
    opcode::AsyncCancel::CODE,
    opcode::Close::CODE,
];

/// L4 payload of a guest frame read from the tap.
struct GuestFrame {
    src_mac: [u8; 6],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    proto: u8,
    /// Byte range of the L4 header + payload within the tap buffer.
    l4: std::ops::Range<usize>,
}

pub struct EventLoop {
    ring: IoUring,
    pool: buf::Pool,
    tap: tap::Tap,
    cfg: Config,
    flows: flow::FlowTable,
    guest_mac: [u8; 6],
    tap_buf: buf::BufId,
    stats: crate::stats::Stats,
    timer_ts: types::Timespec,
}

impl EventLoop {
    /// # Errors
    ///
    /// Fails when the ring cannot be created or registration fails
    /// (needs kernel >= 5.10 for ring restrictions).
    pub fn new(cfg: &Config, tap: tap::Tap) -> io::Result<Self> {
        let ring = IoUring::builder().setup_r_disabled().build(256)?;
        let mut pool = buf::Pool::new(cfg.buffers);

        let ctx = |what: &'static str| {
            move |e: io::Error| io::Error::new(e.kind(), format!("{what}: {e}"))
        };
        ring.submitter()
            .register_files(&[tap.fd().as_raw_fd()])
            .map_err(ctx("register_files"))?;
        let region = pool.region();
        let iov = libc::iovec {
            iov_base: region.as_mut_ptr().cast(),
            iov_len: region.len(),
        };
        // SAFETY: the pool outlives the ring; both live in EventLoop and
        // the ring is dropped first (field order).
        unsafe {
            ring.submitter()
                .register_buffers(&[iov])
                .map_err(ctx("register_buffers"))?;
        }

        let mut restrictions: Vec<Restriction> = ALLOWED_OPS
            .iter()
            .map(|&op| Restriction::sqe_op(op))
            .collect();
        // Registered-file and provided-buffer selection flags on sqes.
        restrictions.push(Restriction::sqe_flags_allowed(
            (squeue::Flags::FIXED_FILE | squeue::Flags::BUFFER_SELECT).bits(),
        ));
        ring.submitter()
            .register_restrictions(&mut restrictions)
            .map_err(ctx("register_restrictions"))?;
        ring.submitter()
            .register_enable_rings()
            .map_err(ctx("enable_rings"))?;

        let Some(tap_buf) = pool.alloc() else {
            return Err(io::Error::other("buffer pool configured with zero buffers"));
        };
        Ok(Self {
            ring,
            pool,
            tap,
            cfg: cfg.clone(),
            flows: flow::FlowTable::default(),
            guest_mac: [0; 6],
            tap_buf,
            stats: crate::stats::Stats::new(),
            timer_ts: types::Timespec::new().sec(TIMER_INTERVAL.as_secs()),
        })
    }

    /// Run until the tap fd reports EOF or an unrecoverable error.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from the ring or the tap fd.
    pub fn run(mut self) -> io::Result<()> {
        self.submit_tap_read()?;
        self.submit_timer()?;
        // Drained CQEs are copied into a scratch vector (reused across
        // iterations) so the borrow on the ring ends before handling.
        let mut completions: Vec<(u64, i32)> = Vec::new();
        loop {
            self.ring.submit_and_wait(1)?;
            completions.clear();
            completions.extend(
                self.ring
                    .completion()
                    .map(|cqe| (cqe.user_data(), cqe.result())),
            );
            self.stats.wakeup(completions.len());
            for &(ud, res) in &completions {
                if ud == TAP_UD {
                    match res {
                        0 => return Ok(()), // tap torn down
                        n if n < 0 => {
                            return Err(io::Error::other(format!(
                                "tap read: {}",
                                io::Error::from_raw_os_error(-n)
                            )));
                        }
                        n => self.handle_tap_frame(n.unsigned_abs() as usize),
                    }
                    self.submit_tap_read()?;
                } else if ud == TIMER_UD {
                    self.expire_flows();
                    self.submit_timer()?;
                } else if ud == CANCEL_UD {
                    // Cancel completions carry no state to clean up.
                } else {
                    #[expect(clippy::cast_possible_truncation, reason = "flow ids fit usize")]
                    let id = ud as usize;
                    let Some(f) = self.flows.get_by_id(id) else {
                        continue;
                    };
                    if f.closing || res == -libc::ECANCELED {
                        if let Some(buf) = self.flows.remove(id) {
                            self.pool.free(buf);
                        }
                    } else if f.kind == flow::FlowKind::Tcp {
                        if res >= 0 {
                            self.tcp_socket_ready(id, res.unsigned_abs());
                        } else {
                            self.tcp_reset(id);
                        }
                    } else {
                        if res >= 0 {
                            self.reply_to_guest(id, res.unsigned_abs() as usize);
                        }
                        self.submit_flow_recv(id)?;
                    }
                }
            }
        }
    }

    fn push(&mut self, entry: &squeue::Entry) -> io::Result<()> {
        // SAFETY: all buffers referenced by entries live in self.pool
        // until the corresponding completion is reaped.
        unsafe {
            self.ring
                .submission()
                .push(entry)
                .map_err(|e| io::Error::other(format!("submission queue full: {e}")))
        }
    }

    fn submit_tap_read(&mut self) -> io::Result<()> {
        let b = self.pool.get_mut(self.tap_buf);
        #[expect(clippy::cast_possible_truncation, reason = "buffer size fits u32")]
        let read = opcode::ReadFixed::new(TAP, b.as_mut_ptr(), b.len() as u32, 0)
            .build()
            .user_data(TAP_UD);
        self.push(&read)
    }

    fn submit_timer(&mut self) -> io::Result<()> {
        let timeout = opcode::Timeout::new(&raw const self.timer_ts)
            .build()
            .user_data(TIMER_UD);
        self.push(&timeout)
    }

    /// Reclaim every idle flow.
    fn expire_flows(&mut self) {
        let Some(cutoff) = Instant::now().checked_sub(FLOW_EXPIRY) else {
            return;
        };
        for id in self.flows.expired(cutoff) {
            self.remove_flow(id);
        }
    }

    /// Close a flow. If an operation is still pending for it, the slot
    /// and buffer are only freed once the cancelled operation
    /// completes, so in-flight completions never hit a reused slot.
    fn remove_flow(&mut self, id: usize) {
        // Flow teardown is a natural checkpoint for the counters.
        self.stats.dump();
        let pending = self
            .flows
            .get_by_id(id)
            .is_some_and(|f| f.tcp.as_ref().is_none_or(|t| t.poll_armed));
        if pending {
            if let Some(f) = self.flows.get_mut(id) {
                f.closing = true;
            }
            let cancel = opcode::AsyncCancel::new(id as u64)
                .build()
                .user_data(CANCEL_UD);
            let _ = self.push(&cancel);
        } else if let Some(buf) = self.flows.remove(id) {
            self.pool.free(buf);
        }
    }

    fn submit_flow_recv(&mut self, id: usize) -> io::Result<()> {
        let Some(f) = self.flows.get_by_id(id) else {
            return Ok(());
        };
        let fd = types::Fd(f.sock.as_raw_fd());
        let buf_id = f.buf;
        let b = &mut self.pool.get_mut(buf_id)[buf::HEADROOM..];
        #[expect(clippy::cast_possible_truncation, reason = "buffer size fits u32")]
        let recv = opcode::Recv::new(fd, b.as_mut_ptr(), b.len() as u32)
            .build()
            .user_data(id as u64);
        self.push(&recv)
    }

    /// Parse the L2/L3 headers of a frame read from the tap.
    fn parse_frame(&self, len: usize) -> Option<GuestFrame> {
        let frame = &self.pool.get(self.tap_buf)[..len];
        let l3_off = tap::VNET_HDR_LEN + proto::ETH_LEN;
        let l3 = frame.get(l3_off..)?;
        let eth = proto::EthHdr::parse(frame.get(tap::VNET_HDR_LEN..)?)?;
        let (src_ip, dst_ip, ip_proto, l4_off, payload_len) = match eth.ethertype {
            proto::ETHERTYPE_IPV4 => {
                let ip = proto::Ipv4Hdr::parse(l3)?;
                let payload = usize::from(ip.total_len).checked_sub(ip.header_len)?;
                (
                    IpAddr::V4(ip.src),
                    IpAddr::V4(ip.dst),
                    ip.proto,
                    ip.header_len,
                    payload,
                )
            }
            proto::ETHERTYPE_IPV6 => {
                let ip = proto::Ipv6Hdr::parse(l3)?;
                (
                    IpAddr::V6(ip.src),
                    IpAddr::V6(ip.dst),
                    ip.next_header,
                    proto::IPV6_HDR_LEN,
                    usize::from(ip.payload_len),
                )
            }
            _ => return None,
        };
        let l4_start = l3_off + l4_off;
        let l4_end = (l4_start + payload_len).min(len);
        Some(GuestFrame {
            src_mac: eth.src,
            src_ip,
            dst_ip,
            proto: ip_proto,
            l4: l4_start..l4_end,
        })
    }

    fn handle_tap_frame(&mut self, len: usize) {
        self.stats.tap_in(len);
        let Some(g) = self.parse_frame(len) else {
            return;
        };
        // Ignore anything not sourced from the configured guest address.
        if g.src_ip != IpAddr::V4(self.cfg.guest4) && g.src_ip != IpAddr::V6(self.cfg.guest6) {
            return;
        }
        self.guest_mac = g.src_mac;
        match g.proto {
            proto::IPPROTO_UDP => self.handle_udp(&g),
            proto::IPPROTO_TCP => self.handle_tcp(&g),
            proto::IPPROTO_ICMP | proto::IPPROTO_ICMPV6 => self.handle_icmp_echo(&g),
            _ => {}
        }
    }

    fn handle_udp(&mut self, g: &GuestFrame) {
        let l4 = &self.pool.get(self.tap_buf)[g.l4.clone()];
        let Some(udp) = proto::UdpHdr::parse(l4) else {
            return;
        };
        let key = flow::FlowKey {
            proto: proto::IPPROTO_UDP,
            guest_port: udp.src_port,
            dst: SocketAddr::new(g.dst_ip, udp.dst_port),
        };
        let payload =
            g.l4.start + proto::UDP_HDR_LEN..(g.l4.start + usize::from(udp.len)).min(g.l4.end);
        self.forward(key, flow::FlowKind::Udp, payload);
    }

    /// Forward an ICMP/ICMPv6 echo request over a ping socket. The
    /// kernel assigns its own echo identifier on send, so replies are
    /// matched per flow and patched back in [`Self::reply_to_guest`].
    fn handle_icmp_echo(&mut self, g: &GuestFrame) {
        let l4 = &self.pool.get(self.tap_buf)[g.l4.clone()];
        let Some(echo) = proto::IcmpEcho::parse(l4) else {
            return;
        };
        let expected = if g.dst_ip.is_ipv4() {
            proto::ICMP_ECHO_REQUEST
        } else {
            proto::ICMPV6_ECHO_REQUEST
        };
        if echo.icmp_type != expected {
            return;
        }
        let key = flow::FlowKey {
            proto: g.proto,
            guest_port: echo.id,
            dst: SocketAddr::new(g.dst_ip, 0),
        };
        self.forward(key, flow::FlowKind::Ping, g.l4.clone());
    }

    /// Look up or create the flow for `key` and send the guest bytes
    /// at `payload` (a range within the tap buffer) to its socket.
    fn forward(
        &mut self,
        key: flow::FlowKey,
        kind: flow::FlowKind,
        payload: std::ops::Range<usize>,
    ) {
        let Some(id) = self.flows.get(&key).or_else(|| self.new_flow(key, kind)) else {
            return;
        };
        if let Some(f) = self.flows.get_mut(id) {
            f.last_active = Instant::now();
            let raw = f.sock.as_raw_fd();
            let data = &self.pool.get(self.tap_buf)[payload];
            let _ = send(raw, data, MsgFlags::MSG_DONTWAIT); // drop on EAGAIN/unreachable
        }
    }

    /// Create the connected host socket for a new guest flow and arm
    /// its first recv. DNS to the gateway is redirected to the host
    /// resolver, re-read from resolv.conf per flow so changes (e.g. by
    /// a DHCP client on the host) are picked up without a reload.
    fn new_flow(&mut self, key: flow::FlowKey, kind: flow::FlowKind) -> Option<usize> {
        let sock = match kind {
            flow::FlowKind::Udp => {
                let gateway_dns = key.dst.port() == 53
                    && (key.dst.ip() == IpAddr::V4(self.cfg.gateway4)
                        || key.dst.ip() == IpAddr::V6(self.cfg.gateway6));
                let target = if gateway_dns && self.cfg.dns_forward {
                    dns::host_resolver()?
                } else {
                    key.dst
                };
                let bind_ip: IpAddr = if target.is_ipv4() {
                    std::net::Ipv4Addr::UNSPECIFIED.into()
                } else {
                    std::net::Ipv6Addr::UNSPECIFIED.into()
                };
                let sock = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).ok()?;
                sock.connect(target).ok()?;
                sock
            }
            flow::FlowKind::Ping => {
                // Requires net.ipv4.ping_group_range to cover our gid;
                // echo is silently unavailable otherwise.
                let sock = ping_socket(key.dst.ip())?;
                sock.connect(key.dst).ok()?;
                sock
            }
            flow::FlowKind::Tcp => unreachable!("TCP flows are created by new_tcp_flow"),
        };
        sock.set_nonblocking(true).ok()?;
        let buf = self.pool.alloc()?;
        let id = self.flows.insert(flow::Flow {
            key,
            kind,
            sock: sock.into(),
            buf,
            last_active: Instant::now(),
            tcp: None,
            closing: false,
        });
        self.submit_flow_recv(id).ok()?;
        Some(id)
    }

    /// Build the ethernet/IP/L4 frame for `len` payload bytes sitting
    /// at the flow buffer's headroom offset and write it to the tap.
    fn reply_to_guest(&mut self, id: usize, len: usize) {
        let Some(f) = self.flows.get_mut(id) else {
            return;
        };
        f.last_active = Instant::now();
        let key = f.key;
        let kind = f.kind;
        let buf_id = f.buf;
        let guest_mac = self.guest_mac;
        let gateway_mac = self.cfg.gateway_mac;
        let (guest4, guest6) = (self.cfg.guest4, self.cfg.guest6);
        let end = buf::HEADROOM + len;

        // L4: prepend a UDP header, or patch the received ICMP echo
        // reply in place (the ping socket's identifier back to the
        // guest's). TCP replies are framed by the TCP handlers.
        let (l4_start, ip_proto) = match kind {
            flow::FlowKind::Udp => (buf::HEADROOM - proto::UDP_HDR_LEN, proto::IPPROTO_UDP),
            flow::FlowKind::Ping => (buf::HEADROOM, key.proto),
            flow::FlowKind::Tcp => return,
        };
        let l4_len = u16::try_from(end - l4_start).unwrap_or(u16::MAX);
        // ICMPv4 checksums have no pseudo-header.
        let pseudo = match (key.dst.ip(), kind) {
            (IpAddr::V4(_), flow::FlowKind::Ping) => 0,
            (IpAddr::V4(src), _) => proto::pseudo_v4(src, guest4, ip_proto, l4_len),
            (IpAddr::V6(src), _) => proto::pseudo_v6(src, guest6, ip_proto, l4_len),
        };
        let ip_start = match key.dst.ip() {
            IpAddr::V4(_) => l4_start - proto::IPV4_HDR_LEN,
            IpAddr::V6(_) => l4_start - proto::IPV6_HDR_LEN,
        };
        let eth_start = ip_start - proto::ETH_LEN;
        let vnet_start = eth_start - tap::VNET_HDR_LEN;

        let b = self.pool.get_mut(buf_id);
        match kind {
            flow::FlowKind::Udp => proto::UdpHdr::write(
                &mut b[l4_start..end],
                key.dst.port(),
                key.guest_port,
                pseudo,
            ),
            flow::FlowKind::Ping => {
                if len < proto::ICMP_HDR_LEN {
                    return;
                }
                proto::IcmpEcho::patch_id(&mut b[l4_start..end], key.guest_port, pseudo);
            }
            flow::FlowKind::Tcp => return,
        }
        match key.dst.ip() {
            IpAddr::V4(src) => {
                proto::Ipv4Hdr::write(&mut b[ip_start..], src, guest4, ip_proto, l4_len);
            }
            IpAddr::V6(src) => {
                proto::Ipv6Hdr::write(&mut b[ip_start..], src, guest6, ip_proto, l4_len);
            }
        }
        proto::EthHdr {
            dst: guest_mac,
            src: gateway_mac,
            ethertype: if key.dst.is_ipv4() {
                proto::ETHERTYPE_IPV4
            } else {
                proto::ETHERTYPE_IPV6
            },
        }
        .write(&mut b[eth_start..]);
        b[vnet_start..eth_start].fill(0);

        self.stats.tap_out(end - vnet_start);
        let _ = nix::unistd::write(self.tap.fd(), &b[vnet_start..end]);
    }

    fn handle_tcp(&mut self, g: &GuestFrame) {
        let l4 = &self.pool.get(self.tap_buf)[g.l4.clone()];
        let Some(hdr) = proto::TcpHdr::parse(l4) else {
            return;
        };
        let key = flow::FlowKey {
            proto: proto::IPPROTO_TCP,
            guest_port: hdr.src_port,
            dst: SocketAddr::new(g.dst_ip, hdr.dst_port),
        };
        let payload = g.l4.start + hdr.header_len..g.l4.end;
        if let Some(id) = self.flows.get(&key) {
            self.tcp_from_guest(id, &hdr, payload);
        } else if hdr.flags & (proto::TCP_SYN | proto::TCP_ACK | proto::TCP_RST) == proto::TCP_SYN {
            self.new_tcp_flow(key, &hdr);
        }
    }

    /// Start a nonblocking connect to the guest's target and poll for
    /// its outcome; the SYN-ACK is only sent once the host connection
    /// is established, so connection refusal maps to RST.
    fn new_tcp_flow(&mut self, key: flow::FlowKey, syn: &proto::TcpHdr) -> Option<usize> {
        let family = if key.dst.is_ipv4() {
            AddressFamily::Inet
        } else {
            AddressFamily::Inet6
        };
        let sock = socket(
            family,
            SockType::Stream,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
            SockProtocol::Tcp,
        )
        .ok()?;
        // The window we advertise to the guest is the free space in the
        // send buffer; the kernel default (~200 KiB, and fixed once we
        // read it) caps upload throughput at window/loop-latency, so
        // ask for a larger buffer up front.
        let _ = setsockopt(&sock, sockopt::SndBuf, &(4 * 1024 * 1024));
        match connect(sock.as_raw_fd(), &SockaddrStorage::from(key.dst)) {
            Ok(()) | Err(nix::errno::Errno::EINPROGRESS) => {}
            Err(_) => return None, // no SYN-ACK; the guest times out
        }
        let sndbuf = getsockopt(&sock, sockopt::SndBuf)
            .ok()
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(u32::from(u16::MAX));
        let buf = self.pool.alloc()?;
        let id = self.flows.insert(flow::Flow {
            key,
            kind: flow::FlowKind::Tcp,
            sock,
            buf,
            last_active: Instant::now(),
            tcp: Some(flow::Tcp {
                state: flow::TcpState::Connecting,
                seq_from_guest: syn.seq.wrapping_add(1),
                seq_una: TCP_ISN,
                sent_unacked: 0,
                guest_window: u32::from(syn.window),
                // Clamp to the RFC 7323 maximum so shifting stays sound.
                guest_wscale: syn.wscale.map(|s| s.min(14)),
                guest_mss: syn.mss.unwrap_or(TCP_DEFAULT_MSS),
                sndbuf,
                host_fin: flow::FinState::NotSent,
                guest_fin_received: false,
                ack_deferred: false,
                poll_armed: false,
            }),
            closing: false,
        });
        self.arm_poll(id, POLL_OUT).ok()?;
        Some(id)
    }

    /// Arm a oneshot poll on the flow's host socket.
    fn arm_poll(&mut self, id: usize, events: u32) -> io::Result<()> {
        let Some(f) = self.flows.get_mut(id) else {
            return Ok(());
        };
        let fd = types::Fd(f.sock.as_raw_fd());
        if let Some(t) = f.tcp.as_mut() {
            t.poll_armed = true;
        }
        let poll = opcode::PollAdd::new(fd, events)
            .build()
            .user_data(id as u64);
        self.push(&poll)
    }

    /// Handle a poll completion on a TCP flow's host socket.
    fn tcp_socket_ready(&mut self, id: usize, events: u32) {
        let Some(f) = self.flows.get_mut(id) else {
            return;
        };
        f.last_active = Instant::now();
        let Some(t) = f.tcp.as_mut() else {
            return;
        };
        t.poll_armed = false;
        let state = t.state;
        let sock_err = getsockopt(&f.sock, sockopt::SocketError).unwrap_or(libc::ECONNRESET);
        match state {
            flow::TcpState::Connecting => {
                if events & (POLL_ERR | POLL_HUP) != 0 || sock_err != 0 {
                    self.tcp_reset(id);
                    return;
                }
                if let Some(t) = self.flows.get_mut(id).and_then(|f| f.tcp.as_mut()) {
                    t.state = flow::TcpState::Established;
                }
                self.send_syn_ack(id);
                let _ = self.arm_poll(id, POLL_RECV);
            }
            flow::TcpState::Established => {
                if events & POLL_ERR != 0 || sock_err != 0 {
                    self.tcp_reset(id);
                    return;
                }
                self.tcp_data_to_guest(id);
                self.tcp_maybe_close(id);
            }
        }
    }

    /// Handle a TCP segment from the guest: acks and window updates,
    /// payload into the host socket, FIN/RST teardown.
    fn tcp_from_guest(&mut self, id: usize, hdr: &proto::TcpHdr, payload: std::ops::Range<usize>) {
        let Some(f) = self.flows.get_mut(id) else {
            return;
        };
        f.last_active = Instant::now();
        let raw = f.sock.as_raw_fd();
        let Some(t) = f.tcp.as_mut() else {
            return;
        };
        if hdr.flags & proto::TCP_RST != 0 {
            self.remove_flow(id);
            return;
        }
        if t.state == flow::TcpState::Connecting {
            // Includes SYN retransmits; the guest retries until the
            // host connect resolves.
            return;
        }
        if hdr.flags & proto::TCP_SYN != 0 {
            // Our SYN-ACK was lost.
            if t.sent_unacked == 0 {
                self.send_syn_ack(id);
            }
            return;
        }
        let mut ack_guest = false;
        if hdr.flags & proto::TCP_ACK != 0 {
            t.guest_window = u32::from(hdr.window) << t.guest_wscale.unwrap_or(0);
            let advance = hdr.ack.wrapping_sub(t.seq_una);
            let max_advance = t.sent_unacked + u32::from(t.host_fin != flow::FinState::NotSent);
            if advance > 0 && advance <= max_advance {
                let data_acked = advance.min(t.sent_unacked);
                t.sent_unacked -= data_acked;
                t.seq_una = t.seq_una.wrapping_add(data_acked);
                if advance > data_acked {
                    t.host_fin = flow::FinState::Acked;
                }
                if data_acked > 0 {
                    discard_acked(raw, data_acked);
                }
            } else if advance == 0
                && payload.is_empty()
                && hdr.flags & proto::TCP_FIN == 0
                && t.sent_unacked > 0
            {
                // Duplicate ack: retransmit everything in flight by
                // re-peeking it from the socket.
                t.sent_unacked = 0;
            }
        }
        // Guest payload into the host socket. Only in-order data is
        // accepted; anything else is dropped and the resulting
        // duplicate ack makes the guest retransmit.
        let expected_seq = self.tcp_state(id).map(|t| t.seq_from_guest);
        let mut accepted = 0;
        if !payload.is_empty() {
            if Some(hdr.seq) == expected_seq {
                let data = &self.pool.get(self.tap_buf)[payload.clone()];
                accepted =
                    send(raw, data, MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL).unwrap_or(0);
                self.stats.sock_send(accepted, payload.len());
                if let Some(t) = self.flows.get_mut(id).and_then(|f| f.tcp.as_mut()) {
                    #[expect(clippy::cast_possible_truncation, reason = "frame fits u32")]
                    {
                        t.seq_from_guest = t.seq_from_guest.wrapping_add(accepted as u32);
                    }
                }
            }
            // Dropped or partially accepted data needs an immediate
            // (duplicate) ack so the guest retransmits; in-order frames
            // without PSH are acked only every second frame to halve
            // tap writes on bulk uploads.
            if let Some(t) = self.flows.get_mut(id).and_then(|f| f.tcp.as_mut()) {
                if accepted == payload.len() && hdr.flags & proto::TCP_PSH == 0 && !t.ack_deferred {
                    t.ack_deferred = true;
                    self.stats.ack_deferred();
                } else {
                    ack_guest = true;
                }
            }
        }
        if hdr.flags & proto::TCP_FIN != 0
            && accepted == payload.len()
            && let Some(t) = self.flows.get_mut(id).and_then(|f| f.tcp.as_mut())
            && !t.guest_fin_received
            && hdr
                .seq
                .wrapping_add(u32::try_from(payload.len()).unwrap_or(0))
                == t.seq_from_guest
        {
            t.guest_fin_received = true;
            t.seq_from_guest = t.seq_from_guest.wrapping_add(1);
            let _ = shutdown(raw, Shutdown::Write);
            ack_guest = true;
        }
        if ack_guest {
            if let Some(t) = self.flows.get_mut(id).and_then(|f| f.tcp.as_mut()) {
                t.ack_deferred = false;
            }
            self.send_tcp_control(id, proto::TCP_ACK);
        }
        // Acks or window updates may allow more data towards the guest.
        self.tcp_data_to_guest(id);
        self.tcp_maybe_close(id);
    }

    fn tcp_state(&self, id: usize) -> Option<&flow::Tcp> {
        self.flows.get_by_id(id)?.tcp.as_ref()
    }

    /// Peek data waiting on the host socket and send whatever fits in
    /// the guest's window as one GSO super-frame (or MSS-sized
    /// segments without TSO). Data is only discarded from the socket
    /// once the guest acks it, so retransmission just re-peeks.
    fn tcp_data_to_guest(&mut self, id: usize) {
        let Some(f) = self.flows.get_by_id(id) else {
            return;
        };
        let raw = f.sock.as_raw_fd();
        let buf_id = f.buf;
        let Some(t) = f.tcp.as_ref() else {
            return;
        };
        if t.state != flow::TcpState::Established || t.host_fin != flow::FinState::NotSent {
            return;
        }
        if t.poll_armed && t.sent_unacked == 0 {
            // Nothing in flight to extend and the armed poll will
            // report new host data; skip the (usually empty) peek that
            // guest acks would otherwise trigger per segment.
            return;
        }
        let sent = t.sent_unacked as usize;
        let budget = t.guest_window.saturating_sub(t.sent_unacked) as usize;
        let mss = t.guest_mss;
        let seq = t.seq_una.wrapping_add(t.sent_unacked);
        let ack = t.seq_from_guest;
        let poll_armed = t.poll_armed;
        if budget == 0 {
            return; // window full; the next guest ack retriggers
        }
        let max_peek = buf::FRAME.min(sent + budget);
        let b = &mut self.pool.get_mut(buf_id)[buf::HEADROOM..buf::HEADROOM + max_peek];
        let n = match recv(raw, b, MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT) {
            Err(nix::errno::Errno::EAGAIN) => {
                self.stats.peek(true);
                if !poll_armed {
                    let _ = self.arm_poll(id, POLL_RECV);
                }
                return;
            }
            Err(_) => {
                self.tcp_reset(id);
                return;
            }
            Ok(0) => {
                // Host closed its sending side; unacked data can no
                // longer sit in the receive queue, so sent == 0 here.
                self.send_tcp_control(id, proto::TCP_FIN | proto::TCP_ACK);
                if let Some(t) = self.flows.get_mut(id).and_then(|f| f.tcp.as_mut()) {
                    t.host_fin = flow::FinState::Sent;
                }
                return;
            }
            Ok(n) => n,
        };
        self.stats.peek(false);
        let new = n.saturating_sub(sent);
        if new == 0 {
            return; // everything readable is already in flight
        }
        let send_len = new.min(budget).min(TCP_MAX_PAYLOAD);
        let window = self.tcp_window_to_guest(id);
        let use_gso = self.tap.offloads().tso() && send_len > usize::from(mss);
        let chunk = if use_gso {
            send_len
        } else {
            send_len.min(usize::from(mss))
        };
        let mut off = 0;
        while off < send_len {
            let len = chunk.min(send_len - off);
            let start = buf::HEADROOM + sent + off;
            #[expect(clippy::cast_possible_truncation, reason = "frame fits u32")]
            self.send_tcp_segment(
                id,
                &TcpSegment {
                    seq: seq.wrapping_add(off as u32),
                    ack,
                    flags: proto::TCP_ACK,
                    window,
                    options: &[],
                    payload: start..start + len,
                    gso_size: use_gso.then_some(mss),
                },
            );
            off += len;
        }
        if let Some(t) = self.flows.get_mut(id).and_then(|f| f.tcp.as_mut()) {
            #[expect(clippy::cast_possible_truncation, reason = "frame fits u32")]
            {
                t.sent_unacked += send_len as u32;
            }
        }
        // Only re-arm when the socket was drained; otherwise the next
        // guest ack opens the window and sends the rest.
        if send_len == new && !poll_armed {
            let _ = self.arm_poll(id, POLL_RECV);
        }
    }

    /// Window to advertise to the guest: free space in the host
    /// socket's send buffer, so accepted guest data always fits.
    fn tcp_window_to_guest(&self, id: usize) -> u16 {
        let Some(f) = self.flows.get_by_id(id) else {
            return 0;
        };
        let Some(t) = f.tcp.as_ref() else {
            return 0;
        };
        let mut queued: libc::c_int = 0;
        // SAFETY: SIOCOUTQ writes a c_int for any socket fd.
        if unsafe { siocoutq(f.sock.as_raw_fd(), &raw mut queued) }.is_err() {
            return 0;
        }
        let free = t.sndbuf.saturating_sub(queued.max(0).unsigned_abs());
        let scaled = if t.guest_wscale.is_some() {
            free >> WINDOW_SHIFT
        } else {
            free
        };
        u16::try_from(scaled).unwrap_or(u16::MAX)
    }

    fn send_syn_ack(&mut self, id: usize) {
        let Some(t) = self.tcp_state(id) else {
            return;
        };
        let mut options = vec![2, 4, 0, 0];
        options[2..4].copy_from_slice(&TCP_MSS.to_be_bytes());
        if t.guest_wscale.is_some() {
            options.extend_from_slice(&[1, 3, 3, WINDOW_SHIFT]);
        }
        // The window field of a SYN-ACK is never scaled.
        let window = u16::try_from(t.sndbuf).unwrap_or(u16::MAX);
        let seg = TcpSegment {
            seq: TCP_ISN,
            ack: t.seq_from_guest,
            flags: proto::TCP_SYN | proto::TCP_ACK,
            window,
            options: &options,
            payload: buf::HEADROOM..buf::HEADROOM,
            gso_size: None,
        };
        self.send_tcp_segment(id, &seg);
        // Assume the SYN-ACK is acked; a lost one shows up as a SYN
        // retransmit and is resent from `tcp_from_guest`.
        if let Some(t) = self.flows.get_mut(id).and_then(|f| f.tcp.as_mut()) {
            t.seq_una = TCP_ISN.wrapping_add(1);
        }
    }

    /// Send a payload-less segment (ACK, FIN, RST) at the current
    /// send position.
    fn send_tcp_control(&mut self, id: usize, flags: u8) {
        self.stats.tcp_ctrl();
        let window = if flags & proto::TCP_RST != 0 {
            0
        } else {
            self.tcp_window_to_guest(id)
        };
        let Some(t) = self.tcp_state(id) else {
            return;
        };
        let seg = TcpSegment {
            seq: t.seq_una.wrapping_add(t.sent_unacked),
            ack: t.seq_from_guest,
            flags,
            window,
            options: &[],
            payload: buf::HEADROOM..buf::HEADROOM,
            gso_size: None,
        };
        self.send_tcp_segment(id, &seg);
    }

    /// Abort the flow towards both sides.
    fn tcp_reset(&mut self, id: usize) {
        self.send_tcp_control(id, proto::TCP_RST | proto::TCP_ACK);
        self.remove_flow(id);
    }

    /// Drop the flow once both directions are closed and acknowledged.
    fn tcp_maybe_close(&mut self, id: usize) {
        if self
            .tcp_state(id)
            .is_some_and(|t| t.host_fin == flow::FinState::Acked && t.guest_fin_received)
        {
            self.remove_flow(id);
        }
    }

    /// Frame one TCP segment in the flow's buffer (headers built right
    /// in front of the payload) and write it to the tap.
    fn send_tcp_segment(&mut self, id: usize, seg: &TcpSegment) {
        let Some(f) = self.flows.get_by_id(id) else {
            return;
        };
        let key = f.key;
        let buf_id = f.buf;
        let guest_mac = self.guest_mac;
        let gateway_mac = self.cfg.gateway_mac;
        let (guest4, guest6) = (self.cfg.guest4, self.cfg.guest6);
        let csum_offload = self.tap.offloads().csum();

        let l4_start = seg.payload.start - proto::TCP_HDR_LEN - seg.options.len();
        let end = seg.payload.end;
        let l4_len = u16::try_from(end - l4_start).unwrap_or(u16::MAX);
        let (ip_start, ethertype, pseudo, gso_type) = match key.dst.ip() {
            IpAddr::V4(src) => (
                l4_start - proto::IPV4_HDR_LEN,
                proto::ETHERTYPE_IPV4,
                proto::pseudo_v4(src, guest4, proto::IPPROTO_TCP, l4_len),
                tap::VIRTIO_NET_HDR_GSO_TCPV4,
            ),
            IpAddr::V6(src) => (
                l4_start - proto::IPV6_HDR_LEN,
                proto::ETHERTYPE_IPV6,
                proto::pseudo_v6(src, guest6, proto::IPPROTO_TCP, l4_len),
                tap::VIRTIO_NET_HDR_GSO_TCPV6,
            ),
        };
        let eth_start = ip_start - proto::ETH_LEN;
        let vnet_start = eth_start - tap::VNET_HDR_LEN;

        let b = self.pool.get_mut(buf_id);
        proto::TcpHdr::write(
            &mut b[l4_start..end],
            (key.dst.port(), key.guest_port),
            seg.seq,
            seg.ack,
            seg.flags,
            seg.window,
            seg.options,
            pseudo,
            csum_offload,
        );
        match key.dst.ip() {
            IpAddr::V4(src) => {
                proto::Ipv4Hdr::write(&mut b[ip_start..], src, guest4, proto::IPPROTO_TCP, l4_len);
            }
            IpAddr::V6(src) => {
                proto::Ipv6Hdr::write(&mut b[ip_start..], src, guest6, proto::IPPROTO_TCP, l4_len);
            }
        }
        proto::EthHdr {
            dst: guest_mac,
            src: gateway_mac,
            ethertype,
        }
        .write(&mut b[eth_start..]);

        let l2_hdr_len = seg.payload.start - eth_start;
        let vnet = tap::VnetHdr {
            flags: if csum_offload {
                tap::VIRTIO_NET_HDR_F_NEEDS_CSUM
            } else {
                0
            },
            gso_type: if seg.gso_size.is_some() { gso_type } else { 0 },
            hdr_len: u16::try_from(l2_hdr_len).unwrap_or(0),
            gso_size: seg.gso_size.unwrap_or(0),
            csum_start: u16::try_from(l4_start - eth_start).unwrap_or(0),
            csum_offset: 16, // TCP checksum field offset
        };
        b[vnet_start..eth_start].copy_from_slice(&vnet.to_bytes());

        self.stats.tap_out(end - vnet_start);
        let _ = nix::unistd::write(self.tap.fd(), &b[vnet_start..end]);
    }
}

/// One TCP segment towards the guest; `payload` is a range within the
/// flow's buffer (empty for control segments).
struct TcpSegment<'a> {
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: &'a [u8],
    payload: std::ops::Range<usize>,
    gso_size: Option<u16>,
}

/// Discard `n` bytes the guest acknowledged from the host socket's
/// receive queue without copying them.
fn discard_acked(raw: RawFd, n: u32) {
    let mut left = n as usize;
    while left > 0 {
        // SAFETY: MSG_TRUNC on TCP discards without writing to the
        // (null) buffer.
        let r = unsafe {
            libc::recv(
                raw,
                std::ptr::null_mut(),
                left,
                libc::MSG_TRUNC | libc::MSG_DONTWAIT,
            )
        };
        if r <= 0 {
            break;
        }
        left -= r.unsigned_abs().min(left);
    }
}

/// Unprivileged ICMP echo ("ping") socket for the given address family.
fn ping_socket(dst: IpAddr) -> Option<UdpSocket> {
    let (family, protocol) = match dst {
        IpAddr::V4(_) => (AddressFamily::Inet, SockProtocol::Icmp),
        IpAddr::V6(_) => (AddressFamily::Inet6, SockProtocol::IcmpV6),
    };
    let fd = socket(family, SockType::Datagram, SockFlag::SOCK_CLOEXEC, protocol).ok()?;
    Some(UdpSocket::from(fd))
}
