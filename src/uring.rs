//! `io_uring` event loop.
//!
//! The ring starts disabled, registers an operation allowlist
//! (`io_uring` submissions bypass seccomp, so the kernel-side
//! restriction is the only enforcement point), the tap fd and the
//! buffer pool, and only then is enabled.

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use io_uring::{IoUring, opcode, register::Restriction, squeue, types};
use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType, socket};

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
    resolver: Option<SocketAddr>,
    guest_mac: [u8; 6],
    tap_buf: buf::BufId,
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
            resolver: dns::host_resolver(),
            guest_mac: [0; 6],
            tap_buf,
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
        loop {
            self.ring.submit_and_wait(1)?;
            let completions: Vec<(u64, i32)> = self
                .ring
                .completion()
                .map(|cqe| (cqe.user_data(), cqe.result()))
                .collect();
            for (ud, res) in completions {
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
                    self.expire_flows()?;
                    self.submit_timer()?;
                } else if ud == CANCEL_UD {
                    // Cancel completions carry no state to clean up.
                } else {
                    #[expect(clippy::cast_possible_truncation, reason = "flow ids fit usize")]
                    let id = ud as usize;
                    let closing = self.flows.get_by_id(id).is_none_or(|f| f.closing);
                    if closing || res == -libc::ECANCELED {
                        if let Some(buf) = self.flows.remove(id) {
                            self.pool.free(buf);
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

    /// Cancel the pending recv of every idle flow; the slot is freed
    /// when the cancelled recv completes.
    fn expire_flows(&mut self) -> io::Result<()> {
        let Some(cutoff) = Instant::now().checked_sub(FLOW_EXPIRY) else {
            return Ok(());
        };
        for id in self.flows.expired(cutoff) {
            if let Some(f) = self.flows.get_mut(id) {
                f.closing = true;
            }
            let cancel = opcode::AsyncCancel::new(id as u64)
                .build()
                .user_data(CANCEL_UD);
            self.push(&cancel)?;
        }
        Ok(())
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
        let data = &self.pool.get(self.tap_buf)[payload];
        if let Some(f) = self.flows.get_mut(id) {
            f.last_active = Instant::now();
            let _ = f.sock.send(data); // drop on EAGAIN/unreachable
        }
    }

    /// Create the connected host socket for a new guest flow and arm
    /// its first recv. DNS to the gateway is redirected to the host
    /// resolver.
    fn new_flow(&mut self, key: flow::FlowKey, kind: flow::FlowKind) -> Option<usize> {
        let sock = match kind {
            flow::FlowKind::Udp => {
                let gateway_dns = key.dst.port() == 53
                    && (key.dst.ip() == IpAddr::V4(self.cfg.gateway4)
                        || key.dst.ip() == IpAddr::V6(self.cfg.gateway6));
                let target = if gateway_dns && self.cfg.dns_forward {
                    self.resolver?
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
        };
        sock.set_nonblocking(true).ok()?;
        let buf = self.pool.alloc()?;
        let id = self.flows.insert(flow::Flow {
            key,
            kind,
            sock,
            buf,
            last_active: Instant::now(),
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
        // guest's).
        let (l4_start, ip_proto) = match kind {
            flow::FlowKind::Udp => (buf::HEADROOM - proto::UDP_HDR_LEN, proto::IPPROTO_UDP),
            flow::FlowKind::Ping => (buf::HEADROOM, key.proto),
        };
        let l4_len = u16::try_from(end - l4_start).unwrap_or(u16::MAX);
        // ICMPv4 checksums have no pseudo-header.
        let pseudo = match (key.dst.ip(), kind) {
            (IpAddr::V4(_), flow::FlowKind::Ping) => 0,
            (IpAddr::V4(src), flow::FlowKind::Udp) => {
                proto::pseudo_v4(src, guest4, ip_proto, l4_len)
            }
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

        let _ = nix::unistd::write(self.tap.fd(), &b[vnet_start..end]);
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
