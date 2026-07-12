//! `io_uring` event loop.
//!
//! The ring starts disabled, registers an operation allowlist
//! (`io_uring` submissions bypass seccomp, so the kernel-side
//! restriction is the only enforcement point), the tap fd and the
//! buffer pool, and only then is enabled.

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;

use io_uring::{IoUring, opcode, register::Restriction, squeue, types};

use crate::{Config, buf, dns, flow, proto, tap};

/// Registered-file index of the tap fd.
const TAP: types::Fixed = types::Fixed(0);
/// `user_data` of the tap read; flow ids use their table index.
const TAP_UD: u64 = u64::MAX;

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

/// A guest UDP datagram parsed out of a tap frame.
struct GuestUdp {
    src_mac: [u8; 6],
    src_ip: IpAddr,
    dst: SocketAddr,
    src_port: u16,
    payload: std::ops::Range<usize>,
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
        })
    }

    /// Run until the tap fd reports EOF or an unrecoverable error.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from the ring or the tap fd.
    pub fn run(mut self) -> io::Result<()> {
        self.submit_tap_read()?;
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
                } else {
                    #[expect(clippy::cast_possible_truncation, reason = "flow ids fit usize")]
                    let id = ud as usize;
                    if res >= 0 {
                        self.reply_to_guest(id, res.unsigned_abs() as usize);
                    }
                    self.submit_flow_recv(id)?;
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

    /// Parse a frame read from the tap; only UDP is handled so far.
    fn parse_guest_udp(&self, len: usize) -> Option<GuestUdp> {
        let frame = &self.pool.get(self.tap_buf)[..len];
        let l3 = frame.get(tap::VNET_HDR_LEN + proto::ETH_LEN..)?;
        let eth = proto::EthHdr::parse(frame.get(tap::VNET_HDR_LEN..)?)?;
        let (src_ip, dst_ip, ip_proto, l4_off) = match eth.ethertype {
            proto::ETHERTYPE_IPV4 => {
                let ip = proto::Ipv4Hdr::parse(l3)?;
                (
                    IpAddr::V4(ip.src),
                    IpAddr::V4(ip.dst),
                    ip.proto,
                    ip.header_len,
                )
            }
            proto::ETHERTYPE_IPV6 => {
                let ip = proto::Ipv6Hdr::parse(l3)?;
                (
                    IpAddr::V6(ip.src),
                    IpAddr::V6(ip.dst),
                    ip.next_header,
                    proto::IPV6_HDR_LEN,
                )
            }
            _ => return None,
        };
        if ip_proto != proto::IPPROTO_UDP {
            return None;
        }
        let udp = proto::UdpHdr::parse(l3.get(l4_off..)?)?;
        let payload_off = tap::VNET_HDR_LEN + proto::ETH_LEN + l4_off + proto::UDP_HDR_LEN;
        let payload_end = payload_off + usize::from(udp.len.checked_sub(8)?).min(len - payload_off);
        Some(GuestUdp {
            src_mac: eth.src,
            src_ip,
            dst: SocketAddr::new(dst_ip, udp.dst_port),
            src_port: udp.src_port,
            payload: payload_off..payload_end,
        })
    }

    fn handle_tap_frame(&mut self, len: usize) {
        let Some(g) = self.parse_guest_udp(len) else {
            return;
        };
        // Ignore anything not sourced from the configured guest address.
        if g.src_ip != IpAddr::V4(self.cfg.guest4) && g.src_ip != IpAddr::V6(self.cfg.guest6) {
            return;
        }
        self.guest_mac = g.src_mac;

        let key = flow::FlowKey {
            proto: proto::IPPROTO_UDP,
            guest_port: g.src_port,
            dst: g.dst,
        };
        let Some(id) = self.flows.get(&key).or_else(|| self.new_udp_flow(key)) else {
            return;
        };
        let data = &self.pool.get(self.tap_buf)[g.payload];
        if let Some(f) = self.flows.get_by_id(id) {
            let _ = f.sock.send(data); // drop on EAGAIN/unreachable
        }
    }

    /// Create the connected host socket for a new guest flow and arm
    /// its first recv. DNS to the gateway is redirected to the host
    /// resolver.
    fn new_udp_flow(&mut self, key: flow::FlowKey) -> Option<usize> {
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
        sock.set_nonblocking(true).ok()?;
        sock.connect(target).ok()?;
        let buf = self.pool.alloc()?;
        let id = self.flows.insert(flow::UdpFlow { key, sock, buf });
        self.submit_flow_recv(id).ok()?;
        Some(id)
    }

    /// Build the ethernet/IP/UDP frame for `len` payload bytes sitting
    /// at the flow buffer's headroom offset and write it to the tap.
    fn reply_to_guest(&mut self, id: usize, len: usize) {
        let Some(f) = self.flows.get_by_id(id) else {
            return;
        };
        let key = f.key;
        let buf_id = f.buf;
        let guest_mac = self.guest_mac;
        let gateway_mac = self.cfg.gateway_mac;
        let (guest4, guest6) = (self.cfg.guest4, self.cfg.guest6);

        let udp_len = u16::try_from(proto::UDP_HDR_LEN + len).unwrap_or(u16::MAX);
        let udp_start = buf::HEADROOM - proto::UDP_HDR_LEN;
        let (ip_start, ethertype, pseudo) = match key.dst.ip() {
            IpAddr::V4(src) => (
                udp_start - proto::IPV4_HDR_LEN,
                proto::ETHERTYPE_IPV4,
                proto::pseudo_v4(src, guest4, proto::IPPROTO_UDP, udp_len),
            ),
            IpAddr::V6(src) => (
                udp_start - proto::IPV6_HDR_LEN,
                proto::ETHERTYPE_IPV6,
                proto::pseudo_v6(src, guest6, proto::IPPROTO_UDP, udp_len),
            ),
        };
        let eth_start = ip_start - proto::ETH_LEN;
        let vnet_start = eth_start - tap::VNET_HDR_LEN;
        let end = buf::HEADROOM + len;

        let b = self.pool.get_mut(buf_id);
        proto::UdpHdr::write(
            &mut b[udp_start..end],
            key.dst.port(),
            key.guest_port,
            pseudo,
        );
        match key.dst.ip() {
            IpAddr::V4(src) => {
                proto::Ipv4Hdr::write(&mut b[ip_start..], src, guest4, proto::IPPROTO_UDP, udp_len);
            }
            IpAddr::V6(src) => {
                proto::Ipv6Hdr::write(&mut b[ip_start..], src, guest6, proto::IPPROTO_UDP, udp_len);
            }
        }
        proto::EthHdr {
            dst: guest_mac,
            src: gateway_mac,
            ethertype,
        }
        .write(&mut b[eth_start..]);
        b[vnet_start..eth_start].fill(0);

        let _ = nix::unistd::write(self.tap.fd(), &b[vnet_start..end]);
    }
}
