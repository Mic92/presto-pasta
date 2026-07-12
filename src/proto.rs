//! Wire formats: ethernet, IPv4/IPv6, TCP/UDP/ICMP header views and
//! builders, plus the internet checksum for the no-offload fallback.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const ETH_LEN: usize = 14;
pub const IPV4_HDR_LEN: usize = 20;
pub const IPV6_HDR_LEN: usize = 40;
pub const UDP_HDR_LEN: usize = 8;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;

pub const TCP_HDR_LEN: usize = 20;
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

pub const ICMP_HDR_LEN: usize = 8;
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;

/// Ethernet header of a frame (after the vnet header).
#[derive(Debug, Clone, Copy)]
pub struct EthHdr {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
}

impl EthHdr {
    #[must_use]
    pub fn parse(b: &[u8]) -> Option<Self> {
        let (dst, rest) = b.split_first_chunk::<6>()?;
        let (src, rest) = rest.split_first_chunk::<6>()?;
        let (ethertype, _) = rest.split_first_chunk::<2>()?;
        Some(Self {
            dst: *dst,
            src: *src,
            ethertype: u16::from_be_bytes(*ethertype),
        })
    }

    pub fn write(&self, out: &mut [u8]) {
        out[0..6].copy_from_slice(&self.dst);
        out[6..12].copy_from_slice(&self.src);
        out[12..14].copy_from_slice(&self.ethertype.to_be_bytes());
    }
}

/// IPv4 header view.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Hdr {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
    pub header_len: usize,
    pub total_len: u16,
}

impl Ipv4Hdr {
    #[must_use]
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < IPV4_HDR_LEN || b[0] >> 4 != 4 {
            return None;
        }
        let header_len = usize::from(b[0] & 0xf) * 4;
        if header_len < IPV4_HDR_LEN || b.len() < header_len {
            return None;
        }
        Some(Self {
            src: Ipv4Addr::new(b[12], b[13], b[14], b[15]),
            dst: Ipv4Addr::new(b[16], b[17], b[18], b[19]),
            proto: b[9],
            header_len,
            total_len: u16::from_be_bytes([b[2], b[3]]),
        })
    }

    /// Write a 20-byte header (no options) with checksum for a payload
    /// of `payload_len` bytes.
    pub fn write(out: &mut [u8], src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload_len: u16) {
        let out = &mut out[..IPV4_HDR_LEN];
        out.fill(0);
        out[0] = 0x45;
        out[2..4].copy_from_slice(&(payload_len + 20).to_be_bytes());
        out[6] = 0x40; // DF
        out[8] = 64; // TTL
        out[9] = proto;
        out[12..16].copy_from_slice(&src.octets());
        out[16..20].copy_from_slice(&dst.octets());
        let csum = checksum(out, 0);
        out[10..12].copy_from_slice(&csum.to_be_bytes());
    }
}

/// IPv6 header view. Extension headers are not parsed; packets that
/// carry them are dropped by the datapath.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Hdr {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub next_header: u8,
    pub payload_len: u16,
}

impl Ipv6Hdr {
    #[must_use]
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < IPV6_HDR_LEN || b[0] >> 4 != 6 {
            return None;
        }
        let src: [u8; 16] = b[8..24].try_into().ok()?;
        let dst: [u8; 16] = b[24..40].try_into().ok()?;
        Some(Self {
            src: Ipv6Addr::from(src),
            dst: Ipv6Addr::from(dst),
            next_header: b[6],
            payload_len: u16::from_be_bytes([b[4], b[5]]),
        })
    }

    /// Write a 40-byte header for a payload of `payload_len` bytes.
    pub fn write(out: &mut [u8], src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload_len: u16) {
        let out = &mut out[..IPV6_HDR_LEN];
        out.fill(0);
        out[0] = 0x60;
        out[4..6].copy_from_slice(&payload_len.to_be_bytes());
        out[6] = next_header;
        out[7] = 64; // hop limit
        out[8..24].copy_from_slice(&src.octets());
        out[24..40].copy_from_slice(&dst.octets());
    }
}

/// ICMP/ICMPv6 echo header view; only messages with code 0 parse.
#[derive(Debug, Clone, Copy)]
pub struct IcmpEcho {
    pub icmp_type: u8,
    pub id: u16,
}

impl IcmpEcho {
    #[must_use]
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < ICMP_HDR_LEN || b[1] != 0 {
            return None;
        }
        Some(Self {
            icmp_type: b[0],
            id: u16::from_be_bytes([b[4], b[5]]),
        })
    }

    /// Rewrite the echo identifier of the ICMP message in `msg` and
    /// recompute its checksum. `pseudo` is zero for `ICMPv4` and the
    /// pseudo-header sum for `ICMPv6`.
    pub fn patch_id(msg: &mut [u8], id: u16, pseudo: u32) {
        msg[4..6].copy_from_slice(&id.to_be_bytes());
        msg[2..4].copy_from_slice(&[0, 0]);
        let csum = checksum(msg, pseudo);
        msg[2..4].copy_from_slice(&csum.to_be_bytes());
    }
}

/// TCP header view. Only the MSS and window-scale options are decoded;
/// others are skipped.
#[derive(Debug, Clone, Copy)]
pub struct TcpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub header_len: usize,
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
}

impl TcpHdr {
    #[must_use]
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < TCP_HDR_LEN {
            return None;
        }
        let header_len = usize::from(b[12] >> 4) * 4;
        if header_len < TCP_HDR_LEN || b.len() < header_len {
            return None;
        }
        let mut hdr = Self {
            src_port: u16::from_be_bytes([b[0], b[1]]),
            dst_port: u16::from_be_bytes([b[2], b[3]]),
            seq: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            ack: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
            flags: b[13],
            window: u16::from_be_bytes([b[14], b[15]]),
            header_len,
            mss: None,
            wscale: None,
        };
        let mut opts = &b[TCP_HDR_LEN..header_len];
        while let Some((&kind, rest)) = opts.split_first() {
            match kind {
                0 => break,
                1 => {
                    opts = rest;
                    continue;
                }
                _ => {}
            }
            let (&len, _) = rest.split_first()?;
            let (opt, rest) = opts.split_at_checked(usize::from(len).max(2))?;
            match (kind, opt) {
                (2, [_, _, hi, lo]) => hdr.mss = Some(u16::from_be_bytes([*hi, *lo])),
                (3, [_, _, shift]) => hdr.wscale = Some(*shift),
                _ => {}
            }
            opts = rest;
        }
        Some(hdr)
    }

    /// Write header (with `options`, whose length must be a multiple
    /// of 4) and checksum into `out`. `pseudo` is the pseudo-header
    /// sum, plus the payload's `sum` when the payload lives in a
    /// separate buffer; with `csum_offload` the checksum field carries
    /// just the folded pseudo-header sum for the tap device to
    /// complete.
    #[expect(clippy::too_many_arguments, reason = "mirrors the header fields")]
    #[expect(clippy::cast_possible_truncation, reason = "folded to 16 bits")]
    pub fn write(
        out: &mut [u8],
        ports: (u16, u16),
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        options: &[u8],
        pseudo: u32,
        csum_offload: bool,
    ) {
        let header_len = TCP_HDR_LEN + options.len();
        debug_assert_eq!(options.len() % 4, 0);
        out[0..2].copy_from_slice(&ports.0.to_be_bytes());
        out[2..4].copy_from_slice(&ports.1.to_be_bytes());
        out[4..8].copy_from_slice(&seq.to_be_bytes());
        out[8..12].copy_from_slice(&ack.to_be_bytes());
        out[12] = ((header_len / 4) as u8) << 4;
        out[13] = flags;
        out[14..16].copy_from_slice(&window.to_be_bytes());
        out[16..20].fill(0);
        out[TCP_HDR_LEN..header_len].copy_from_slice(options);
        let csum = if csum_offload {
            // Fold the pseudo-header sum without complementing it.
            !checksum(&[], pseudo)
        } else {
            checksum(out, pseudo)
        };
        out[16..18].copy_from_slice(&csum.to_be_bytes());
    }
}

/// UDP header view.
#[derive(Debug, Clone, Copy)]
pub struct UdpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub len: u16,
}

impl UdpHdr {
    #[must_use]
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < UDP_HDR_LEN {
            return None;
        }
        Some(Self {
            src_port: u16::from_be_bytes([b[0], b[1]]),
            dst_port: u16::from_be_bytes([b[2], b[3]]),
            len: u16::from_be_bytes([b[4], b[5]]),
        })
    }

    /// Write header and checksum into `out`, which must already hold
    /// the payload after the first 8 bytes. `pseudo` is the pseudo
    /// header sum from [`pseudo_v4`]; with `csum_offload` the checksum
    /// field carries just the folded pseudo-header sum for the tap
    /// device to complete.
    ///
    /// # Panics
    ///
    /// Panics if `out` exceeds a UDP datagram (65535 bytes).
    pub fn write(out: &mut [u8], src_port: u16, dst_port: u16, pseudo: u32, csum_offload: bool) {
        let len = u16::try_from(out.len()).expect("UDP datagram fits u16");
        out[0..2].copy_from_slice(&src_port.to_be_bytes());
        out[2..4].copy_from_slice(&dst_port.to_be_bytes());
        out[4..6].copy_from_slice(&len.to_be_bytes());
        out[6..8].copy_from_slice(&[0, 0]);
        let csum = if csum_offload {
            !checksum(&[], pseudo)
        } else {
            match checksum(out, pseudo) {
                0 => 0xffff,
                c => c,
            }
        };
        out[6..8].copy_from_slice(&csum.to_be_bytes());
    }
}

/// Pseudo-header sum for IPv4 UDP/TCP checksums.
#[must_use]
pub fn pseudo_v4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, len: u16) -> u32 {
    let s = src.octets();
    let d = dst.octets();
    u32::from(u16::from_be_bytes([s[0], s[1]]))
        + u32::from(u16::from_be_bytes([s[2], s[3]]))
        + u32::from(u16::from_be_bytes([d[0], d[1]]))
        + u32::from(u16::from_be_bytes([d[2], d[3]]))
        + u32::from(proto)
        + u32::from(len)
}

/// Pseudo-header sum for IPv6 UDP/TCP/ICMPv6 checksums.
#[must_use]
pub fn pseudo_v6(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, len: u16) -> u32 {
    let mut sum = u32::from(proto) + u32::from(len);
    for seg in src.segments().into_iter().chain(dst.segments()) {
        sum += u32::from(seg);
    }
    sum
}

/// Unfolded 16-bit one's complement sum over a payload split across
/// two slices (a ring buffer wrap), for feeding it into `checksum` via
/// its initial sum. Only used when checksum offload is unavailable.
#[must_use]
pub fn sum2(a: &[u8], b: &[u8]) -> u32 {
    let mut s2 = sum(b);
    if a.len() % 2 == 1 {
        // `b` starts at an odd offset within the payload; its folded
        // sum contributes byte-swapped.
        while s2 > 0xffff {
            s2 = (s2 & 0xffff) + (s2 >> 16);
        }
        s2 = (s2 >> 8) | ((s2 & 0xff) << 8);
    }
    sum(a) + s2
}

/// Unfolded 16-bit one's complement sum over `data`; building block
/// for `checksum` and `sum2`.
#[must_use]
pub fn sum(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let (pairs, rest) = data.as_chunks::<2>();
    for c in pairs {
        sum += u32::from(u16::from_be_bytes(*c));
    }
    if let [last] = rest {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    sum
}

/// RFC 1071 internet checksum over `data` with an initial sum (for
/// pseudo-headers). Only used when checksum offload is unavailable.
#[must_use]
pub fn checksum(data: &[u8], init: u32) -> u16 {
    let mut sum = init + sum(data);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    #[expect(clippy::cast_possible_truncation, reason = "folded to 16 bits above")]
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_known_vector() {
        // Example from RFC 1071 section 3.
        let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&data, 0), !0xddf2);
    }

    #[test]
    fn udp_checksum_matches_known_packet() {
        // DNS query 169.254.1.2:40000 -> 169.254.1.1:53, payload "hi".
        let src = Ipv4Addr::new(169, 254, 1, 2);
        let dst = Ipv4Addr::new(169, 254, 1, 1);
        let mut dgram = vec![0u8; UDP_HDR_LEN + 2];
        dgram[UDP_HDR_LEN..].copy_from_slice(b"hi");
        let len = u16::try_from(dgram.len()).unwrap();
        UdpHdr::write(
            &mut dgram,
            40000,
            53,
            pseudo_v4(src, dst, IPPROTO_UDP, len),
            false,
        );
        // Verifying the checksum over pseudo header + datagram yields 0.
        assert_eq!(checksum(&dgram, pseudo_v4(src, dst, IPPROTO_UDP, len)), 0);
    }

    #[test]
    fn ipv6_roundtrip() {
        let mut b = [0u8; IPV6_HDR_LEN];
        let src = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        Ipv6Hdr::write(&mut b, src, dst, IPPROTO_UDP, 100);
        let h = Ipv6Hdr::parse(&b).unwrap();
        assert_eq!(h.src, src);
        assert_eq!(h.dst, dst);
        assert_eq!(h.next_header, IPPROTO_UDP);
        assert_eq!(h.payload_len, 100);
    }

    #[test]
    fn ipv4_roundtrip() {
        let mut b = [0u8; IPV4_HDR_LEN];
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(169, 254, 1, 2);
        Ipv4Hdr::write(&mut b, src, dst, IPPROTO_UDP, 100);
        let h = Ipv4Hdr::parse(&b).unwrap();
        assert_eq!(h.src, src);
        assert_eq!(h.dst, dst);
        assert_eq!(h.proto, IPPROTO_UDP);
        assert_eq!(h.total_len, 120);
        assert_eq!(checksum(&b, 0), 0);
    }

    #[test]
    fn tcp_roundtrip_with_options() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(169, 254, 1, 2);
        let options = [2, 4, 0xff, 0xd7, 1, 3, 3, 7]; // MSS 65495, wscale 7
        let mut seg = vec![0u8; TCP_HDR_LEN + options.len() + 3];
        seg[TCP_HDR_LEN + options.len()..].copy_from_slice(b"abc");
        let len = u16::try_from(seg.len()).unwrap();
        let pseudo = pseudo_v4(src, dst, IPPROTO_TCP, len);
        TcpHdr::write(
            &mut seg,
            (443, 40000),
            0x1234_5678,
            0x9abc_def0,
            TCP_SYN | TCP_ACK,
            4096,
            &options,
            pseudo,
            false,
        );
        assert_eq!(checksum(&seg, pseudo), 0);
        let h = TcpHdr::parse(&seg).unwrap();
        assert_eq!(h.src_port, 443);
        assert_eq!(h.dst_port, 40000);
        assert_eq!(h.seq, 0x1234_5678);
        assert_eq!(h.ack, 0x9abc_def0);
        assert_eq!(h.flags, TCP_SYN | TCP_ACK);
        assert_eq!(h.window, 4096);
        assert_eq!(h.header_len, TCP_HDR_LEN + options.len());
        assert_eq!(h.mss, Some(65495));
        assert_eq!(h.wscale, Some(7));
    }

    #[test]
    fn sum2_matches_contiguous_sum() {
        let data: Vec<u8> = (0u16..300).map(|i| (i % 251) as u8).collect();
        for split in [0, 1, 7, 128, 299, 300] {
            let (a, b) = data.split_at(split);
            assert_eq!(
                checksum(&data, 0),
                checksum(&[], sum2(a, b)),
                "split {split}"
            );
        }
    }

    #[test]
    fn eth_roundtrip() {
        let hdr = EthHdr {
            dst: [1, 2, 3, 4, 5, 6],
            src: [7, 8, 9, 10, 11, 12],
            ethertype: ETHERTYPE_IPV4,
        };
        let mut b = [0u8; ETH_LEN];
        hdr.write(&mut b);
        let p = EthHdr::parse(&b).unwrap();
        assert_eq!(p.dst, hdr.dst);
        assert_eq!(p.src, hdr.src);
        assert_eq!(p.ethertype, hdr.ethertype);
    }
}
