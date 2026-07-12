//! Wire formats: ethernet, IPv4/IPv6, TCP/UDP/ICMP header views and
//! builders, plus the internet checksum for the no-offload fallback.

pub const ETH_LEN: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;

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

/// RFC 1071 internet checksum over `data` with an initial sum (for
/// pseudo-headers). Only used when checksum offload is unavailable.
#[must_use]
pub fn checksum(data: &[u8], init: u32) -> u16 {
    let mut sum = init;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
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
