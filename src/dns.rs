//! Host resolver discovery for DNS forwarding and DNS64-based NAT64
//! prefix discovery.

use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// First nameserver from /etc/resolv.conf, port 53. Loopback resolvers
/// work because presto-pasta's sockets live in the host netns.
#[must_use]
pub fn host_resolver() -> Option<SocketAddr> {
    parse(&std::fs::read_to_string("/etc/resolv.conf").ok()?)
}

fn parse(conf: &str) -> Option<SocketAddr> {
    conf.lines()
        .filter_map(|l| l.strip_prefix("nameserver"))
        .filter_map(|a| a.trim().parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, 53))
        .next()
}

/// IPv4 addresses `ipv4only.arpa` resolves to (RFC 7050); a DNS64
/// resolver synthesizes AAAA records embedding one of them.
const WELL_KNOWN_V4: [[u8; 4]; 2] = [[192, 0, 0, 170], [192, 0, 0, 171]];

/// Discover the host resolver's NAT64 prefix via DNS64 (RFC 7050):
/// query `ipv4only.arpa` for AAAA records and extract the /96 prefix
/// the well-known IPv4 addresses are embedded in. Returns `None` when
/// the resolver does not do DNS64, uses a non-/96 prefix, or does not
/// answer. Intended for [`crate::Config::nat64_prefix`], called before
/// the datapath starts.
#[must_use]
pub fn discover_nat64_prefix() -> Option<Ipv6Addr> {
    let resolver = host_resolver()?;
    let bind: IpAddr = if resolver.is_ipv4() {
        std::net::Ipv4Addr::UNSPECIFIED.into()
    } else {
        Ipv6Addr::UNSPECIFIED.into()
    };
    let sock = UdpSocket::bind(SocketAddr::new(bind, 0)).ok()?;
    sock.connect(resolver).ok()?;
    sock.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
    let query = ipv4only_arpa_query();
    let mut response = [0u8; 512];
    for _ in 0..3 {
        sock.send(&query).ok()?;
        if let Ok(n) = sock.recv(&mut response) {
            return parse_nat64_prefix(&response[..n]);
        }
    }
    None
}

/// AAAA query for `ipv4only.arpa` (recursion desired, id 0).
fn ipv4only_arpa_query() -> Vec<u8> {
    let mut q = vec![0, 0, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(b"\x08ipv4only\x04arpa\x00");
    q.extend_from_slice(&[0, 28, 0, 1]); // AAAA, IN
    q
}

/// Extract the /96 NAT64 prefix from a DNS response's AAAA records.
fn parse_nat64_prefix(b: &[u8]) -> Option<Ipv6Addr> {
    let qdcount = usize::from(u16::from_be_bytes([*b.get(4)?, *b.get(5)?]));
    let ancount = usize::from(u16::from_be_bytes([*b.get(6)?, *b.get(7)?]));
    let mut i = 12;
    for _ in 0..qdcount {
        i = skip_name(b, i)? + 4;
    }
    for _ in 0..ancount {
        i = skip_name(b, i)?;
        let rtype = u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]);
        let rdlen = usize::from(u16::from_be_bytes([*b.get(i + 8)?, *b.get(i + 9)?]));
        let rdata = b.get(i + 10..i + 10 + rdlen)?;
        i += 10 + rdlen;
        if rtype != 28 || rdlen != 16 {
            continue;
        }
        if WELL_KNOWN_V4.iter().any(|wka| &rdata[12..16] == wka) {
            let mut prefix: [u8; 16] = rdata.try_into().ok()?;
            prefix[12..16].fill(0);
            return Some(Ipv6Addr::from(prefix));
        }
    }
    None
}

/// Index just past a (possibly compressed) DNS name starting at `i`.
fn skip_name(b: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let len = *b.get(i)?;
        if len & 0xc0 == 0xc0 {
            return Some(i + 2);
        }
        if len == 0 {
            return Some(i + 1);
        }
        i += 1 + usize::from(len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DNS response with one AAAA answer for `ipv4only.arpa`.
    fn response(addr: Ipv6Addr) -> Vec<u8> {
        let mut r = ipv4only_arpa_query();
        r[2] = 0x81; // response, RD
        r[3] = 0x80; // RA
        r[7] = 1; // ancount
        r.extend_from_slice(&[0xc0, 0x0c]); // name pointer to question
        r.extend_from_slice(&[0, 28, 0, 1, 0, 0, 0, 60, 0, 16]); // AAAA IN ttl rdlen
        r.extend_from_slice(&addr.octets());
        r
    }

    #[test]
    fn extracts_well_known_prefix() {
        let addr = "64:ff9b::c000:aa".parse().unwrap();
        assert_eq!(
            parse_nat64_prefix(&response(addr)),
            Some("64:ff9b::".parse().unwrap())
        );
    }

    #[test]
    fn extracts_network_specific_prefix() {
        let addr = "fd00:64::c000:ab".parse().unwrap();
        assert_eq!(
            parse_nat64_prefix(&response(addr)),
            Some("fd00:64::".parse().unwrap())
        );
    }

    #[test]
    fn no_dns64_synthesis() {
        // A real (non-synthesized) AAAA answer carries no embedded
        // well-known IPv4 address.
        let addr = "2001:db8::1".parse().unwrap();
        assert_eq!(parse_nat64_prefix(&response(addr)), None);
        // Empty answer section.
        assert_eq!(parse_nat64_prefix(&ipv4only_arpa_query()), None);
    }

    #[test]
    fn parses_first_nameserver() {
        let conf = "search example.org\nnameserver 127.0.0.53\nnameserver 9.9.9.9\n";
        assert_eq!(parse(conf), Some("127.0.0.53:53".parse().unwrap()));
    }

    #[test]
    fn no_nameserver() {
        assert_eq!(parse("search example.org\n"), None);
    }
}
