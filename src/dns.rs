//! Host resolver discovery for DNS forwarding.

use std::net::{IpAddr, SocketAddr};

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

#[cfg(test)]
mod tests {
    use super::*;

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
