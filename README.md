# presto-pasta

A user-mode NAT datapath for sandboxes, as a Rust library.

[![crates.io](https://img.shields.io/crates/v/presto-pasta.svg)](https://crates.io/crates/presto-pasta)
[![docs.rs](https://img.shields.io/docsrs/presto-pasta)](https://docs.rs/presto-pasta)

Build systems and sandbox runners give each job its own network
namespace because sharing the host's namespace exposes localhost
services, link-local addresses and abstract unix sockets (which ignore
filesystem permissions, so a mount namespace does not protect them).
A fresh netns has no connectivity, and the usual ways to add some
(veth pairs, bridges, NAT rules) need root and change host network
configuration.

pasta addresses this with user-mode NAT: the namespace gets outbound
TCP, UDP, ICMP echo and DNS without privileges. The host kernel runs
the real TCP stack; the datapath moves bytes between an L2 tap device
and native host sockets, rewriting headers. presto-pasta implements
the same model as a Rust library.

## Why not just run pasta?

pasta is a standalone C program that attaches to an existing network
namespace. Embedding it in a runner means forking one pasta process
per sandbox, letting it `setns()` into the namespace, configure
interfaces over netlink, signal readiness, and supervising it for the
lifetime of the job. presto-pasta avoids that:

- No extra process. The runner already creates the namespace and can
  open the tap device there; it hands presto-pasta the tap fd and runs
  the datapath on a thread. Setup, readiness and teardown are function
  calls and fd lifetimes.
- Memory safe. The packet path is safe Rust; the unsafe blocks wrap
  io_uring submission and ioctls.
- Faster. io_uring, a fixed pre-registered buffer pool, GSO/GRO
  super-frames in both directions, UDP GSO coalescing. Single-stream
  iperf3 against pasta on the same idle EPYC 9654: 31 vs 29 Gbit/s
  upload, 24 vs 9–16 Gbit/s download, and 3–13× on UDP/QUIC downloads.
  See [BENCH.md](BENCH.md).
- Less code in the datapath: no netlink, no namespace handling, no
  privilege management, no CLI. An optional seccomp filter and an
  io_uring op allowlist confine the datapath thread.

## Usage

Add the crate:

```console
cargo add presto-pasta
```

The caller owns the sandbox: create the user+net namespace, open the
tap inside it (`IFF_TAP | IFF_NO_PI | IFF_VNET_HDR`), assign
addresses, routes and a neighbor entry for the gateway MAC, point
resolv.conf at the gateway, then:

```rust
let cfg = presto_pasta::Config {
    // Internet only: no host LANs, VPN subnets or link-local services.
    // Without a callback the default policy refuses loopback destinations.
    allow_flow: Some(std::sync::Arc::new(|dst: &presto_pasta::FlowDst| dst.is_public())),
    ..presto_pasta::Config::default()
};
let mut presto = presto_pasta::Presto::new(cfg, tap_fd);
let liveness = presto.liveness_fd()?;   // POLLHUP when the datapath dies
std::thread::spawn(move || presto.run());
```

`Config` also carries the guest/gateway addresses (defaults suit build
sandboxes), DNS forwarding and the buffer pool size. The netns test in
[`tests/netns.rs`](tests/netns.rs) is a complete, runnable example of
the namespace and tap setup.

## Scope

Outbound TCP, UDP and ICMP/ICMPv6 echo with per-flow connected host
sockets, plus DNS forwarding to the host resolver. NAT64 carries the
guest's IPv4 traffic on IPv6-only hosts (`Config::nat64_prefix`, with
DNS64 prefix discovery). Inbound port
forwarding, DHCP/RA, ARP/NDP responders and pasta's other modes are
out of scope. Architecture: [DESIGN.md](DESIGN.md).

## License

MIT
