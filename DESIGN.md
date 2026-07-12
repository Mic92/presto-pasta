# presto-pasta — design

User-mode NAT datapath for sandboxes. Library only, no CLI.

Consumers are build systems and sandbox runners that give an isolated
build outbound network access: TCP, UDP, ICMP echo, DNS. No inbound
port forwarding.

## Model

Same translation model as pasta: the host kernel runs the real TCP
stack; presto-pasta moves bytes between an L2 tap device and native host
sockets, rewriting headers. No user-space retransmit/congestion logic.

Unlike pasta, presto-pasta does not attach to a foreign netns. The caller
owns the sandbox: it creates the netns, opens the tap inside it,
configures addresses, routes, a permanent neighbor entry for the
gateway MAC, and resolv.conf pointing at the gateway, then hands presto-pasta
the tap fd. presto-pasta is a pure datapath over that fd.

Not in presto-pasta because of this: setns/userns handling, netlink
configuration, ARP/NDP responders, readiness barriers, privilege drop.
The caller runs presto-pasta under whatever uid and seccomp policy it wants;
a built-in seccomp filter is an optional feature.

## Datapath

1. **Tap offloads.** Caller opens the tap with `IFF_VNET_HDR`; presto-pasta
   probes TSO4/TSO6/USO/CSUM via `TUNSETOFFLOAD` (USO needs kernel
   ≥ 6.2) and checksums in software when CSUM is unavailable. Frame
   sizing follows the vnet header, not the interface MTU; buffers hold
   64k super-frames.
2. **io_uring.** Multishot recv on TCP sockets and the tap fd,
   registered buffers/fds, `SEND_ZC` where profitable. io_uring bypasses
   seccomp, so the ring registers an op allowlist
   (`IORING_REGISTER_RESTRICTIONS`) before enabling.
3. **Buffers.** Fixed pool of 64k buffers with headroom; headers are
   built in the headroom in front of the payload. No memmove, no
   per-packet allocation.
4. **Flow table.** Open-addressing hash over the 5-tuple (keyed
   foldhash), flows in a slab, timers on a hierarchical wheel.
5. **Threads.** Single-threaded event loop. Multi-queue tap sharding
   only if one thread cannot saturate the link.

## Scope

- outbound TCP and UDP, per-flow connected host sockets
- ICMP/ICMPv6 echo via ping sockets; if `net.ipv4.ping_group_range`
  excludes the caller's gid, echo is disabled instead of failing
- DNS forwarding: queries to the gateway address go to the host
  resolver; resolv.conf re-read on change; loopback resolvers
  (127.0.0.53) work because presto-pasta's sockets are in the host netns
- liveness event fd on the handle so a supervisor can fail the job when
  the event loop exits

Out of scope: inbound port forwarding, ARP/NDP, DHCP/RA, namespace
setup, privilege management, passt socket mode, vhost-user, migration,
pcap.

## API

```rust
let presto-pasta = presto_pasta::Presto::new(presto_pasta::Config::default(), tap_fd)?;
let liveness = presto-pasta.liveness_fd();
presto-pasta.run()?; // until the tap fd is torn down
```

`Config`: gateway/guest addresses (to synthesize headers and recognize
DNS traffic), GSO limits, buffer pool size. Defaults use link-local v4
and a fixed ULA-style v6 scheme suitable for build sandboxes.
