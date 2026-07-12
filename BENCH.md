# Benchmark: presto vs pasta

Single TCP stream through the datapath with iperf3, measured by the
`bench` test in `tests/netns.rs` (needs `iperf3` and `pasta` from the
dev shell):

```
cargo test --release --test netns -- --ignored --nocapture bench
```

Both backends see the same topology: a user+net namespace holds the
iperf3 server on a loopback address, the client runs in a nested
namespace whose only path out is the datapath under test (presto over
its tap fd, pasta with `--config-net` and port forwarding disabled,
matching how sandbox runners invoke it).

## Results

AMD Ryzen 7 PRO 8840HS, Linux 6.18, 2026-07-12, commit `89a2e8a`
(defaults: 64 buffers, single thread), 5 s per direction:

| direction               | presto        | pasta         |
| ----------------------- | ------------- | ------------- |
| upload (guest → host)   | 7.1 Gbits/s   | 14.2 Gbits/s  |
| download (host → guest) | 14.3 Gbits/s  | 16.8 Gbits/s  |

Download is close to pasta. Upload trails because guest→host copies
each GSO frame with a plain blocking `send()` per segment batch;
`SEND_ZC`/batched submissions on the host socket side are still
pending.
