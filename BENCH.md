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

## Profiling

Attach perf to the process whose environment carries
`PRESTO_ROLE=bench-host` (it hosts the presto thread) while the bench
runs:

```
perf record -g --call-graph dwarf -p <pid> -- sleep 4
perf report --stdio --no-children
```

## Results

AMD Ryzen 7 PRO 8840HS, Linux 6.18, 2026-07-12 (defaults: 64 buffers,
single thread), 5 s per direction, three runs; the spread is
run-to-run variance on a busy laptop, not a stable difference:

| direction               | presto           | pasta            |
| ----------------------- | ---------------- | ---------------- |
| upload (guest → host)   | 15–31 Gbits/s    | 15–37 Gbits/s    |
| download (host → guest) | 20–22 Gbits/s    | 12–23 Gbits/s    |
