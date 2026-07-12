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

## Reducing noise

Set `PRESTO_BENCH_CPUS=<server>,<datapath>,<client>` to pin the iperf3
server, the datapath (presto thread or pasta process) and the iperf3
client to fixed cores. Without pinning, scheduler placement on large
machines swings results by a factor of two between runs.

## Datapath counters and captures

Build with `--features stats` to get event counters on stderr whenever
a flow is torn down. Set `PRESTO_BENCH_PCAP=<file>` to capture the
guest side of the tap with tcpdump during the bench.

## Results

AMD EPYC 9654 (idle), Linux 7.1, 2026-07-12, defaults (64 buffers,
single thread), tap MTU 65520, `PRESTO_BENCH_CPUS=2,4,6`, 5 s per
direction, median of 5 runs:

| direction               | presto        | pasta         |
| ----------------------- | ------------- | ------------- |
| upload (guest → host)   | 31.2 Gbits/s  | 29.5 Gbits/s  |
| download (host → guest) | 23.9 Gbits/s  | 9–16 Gbits/s  |
