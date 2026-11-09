+++
title = "Performance"
description = "Receive throughput and latency of rawether's ring and plain paths against libpcap (the pcap crate) and pnet_datalink, measured over a veth pair, with the method and the command to reproduce it."
weight = 125

[extra]
group = "Help"
+++

Measured on 2026-11-09 with `scripts/bench.sh --docker`: Linux 7.0.14 (Docker Desktop, linuxkit), 14 CPUs, aarch64, Rust 1.99.1.

| Receiver | Frames/s received | Received of 500 000 | Latency p50 | p99 | max |
|---|---|---|---|---|---|
| rawether, ring (default) | 2 779 k | 100.0 % | 550 µs | 974 µs | 1 199 µs |
| rawether, plain (`recvmsg`) | 987 k | 50.5 % | 15 µs | 30 µs | 137 µs |
| pcap 2 (libpcap, immediate mode) | 1 763 k | 100.0 % | 15 µs | 48 µs | 352 µs |
| pnet_datalink 0.35 | 1 189 k | 56.1 % | 17 µs | 37 µs | 102 µs |

## Reading the numbers

- **Throughput: use the ring.** The TPACKET_V3 ring keeps up with a saturating sender and receives every frame, at about 1.6× libpcap's rate. Paths that copy one frame per system call (rawether plain, pnet) fall behind and the kernel drops the rest. Those drops are counted, not hidden: see `stats()`.
- **Latency: use the plain path.** A ring hands over a block when it is full or when `retire_ms` (1 ms) expires, so a lone frame waits up to a millisecond. `RxMode::Plain` wakes per frame, at about 15 µs. libpcap's immediate mode gets both by switching to a per-frame ring (TPACKET_V2).
- **These are comparisons on one machine.** Docker Desktop runs a VM, so absolute numbers on bare metal will differ.

## Method

- **Pair:** a veth pair in one container (`rwbench0` → `rwbench1`).
- **Sender:** rawether, the same for every receiver.
- **Throughput:** 500 000 frames of 60 octets, sent in batches of 64 as fast as possible. The rate is counted from a receiver's first frame to its last.
- **Latency:** 5 000 frames, one every 200 µs, each carrying its `CLOCK_MONOTONIC` send time. The receiver records receipt time minus send time.
- **Filters:** rawether and pcap filter the test EtherType in the kernel (`ether proto 0x88b5` for pcap). pnet has no kernel filter, so it receives everything and filters in user space, as its users do.
- **End of a run:** the sender sends end-of-run frames after the measured traffic, because libpcap ignores its timeout in immediate mode.

## Reproduce

```sh
scripts/bench.sh --docker     # any host with Docker
scripts/bench.sh              # Linux with libpcap-dev; the harness runs with sudo
```

The harness is [`bench/`](https://github.com/hupe1980/rawether/tree/main/bench), a crate of its own that is not part of the published package.
