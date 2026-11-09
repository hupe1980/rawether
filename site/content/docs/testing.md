+++
title = "Testing"
description = "How rawether is tested: unit tests for the ring parser, VLAN re-insertion and BPF interpreter, a kernel suite on a real veth pair on both receive paths, a counting allocator for the steady state, and CI on Linux, macOS and Windows. How to run it yourself."
weight = 120

[extra]
group = "Security"
+++

Documentation describes what the kernel should do. rawether's claims about kernel behaviour are backed by tests against a real kernel, and every [threat model](@/docs/threat-model.md) class names the test that guards it.

## Layers

| Layer | What it checks | Where it runs |
|---|---|---|
| Unit tests | The ring walker on hand-made blocks (including corrupt ones), VLAN re-insertion over every small input, the BPF validator and interpreter, configuration checks, MAC parsing | Every platform, no privileges |
| Compile-fail doc test | A `Packet` cannot outlive the next `recv` | Every platform |
| veth suite (`tests/veth.rs`) | Filtering of tagged and untagged frames, timestamps, truncation, 100 000-frame floods received or counted as dropped, sparse traffic kept in the ring, launch times through `etf` and without it, explicit ring errors, close-on-exec | Linux, on a veth pair, once on the ring and once on the plain path |
| Allocation test | The steady-state receive loop makes zero allocations, counted by a global allocator | Linux, both paths |
| Capability drop (`tests/drop_capabilities.rs`) | Refusal while a second thread exists; afterwards every thread's sets are empty, the bounding set lost the network capabilities, the socket still works | Linux, as its own single-threaded program |
| Link loss | Link down and interface deletion end a waiting receive within 100 ms on both paths; frames return after link up | Linux, on private veth pairs |
| Miri | The pure modules (ring walk, VLAN re-insertion, BPF, frame view, BPF records, the hardware-timestamp decision) run without undefined behaviour | CI |
| Fuzzing | `frame_view`, `bpf_program`, `ring_walk`, `bpf_record`, `vlan_reinsert`, 60 s each | CI |
| BPF suite (`tests/bpf.rs`) | Filtering of tagged and untagged frames, timestamps, own frames hidden, 1 000 frames received or counted, truncation, timeouts, multicast membership without root | macOS 15 and 26 (`feth`, as a user), FreeBSD 14 (`epair`) |
| Benchmarks (`bench/`) | Receive throughput and latency against `pcap` and `pnet_datalink`: see [Performance](@/docs/performance.md) | On demand, `scripts/bench.sh --docker` |
| BPF record layouts | macOS and FreeBSD records, malformed and truncated ones, against the platform's own header | everywhere; FreeBSD in a VM |

## Running it

```sh
cargo test                       # unit tests, any platform
scripts/veth-test.sh             # the kernel suite, Linux, with sudo
scripts/veth-test.sh --docker    # the same in a Linux container, from any host
scripts/bpf-test.sh              # the BPF suite on macOS (sudo for the pair) or FreeBSD (root)
just ci                          # every local gate: fmt, clippy (7 targets), tests, docs, deny, MSRV, package
just miri                        # the pure modules under Miri
just fuzz 60                     # every fuzz target for 60 s
```

`veth-test.sh` creates the pair `rawether0`/`rawether1`, builds the test binary as you, and runs only that binary with privileges. The launch-time half of the suite runs only where the kernel has the `etf` qdisc (`sch_etf`); Docker Desktop's kernel does not, GitHub's Ubuntu runners do.

## Testing your own code

- **Filters:** `bpf::Program::run` interprets a program like the kernel. Unit-test your filters on byte arrays, without a socket. See [Filtering frames](@/docs/filtering.md#testing-a-filter-without-a-kernel).
- **Protocol logic:** write your handlers against `&[u8]`, not against `Packet`, and feed them frames from tests.
- **End to end:** a veth pair is two interfaces joined by a virtual cable. Send on one end and receive on the other, as rawether's own suite does:

```sh
sudo ip link add rawether0 type veth peer name rawether1
sudo ip link set rawether0 up && sudo ip link set rawether1 up
```

## Continuous integration

Every push runs:

| Lane | What runs |
|---|---|
| `ubuntu-24.04` | Unit tests, the veth suite on both receive paths, the capability drop, the gates (fmt, clippy for Linux (glibc and musl), macOS, FreeBSD, Windows and 32-bit Linux, docs, cargo-deny, MSRV, package, workflow hygiene) |
| FreeBSD 14 (VM) | Unit tests and the BPF suite on an `epair` |
| Miri, fuzz | The pure modules under Miri; every fuzz target for 60 s |
| `macos-15`, `macos-26` | Unit tests and the BPF suite on a `feth` pair |
| `windows-2025` | Build and tests; `open` returns `Unsupported` |
