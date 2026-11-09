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
| veth suite (`tests/veth.rs`) | Filtering of tagged and untagged frames, timestamps, truncation, 100 000-frame floods received or counted as dropped, sparse traffic kept in the ring, launch times through `etf`, close-on-exec, dropping capabilities | Linux, on a veth pair, once on the ring and once on the plain path |
| Allocation test | The steady-state receive loop makes zero allocations, counted by a global allocator | Linux, both paths |
| BPF device test | A BPF device opens on the loopback interface, or the error names the missing access | macOS |

## Running it

```sh
cargo test                       # unit tests, any platform
scripts/veth-test.sh             # the kernel suite, Linux, with sudo
scripts/veth-test.sh --docker    # the same in a Linux container, from any host
just ci                          # every local gate: fmt, clippy, tests, docs, deny, MSRV, package
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
| `ubuntu-24.04` | Unit tests, the veth suite on both receive paths, the gates (fmt, clippy for Linux, macOS and Windows targets, docs, cargo-deny, MSRV, package, workflow hygiene) |
| `macos-15` | Unit tests, including opening a BPF device |
| `windows-2025` | Build and tests; `open` returns `Unsupported` |
