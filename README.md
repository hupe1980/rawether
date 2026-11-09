# rawether

[![CI](https://github.com/hupe1980/rawether/actions/workflows/ci.yml/badge.svg)](https://github.com/hupe1980/rawether/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/rawether.svg)](https://crates.io/crates/rawether)
[![docs.rs](https://img.shields.io/docsrs/rawether)](https://docs.rs/rawether)
[![Website](https://img.shields.io/badge/docs-website-2457d6)](https://hupe1980.github.io/rawether/)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

🔌 **Raw layer-2 Ethernet I/O for Rust.** Send and receive whole Ethernet frames on a named
interface, with the kernel features that make it fast and precise: a TPACKET_V3 receive ring,
hardware and software timestamps, in-kernel classic-BPF filters, batched and launch-time
(`SO_TXTIME`) transmission on Linux; BPF devices on macOS and FreeBSD. One small, safe API;
one dependency (`libc`).

For anything that lives below IP: PTP (0x88F7), LLDP (0x88CC), PRP/HSR, PROFINET, EtherCAT,
TSN streams, industrial process buses, custom test traffic.

```sh
cargo add rawether
```

```rust
use std::time::Duration;

use rawether::EtherType;

let mut sock = rawether::Config::new("eth0")
    .ethertypes([EtherType::LLDP, EtherType::PTP])   // VLAN-tagged or not
    .open()?;
rawether::drop_capabilities()?;            // CAP_NET_RAW is no longer needed

// Receive until a second passes without a frame.
while let Some(p) = sock.recv(Some(Duration::from_secs(1)))? {
    let Some(f) = p.frame() else { continue };    // too short for a header: skip, never panic
    println!("{} sent {} at {:?}", f.source(), f.ethertype(), p.timestamp());   // "… sent PTP (0x88f7) at …"
}
```

Sending is the other half: describe the header once and write frames into a buffer you reuse.

```rust
use rawether::{EtherType, FrameBuilder, MacAddr};

let mut buf = Vec::with_capacity(1518);
FrameBuilder::new(MacAddr::BROADCAST, sock.mac_address(), EtherType::LOCAL_EXPERIMENTAL_1)
    .write(&mut buf, b"hello, layer 2");                // header, payload, padded to 60 octets
sock.send(&buf)?;
```

📖 [Documentation](https://hupe1980.github.io/rawether/) ·
📚 [API reference](https://docs.rs/rawether) ·
🔐 [Threat model](THREAT_MODEL.md) ·
📐 [Design records](https://github.com/hupe1980/rawether/blob/main/specs/README.md) ·
📝 [Changelog](CHANGELOG.md) ·
🚨 [Report a vulnerability](SECURITY.md)

> 🚧 **Pre-1.0.** The API may change between minor versions.

## ✨ Features

- 🎯 **Filtered in the kernel.** A set of EtherTypes — untagged, 802.1Q, 802.1ad or double-tagged
  — compiles to classic BPF and is attached *before* the socket is bound, so no unwanted frame is
  ever queued. Or bring your own program; `bpf::Program::run` interprets it for tests.
- 🌀 **Zero-copy receive.** On Linux a TPACKET_V3 ring hands out frames borrowed from shared
  memory; a frame's borrow ends at the next receive, enforced by the compiler. Falls back to
  `recvmsg` when the kernel refuses the ring, and says which path it is on.
- ⏱️ **Timestamps that say whose they are.** Receive and transmit timestamps from the NIC or
  the kernel, each labelled; transmit timestamps matched to their frame by id, and the PTP
  hardware clock behind an interface. The NIC's stamping configuration is never lowered, so it
  is safe next to `ptp4l`.
- 🏷️ **VLAN tags as on the wire.** A tag the driver stripped into metadata is put back in place,
  using head-room the ring reserves.
- 🔤 **EtherTypes with names.** `EtherType::PTP`, `EtherType::GOOSE`, … for the well-known types,
  each checked against the IEEE registry; any other value works as `EtherType(0x88b5)`, and logs
  read `PTP (0x88f7)`.
- 🧩 **Frames without index arithmetic.** `p.frame()` names the addresses, up to two VLAN tags
  (PCP, DEI, VID), the EtherType and the payload, and never panics on a short frame.
  `FrameBuilder` writes frames into a reused buffer, padded to the minimum; `reply` answers one.
- 🚀 **Batched and timed send.** `sendmmsg` batches; `SO_TXTIME` launch times for `etf`/`taprio`;
  `SO_PRIORITY`; optional qdisc bypass.
- 📊 **Drops are counted.** `stats()` reports received and dropped frames, with one meaning on
  every platform; `tx_errors()` says why launch-time frames were dropped.
- 🔁 **Any event loop.** `AsFd`/`AsRawFd`, non-blocking mode, timed and blocking receive.
- 🛡️ **Least privilege.** Every descriptor is close-on-exec; `drop_capabilities()` sheds every
  capability for the whole process once the sockets are open, or refuses if another thread
  would keep one.
- 🧱 **No allocation in the steady state**, measured by a counting allocator.
- 📈 **Measured.** The ring receives 2.8 M frames/s without loss over veth, 1.6× libpcap; the
  plain path answers in 15 µs ([benchmarks](https://hupe1980.github.io/rawether/docs/performance/)).

## 🖥️ Platforms

| | Linux (AF_PACKET) | macOS, FreeBSD (BPF) |
|---|---|---|
| EtherType filter, tagged or not; custom classic BPF | ✓ in kernel | ✓ in kernel |
| Multicast membership · all-multicast · promiscuous | ✓ · ✓ · ✓ | ✓ · via promiscuous · ✓ |
| Receive | TPACKET_V3 ring, `recvmsg` fallback | read buffer |
| Timestamps | hardware or software, labelled | software |
| Stripped VLAN tags put back | ✓ | not needed |
| Batched send | `sendmmsg` | loop |
| Launch time (`SO_TXTIME`), `SO_PRIORITY`, qdisc bypass | ✓ | — |
| Drop counters | `PACKET_STATISTICS` | `BIOCGSTATS` |
| Privilege | `CAP_NET_RAW` (`drop_capabilities()` after opening) | access to `/dev/bpf*` |

Other platforms compile; `Socket::open` returns `ErrorKind::Unsupported`.

**Tested releases** — every lane runs on each push:

| Lane | What runs |
|---|---|
| `ubuntu-24.04` | unit tests; the veth suite on the ring and the plain path; the capability drop; clippy for Linux (glibc and musl), macOS, FreeBSD, Windows and 32-bit; MSRV, docs, cargo-deny |
| `macos-15`, `macos-26` | unit tests; the BPF suite on a `feth` pair, as an ordinary user |
| FreeBSD 14 (VM) | unit tests; the BPF suite on an `epair` |
| Miri, fuzz | the pure parsers under Miri; five fuzz targets, 60 s each |
| `windows-2025` | build; `open` returns `Unsupported` |

Linux ≥ 3.2 for the ring, ≥ 4.19 for `SO_TXTIME`. Rust ≥ 1.88.

## 🧪 Examples

```sh
cargo run --example sniff -- eth0 88cc     # print frames with timestamps
cargo run --example lldp  -- eth0          # announce over LLDP, list neighbours
cargo run --example echo  -- eth0 88b5     # reflect frames of one EtherType, in batches
cargo run --example txstamp -- eth0 10     # send frames, print when each one left
```

On Linux, grant the capability to the binary instead of running it as root:
`sudo setcap cap_net_raw+ep target/debug/examples/sniff`.

## 🔧 Develop

```sh
just ci                      # fmt, clippy (7 targets), tests, docs, cargo-deny, MSRV, package
just miri                     # the pure modules under Miri
just fuzz 60                  # every fuzz target for 60 s
scripts/veth-test.sh          # the kernel suite on a veth pair (Linux, sudo)
scripts/veth-test.sh --docker # the same from any host with Docker
just site                     # check and build the website (needs Zola)
```

The website's sources are in [`site/`](site); it is built with [Zola](https://www.getzola.org/)
and deployed to GitHub Pages from `main`.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
