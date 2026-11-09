# rawether

[![CI](https://github.com/hupe1980/rawether/actions/workflows/ci.yml/badge.svg)](https://github.com/hupe1980/rawether/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/rawether.svg)](https://crates.io/crates/rawether)
[![docs.rs](https://img.shields.io/docsrs/rawether)](https://docs.rs/rawether)
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

let mut sock = rawether::Config::new("eth0")
    .ethertypes(&[0x88cc, 0x88f7])        // LLDP and PTP, VLAN-tagged or not
    .open()?;
rawether::drop_capabilities()?;            // CAP_NET_RAW is no longer needed

while let Some(p) = sock.recv(Some(Duration::from_secs(1)))? {
    println!("{} octets, {:?}", p.data().len(), p.timestamp());
}
```

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
- ⏱️ **Timestamps that say whose they are.** Hardware (where the NIC has them), kernel software,
  or — for the frames before the kernel's lazily enabled stamping kicks in — rawether's own read,
  each labelled.
- 🏷️ **VLAN tags as on the wire.** A tag the driver stripped into metadata is put back in place,
  using head-room the ring reserves.
- 🚀 **Batched and timed send.** `sendmmsg` batches; `SO_TXTIME` launch times for `etf`/`taprio`;
  `SO_PRIORITY`; optional qdisc bypass.
- 📊 **Drops are counted.** `stats()` accumulates the kernel's received and dropped counters.
- 🔁 **Any event loop.** `AsFd`/`AsRawFd`, non-blocking mode, timed and blocking receive.
- 🛡️ **Least privilege.** Every descriptor is close-on-exec; `drop_capabilities()` sheds
  `CAP_NET_RAW` once the sockets are open.
- 🧱 **No allocation in the steady state**, measured by a counting allocator.

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
| `ubuntu-24.04` | unit tests, the veth suite on the ring and the plain path, MSRV, docs, cargo-deny |
| `macos-15` | unit tests, including opening a BPF device |
| `windows-2025` | build; `open` returns `Unsupported` |

Linux ≥ 3.2 for the ring, ≥ 4.19 for `SO_TXTIME`. Rust ≥ 1.88.

## 🧪 Examples

```sh
cargo run --example sniff -- eth0 88cc     # print frames with timestamps
cargo run --example lldp  -- eth0          # announce over LLDP, list neighbours
cargo run --example echo  -- eth0 88b5     # reflect frames of one EtherType, in batches
```

On Linux, grant the capability to the binary instead of running it as root:
`sudo setcap cap_net_raw+ep target/debug/examples/sniff`.

## 🔧 Develop

```sh
just ci                      # fmt, clippy, tests, docs, cargo-deny, MSRV, package
scripts/veth-test.sh          # the kernel suite on a veth pair (Linux, sudo)
scripts/veth-test.sh --docker # the same from any host with Docker
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
