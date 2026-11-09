# Changelog

All notable changes to rawether are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-09

### Added

- Transmit timestamps: `Config::tx_timestamping`, `Socket::next_tx_id`, `Socket::tx_timestamp`
  and `TxTimestamp`. Each frame's id is exact on Linux 6.13 and later (`SCM_TS_OPT_ID`); hardware
  transmit stamping follows the never-lower rule.
- `timestamp_info` and `Socket::timestamp_info`: what an interface stamps and its PTP hardware
  clock (`TimestampInfo::phc_path`), without privilege.
- `TxErrors::timestamps_lost`; example `txstamp`.
- The BPF suite runs on macOS 15, macOS 26 (`feth`) and FreeBSD 14 (`epair`) in CI.
- Published receive benchmarks against `pcap` and `pnet_datalink` (website, `scripts/bench.sh`).
- `EtherType`: a typed EtherType with names for 21 well-known types (IEEE registry), `Display`
  as `PTP (0x88f7)`, and `is_length()`.

### Changed

- `TxErrors::total` is now `TxErrors::dropped` (launch-time drops only).
- EtherTypes are typed: `Config::ethertypes` and `bpf::Program::ethertypes` take names, numbers
  or both (`[EtherType::PTP]`, `&[0x88b5u16]`); `Frame::ethertype` returns `EtherType`;
  `FrameBuilder::new` takes one.

### Fixed

- Builds for musl targets (an ioctl request is now cast to the libc's own type); CI lints
  `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`.

## [0.1.0] - 2026-11-09

First release. (0.0.1 reserved the name and contains no code.)

### Added

- `Socket` over one named interface: `recv` (blocking, timed, non-blocking), `try_recv`, `send`,
  `send_batch`, `send_at`, `stats`, `tx_errors`, `timestamping`, `set_nonblocking`,
  `AsFd`/`AsRawFd`.
- `Config`: EtherType filters (untagged, 802.1Q, 802.1ad, double-tagged), custom classic-BPF
  filters, multicast membership, all-multicast, promiscuous mode, receive mode, timestamping,
  `SO_PRIORITY`, `SO_TXTIME`, qdisc bypass, VLAN restoration, own-traffic suppression.
- Linux backend: AF_PACKET with a TPACKET_V3 receive ring and a `recvmsg` fallback, the filter
  attached before bind, hardware and software timestamps, `sendmmsg`, `SO_TXTIME` with
  error-queue reporting, `PACKET_STATISTICS`.
- macOS and FreeBSD backend: BPF devices with in-kernel filters, multicast membership and
  software timestamps.
- `Packet` with captured and wire length, the timestamp and its source (`Hardware`, `Software`,
  `User`), and whether a stripped VLAN tag was put back.
- `Frame`: a panic-free view of a frame's Ethernet header (addresses, up to two VLAN tags,
  EtherType, payload), over any byte slice or through `Packet::frame()`. `FrameBuilder` writes
  frames into a reused `Vec` or a fixed slice, zero-padded to 60 octets; `Frame::reply` answers
  a frame. `VlanTag` and `TagKind` with range-checked fields.
- `TxErrors`: launch-time drops by reason (missed deadline, invalid parameters).
- `bpf::Program`: an EtherType filter builder, a validator matching the kernel's checks, and an
  interpreter.
- `drop_capabilities()` and `clock_now()`.
- Examples `sniff`, `lldp`, `echo`; a veth-pair test suite on both receive paths; Miri, fuzzing
  and a FreeBSD lane in CI.
- The threat model, rendered on docs.rs as `rawether::threat_model`, and a website with guides:
  <https://hupe1980.github.io/rawether/>.

### Security

- `drop_capabilities()` holds for the whole process: it clears the ambient and bounding sets as
  well, and refuses while another thread still holds a capability.
- Hardware timestamping never lowers the NIC's device-wide configuration, so it is safe next to
  `ptp4l`.
- A receive returns the socket's error when the link goes down or the interface disappears,
  instead of spinning.

[Unreleased]: https://github.com/hupe1980/rawether/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/hupe1980/rawether/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/hupe1980/rawether/releases/tag/v0.1.0
