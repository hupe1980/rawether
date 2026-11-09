# Changelog

All notable changes to rawether are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/hupe1980/rawether/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hupe1980/rawether/releases/tag/v0.1.0
