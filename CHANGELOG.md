# Changelog

All notable changes to rawether are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-09

First release. (0.0.1 reserved the name and contains no code.)

### Added

- `Socket` over one named interface: `recv` (blocking, timed, non-blocking), `try_recv`, `send`,
  `send_batch`, `send_at`, `stats`, `tx_errors`, `set_nonblocking`, `AsFd`/`AsRawFd`.
- `Config`: EtherType filters (untagged, 802.1Q, 802.1ad, double-tagged), custom classic-BPF
  filters, multicast membership, all-multicast, promiscuous mode, receive mode, timestamping,
  `SO_PRIORITY`, `SO_TXTIME`, qdisc bypass, VLAN restoration, own-traffic suppression.
- Linux backend: AF_PACKET with a TPACKET_V3 receive ring and a `recvmsg` fallback, filter attached
  before bind, hardware and software timestamps, `sendmmsg`, `SO_TXTIME` with error-queue
  reporting, `PACKET_STATISTICS`.
- macOS and FreeBSD backend: BPF devices with in-kernel filters, multicast membership and software
  timestamps.
- `Packet` with captured and wire length, the timestamp and its source (`Hardware`, `Software`,
  `User`), and whether a stripped VLAN tag was put back.
- `bpf::Program`: an EtherType filter builder, a validator matching the kernel's checks, and an
  interpreter.
- `drop_capabilities()` and `clock_now()`.
- Examples: `sniff`, `lldp`, `echo`. A veth-pair test suite run on both receive paths.

[Unreleased]: https://github.com/hupe1980/rawether/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hupe1980/rawether/releases/tag/v0.1.0
