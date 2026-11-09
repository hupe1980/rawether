# Changelog

All notable changes to rawether are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `Frame`: a panic-free view of a frame's Ethernet header (destination, source, up to two
  802.1Q/802.1ad tags, EtherType, payload), over any byte slice or through `Packet::frame()`.
  It steps over the same tags as the EtherType filter.
- `FrameBuilder`: writes destination, source, optional tags, EtherType and payload into a reused
  `Vec` (`write`) or a fixed slice (`write_into`), zero-padded to `frame::MIN_FRAME_LEN` (60).
- `Frame::reply`: the header of an answer to a received frame; `None` for a group source address.
- `VlanTag` and `TagKind`, with range-checked PCP and VID.
- The examples and guides read and build frames through these instead of index arithmetic.
- Threat model classes T-10 (replies to group addresses) and T-11 (stale bytes in reused
  buffers); T-03 covers the header view.

- The threat model is rendered on docs.rs as the `rawether::threat_model` module.
- A website with guides and the API overview: <https://hupe1980.github.io/rawether/>.

### Changed

- `drop_capabilities` documents that Linux capabilities are per thread.

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
