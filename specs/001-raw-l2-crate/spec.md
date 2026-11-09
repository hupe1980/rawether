# Feature Specification: rawether 0.1.0 — raw layer-2 Ethernet I/O

**Feature Branch**: `001-raw-l2-crate` (directory identity; no git branch)
**Created**: 2026-11-09
**Status**: Clarified
**Input**: Maintainer brief: a generic, best-in-class raw L2 crate usable for PTP (0x88F7),
PRP/HSR, LLDP (0x88CC), PROFINET, TSN and industrial protocols; first consumer is
`iec61850-rs`'s `net` feature. crates.io holds a 0.0.1 placeholder; this is 0.1.0.

## Clarifications

### Session 2026-11-09

- Q: Which platforms, at what depth? → A: Linux (AF_PACKET) is the reference with every
  feature; macOS/FreeBSD (BPF) support open, filter, multicast, promiscuous, send, batched send
  (a loop), receive with software timestamps and timeouts; launch time returns `Unsupported`
  there, and a request for hardware timestamps falls back to software ones, labelled so; Windows and others: `Socket::open` returns `Unsupported`.
- Q: How is a received frame handed out? → A: Borrowed from the ring (or the socket's own
  buffer) as `Packet<'_>`; the next `recv` releases it. No copy, no allocation.
- Q: What if the driver strips the VLAN tag? → A: It is re-inserted by default (configurable),
  so the caller sees the frame as it was on the wire; `Packet::vlan_restored()` says so.
- Q: Is a TX ring (PACKET_TX_RING) in scope? → A: No — `sendmmsg` batching covers throughput and
  keeps per-frame launch times; revisit if a benchmark asks for it.
- Q: Minimum Rust and kernel? → A: Rust 1.88 (edition 2024 with let-chains; 1.85 was planned and
  measured to fail); Linux ≥ 3.2 for TPACKET_V3 (older kernels fall back to plain receive),
  ≥ 4.19 for `SO_TXTIME`.

## User Scenarios & Testing

### User Story 1 - Send and receive frames of chosen EtherTypes (Priority: P1)

A developer opens a socket on `eth0` for EtherTypes {0x88CC} (LLDP), sends a frame and receives
frames of that type only — VLAN-tagged or not — each with a timestamp.

**Why this priority**: the whole crate; everything else refines it.

**Independent Test**: on a veth pair, frames sent on one end with EtherType X arrive on the
other; frames of EtherType Y do not.

**Acceptance Scenarios**:

1. **Given** a socket filtered to {X}, **When** frames of X and Y arrive, **Then** only X is
   delivered, with `timestamp()` set.
2. **Given** no `CAP_NET_RAW`, **When** `Socket::open` runs, **Then** it returns
   `PermissionDenied` whose message names `CAP_NET_RAW`.
3. **Given** a timeout of 50 ms and no traffic, **When** `recv` runs, **Then** it returns
   `Ok(None)` after ≈50 ms.

### User Story 2 - Precise and fast I/O (Priority: P1)

A TSN or industrial developer needs the kernel's best paths: a TPACKET_V3 receive ring,
hardware timestamps where the NIC has them, batched send, launch-time (`SO_TXTIME`) send, socket
priority, qdisc bypass, and drop counters.

**Why this priority**: it is what separates this crate from a plain raw socket.

**Independent Test**: on a veth pair, 100 000 frames sent in batches arrive on the ring path and
on the forced plain path with no loss (or with the loss counted); a launch-time send succeeds
when an `etf` qdisc is installed and reports an error when it is not.

**Acceptance Scenarios**:

1. **Given** `RxMode::Auto`, **When** the ring can be set up, **Then** `rx_path()` is `Ring`;
   **When** it cannot, **Then** `Plain` and receive still works.
2. **Given** `Timestamping::Hardware` on a NIC without support, **When** frames arrive, **Then**
   they carry software timestamps labelled `Software`.

### User Story 3 - Fits any event loop and any filter (Priority: P2)

A developer integrates the socket with `mio`/`tokio` (`AsFd`, non-blocking) and installs a custom
classic-BPF program (e.g. "LLDP from one source MAC only").

**Why this priority**: integration breadth; not needed for the first consumer's blocking loop.

**Independent Test**: a non-blocking socket returns `Ok(None)` immediately when idle and becomes
readable in `poll(2)` when a frame arrives; a user BPF program filters as written.

### Edge Cases

- A frame captured short — a filter returning a smaller snap length, or a frame larger than a
  ring block — is truncated: `Packet::original_len()` reports the wire length and
  `data().len()` the captured length, on the ring and on the plain path alike. (TPACKET_V3 does
  not cut frames at its slot size; that was measured on 2026-11-09 and corrected here.)
- Multicast membership on an interface that is down or missing: an error naming the interface.
- An interface name that does not exist: `NotFound` naming it.
- The ring is full: the kernel drops; `stats()` counts it.
- A frame shorter than 14 octets on send: `InvalidInput`.

## Requirements

### Functional Requirements

- **FR-001**: `Socket::open(&Config)` MUST bind to one named interface and filter by a set of
  EtherTypes (tagged with 802.1Q/802.1ad or not), a caller's classic-BPF program, or nothing.
- **FR-002**: It MUST join arbitrary multicast MACs, or all multicast, or go promiscuous.
- **FR-003**: Receive MUST use a TPACKET_V3 ring on Linux by default and fall back to
  `recvmsg`; it MUST support blocking, timed and non-blocking receive and expose the fd.
- **FR-004**: Each packet MUST carry its captured data, wire length, timestamp with source
  (hardware/software) when available, and whether a stripped VLAN tag was re-inserted.
- **FR-005**: Send MUST offer single, batched (`sendmmsg` on Linux) and launch-time
  (`SO_TXTIME`) transmission, socket priority and optional qdisc bypass.
- **FR-006**: `stats()` MUST report packets received and dropped by the kernel.
- **FR-007**: `mac_address()`/`index()` MUST report the interface's hardware address and index.
- **FR-008**: The crate MUST contain no protocol-specific API (constitution I) and expose a
  classic-BPF builder for EtherType sets plus an interpreter to test programs.
- **FR-009**: `unsafe` MUST be confined to backend modules with `// SAFETY:` comments.

### Key Entities

`Config`, `Socket`, `Packet<'_>`, `Timestamp`, `TimestampSource`, `RxMode`, `RxPath`,
`Timestamping`, `TxTime`, `Clock`, `Filter`, `bpf::Insn`, `bpf::Program`, `MacAddr`, `Stats`.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): The ring walker MUST NOT form a slice outside the block, and MUST NOT read a block whose status lacks TP_STATUS_USER.
  - Mitigates: `threat.ring-offsets-out-of-bounds` via `mitigation.checked-ring-walk`
  - Given a synthetic block whose frame claims data beyond the block, when it is walked, then the walk ends and the rest of the block is skipped
  - Given a block owned by the kernel, when the walker starts, then it reads nothing
- **SR-002** (P1): A received Packet MUST borrow the Socket so that no further receive, and no block release, can happen while it is alive.
  - Mitigates: `threat.packet-outlives-block` via `mitigation.borrowed-packets`
  - Given a Packet from recv, when the caller calls recv again while holding it, then the program does not compile (compile-fail doc test)
- **SR-003** (P1): VLAN re-insertion and length reporting MUST be total over every input: no panic, captured length never above wire length, truncation flagged.
  - Mitigates: `threat.hostile-frame-shape` via `mitigation.bounded-frame-handling`
  - Given any buffer, start, length and tag, when re-insertion runs, then it either succeeds inside the buffer or leaves it untouched, never panicking (property test)
- **SR-004** (P2): The Linux backend MUST attach the filter before binding, and Program::new MUST reject what the kernel rejects (empty, too long, jumps past the end, bad scratch slot, no final return).
  - Mitigates: `threat.unfiltered-window` via `mitigation.filter-before-bind`
  - Given a filtered socket on a busy veth, when the first frames are received, then none of another EtherType appears
  - Given an invalid program, when Program::new runs, then it returns InvalidInput
- **SR-005** (P1): rawether MUST offer drop_capabilities() that leaves the process with no effective or permitted capabilities while open sockets keep receiving and sending.
  - Mitigates: `threat.capability-retained` via `mitigation.drop-capabilities`
  - Given a socket opened with CAP_NET_RAW, when drop_capabilities() returns, then CapEff and CapPrm are zero and the socket still sends and receives
- **SR-006** (P1): Every descriptor rawether opens MUST be close-on-exec.
  - Mitigates: `threat.fd-inherited-by-child` via `mitigation.close-on-exec`
  - Given an open socket, when its descriptor flags are read, then FD_CLOEXEC is set
- **SR-007** (P2): A default Config MUST NOT enable promiscuous or all-multicast mode.
  - Mitigates: `threat.promiscuous-disclosure` via `mitigation.explicit-promiscuity`
  - Given Config::new(iface), when it is inspected, then promiscuous and all-multicast are false
- **SR-008** (P2): stats() MUST report kernel drops so that received plus dropped equals what passed the filter.
  - Mitigates: `threat.ring-exhaustion` via `mitigation.bounded-buffers-and-counted-drops`
  - Given 100 000 frames sent over veth, when stats() is read after receiving, then received plus dropped equals the frames sent
- **SR-009** (P2): send_at MUST fail with InvalidInput unless Config::tx_time was set, and tx_errors() MUST count frames the kernel reported dropped.
  - Mitigates: `threat.launch-time-abuse` via `mitigation.txtime-opt-in-and-reported`
  - Given a socket without tx_time, when send_at is called, then it returns InvalidInput
  - Given a socket with tx_time on an interface without an etf qdisc, when a frame is sent with a launch time, then tx_errors() counts it or the send fails
<!-- threatspec:end -->

## Success Criteria

### Measurable Outcomes

- **SC-001**: The veth suite passes on Linux on the ring and on the plain path: EtherType
  filtering (tagged and untagged), multicast membership, timestamps on every frame, timeouts,
  non-blocking, batched send.
- **SC-002**: 100 000 frames over veth: received + dropped = sent, on both paths.
- **SC-003**: Zero allocations across a steady-state send/receive loop (counting allocator).
- **SC-004**: macOS: builds, unit tests pass, `open` on `lo0` either works (with BPF access) or
  fails with `PermissionDenied`; a Windows target builds and `open` returns `Unsupported`.
- **SC-005**: `cargo publish --dry-run` is clean; docs build with `-D warnings`; MSRV 1.85
  builds; examples build.

## Assumptions

- CI Linux runners have sudo (network namespaces and veth pairs); local testing uses Docker.
- Hardware timestamps cannot be tested on veth; the code path is exercised up to the driver's
  refusal, which must fall back.
