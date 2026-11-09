# Feature Specification: Low-latency frame ring

**Feature Branch**: `016-low-latency-ring` (directory identity; no git branch)
**Created**: 2026-11-09
**Status**: Draft
**Input**: Maintainer, after record 006's numbers: "do it before tagging". The TPACKET_V3 ring
receives 2.8 M frames/s without loss but hands a lone frame over only when its block retires
(p50 550 µs); the plain path answers in 15 µs but loses half the frames at full rate; libpcap's
immediate mode does both (1.8 M/s, 15 µs) with a per-frame TPACKET_V2 ring. rawether should
match or beat that in one mode.

## User Scenarios & Testing

### User Story 1 - Low latency and no loss in one mode (Priority: P1)

A developer with a tight time budget (GOOSE, PTP) chooses `RxMode::low_latency()` and gets
every frame within tens of microseconds, also when traffic bursts.

**Why this priority**: the whole feature.

**Independent Test**: the benchmark: throughput within 10 % of libpcap's or better with no loss,
and median latency within a few microseconds of the plain path.

**Acceptance Scenarios**:

1. **Given** the benchmark, **When** the frame ring is measured, **Then** it receives every frame
   of the flood and its median latency is at most 25 µs.
2. **Given** `rx_path()`, **When** a frame ring is in use, **Then** it reports `FrameRing`.

### User Story 2 - Everything else works the same (Priority: P1)

Filters, timestamps (software and hardware), VLAN restoration, truncation, drop counters,
own-frame suppression, timeouts, link loss and zero allocation behave on the frame ring exactly
as on the other paths.

**Why this priority**: a third path must not be a second-class one.

**Independent Test**: the whole veth suite runs on the frame ring as on the ring and plain paths.

**Acceptance Scenarios**:

1. **Given** `RAWETHER_RX=frame`, **When** the veth suite runs, **Then** every test passes.

### User Story 3 - Hostile slot metadata is harmless (Priority: P1)

The frame ring reads kernel-written slot headers; any inconsistent offset or length is skipped,
never trusted, as for the block ring (T-01).

**Why this priority**: memory safety.

**Independent Test**: unit tests over synthetic slots, Miri, fuzzing.

**Acceptance Scenarios**:

1. **Given** a slot whose `tp_mac` or `tp_snaplen` points outside the slot, **When** it is read,
   **Then** no frame is formed and the slot is returned to the kernel.

### Edge Cases

- A frame larger than a slot is captured short and flagged truncated; the slot size is
  configurable for jumbo frames.
- A full ring: the kernel drops and counts (`stats().dropped`).
- A kernel that refuses the ring: an explicit request fails `open` with the reason.
- macOS and FreeBSD have no rings: the BPF path is used, as for `RxMode::Ring`.

## Requirements

### Functional Requirements

- **FR-001**: rawether MUST offer a per-frame (TPACKET_V2) receive ring with configurable slot
  size and count, and a `low_latency()` shorthand with defaults fitting 1 500-octet frames.
- **FR-002**: The frame ring MUST hand out frames zero-copy, borrowed until the next receive.
- **FR-003**: Every slot header MUST be bounds-checked before a slice is formed; an inconsistent
  slot is skipped and returned to the kernel.
- **FR-004**: All receive features (filters, timestamps, VLAN restoration, truncation, counters,
  own-frame suppression, link loss) MUST work on it.
- **FR-005**: An explicit frame ring the kernel refuses MUST fail `open`.
- **FR-006**: The benchmark, documentation and README MUST include it.

### Key Entities

- **Frame ring geometry**: slot size, slot count.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P2): The frame-ring walker MUST NOT form a slice outside the slot, and MUST NOT read a slot whose status lacks TP_STATUS_USER.
  - Mitigates: `threat.slot-offsets-out-of-bounds` via `mitigation.checked-slot-walk`
  - Given synthetic slots with tp_mac below the header, tp_mac or tp_snaplen past the slot, and a kernel-owned status, when they are read, then no frame is formed
  - Given random slots, when fuzzed and run under Miri, then no panic, no out-of-bounds access
- **SR-002** (P2): Every frame-ring slot the reader takes MUST be returned to the kernel by the next receive, whether it was delivered or skipped.
  - Mitigates: `threat.slot-never-released` via `mitigation.release-every-slot`
  - Given the veth suite on the frame ring (100 000-frame flood, sparse frames, malformed-free traffic), when it runs, then received plus dropped equals sent and later frames keep arriving
<!-- threatspec:end -->

## Success Criteria

### Measurable Outcomes

- **SC-001**: Frame ring: 100 % of the flood received; throughput ≥ libpcap's on the same run;
  median latency ≤ 25 µs.
- **SC-002**: The veth suite passes on all three Linux paths.
- **SC-003**: No allocation in the steady state on the frame ring.

## Assumptions

- Default geometry: 4 096 slots of 2 048 octets (8 MiB), enough for 1 500-octet frames with
  their headers.
