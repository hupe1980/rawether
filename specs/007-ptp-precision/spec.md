# Feature Specification: PTP precision — transmit timestamps and clock discovery

**Feature Branch**: `007-ptp-precision` (directory identity; no git branch)
**Created**: 2026-11-09
**Status**: Draft
**Input**: Maintainer brief for 0.2.0, "precision, proven": rawether timestamps received frames
only. Protocols that measure time on the wire — PTP clocks (Sync, Delay_Req), IEC 61850 Sampled
Values publishers checking their send jitter, latency measurements — need when each frame
*left*, and which hardware clock stamped it so the value can be related to the PTP clock
`ptp4l` disciplines. Add transmit timestamps that identify their frame exactly, and discovery
of an interface's timestamping capabilities and PTP hardware clock. Breaking changes are
allowed; nothing may disturb other programs on the host (threat model T-12).

## User Scenarios & Testing

### User Story 1 - Know when each frame left (Priority: P1)

A developer enables transmit timestamping on a socket. Every frame sent through it gets an
identifier, and the socket later hands back `(identifier, timestamp)` pairs: from the NIC's
clock where it stamps transmitted frames, otherwise from the kernel's clock as the frame
reaches the driver, each labelled with its source.

**Why this priority**: the reason for the feature; PTP and SV need it.

**Independent Test**: on a veth pair (software transmit stamps), send a burst of frames and
read one timestamp per frame, with the identifiers the sends were given, in order, each close
to the send time.

**Acceptance Scenarios**:

1. **Given** a socket with software transmit timestamping, **When** 100 frames are sent (single
   and batched), **Then** 100 timestamps arrive whose identifiers are exactly those of the
   frames, each labelled `Software`, not earlier than the send call.
2. **Given** a socket asking for hardware transmit timestamps on a NIC without them, **When** it
   opens, **Then** it delivers software transmit timestamps and says so.
3. **Given** a send that the kernel refuses, **When** the next frame is sent, **Then** its
   identifier is still the one the socket announced for it (no drift on Linux 6.13 and later).
4. **Given** no timestamp waiting, **When** the developer waits with a timeout, **Then** the call
   returns nothing after the timeout, and immediately on a non-blocking socket.

### User Story 2 - Know which clock stamps an interface (Priority: P1)

A developer asks rawether, without any privilege, what an interface can timestamp (hardware
and software, receive and transmit) and which PTP hardware clock (`/dev/ptpN`) its hardware
stamps come from, so they can compare stamps with the clock `ptp4l`/`phc2sys` discipline.

**Why this priority**: a hardware timestamp is meaningless without its clock.

**Independent Test**: query a veth interface (software only, no hardware clock) and a missing
interface; on macOS and FreeBSD, a loopback interface.

**Acceptance Scenarios**:

1. **Given** a veth interface, **When** its capabilities are queried, **Then** software receive
   and transmit stamping are reported, hardware is not, and there is no hardware clock.
2. **Given** an interface name that does not exist, **When** it is queried, **Then** the error
   names it.
3. **Given** a NIC with a hardware clock, **When** it is queried, **Then** the clock's index is
   reported, and the path `/dev/ptpN` can be derived from it.

### User Story 3 - Hardware transmit stamps without disturbing the host (Priority: P2)

A developer on a station where `ptp4l` already runs asks for hardware transmit stamps. rawether
uses the NIC's configuration as it is when transmit stamping is already on, and only turns it
on (never off, never to a one-step mode) when it is off and the process may configure the NIC.

**Why this priority**: 0.1.0 promised never to lower the NIC's configuration (T-12); transmit
stamping must keep that promise.

**Independent Test**: the configuration decision, exhaustively over every transmit mode and
receive filter, with and without transmit stamping requested.

**Acceptance Scenarios**:

1. **Given** transmit stamping already on (or a one-step mode), **When** hardware transmit stamps
   are requested, **Then** the configuration is unchanged.
2. **Given** transmit stamping off, **When** hardware transmit stamps are requested, **Then** only
   the transmit mode is raised to on; the receive filter follows the existing rule.

### User Story 4 - Timestamps, launch-time reports and receiving work together (Priority: P2)

Transmit timestamps share the kernel's error queue with launch-time drop reports. Reading one
never loses the other; a receive never spins while timestamps wait unread; unread timestamps
are bounded and the number lost is reported.

**Why this priority**: the socket must stay correct when every feature is on.

**Independent Test**: a socket with launch times and transmit timestamps through `etf`: refused
launch times are counted, timestamps of the frames that left arrive, and receiving in between
neither blocks forever nor spins.

**Acceptance Scenarios**:

1. **Given** transmit timestamps waiting unread, **When** the developer waits to receive,
   **Then** the wait ends only on a frame, an error or the timeout.
2. **Given** more unread timestamps than the socket keeps, **When** more arrive, **Then** the
   oldest are dropped and the count of lost timestamps says how many.

### User Story 5 - Documented and shown (Priority: P3)

The README, the website and the rustdoc explain transmit timestamps, identifiers, clocks and
their limits, with an example.

**Why this priority**: follows from stories 1–4.

**Independent Test**: the site builds with its link checker; every snippet compiles.

**Acceptance Scenarios**:

1. **Given** the documentation, **When** a reader looks up transmit timestamps or hardware
   clocks, **Then** they find how to enable, read and relate them, and what the platform limits
   are.

### Edge Cases

- **Kernels before 6.13** cannot take an identifier per frame: the kernel numbers frames itself.
  rawether follows that numbering; a send the kernel refuses after numbering it (a qdisc drop)
  shifts later identifiers by one. Documented; detected automatically, not by version number.
- **Identifier wrap**: identifiers are 32-bit and wrap.
- **macOS and FreeBSD** have no transmit timestamps: asking for them makes `open` fail with
  `Unsupported`. Capability discovery there reports software receive stamps and no clock.
- **One-step PTP modes** (the NIC inserts the time into the frame): left as they are; transmit
  reports for non-PTP frames depend on the driver.
- **Frames never sent** (dropped by the qdisc) produce no timestamp; the launch-time report
  counts them where launch times are used.

## Requirements

### Functional Requirements

- **FR-001**: A socket MUST offer transmit timestamping (off, software, hardware), off by default.
- **FR-002**: Every frame sent on a timestamping socket MUST carry an identifier the socket
  announces before the send; single, batched and launch-time sends alike.
- **FR-003**: The socket MUST hand back each transmit timestamp with its frame's identifier and
  its source (hardware or software), waiting at most a given timeout.
- **FR-004**: On Linux 6.13 and later, identifiers MUST be exact even after failed sends; on
  older kernels the documented kernel numbering applies.
- **FR-005**: Hardware transmit stamping MUST follow the read-first, never-lower rule: transmit
  stamping is turned on only from off, and only when the configuration could be read.
- **FR-006**: The socket MUST report the transmit timestamping it delivers.
- **FR-007**: rawether MUST report, without privilege and without opening a raw socket, an
  interface's timestamping capabilities and its PTP hardware clock index, if any.
- **FR-008**: Transmit timestamps and launch-time reports MUST be read from the shared error
  queue without losing either; a receive MUST NOT spin while reports wait.
- **FR-009**: Unread transmit timestamps MUST be bounded inside rawether; drops MUST be counted.
- **FR-010**: Requesting transmit timestamps on a platform without them MUST fail with
  `Unsupported`.
- **FR-011**: The steady state (send, then read the timestamp) MUST NOT allocate.
- **FR-012**: README, website and rustdoc MUST document FR-001–FR-010.

### Key Entities

- **Transmit timestamp**: a frame identifier and a timestamp with its source.
- **Timestamping capabilities**: software/hardware × receive/transmit, raw hardware clock, PTP
  hardware clock index.
- **Frame identifier**: a 32-bit per-socket sequence assigned at send.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): Every transmit timestamp MUST carry the identifier the socket announced for its frame, also after a send the kernel refused (Linux 6.13 and later).
  - Mitigates: `threat.tx-timestamp-misattributed` via `mitigation.explicit-ids`
  - Given 1 000 frames sent in single and batched sends with software transmit timestamps on veth, when the timestamps are read, then their identifiers are exactly the announced ones
  - Given a send refused by an etf qdisc (past launch time), when 10 more frames are sent, then their timestamps carry the identifiers announced for them
- **SR-002** (P1): Requesting hardware transmit timestamps MUST NOT change a NIC whose configuration could not be read, MUST raise tx_type only from OFF to ON, and MUST leave every other tx_type and the receive filter rule of 0.1.0 unchanged.
  - Mitigates: `threat.nic-tx-config-lowered` via `mitigation.tx-read-first-never-lower`
  - Given every tx_type 0..=3, rx_filter 0..=15, and receive/transmit requests, when the decision runs, then a write raises tx_type only from OFF to ON, rx_filter only from NONE to ALL, and changes nothing else
- **SR-003** (P1): Unread transmit timestamps MUST NOT make a receive spin, and rawether MUST keep at most a fixed number of them, counting the ones it drops.
  - Mitigates: `threat.error-queue-starves-receive` via `mitigation.bounded-report-queue`
  - Given a socket with transmit timestamps and 2 000 frames sent without reading their timestamps, when recv waits 200 ms with nothing to receive, then it returns after about 200 ms using little CPU, 1 024 timestamps can be read, and the lost count is the rest
- **SR-004** (P2): Reading transmit timestamps MUST NOT discard launch-time reports, and reading launch-time reports MUST NOT discard timestamps.
  - Mitigates: `threat.tx-reports-lost` via `mitigation.one-dispatcher`
  - Given a socket with launch times and transmit timestamps through etf, one refused launch time and frames that left, when tx_errors and the timestamps are read in either order, then invalid = 1 and every sent frame's timestamp is there
- **SR-005** (P2): Error-queue control messages MUST be read only through the length-checked reader and ignored when the control buffer was truncated.
  - Mitigates: `threat.timestamp-cmsg-overread` via `mitigation.checked-report-cmsgs`
  - Given the error-queue reader, when it is reviewed, then every payload is read with cmsg_payload and MSG_CTRUNC skips the message (unit test of the classifier over hand-built reports)
- **SR-006** (P2): Requesting transmit timestamps on a platform without them MUST make open fail with Unsupported.
  - Mitigates: `threat.unsupported-silently-ignored` via `mitigation.unsupported-is-an-error`
  - Given macOS or FreeBSD, when a socket with transmit timestamps opens, then Unsupported, naming transmit timestamps
<!-- threatspec:end -->

## Success Criteria

### Measurable Outcomes

- **SC-001**: For 1 000 frames sent in a mix of single and batched sends on a veth pair, 1 000
  timestamps arrive with exactly the announced identifiers, on both receive paths.
- **SC-002**: After a refused send on a 6.13+ kernel, the next 10 frames' identifiers match
  their announcement (100%).
- **SC-003**: The configuration decision never lowers or narrows any value, over all 4 transmit
  modes × 16 receive filters × request combinations (exhaustive test).
- **SC-004**: Capability discovery works unprivileged on Linux, macOS and FreeBSD CI lanes.
- **SC-005**: Zero allocations in a send-and-read-timestamp loop; the gates and the veth suite
  pass.

## Assumptions

- Hardware transmit stamps cannot be produced on veth; the hardware path is covered by the
  configuration decision's tests and by the software path sharing all code after the stamp.
- Up to 1 024 unread transmit timestamps are kept per socket.
- `ptp4l`'s transmit stamping uses its own socket; rawether's socket-level options do not affect
  it, only the NIC-wide configuration does (covered by FR-005).
