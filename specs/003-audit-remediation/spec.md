# Feature Specification: Audit remediation — correct on every platform, harmless to the host

**Feature Branch**: `003-audit-remediation` (directory identity; no git branch)
**Created**: 2026-11-09
**Status**: Draft
**Input**: Maintainer brief: fix every finding of the 2026-11-09 security and soundness audit
(one high, two medium, eight low), close the gaps found while documenting the crate, and make
the result best in class. Nothing is published, so breaking changes are allowed (hard cut, no
compatibility shims). The site, the README and the threat model must match the result.

Findings this record answers, by audit id: **H1** FreeBSD receive rejects every record. **M1**
dropping capabilities covers one thread only. **M2** hardware timestamping overwrites the NIC's
device-wide configuration. **L1** a mutable slice covers ring memory the kernel reads. **L2**
control messages are read without length checks. **L3** a pointer-provenance violation in the
BSD hardware-address lookup. **L4** a panic on very long timeouts. **L5** ring-size integer
overflow. **L6** BPF jump-target overflow on 32-bit targets. **L7** an explicitly requested ring
falls back silently. **L8** FreeBSD ignores "do not see own frames"; `tx_errors` counts any
error-queue message. Found during this work: a receive on the ring busy-loops when the link goes
down or the interface disappears; `Stats.received` means different things per platform; the
documentation disagrees with itself on launch times without an `etf` qdisc.

## User Scenarios & Testing

### User Story 1 - rawether works on FreeBSD, and CI proves it (Priority: P1)

A developer on FreeBSD opens a socket and receives frames, exactly as on macOS. Frames this
host sends are hidden unless asked for, as documented.

**Why this priority**: the README promises FreeBSD support, and today `recv` never returns a
frame there.

**Independent Test**: unit tests over byte buffers laid out as FreeBSD and macOS BPF devices
write them (records of hdrlen 26 and 18, a header below the minimum, a truncated trailing
header), on any host; a FreeBSD CI lane that builds the crate and runs its tests.

**Acceptance Scenarios**:

1. **Given** a FreeBSD-layout read buffer with three records, **When** it is parsed, **Then**
   all three frames are returned with their captured and wire lengths and timestamps.
2. **Given** a record whose header length is below the platform minimum, or a header cut off
   at the end of the buffer, **When** it is parsed, **Then** parsing stops without reading
   outside the buffer and nothing panics.
3. **Given** a FreeBSD socket opened without `see_outgoing`, **When** the host sends a frame,
   **Then** the socket does not receive it.
4. **Given** an interface whose name is longer than six characters (e.g. `bridge100`), **When**
   its hardware address is looked up, **Then** the result is correct and the lookup is sound
   under the language's aliasing rules (checked by Miri where reachable, otherwise by review).

### User Story 2 - Dropping the privilege holds for the whole process, or says why not (Priority: P1)

A developer opens their sockets and calls `drop_capabilities()`. Afterwards no thread of the
process holds the raw-socket privilege, and no later `exec` can regain it. If another thread
still holds capabilities, the call fails with an error that names how many and what to do,
instead of reporting success.

**Why this priority**: the threat model's T-05 claim ("mitigated") is false for every
multi-threaded caller today.

**Independent Test**: a single-threaded test program drops the privilege and reads every
thread's capability sets; a second program starts a thread first and observes the refusal.

**Acceptance Scenarios**:

1. **Given** a single-threaded process with `CAP_NET_RAW` and an open socket, **When**
   `drop_capabilities()` returns `Ok`, **Then** every thread's effective, permitted, inheritable
   and ambient sets are empty, `no_new_privs` is set, and the socket still sends and receives.
2. **Given** a process with a second thread that holds capabilities, **When**
   `drop_capabilities()` runs, **Then** it returns an error naming the number of threads that
   still hold capabilities and telling the caller to drop before spawning threads.
3. **Given** the process holds `CAP_SETPCAP`, **When** the privilege is dropped, **Then**
   `CAP_NET_RAW` and `CAP_NET_ADMIN` are also removed from the bounding set.

### User Story 3 - Hardware timestamps never disturb other programs on the host (Priority: P1)

A developer on a station where `ptp4l` keeps the clock in sync asks for hardware timestamps.
rawether reads the NIC's current timestamping configuration and never lowers it: transmit
stamping stays on, a receive filter that already stamps frames is used as it is, and only a NIC
that stamps nothing is switched to stamp received frames. Where the NIC already stamps, the
developer gets hardware timestamps without needing `CAP_NET_ADMIN`. The socket reports which
kind of timestamps it delivers.

**Why this priority**: today opening such a socket silently breaks the host's time
synchronisation, and the main consumer runs on exactly such stations.

**Independent Test**: unit tests of the configuration decision over every combination of
current transmit mode and receive filter; on a NIC without hardware timestamping (veth), the
socket opens and reports software timestamps.

**Acceptance Scenarios**:

1. **Given** a NIC with transmit stamping on and a PTP-only receive filter, **When** a socket
   with hardware timestamps opens, **Then** the NIC's configuration is unchanged, and the socket
   requests hardware stamps.
2. **Given** a NIC that stamps nothing, **When** a socket with hardware timestamps opens with
   the right to configure it, **Then** only the receive filter is widened to all frames;
   transmit stamping is left as it was.
3. **Given** a NIC that stamps nothing and no right to configure it, or a NIC without hardware
   timestamping, **When** a socket with hardware timestamps opens, **Then** it opens, delivers
   software timestamps, and says so.
4. **Given** any NIC, **When** the configuration cannot be read, **Then** rawether does not
   write one.

### User Story 4 - No panic, no busy loop, no silent misconfiguration (Priority: P1)

A developer can pass any timeout, any ring geometry and any filter program, and unplug the
cable, without crashing or spinning. A request rawether cannot honour is an error, not a quiet
downgrade.

**Why this priority**: these are the remaining ways a correct program can crash, burn a CPU
core, or run with a configuration it did not ask for.

**Independent Test**: unit tests for timeouts, ring geometry and BPF programs at the numeric
limits; veth tests that take the link down and delete the interface while a socket waits.

**Acceptance Scenarios**:

1. **Given** a timeout of `Duration::MAX`, **When** `recv` waits, **Then** it waits as if no
   timeout had been given, and nothing panics.
2. **Given** a ring geometry whose total size overflows, or a block count beyond what the
   kernel accepts, **When** the configuration is checked, **Then** it is refused with
   `InvalidInput` before any system call.
3. **Given** an explicit `RxMode::Ring` that the kernel refuses, **When** the socket opens,
   **Then** opening fails with the kernel's reason. `RxMode::Auto` still falls back to the plain
   path and reports it.
4. **Given** a BPF jump whose target overflows the address space, **When** the program is
   validated or interpreted, **Then** it is refused or ends with 0, on 32-bit and 64-bit
   targets.
5. **Given** a socket waiting in `recv` on either receive path, **When** the link goes down or
   the interface is deleted, **Then** `recv` returns an error naming the condition promptly
   (well within its timeout) instead of spinning; after the link comes back up, frames arrive
   again.
6. **Given** a timeout of less than a millisecond but more than zero, **When** `recv` waits,
   **Then** it waits at least that long rather than returning early.

### User Story 5 - Counters and errors that mean what they say (Priority: P2)

A developer reads `stats()` and `tx_errors()` and can act on them. `received` and `dropped`
mean the same on every platform. `tx_errors()` says how many launch-time frames were dropped
and why (deadline missed or invalid parameters), and ignores error-queue messages that are not
about launch times. The documentation says what happens to a timed frame when no `etf` qdisc
is installed, as measured.

**Why this priority**: precise accounting is what a time-sensitive application relies on;
wrong numbers are worse than none.

**Independent Test**: veth tests for launch-time drops, both reasons where the kernel allows,
and for `send_at` without `etf`; unit tests for parsing error-queue messages; BSD statistics
semantics by source reading and a macOS test.

**Acceptance Scenarios**:

1. **Given** frames sent with a launch time in the past through `etf`, **When** `tx_errors()`
   is read, **Then** the count of missed deadlines covers them, and any non-launch-time message
   on the error queue is not counted.
2. **Given** a filter that rejects some traffic, **When** `stats()` is read on any platform,
   **Then** `received` counts only frames that passed the filter.
3. **Given** a launch-time socket on an interface without `etf`, **When** a frame is sent with a
   future launch time, **Then** the observed behaviour (sent at once, held, or dropped) is the
   one the documentation states.

### User Story 6 - Evidence that keeps it correct (Priority: P2)

A maintainer changes a parser and CI tells them if they broke soundness or totality: the pure
parsers run under Miri, the parsers are fuzzed, FreeBSD and a 32-bit target are built, and the
unsafe code holds no reference wider than what it may touch.

**Why this priority**: the audit found its issues by hand; the next regression should be
caught by a machine.

**Independent Test**: the CI workflow has Miri, fuzz, FreeBSD and 32-bit jobs, and they pass;
`just ci` runs the cross-checks locally.

**Acceptance Scenarios**:

1. **Given** the pure modules (ring walk, VLAN re-insertion, BPF, frame view, BSD record
   parsing), **When** their tests run under Miri, **Then** no undefined behaviour is reported.
2. **Given** each parser, **When** it is fuzzed for a fixed time in CI, **Then** no panic and no
   out-of-bounds access is found.
3. **Given** the ring walker, **When** it reads a block, **Then** it holds only a shared view of
   the block, and a mutable view only of the frame range VLAN re-insertion writes.
4. **Given** a control message shorter than the structure rawether expects, or a truncated
   control buffer, **When** it is parsed, **Then** it is skipped rather than read past its end.

### User Story 7 - Documentation and threat model tell the truth (Priority: P3)

The README, the website, the rustdoc and THREAT_MODEL.md state the new behaviour: the
re-rated and new threat classes, what `drop_capabilities` guarantees, how hardware timestamps
treat other programs, platform differences, latency guidance for the ring at low rates, and
what old kernels do with 802.1ad tags.

**Why this priority**: it follows from the stories above.

**Independent Test**: every claim changed by stories 1–6 is reflected; the site builds with its
link checker; the gates pass.

**Acceptance Scenarios**:

1. **Given** the published documents, **When** a reader looks up any behaviour changed here,
   **Then** they find it stated once and consistently.

### Edge Cases

- `drop_capabilities` on a system without `/proc` (a minimal container): the thread check
  cannot run, so the call fails with an error that says the check was impossible, rather than
  claiming success.
- `drop_capabilities` on macOS and FreeBSD: unchanged no-op (the open descriptor is the
  privilege).
- `drop_capabilities` in an async program: a multi-threaded runtime starts its worker threads
  before the program's main body runs, so the call is refused there. The documentation shows
  the order that works: open the sockets and drop the privilege in a plain `main`, then build
  the runtime.
- Hardware timestamps on a NIC that stamps only some received frames (e.g. PTP only): those
  frames are labelled `Hardware`, the others `Software`, frame by frame.
- An interface deleted and recreated with the same name: the old socket stays dead (it is bound
  by index); a new socket must be opened.
- `RxMode::Ring` with a geometry the platform has no ring for (macOS, FreeBSD): the BPF path is
  used as today; the explicit request only errors where a ring exists and fails.
- Statistics on BSD count frames delivered by the device; frames still unread in the kernel
  buffer are not yet counted.

## Requirements

### Functional Requirements

- **FR-001**: The BSD record parser MUST accept every record layout the macOS and FreeBSD kernels
  write (minimum header 18 and 26 octets respectively), MUST read the header field by field
  within the buffer, and MUST stop without panicking at a malformed or truncated record.
- **FR-002**: On FreeBSD, a socket without `see_outgoing` MUST NOT receive the host's own
  transmissions.
- **FR-003**: The BSD hardware-address lookup MUST read the link-layer address through a pointer
  whose provenance covers the whole kernel record.
- **FR-004**: `drop_capabilities` on Linux MUST clear the calling thread's effective, permitted,
  inheritable and ambient capability sets; MUST set `no_new_privs` and fail if that fails; MUST
  remove `CAP_NET_RAW` and `CAP_NET_ADMIN` from the bounding set when permitted; and MUST return
  an error, naming the number of threads, when any other thread of the process still holds a
  capability afterwards, or when that cannot be determined.
- **FR-005**: With hardware timestamping requested, rawether MUST read the NIC's timestamping
  configuration before changing it, MUST NOT write one it could not read, MUST NOT turn off
  transmit stamping or narrow the receive filter, and MUST widen the receive filter only from
  "none".
- **FR-006**: A socket MUST request hardware receive stamps whenever the NIC already stamps
  received frames, whether or not rawether configured it.
- **FR-007**: The socket MUST report the timestamping it delivers (none, software, or hardware
  where the NIC stamps).
- **FR-008**: No receive timeout MUST panic; a timeout too large to represent MUST mean "wait
  without limit"; a non-zero timeout shorter than the poll resolution MUST NOT return before it
  has elapsed.
- **FR-009**: Ring geometry MUST be checked for overflow and for the kernel's limits before any
  system call; an explicit `RxMode::Ring` that cannot be set up MUST fail the open with the
  reason; `RxMode::Auto` MUST keep its reported fallback.
- **FR-010**: BPF validation and interpretation MUST be free of integer overflow on every
  pointer width.
- **FR-011**: A receive MUST return an error, not spin, when the socket reports a pending error
  (link down, interface removed), on both Linux receive paths and on BSD.
- **FR-012**: The ring walker MUST hold a shared view of a block and a mutable view only of the
  octets VLAN re-insertion writes.
- **FR-013**: Control messages MUST be read only when the control buffer was not truncated and
  each message is long enough for what is read from it.
- **FR-014**: `tx_errors` MUST count only launch-time error-queue messages and MUST report
  missed deadlines and invalid parameters separately.
- **FR-015**: `Stats.received` MUST count, on every platform, frames that passed the filter and
  were delivered to the socket; the documentation MUST state what `dropped` excludes.
- **FR-016**: The behaviour of `send_at` without a launch-time qdisc MUST be measured on a real
  kernel and documented consistently in the rustdoc and the site.
- **FR-017**: CI MUST run the pure modules under Miri, fuzz each parser for a bounded time,
  build and test on FreeBSD, and build for a 32-bit target.
- **FR-018**: The minimum `libc` version MUST be the audited one.
- **FR-019**: THREAT_MODEL.md MUST re-rate T-05 to match FR-004, and add classes for host-wide
  NIC state (T-12), BPF read-buffer parsing (T-13), control messages (T-14) and a receive
  starved by link loss (T-15), each with the test that guards it.
- **FR-020**: The README, the website and the rustdoc MUST describe every behaviour changed by
  FR-001–FR-016.

### Key Entities

- **Hardware timestamp configuration**: the NIC-wide transmit mode and receive filter; read,
  possibly widened, never lowered.
- **Effective timestamping**: what a socket delivers (none, software, hardware).
- **Launch-time error counts**: missed deadlines and invalid parameters since the last read.
- **BPF record layout**: the per-platform minimum header length and field offsets.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): The BSD record parser MUST accept both macOS (minimum header 18) and FreeBSD (minimum header 26) layouts, read header fields only inside the buffer, and stop without panicking at a malformed or truncated record.
  - Mitigates: `threat.bpf-record-misparse` via `mitigation.layout-aware-record-parse`
  - Given a FreeBSD-layout buffer with three records, when it is parsed, then three frames are returned with their lengths and timestamps
  - Given a record with hdrlen below the minimum, or a header cut off at the buffer end, when it is parsed, then parsing stops and nothing panics or reads outside the buffer
  - Given random buffers, when they are parsed with each layout, then no panic and every frame lies inside the buffer
- **SR-002** (P1): drop_capabilities MUST leave no thread of the process with an effective, permitted, inheritable or ambient capability and MUST set no_new_privs, or return an error naming the threads that still hold capabilities.
  - Mitigates: `threat.capability-kept-by-other-threads` via `mitigation.process-wide-capability-check`
  - Given a single-threaded process with CAP_NET_RAW and an open socket, when drop_capabilities returns Ok, then every /proc/self/task/*/status shows zero CapEff, CapPrm, CapInh and CapAmb, NoNewPrivs is 1, and the socket still sends and receives
  - Given a second thread holding capabilities, when drop_capabilities runs, then it returns an error naming one thread
- **SR-003** (P1): With hardware timestamps requested, rawether MUST NOT write a NIC timestamp configuration it could not read, MUST NOT lower tx_type or narrow the RX filter, and MUST widen the RX filter only from none.
  - Mitigates: `threat.nic-timestamp-config-clobbered` via `mitigation.read-first-never-lower`
  - Given every combination of current tx_type and rx_filter, and whether configuring is allowed, when the decision runs, then the written configuration (if any) keeps tx_type and changes rx_filter only from NONE to ALL
  - Given a NIC whose configuration cannot be read, when a hardware-timestamping socket opens, then no configuration is written and the socket reports software timestamps
- **SR-004** (P1): A receive on either Linux path MUST return the socket's pending error instead of polling again when the descriptor reports an error or hang-up.
  - Mitigates: `threat.recv-spins-on-socket-error` via `mitigation.socket-error-surfaces`
  - Given a socket waiting in recv with a 2 s timeout on the ring and on the plain path, when the link goes down or the interface is deleted, then recv returns an error within 100 ms
  - Given the link back up, when a frame is sent, then the socket receives it again
- **SR-005** (P2): Control messages MUST be read only when MSG_CTRUNC is clear and cmsg_len covers the payload read.
  - Mitigates: `threat.control-message-overread` via `mitigation.checked-control-messages`
  - Given a control buffer with a message whose cmsg_len is shorter than the payload type, when it is parsed, then the message is skipped
  - Given msg_flags with MSG_CTRUNC, when the messages are parsed, then none is read
- **SR-006** (P2): The ring walker MUST read blocks through a shared slice and borrow mutably only the octets VLAN re-insertion writes.
  - Mitigates: `threat.ring-mutable-alias` via `mitigation.narrow-ring-borrows`
  - Given the ring module, when its signatures are reviewed and its tests run under Miri, then the walker takes &[u8], re-insertion takes a &mut range of the frame only, and Miri reports nothing
- **SR-007** (P3): The BSD hardware-address lookup MUST derive its read pointer from the raw ifa_addr pointer, never from a reference to sockaddr_dl.
  - Mitigates: `threat.sockaddr-provenance` via `mitigation.raw-pointer-provenance`
  - Given the lookup code, when it is reviewed, then no &sockaddr_dl is formed and the offset comes from offset_of!; the macOS test still opens lo0
- **SR-008** (P2): No timeout, ring geometry or BPF program MUST cause a panic or a wrapped value, on 64-bit and 32-bit targets.
  - Mitigates: `threat.numeric-limits-panic` via `mitigation.checked-arithmetic`
  - Given recv with Duration::MAX, when it runs on a non-blocking socket, then it returns without panicking
  - Given a ring geometry whose total size overflows u32 or usize, or a block count above the limit, when it is validated, then InvalidInput
  - Given a BPF ja with k = u32::MAX, when Program::new and Program::run run, then it is refused, and run returns 0
- **SR-009** (P2): An explicit RxMode::Ring that cannot be set up MUST fail the open with the kernel's reason; RxMode::Auto MUST fall back and report RxPath::Plain.
  - Mitigates: `threat.silent-downgrade` via `mitigation.explicit-ring-errors`
  - Given RxMode::Ring with a block size that is not a page multiple, when the socket opens, then it fails with InvalidInput
- **SR-010** (P2): On FreeBSD a socket without see_outgoing MUST set BIOCSDIRECTION to BPF_D_IN.
  - Mitigates: `threat.own-frames-on-freebsd` via `mitigation.freebsd-direction`
  - Given the FreeBSD backend, when a socket opens without see_outgoing, then BIOCSDIRECTION(BPF_D_IN) is issued and checked (FreeBSD CI build; review)
- **SR-011** (P2): tx_errors MUST count only SO_EE_ORIGIN_TXTIME messages and report missed deadlines and invalid parameters separately.
  - Mitigates: `threat.tx-errors-miscounted` via `mitigation.parsed-error-queue`
  - Given sock_extended_err records of origin TXTIME code MISSED, code INVALID_PARAM, and origin LOCAL, when they are classified, then one missed, one invalid, the LOCAL one ignored
  - Given a frame with a past launch time through etf on veth, when send_at runs and tx_errors is read, then send_at fails naming the launch time, and tx_errors reports invalid = 1, missed = 0 (etf refuses a past time at enqueue as INVALID_PARAM; MISSED is for frames late at dequeue)
- **SR-012** (P3): stats().received MUST count only frames that passed the filter, on every backend.
  - Mitigates: `threat.stats-misreport` via `mitigation.counted-deliveries`
  - Given a BSD socket with a filter, when frames are read and stats() is read, then received equals the frames delivered (review of the counter; macOS loopback test where privileged)
<!-- threatspec:end -->

## Success Criteria

### Measurable Outcomes

- **SC-001**: On FreeBSD, the crate builds, its unit tests pass in CI, and FreeBSD-layout
  record tests pass on every host.
- **SC-002**: After a successful `drop_capabilities()`, 0 threads of the process hold any
  capability; with a second privileged thread the call fails in 100% of runs.
- **SC-003**: For all 3 × 16+ combinations of transmit mode and receive filter, the decision
  never lowers either value (exhaustive unit test).
- **SC-004**: With the link taken down or the interface deleted, a waiting `recv` returns an
  error within 100 ms on both Linux receive paths, using no more than a few milliseconds of CPU.
- **SC-005**: Zero panics for any timeout, ring geometry or BPF program at the numeric limits,
  on 64-bit and 32-bit targets.
- **SC-006**: Miri reports no undefined behaviour in the pure modules; each fuzz target runs
  for at least 60 s per CI run without a finding.
- **SC-007**: Every audit finding (H1, M1, M2, L1–L8) and every gap listed in the Input is
  closed by a test, a measurement, or a documented decision; the full gate set and the veth
  suite pass.

## Assumptions

- 64-bit Linux, macOS and FreeBSD are the supported targets; 32-bit targets must stay correct
  (no overflow, no panic) and build, but have no runtime CI lane.
- A FreeBSD VM in CI runs unprivileged unit tests; opening a BPF device there is attempted and
  may be refused without root, as on macOS.
- veth has no hardware timestamping, so the hardware-timestamp decision is tested as a pure
  function; driver behaviour is out of reach without such a NIC.
- The hard cut applies: `drop_capabilities` may now fail where it used to succeed, `tx_errors`
  returns a structure, and an explicit `RxMode::Ring` can fail. The consumer `iec61850-rs`
  adapts.
- Hardware transmit timestamps and PHC discovery stay out of scope (a later record).
