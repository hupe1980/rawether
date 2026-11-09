# Feature Specification: BSD receive proven — macOS and FreeBSD kernel suites

**Feature Branch**: `004-macos-receive` (directory identity; no git branch)
**Created**: 2026-11-09
**Status**: Draft
**Input**: Roadmap 0.2.0 row 3 (R-25, Q-08, Q-15): on macOS, CI only opens a BPF device; no
lane sends or receives a frame on macOS or FreeBSD. Run a kernel suite on a real pair of
Ethernet-like interfaces on both systems — `feth` on macOS, `epair` on FreeBSD — the way the
veth suite runs on Linux, as an unprivileged user with access to `/dev/bpf*` where possible.
Decide the lowest macOS supported and whether joining a multicast group needs root.

## User Scenarios & Testing

### User Story 1 - Frames really flow on macOS and FreeBSD (Priority: P1)

A maintainer sees, in CI, frames sent on one end of a pair arrive on the other through BPF on
macOS and FreeBSD: filtered by EtherType (tagged or not), timestamped, counted, with the
host's own frames hidden.

**Why this priority**: the README promises both platforms; today no frame has been received
on either in CI.

**Independent Test**: the suite on a `feth` pair (macOS) and an `epair` (FreeBSD), in CI.

**Acceptance Scenarios**:

1. **Given** a socket filtered to type A, **When** frames of A (untagged and 802.1Q-tagged) and B
   are sent from the peer, **Then** only A arrives, each with a software timestamp, and the tag
   is where it was on the wire.
2. **Given** a socket without `see_outgoing`, **When** it sends a frame, **Then** it does not
   receive it itself.
3. **Given** 1 000 frames, **When** they are received, **Then** `stats()` reports received plus
   dropped equal to the frames sent that passed the filter.
4. **Given** a filter keeping 20 octets, **When** a 60-octet frame arrives, **Then** it is marked
   truncated with its wire length.
5. **Given** a socket waiting with a timeout and nothing arriving, **When** the time passes,
   **Then** `recv` returns nothing after about that long.

### User Story 2 - What a non-root user can do (Priority: P2)

A maintainer knows what an unprivileged user with access to `/dev/bpf*` can do: open, filter,
send and receive, and whether joining a multicast group works without root (Q-15). The answer
is in the documentation.

**Why this priority**: most deployments run without root (Wireshark's ChmodBPF).

**Independent Test**: the suite runs as the CI user after `/dev/bpf*` is made accessible; the
multicast test records the outcome.

**Acceptance Scenarios**:

1. **Given** access to `/dev/bpf*` but no root, **When** a socket joins a multicast group,
   **Then** the result (works, or fails naming what is missing) is what the docs state.

### User Story 3 - Supported macOS versions (Priority: P3)

The CI runs on the current macOS (26) and the previous one (15); the documentation names them
as the supported range.

**Why this priority**: Q-08; a claim without a lane is a guess.

**Independent Test**: CI lanes on both versions.

**Acceptance Scenarios**:

1. **Given** the CI matrix, **When** it runs, **Then** both macOS versions run the suite.

### Edge Cases

- A pair cannot be created (no privilege, or the kernel lacks `feth`/`epair`): the suite fails
  in CI (`RAWETHER_REQUIRE_PAIR`) instead of passing silently, and skips locally.
- Loopback (`lo0`) uses null framing, not Ethernet; the suite does not use it.

## Requirements

### Functional Requirements

- **FR-001**: A kernel suite MUST run on macOS (`feth`) and FreeBSD (`epair`) covering filtering
  (tagged and untagged), timestamps, own-frame suppression, statistics, truncation and timeouts.
- **FR-002**: The suite MUST run without root where the platform allows, after making
  `/dev/bpf*` accessible, and MUST record whether multicast membership needs root.
- **FR-003**: CI MUST run it on macOS 15 and macOS 26 and on FreeBSD 14, and MUST fail when
  the pair cannot be created.
- **FR-004**: The documentation MUST state the tested macOS versions and the multicast finding.

### Key Entities

- **Interface pair**: two Ethernet-like interfaces joined back to back (`feth`, `epair`).

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P2): In CI the BSD suite MUST fail, not skip, when its interface pair is missing.
  - Mitigates: `threat.silent-skip` via `mitigation.require-pair`
  - Given RAWETHER_REQUIRE_PAIR set and no pair, when the suite starts, then it fails naming the missing pair
<!-- threatspec:end -->

## Success Criteria

### Measurable Outcomes

- **SC-001**: The suite passes on macOS 15, macOS 26 and FreeBSD 14 in CI.
- **SC-002**: Received plus dropped equals sent for 1 000 frames on both systems.
- **SC-003**: The multicast-without-root question has a measured answer in the docs.

## Assumptions

- GitHub's macOS runners allow `sudo` (to create `feth` and change `/dev/bpf*`), and the
  FreeBSD VM runs as root (the suite then runs as root there).
