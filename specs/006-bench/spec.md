# Feature Specification: Published benchmarks

**Feature Branch**: `006-bench` (directory identity; no git branch)
**Created**: 2026-11-09
**Status**: Draft
**Input**: Roadmap 0.2.0 row 2 (R-36): "fast and precise" has no number. Measure receive
throughput and receive latency per path, against the two crates people compare rawether with
(`pnet_datalink`, `pcap`), with a reproducible method, and publish the numbers with that
method and the environment.

## User Scenarios & Testing

### User Story 1 - See the numbers (Priority: P1)

A reader evaluating rawether finds, on the website, frames per second and latency percentiles
for rawether's ring and plain paths, `pnet_datalink` and `pcap`, measured the same way, with the
date, kernel, CPU and command.

**Why this priority**: the claim needs evidence; choices (ring vs plain, rawether vs others)
need data.

**Independent Test**: the page exists with a table and a method section; the numbers come from
the harness output.

**Acceptance Scenarios**:

1. **Given** the performance page, **When** a reader reads it, **Then** they see throughput
   (frames/s received, loss) and latency (p50, p99, max) for each receiver, the environment, and
   how to reproduce it.

### User Story 2 - Reproduce them (Priority: P1)

A maintainer runs one command and gets the same table for their machine.

**Why this priority**: numbers nobody can reproduce are marketing.

**Independent Test**: `scripts/bench.sh --docker` prints the table.

**Acceptance Scenarios**:

1. **Given** a host with Docker, **When** the command runs, **Then** it prints the table in
   Markdown, and exits non-zero if a receiver failed.

### Edge Cases

- `pnet_datalink` has no in-kernel filter: it receives every frame and filters in user space,
  as its users do; the method says so.
- At saturation the sender outruns every receiver; throughput is frames received per second,
  with loss reported, not hidden.
- Docker Desktop runs a VM: absolute numbers are for comparison on the same machine only.

## Requirements

### Functional Requirements

- **FR-001**: A harness MUST measure receive throughput and per-frame latency over a veth pair
  for rawether (ring, plain), `pnet_datalink` and `pcap`, with the same sender and traffic.
- **FR-002**: Latency MUST be measured on `CLOCK_MONOTONIC` from just before the send to the
  moment the receiver gets the frame.
- **FR-003**: The harness MUST NOT become a dependency of the published crate.
- **FR-004**: The website MUST publish the numbers, the environment, the method and the command.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P2): Every published number MUST come from a recorded harness run whose date, environment, command and method are on the page, with the same sender and traffic for every receiver.
  - Mitigates: `threat.misleading-numbers` via `mitigation.recorded-runs`
  - Given the performance page, when it is reviewed against the harness output, then every number matches the recorded run, and the method lists sender, traffic and filters per receiver
<!-- threatspec:end -->

## Success Criteria

### Measurable Outcomes

- **SC-001**: One command reproduces the table.
- **SC-002**: Every number on the page comes from a harness run recorded with its date and
  environment.

## Assumptions

- Comparisons are on one machine and one run; absolute numbers vary by host.
