---
description: "Tasks for 007 — transmit timestamps and clock discovery"
---

# Tasks: PTP precision — transmit timestamps and clock discovery

**Input**: plan.md, spec.md, research.md, data-model.md, contracts/api.md · **Tests**: required.
**Markers**: test comments cite `Spec 007 SR-00N`.

## Phase 1: Foundational

- [X] T001 [SR-002] src/hwtstamp.rs: `decide(current, want_rx, want_tx)`; a write only raises rx_filter NONE→ALL (want_rx) and tx_type OFF→ON (want_tx); `Effective { rx, tx }` from the final configuration; exhaustive test over flags × tx_type 0..=3 × rx_filter 0..=15 × the four request combinations
- [X] T002 src/packet.rs: `TxTimestamp { id, timestamp }`; `TxErrors::timestamps_lost`; `TimestampInfo` + `phc_path()`
- [X] T003 src/config.rs: `Config::tx_timestamping(Timestamping)` (Off by default); src/sys/mod.rs: `wait(fd, timeout, events)` (POLLIN for receive, 0 for the error queue)

## Phase 2: User Story 1 — know when each frame left (P1)

- [X] T004 [US1] [SR-001] src/sys/linux.rs: socket flags (`TX_SOFTWARE|SOFTWARE|OPT_ID|OPT_TSONLY`, plus `TX_HARDWARE|RAW_HARDWARE` when the NIC stamps); `send`, `send_at`, `send_batch` go through `sendmsg`/`sendmmsg` with an `SCM_TS_OPT_ID` cmsg (and `SCM_TXTIME` for `send_at`) when stamping; id mode Explicit→Implicit on the kernel's `EINVAL` with one retry; `next_tx_id` wraps and advances per accepted frame
- [X] T005 [US1] [SR-004] [SR-005] src/sys/linux.rs: one error-queue reader (`drain_error_queue`) classifying `PACKET_TX_TIMESTAMP` + `SCM_TIMESTAMPING` reports (origin TIMESTAMPING, `SCM_TSTAMP_SND`) into the queue and TXTIME reports into the counts, through `cmsg_payload`; a pure `classify` with unit tests
- [X] T006 [US1] [SR-003] src/sys/linux.rs: bounded queue (1 024, preallocated) with `timestamps_lost`; `tx_timestamp(timeout)` waits on POLLERR only (events 0), surfaces socket errors; recv's error path fills the same queue
- [X] T007 [US1] src/lib.rs: `Socket::{tx_timestamping, next_tx_id, tx_timestamp, timestamp_info}`, rustdoc with an example
- [X] T008 [US1] [SR-001] tests/veth.rs: 1 000 frames (single and batched, both paths) → timestamps with exactly the announced ids, `Software`, not before the send; after an `etf`-refused send, the next 10 ids match (SR-001 scenario 2; with `RAWETHER_REQUIRE_ETF` in CI); `tx_timestamp(50 ms)` with nothing waiting returns `None` after ≥ 45 ms, and at once when non-blocking (US1 scenario 4); `next_tx_id` wraps (unit test)

## Phase 3: User Story 2 — know which clock (P1)

- [X] T009 [US2] src/sys/linux.rs: `timestamp_info(name)` via `SIOCETHTOOL`/`ETHTOOL_GET_TS_INFO` on an `AF_INET` datagram socket; `ENODEV` → `NotFound` naming the interface; pure `TimestampInfo::from_bits(so_timestamping, phc_index)` with unit tests
- [X] T010 [US2] src/sys/bsd.rs, src/sys/unsupported.rs: `timestamp_info` (BSD: software receive, no PHC, NotFound for a missing interface; others: Unsupported); tests on veth (software rx/tx, no PHC) and macOS `lo0`

## Phase 4: User Story 3 — hardware without harm (P2)

- [X] T011 [US3] [SR-002] src/sys/linux.rs: `hardware_timestamps` uses the new `decide` for receive and transmit together, one read and at most one write; `tx_timestamping()` reports the effective mode; veth: Hardware requested → Software reported

## Phase 5: User Story 4 — together (P2)

- [X] T012 [US4] [SR-003] [SR-004] tests/veth.rs: 2 000 unread stamps → `recv(200 ms)` returns after ~200 ms, 1 024 readable, `timestamps_lost` = 976; `etf` + stamping: refused launch time counted `invalid` = 1 and every sent frame's stamp read, in both reading orders
- [X] T013 [US4] [SR-006] src/sys/bsd.rs: `tx_timestamping != Off` → `Unsupported` naming transmit timestamps; unit test on macOS
- [X] T014 [US4] tests/veth.rs: the allocation test sends with stamping and reads each timestamp

## Phase 6: User Story 5 — documented (P3)

- [X] T015 [P] [US5] examples/txstamp.rs (send N frames, print id/source/time; capability line first)
- [X] T016 [P] [US5] site/content/docs/timestamps.md ("Transmit timestamps", "Which clock"), linux.md (facilities, 6.13 note), faq.md (PTP answer), _index (landing card, docs overview); README feature line; CHANGELOG `[Unreleased]`; THREAT_MODEL.md T-16 (transmit timestamp misattribution) and T-12/T-15 extended
- [X] T017 [US5] (moved to record 015: typed EtherType names) Named EtherType constants in README, landing and getting-started snippets (`const LLDP`, `const PTP`), not in the API (constitution I)

## Phase 7: Polish

- [X] T018 `just ci site`, `just miri`, `scripts/veth-test.sh --docker`; specs/README index

## Dependencies

T001–T003 → US1 (T004–T008) → US2 (T009–T010) → US3 (T011) → US4 (T012–T014) → docs (T015–T017) → T018. linux.rs tasks are sequential.
