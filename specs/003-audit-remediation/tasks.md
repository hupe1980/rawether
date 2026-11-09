---
description: "Tasks for 003 — audit remediation"
---

# Tasks: Audit remediation — correct on every platform, harmless to the host

**Input**: plan.md, spec.md, research.md, data-model.md, contracts/api.md, quickstart.md
**Tests**: required (SR-001…SR-012, SC-001…SC-007; constitution IV).
**Markers**: test doc comments cite `Spec 003 SR-0NN`.

## Phase 1: Setup

- [X] T001 Cargo.toml: `libc = "0.2.191"` (audited floor, R-34); `[[test]] name = "drop_capabilities", harness = false`; `[lints.rust] unexpected_cfgs` with `check-cfg = ['cfg(fuzzing)']`; keep `fuzz/` out of `include`
- [X] T002 [P] justfile: `lint` adds `cargo clippy --target x86_64-unknown-freebsd` and `--target i686-unknown-linux-gnu`; `doc` adds FreeBSD; new recipes `miri` (`cargo +nightly miri test --lib`) and `fuzz secs` (each target for `secs`)

## Phase 2: Foundational

- [X] T003 [SR-008] src/sys/mod.rs: `deadline(timeout) -> Option<Instant>` with `checked_add` (overflow = no deadline); poll milliseconds rounded up and clamped; `wait(fd, timeout) -> io::Result<Ready>` with `Ready::{Readable, Error, Timeout}` (POLLERR/POLLHUP/POLLNVAL = Error); `socket_error(fd) -> io::Error` reading `SO_ERROR`; unit tests for rounding and overflow

## Phase 3: User Story 1 — FreeBSD works (P1)

- [X] T004 [US1] [SR-001] src/bpf_record.rs (new, pure, compiled on BSD, in tests and with cfg(fuzzing)): `Layout { ts_width, caplen, datalen, hdrlen, min_header, align }`, consts `MACOS` (4, 8, 12, 16, 18, 4) and `FREEBSD_LP64` (8, 16, 20, 24, 26, 8), `Layout::native()` from `libc::bpf_hdr` via `offset_of!` on BSD; `next(buf, &mut pos, layout) -> Option<Record>`, reading fields with `from_ne_bytes` inside the buffer, refusing `hdrlen < min_header`, needing only `min_header` octets for the last header
- [X] T005 [US1] [SR-001] src/bpf_record.rs tests: three FreeBSD records (hdrlen 26); three macOS records (hdrlen 18); hdrlen below minimum; truncated trailing header; caplen beyond the buffer; fixed-seed random buffers with both layouts (no panic, every frame inside); on BSD, `Layout::native()` equals the platform constant
- [X] T006 [US1] [SR-001] [SR-012] src/sys/bsd.rs: use `bpf_record` (drop the `unsafe` record read); count delivered records for `stats().received`, `dropped` from `bs_drop`
- [X] T007 [US1] [SR-010] src/sys/bsd.rs: on FreeBSD, `BIOCSDIRECTION` (`0x8004_4277`, `BPF_D_IN` = 0) unless `see_outgoing`, error-checked
- [X] T008 [US1] [SR-007] src/sys/bsd.rs: `hardware_address` reads through `ifa_addr.cast::<u8>()` + `offset_of!(sockaddr_dl, sdl_data)` + `sdl_nlen`, bounded by `sdl_len`, never forming `&sockaddr_dl` for the read
- [X] T009 [US1] .github/workflows/ci.yml: job `freebsd` with `vmactions/freebsd-vm@c46abacb49f09938ca4e1702d15d836285d694cc # v1.5.9` (`pkg install -y rust`, `cargo test`); gates install the `x86_64-unknown-freebsd` and `i686-unknown-linux-gnu` targets

## Phase 4: User Story 2 — privilege drop holds (P1)

- [X] T010 [US2] [SR-002] src/sys/linux.rs `drop_capabilities`: ambient clear (`PR_CAP_AMBIENT` with `PR_CAP_AMBIENT_CLEAR_ALL`, ignore `EINVAL`); bounding drop 0..=`cap_last_cap` (ignore `EPERM`/`EINVAL`); `capset` zero; `PR_SET_NO_NEW_PRIVS` checked; scan `/proc/self/task/*/status` (`CapInh`, `CapPrm`, `CapEff`, `CapAmb` hex) and return `Err` "N other thread(s) still hold capabilities: call drop_capabilities before spawning threads (or building an async runtime)" or "cannot verify other threads: …"; a pure parser of status lines with unit tests
- [X] T011 [US2] [SR-002] tests/drop_capabilities.rs (`harness = false`, single-threaded `main`, skips without `RAWETHER_TEST_IFACE`/`PEER` or without `CAP_NET_RAW`): open a socket; spawn a thread that blocks; `drop_capabilities()` → `Err` naming 1 thread; release and join it; `drop_capabilities()` → `Ok`; every task has zero sets and `NoNewPrivs: 1`; when `CAP_SETPCAP` was held (root in Docker), `CapBnd` lacks `CAP_NET_RAW` (13) and `CAP_NET_ADMIN` (12) (US2 scenario 3); the socket still sends and receives; opening a new socket gives `PermissionDenied` naming `CAP_NET_RAW`
- [X] T012 [US2] tests/veth.rs: remove the libtest-based capability test (superseded by T011; record 001 keeps its historical evidence, THREAT_MODEL T-05 names the new test in T032); scripts/veth-test.sh runs the `drop_capabilities` binary on each path
- [X] T013 [US2] src/lib.rs: `drop_capabilities` rustdoc: what it clears, refuses and why, the async-runtime order; macOS/FreeBSD no-op

## Phase 5: User Story 3 — hardware timestamps do no harm (P1)

- [X] T014 [US3] [SR-003] src/hwtstamp.rs (new, pure): `Current { flags, tx_type, rx_filter }`, `Plan::{Software, Hardware, Widen(Current)}`, `decide(Option<Current>) -> Plan`; exhaustive test over tx_type 0..=3 × rx_filter 0..=15 that a widen keeps `tx_type`/`flags` and only changes NONE → ALL, and `None` → Software
- [X] T015 [US3] [SR-003] src/sys/linux.rs: `SIOCGHWTSTAMP` → `decide` → optional `SIOCSHWTSTAMP` (using the returned config); request `SOF_TIMESTAMPING_RX_HARDWARE | RAW_HARDWARE` and ring `PACKET_TIMESTAMP` only for the Hardware outcome; never write after a failed read
- [X] T016 [US3] src/lib.rs + both backends: `Socket::timestamping() -> Timestamping` (the effective mode); veth test: `Timestamping::Hardware` on veth opens and reports `Software`

## Phase 6: User Story 4 — no panic, no spin, no silent misconfiguration (P1)

- [X] T017 [US4] [SR-008] src/sys/linux.rs, src/sys/bsd.rs: use `deadline()`; unit/veth test `recv(Some(Duration::MAX))` on a non-blocking socket and `try_recv` with a long timeout do not panic
- [X] T018 [US4] [SR-008] [SR-009] src/config.rs `validate`: `block_count >= 1`, `(block_size / frame_size) × block_count` fits `u32`, `block_size × block_count` fits `usize`, all with `checked_mul`; unit tests at the limits
- [X] T019 [US4] [SR-009] src/sys/linux.rs: `setup_ring` uses checked sizes; an explicit `RxMode::Ring` error fails `open` with the reason; `Auto` falls back; veth test: `RxMode::Ring` with a non-page-multiple block fails with `InvalidInput`
- [X] T020 [US4] [SR-008] src/bpf.rs: `checked_add` for jump targets in `new` and for `pc` in `run` (overflow → refuse / return 0); tests with `k = u32::MAX`
- [X] T021 [US4] [SR-004] src/sys/linux.rs: both receive paths use `wait()`; on `Ready::Error` return `socket_error` with "interface {name}: …"; veth tests on a private veth pair: link down → `recv` errors within 100 ms on ring and plain; link up → frames again; interface deleted → `recv` errors within 100 ms and later calls do not spin
- [X] T022 [US4] src/sys/bsd.rs: `recv` uses `wait()` so a device error ends the wait (BSD reads already return the error)

## Phase 7: User Story 5 — counters and errors that mean what they say (P2)

- [X] T023 [US5] [SR-011] src/lib.rs: `TxErrors { missed, invalid }` with `total()`; `Socket::tx_errors() -> io::Result<TxErrors>`; BSD and unsupported return the default
- [X] T024 [US5] [SR-011] src/sys/linux.rs `tx_errors`: read the error queue with a control buffer; for `SOL_PACKET`/`PACKET_TX_TIMESTAMP` (16) cmsgs read `sock_extended_err` (length-checked); count `ee_origin == 6` by `ee_code` (2 missed, 1 invalid); a pure `classify(origin, code)` with unit tests; veth launch-time test asserts `missed >= 1`
- [X] T025 [US5] tests/veth.rs: `a_launch_time_without_etf_is_sent_at_once` (measure Q-06: launch +300 ms on a veth without etf arrives in < 100 ms); fix `Config::tx_time`/`TxTime` rustdoc accordingly
- [X] T026 [US5] [SR-012] src/packet.rs `Stats` rustdoc: one meaning on every platform, what `dropped` excludes

## Phase 8: User Story 6 — evidence and soundness (P2)

- [X] T027 [US6] [SR-006] src/ring.rs, src/vlan.rs, src/sys/linux.rs: the walker takes `&[u8]` (`Ring::block`); re-insertion receives `Ring::frame_mut(block, start - 4 .. start + len)`; `reinsert` works on that narrow slice; SAFETY comments state exactly what is borrowed and why
- [X] T028 [US6] [SR-005] src/sys/linux.rs plain path: skip all control messages when `MSG_CTRUNC`; a `cmsg_payload::<T>(hdr)` helper returning `None` when `cmsg_len < CMSG_LEN(size_of::<T>())`; unit test (Linux) over a hand-built control buffer with a short message
- [X] T029 [US6] src/lib.rs `#[cfg(fuzzing)] #[doc(hidden)] pub mod fuzzing` (ring walk, BSD records with both layouts, VLAN re-insertion); `cfg_attr(miri, ignore)` on tests that open devices
- [X] T030 [P] [US6] fuzz/ (Cargo.toml, `fuzz_targets/{frame_view,bpf_program,ring_walk,bpf_record,vlan_reinsert}.rs`, .gitignore for corpus/artifacts)
- [X] T031 [US6] .github/workflows/ci.yml: jobs `miri` (nightly + miri, `cargo miri test --lib`) and `fuzz` (nightly, cargo-fuzz via `taiki-e/install-action`, 60 s per target); every action SHA-pinned (the `workflows` gate)

## Phase 9: User Story 7 — documents tell the truth (P3)

- [X] T032 [P] [US7] THREAT_MODEL.md: T-05 re-rated (process-wide or refused), T-12 host NIC timestamp config, T-13 BPF read-buffer parsing, T-14 control messages, T-15 receive starved by link loss; deployment section (async order); guarding tests
- [X] T033 [P] [US7] README.md: platform table (FreeBSD tested in CI, hardware stamps never lower the NIC config), CI lanes table, `drop_capabilities` note
- [X] T034 [P] [US7] site/content/docs: timestamps.md (read-first rule, no `CAP_NET_ADMIN` when already stamping, `timestamping()`), getting-started.md (privileges), receiving.md (link loss, `Duration::MAX`, ring latency guidance at low rates, 802.1ad on old kernels, `Stats` meaning), launch-time.md (`TxErrors`, no-etf behaviour), event-loops.md (drop before building a runtime), linux.md (explicit ring errors, requirements), macos-freebsd.md (FreeBSD in CI, direction, stats), threat-model.md (T-05, T-12…T-15), testing.md (Miri, fuzz, FreeBSD, capability binary), faq.md (PTP next to ptp4l), _index/landing claims
- [X] T035 [P] [US7] examples: `drop_capabilities()?` stays first after open; nothing else changes (check)
- [X] T036 [US7] CHANGELOG.md: fold `[Unreleased]` into the single `[0.1.0]` section (D-034) with Added/Changed/Fixed/Security entries for 002 and 003

## Phase 10: Polish

- [X] T037 Run `just ci site`, `just miri`, `just fuzz 60`, `scripts/veth-test.sh --docker`; record results for converge
- [X] T038 specs/README.md index: 003; concepts are updated outside the published tree

## Dependencies

T001–T003 come first. US1 (T004–T009), US2 (T010–T013), US3 (T014–T016) and US4 (T017–T022) are
independent, apart from shared files (linux.rs tasks run in order: T010, T015, T017, T019, T021,
T024, T027, T028). US5 depends on T003. US6's T029–T031 come after T004 and T027. US7 comes
after everything it describes.

## Implementation strategy

Do the P1 stories first, in the order US4 (shared wait primitives), US1, US2, US3, then US5,
US6 and the documents. `cargo test` stays green after each task.

## Phase 11: Security Convergence

**Purpose**: Close security gaps found by ThreatSpec converge on 2026-11-09 (commit 724140a).

- [ ] T039 [SR-011] Add a test for SR-011 (tx_errors MUST count only SO_EE_ORIGIN_TXTIME messages and report missed deadlines and invalid parameters separately) — touchpoints: src/lib.rs, src/sys/linux.rs [converge: implemented-unverified; Classification by origin and code is unit-tested; the veth assertion missed >= 1 runs only where the kernel has sch_etf (GitHub's ubuntu-24.04), not in Docker Desktop. Verify with the CI run.]
