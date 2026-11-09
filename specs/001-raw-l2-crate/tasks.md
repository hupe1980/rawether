---
description: "Tasks for rawether 0.1.0"
---

# Tasks: rawether 0.1.0 — raw layer-2 Ethernet I/O

**Input**: plan.md, spec.md, research.md, data-model.md, contracts/api.md, quickstart.md
**Tests**: required (constitution IV, V; spec SC-001…SC-005).

## Phase 1: Setup

- [x] T001 Cargo.toml (name `rawether`, 0.1.0, edition 2024, rust-version 1.85, MIT OR Apache-2.0, repository https://github.com/hupe1980/rawether, `libc` 0.2), rustfmt.toml, lints (`unsafe_op_in_unsafe_fn`, `clippy::undocumented_unsafe_blocks` = deny)
- [x] T002 [P] README.md, CHANGELOG.md (0.1.0), crate docs in src/lib.rs

## Phase 2: Foundational (pure, every OS)

- [x] T003 [P] src/packet.rs: `MacAddr` (`Display` `aa:bb:cc:dd:ee:ff`, `FromStr` accepting `:` or `-`), `Timestamp`, `TimestampSource`, `Packet<'_>`, `Stats`, `RxPath`
- [x] T004 [P] [SR-007] src/config.rs: `Config` builder, `Filter` ("an empty EtherType set is `InvalidInput`"), `RxMode`, `Timestamping` (hardware "falls back to software, never mislabelled"), `TxTime`, `Clock`; promiscuous and all-multicast default off (unit test)
- [x] T005 [P] [SR-004] src/bpf.rs: `Insn`, `Program`, `Program::ethertypes` (tagged 0x8100/0x88a8 and untagged), classic-BPF interpreter `Program::run`; unit tests over synthetic frames
- [x] T006 [P] [SR-001] src/ring.rs: TPACKET_V3 block walker over a byte slice with every offset bounds-checked; unit tests over synthetic blocks (including malformed offsets)
- [x] T007 [P] [SR-003] src/vlan.rs: in-place tag re-insertion; unit tests and an exhaustive small-input property test (no panic, untouched on refusal)

## Phase 3: User Story 1 — send and receive chosen EtherTypes (P1)

- [x] T008 [US1] [SR-004] [SR-006] src/sys/linux.rs: open sequence (research "Linux open sequence"), ifindex/MAC, filter, membership, promiscuous, plain `recvmsg` path with `PACKET_AUXDATA` + `SO_TIMESTAMPING`, `send` via `sendto`, error mapping (`PermissionDenied` naming `CAP_NET_RAW`, `NotFound` naming the interface); `SOCK_CLOEXEC`; filter attached before `bind`
- [x] T009 [US1] [SR-006] src/sys/bsd.rs: `/dev/bpf` backend (research "BSD/macOS"), multicast via `SIOCADDMULTI`, MAC via `getifaddrs`; device opened `O_CLOEXEC`
- [x] T010 [US1] [SR-002] [SR-005] src/sys/unsupported.rs and src/sys/mod.rs dispatch; `Socket` in src/lib.rs (`AsFd`, `AsRawFd`, `recv`, `try_recv`, `send`, `set_nonblocking`, `interface`, `index`, `mac_address`); `Packet<'_>` borrows `&mut Socket` with a compile-fail doc test; `drop_capabilities()` (Linux `capset` to empty, a no-op elsewhere)
- [x] T011 [US1] [SR-004] [SR-005] [SR-006] tests/veth.rs (skips unless `RAWETHER_TEST_IFACE`/`RAWETHER_TEST_PEER`): filter tagged/untagged, multicast join, timeouts, permission error, `FD_CLOEXEC` set, `drop_capabilities()` leaves CapEff/CapPrm zero and the socket still works, `send` of a frame under 14 octets is `InvalidInput`; a macOS test opens `lo0` and accepts success or `PermissionDenied` (SC-004); scripts/veth-test.sh (sudo, or `--docker`)

## Phase 4: User Story 2 — precise and fast (P1)

- [x] T012 [US2] [SR-001] [SR-002] Linux TPACKET_V3 ring in src/sys/linux.rs using src/ring.rs: setup, `poll` wait, block release, VLAN restore through `PACKET_RESERVE`, timestamp source from status bits; `RxMode::Auto` fallback to plain
- [x] T013 [US2] [SR-008] [SR-009] Linux `send_batch` (`sendmmsg`, reused `mmsghdr`/`iovec`), `send_at` (`SO_TXTIME` + `SCM_TXTIME`), `SO_PRIORITY`, `PACKET_QDISC_BYPASS`, `SIOCSHWTSTAMP` best-effort, `stats()` (`PACKET_STATISTICS` accumulated), `clock_now`; BSD: `send_batch` loop, `stats` via `BIOCGSTATS`, `send_at`/hardware → `Unsupported`
- [x] T014 [US2] [SR-008] [SR-009] tests/veth.rs: ring and plain path (`RAWETHER_RX`), 100 000-frame batch with received + dropped = sent, timestamp on every frame, `send_at` without `tx_time` is `InvalidInput`, `send_at` without an `etf` qdisc returns an error or is counted by `tx_errors()`, zero allocations in a steady-state loop (counting allocator)

## Phase 5: User Story 3 — event loops and custom filters (P2)

- [x] T015 [US3] Non-blocking `try_recv` and `poll(2)` readability test; custom `Filter::Bpf` test in tests/veth.rs
- [x] T016 [P] [US3] examples/lldp.rs, examples/echo.rs, examples/sniff.rs

## Phase 6: Polish

- [x] T017 .github/workflows/ci.yml: fmt, clippy `-D warnings`, test (ubuntu), `linux-veth` job (sudo netns/veth, both paths), macOS build+test, Windows `cargo check`, docs `-D warnings`, MSRV 1.85, `cargo publish --dry-run`
- [x] T018 .github/workflows/release.yml: tag-triggered; guard (tag = version, dry-run), publish job `environment: crates-io`, `permissions: { id-token: write, contents: read }`, `rust-lang/crates-io-auth-action@v1` (`id: auth`), `cargo publish --locked` with `CARGO_REGISTRY_TOKEN: ${{ steps.auth.outputs.token }}`, GitHub release
- [x] T019 Full gate: fmt, clippy, tests (macOS + Docker veth), docs, MSRV, `cargo publish --dry-run`; commit

## Dependencies

T001 → T003–T007 → T008–T010 → T011 → T012–T014 → T015–T016 → T017–T019.

## Parallel opportunities

T003–T007 are independent pure modules; T016 with T015.

## Implementation strategy

MVP = Phases 1–3 (plain receive + send on both backends). Then the ring and precision features.

## Phase 7: Security Convergence

**Purpose**: Close security gaps found by ThreatSpec converge on 2026-11-09 (commit 0c1eb6b).

- [ ] T020 [SR-009] Add a test for SR-009 (send_at MUST fail with InvalidInput unless Config::tx_time was set, and tx_errors() MUST count frames the kernel reported dropped) — touchpoints: src/sys/linux.rs [converge: implemented-unverified; Scenario 1 passed (send_at without tx_time is InvalidInput, tests/veth.rs::launch_time_needs_configuration_and_a_qdisc_that_honours_it). Scenario 2 (etf drops a past launch time and tx_errors counts it) is implemented and tested, but the test skipped: the local Docker kernel has no sch_etf. It runs in the ubuntu-24.04 CI lane.]
