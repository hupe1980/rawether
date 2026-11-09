# Implementation Plan: Audit remediation — correct on every platform, harmless to the host

**Branch**: `003-audit-remediation` (directory identity) | **Date**: 2026-11-09 | **Spec**: [spec.md](spec.md)

## Summary

Fix every audit finding and the gaps found while documenting, as a hard cut (no compatibility
shims). The approach:

- **Pure code**: the BSD record parser and the hardware-timestamp decision move into pure
  modules that run everywhere, so unit tests, Miri and fuzzing reach them.
- **Kernel-shared memory**: the ring walker gets a shared view of a block; only VLAN
  re-insertion gets a mutable one, over the bytes it writes.
- **Waiting**: deadlines and poll timeouts can no longer overflow or truncate, and a pending
  socket error ends a wait.
- **Privilege**: `drop_capabilities` clears every capability set, then refuses while another
  thread still holds one.
- **Hardware timestamps**: the NIC's config is read first and never lowered.
- **Launch times**: `tx_errors` parses the error queue.
- **Evidence**: CI gains Miri, cargo-fuzz, a FreeBSD VM and a 32-bit check.
- **Documents**: the README, site, rustdoc and THREAT_MODEL.md follow.

## Technical Context

**Language/Version**: Rust 1.88 (MSRV), edition 2024
**Primary Dependencies**: `libc` ≥ 0.2.191, the only dependency. The fuzz crate depends on `libfuzzer-sys` and is outside the package
**Storage**: N/A
**Testing**: `cargo test`; Miri (`cargo +nightly miri test --lib`); cargo-fuzz (5 targets, 60 s each in CI); veth suite (new: link down/up, interface deleted, `send_at` without `etf`, launch-time reasons); a `harness = false` test binary for `drop_capabilities` (libtest's own threads would otherwise hold capabilities); a FreeBSD VM lane
**Target Platform**: Linux (reference), macOS, FreeBSD (64-bit); 32-bit Linux builds and is overflow-free; others `Unsupported`
**Project Type**: library
**Performance Goals**: unchanged steady state (no allocation, one system call per ring block); a link-loss error within 100 ms
**Constraints**: no new runtime dependency; `unsafe` only in `sys/`; the record parser and the hwtstamp decision have none
**Scale/Scope**: about 900 changed lines in src/tests, 5 fuzz targets, 3 CI jobs, 11 documents

## Constitution Check

| Principle | Plan |
|---|---|
| I Generic | No protocol knowledge added. The hwtstamp decision concerns all frames, not PTP ✅ |
| II `unsafe` confined | Fewer and narrower `unsafe` blocks: the BSD parser becomes safe code; the ring's `&mut` over a block shrinks to the re-insertion range; the `sockaddr_dl` read uses raw-pointer provenance; cmsg reads are length-checked. Every new block has `// SAFETY:` ✅ |
| III Honest fallback | `Auto` falls back and reports it; an explicit `Ring` errors; `Socket::timestamping()` reports what is delivered; BSD `received` counts what was delivered ✅ |
| IV Real kernel | New veth tests: link down/up, interface removal, `send_at` without `etf`, launch-time reasons; capability drop on a real kernel; FreeBSD in a VM ✅ |
| V No steady-state allocation | Unchanged; the error-queue and capability paths are not steady state ✅ |
| VI Errors say what to do | Capability refusal names the threads and the remedy; ring errors name the geometry; link loss returns `ENETDOWN` naming the interface ✅ |
| VII Breaking changes | CHANGELOG `Changed`: `drop_capabilities` can refuse, `tx_errors` returns `TxErrors`, explicit `Ring` can fail ✅ |

Post-design re-check: no change.

## Project Structure

### Documentation (this feature)

```text
specs/003-audit-remediation/
├── spec.md · plan.md · research.md · data-model.md · quickstart.md · contracts/api.md
├── threat-model.yaml · threat-model.md · security/
└── tasks.md
```

### Source Code

```text
src/bpf_record.rs      # NEW pure: BSD read-buffer records, per-platform Layout (macOS, FreeBSD LP64, libc-derived on BSD)
src/hwtstamp.rs        # NEW pure: decide(current) -> Plan; exhaustive tests
src/lib.rs             # TxErrors, Socket::timestamping(), drop_capabilities docs; mod wiring; cfg(fuzzing) hooks
src/config.rs          # ring geometry checked (overflow, limits); docs (TxTime, RxMode)
src/bpf.rs             # checked jump arithmetic in new/run
src/ring.rs            # walker over &[u8]
src/vlan.rs            # reinsert on a narrow &mut range
src/sys/mod.rs         # deadline(), poll ms rounded up, wait() reporting errors
src/sys/linux.rs       # read-first hwtstamp; SO_ERROR on POLLERR/POLLHUP; checked cmsgs; tx_errors parsing; explicit Ring errors; drop_capabilities
src/sys/bsd.rs         # bpf_record; BIOCSDIRECTION on FreeBSD; raw-pointer sockaddr_dl; delivered-frame stats
src/sys/unsupported.rs # signatures
tests/veth.rs          # link down/up, interface deleted, send_at without etf, tx_errors reasons
tests/drop_capabilities.rs  # harness = false, single-threaded
fuzz/                  # cargo-fuzz: frame_view, bpf_program, ring_walk, bpf_record, vlan_reinsert
.github/workflows/ci.yml  # miri, fuzz, freebsd jobs; gates add FreeBSD and i686 checks
justfile               # lint/doc add x86_64-unknown-freebsd, i686-unknown-linux-gnu; miri, fuzz recipes
Cargo.toml             # libc 0.2.191; [[test]] drop_capabilities harness=false; check-cfg fuzzing
README.md, CHANGELOG.md, THREAT_MODEL.md, SECURITY.md (if needed), site/content/**, examples
```

**Structure Decision**: two new pure modules beside the existing pure ones (`ring`, `vlan`,
`bpf`, `frame`); the backends call them.

## Complexity Tracking

| Deviation | Why | Rejected alternative |
|---|---|---|
| A `harness = false` test binary | libtest runs every test on a spawned thread while its main thread keeps the capabilities, so in-harness tests cannot observe a process-wide drop | A child process from inside libtest (the current approach) still has libtest's threads |
| A `fuzz/` crate with `libfuzzer-sys` | the parsers need coverage-guided input; outside the package and the workspace, so the crate keeps one dependency | Only the existing fixed-seed randomised tests: they find shallow bugs only |
