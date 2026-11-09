# Implementation Plan: rawether 0.1.0 — raw layer-2 Ethernet I/O

**Branch**: `001-raw-l2-crate` (directory identity) | **Date**: 2026-11-09 | **Spec**: [spec.md](spec.md)

## Summary

One safe API (`Config` → `Socket` → `Packet<'_>`) over two OS backends: Linux AF_PACKET
(TPACKET_V3 ring, `SO_TIMESTAMPING`, `SO_TXTIME`, `sendmmsg`, classic BPF, multicast membership)
and BSD/macOS BPF devices. Pure parts — the classic-BPF builder and interpreter, the TPACKET_V3
block walker, VLAN re-insertion — are platform-independent and unit-tested everywhere; kernel
behaviour is tested on a veth pair (CI with sudo, Docker locally).

## Technical Context

**Language/Version**: Rust 1.88 (MSRV), edition 2024
**Primary Dependencies**: `libc` 0.2 (only)
**Storage**: N/A
**Testing**: `cargo test` (unit + doc); `tests/veth.rs` gated on `RAWETHER_TEST_IFACE`/`RAWETHER_TEST_PEER`; `scripts/veth-test.sh` (sudo or Docker)
**Target Platform**: Linux (reference), macOS/FreeBSD (BPF), others compile with `Unsupported`
**Project Type**: library
**Performance Goals**: line rate over veth without allocation; one syscall per ring block on receive, one per batch on send
**Constraints**: safe public API; `unsafe` only in `sys/`; no dependency beyond `libc`
**Scale/Scope**: one socket = one interface; many sockets per process

## Constitution Check

| Principle | Plan |
|---|---|
| I Generic | API is EtherTypes / BPF / MACs; examples (LLDP, echo) live in `examples/`, not the API ✅ |
| II `unsafe` confined | `src/sys/linux.rs`, `src/sys/bsd.rs` only; `#![deny(unsafe_op_in_unsafe_fn, clippy::undocumented_unsafe_blocks)]`; `src/lib.rs` other modules `#![forbid(unsafe_code)]` via module attributes ✅ |
| III Best path + honest fallback | `RxMode::Auto` ring → plain; `RxPath` and `TimestampSource` reported ✅ |
| IV Real kernel | `tests/veth.rs` + CI `linux-veth` job, both paths ✅ |
| V No steady-state allocation | ring slices borrowed; plain path reuses its buffer; batch reuses `mmsghdr`/`iovec` vectors; counting-allocator test ✅ |
| VI Errors say what to do | `PermissionDenied` naming `CAP_NET_RAW`; `NotFound` naming the interface; `Unsupported` with reason ✅ |
| VII Breaking changes | CHANGELOG from 0.1.0 ✅ |

Post-design re-check: no change.

## Project Structure

```text
Cargo.toml · README.md · CHANGELOG.md · LICENSE-* · rustfmt.toml
src/lib.rs            # API surface, docs, re-exports
src/config.rs         # Config builder, Filter, RxMode, Timestamping, TxTime, Clock
src/packet.rs         # Packet<'_>, Timestamp, TimestampSource, Stats, RxPath, MacAddr
src/bpf.rs            # classic BPF: Insn, Program, ethertypes(), interpreter (pure)
src/ring.rs           # TPACKET_V3 block walker over a byte slice (pure, bounds-checked)
src/vlan.rs           # in-place tag re-insertion (pure)
src/sys/mod.rs        # backend selection
src/sys/linux.rs      # AF_PACKET (unsafe confined)
src/sys/bsd.rs        # /dev/bpf (unsafe confined)
src/sys/unsupported.rs
examples/lldp.rs      # send an LLDP frame, print neighbours
examples/echo.rs      # reflect frames of one EtherType
examples/sniff.rs     # print frames with timestamps
tests/veth.rs         # kernel behaviour on a veth pair
scripts/veth-test.sh  # namespace + veth, sudo or Docker
.github/workflows/ci.yml · release.yml
```

**Structure Decision**: single library crate; backends selected with `cfg(target_os)`.

## Complexity Tracking

| Deviation | Why | Rejected alternative |
|---|---|---|
| `unsafe` FFI | AF_PACKET/BPF have no safe binding with rings, timestamps and txtime | rustix/nix/socket2 lack `sockaddr_ll`/ring support; pnet lacks rings/timestamps/txtime |
