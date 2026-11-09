# Implementation Plan: Low-latency frame ring

**Branch**: `016-low-latency-ring` | **Date**: 2026-11-09 | **Spec**: [spec.md](spec.md)

## Summary

`RxMode::FrameRing(FrameRingConfig { frame_size, frame_count })`, plus `RxMode::low_latency()`,
sets up a TPACKET_V2 ring. Each frame gets its own slot and status word, and the kernel wakes a
poller per frame. Geometry: 64 KiB blocks (rounded up to the page size), frames per block =
block / frame size, and the block count rounded up to cover `frame_count`.

- **Pure code:** `ring::FrameMeta::read_v2(slot)`, a bounds-checked parse of `tpacket2_hdr`
  (32 octets; `sockaddr_ll` at 32, so `sll_pkttype` at 42).
- **Linux backend:** a `FrameRing` beside the block ring. A slot is read after
  `TP_STATUS_USER` (acquire); the slot taken is released (store KERNEL, release) at the next
  receive, delivered or skipped. VLAN re-insertion borrows the slot's head-room only. Timestamps
  come from `tp_sec`/`tp_nsec`, labelled by `TP_STATUS_TS_RAW_HARDWARE`. Drops come from
  `PACKET_STATISTICS`, the V2 layout.
- **API:** `RxPath::FrameRing`. An explicit request the kernel refuses fails `open`. BSD uses
  BPF.

## Constitution Check

II: two new `unsafe` blocks (slot view, slot status), each with a SAFETY comment ✅. III: the
path is reported ✅. IV: the whole veth suite runs on it ✅. V: borrowed slots, no allocation ✅.
VII: additive ✅.

## Project Structure

`src/config.rs`, `src/packet.rs`, `src/ring.rs`, `src/sys/linux.rs`, `src/sys/bsd.rs`,
`src/lib.rs` (fuzzing hook), `fuzz/fuzz_targets/ring_walk.rs`, `tests/veth.rs`,
`scripts/veth-test.sh`, `bench/src/main.rs`, docs (receiving, linux, performance, how-it-works),
README, CHANGELOG, THREAT_MODEL (T-01 covers both rings).

## Complexity Tracking

None.
