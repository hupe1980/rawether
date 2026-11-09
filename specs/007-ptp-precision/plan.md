# Implementation Plan: PTP precision — transmit timestamps and clock discovery

**Branch**: `007-ptp-precision` (directory identity) | **Date**: 2026-11-09 | **Spec**: [spec.md](spec.md)

## Summary

`Config::tx_timestamping` turns on transmit stamps:

- **Ids:** each frame gets a rawether-assigned id (`Socket::next_tx_id`), passed with
  `SCM_TS_OPT_ID`. On kernels older than 6.13 the kernel numbers frames itself; rawether detects
  this from its `EINVAL`.
- **Reading:** reports are read from the error queue by one reader that also counts launch-time
  drops. Timestamps go into a bounded, preallocated queue, and `Socket::tx_timestamp(timeout)`
  hands them out.
- **Hardware:** stamps follow the 0.1.0 read-first rule, extended to the transmit mode
  (OFF → ON only).
- **Clock discovery:** `rawether::timestamp_info(interface)` reports capabilities and the PTP
  hardware clock (PHC) through `ETHTOOL_GET_TS_INFO`.

## Technical Context

**Language/Version**: Rust 1.88, edition 2024 · **Dependencies**: `libc` only · **Storage**: N/A
**Testing**: unit (decision, report classification, info bits), veth suite (ids exact over 1 000 frames on both paths, after a refused send, bounded queue, shared queue with `etf`), allocation test, Miri, CI lanes
**Target Platform**: Linux for transmit stamps; capability discovery everywhere; BSD `Unsupported` for transmit stamps
**Performance Goals**: no allocation per frame; one extra cmsg per send when stamping
**Constraints**: never lower the NIC configuration (T-12); `unsafe` only in `sys/`

## Constitution Check

| Principle | Plan |
|---|---|
| I Generic | No PTP parsing; the ids and timestamps cover any frame ✅ |
| II `unsafe` confined | New system calls in `sys/linux.rs` and `sys/bsd.rs` only, each with a SAFETY comment; the decision and classification code is pure ✅ |
| III Honest | `tx_timestamping()` reports what is delivered; each stamp is labelled; the id mode falls back on evidence (the kernel's `EINVAL`), not by guessing ✅ |
| IV Real kernel | veth tests on both paths, including `etf` ✅ |
| V No steady-state allocation | Queue preallocated at open; cmsg buffers on the stack ✅ |
| VI Errors say what to do | `Unsupported` names transmit timestamps; an unknown interface is named ✅ |
| VII Breaking changes | `TxErrors` gains `timestamps_lost`; `hwtstamp::decide` changes (internal) ✅ |

## Project Structure

```text
src/hwtstamp.rs     # decide(current, want_rx, want_tx): widens rx NONE→ALL and tx OFF→ON only
src/packet.rs       # TxTimestamp; TxErrors::timestamps_lost; TimestampInfo
src/config.rs       # Config::tx_timestamping
src/lib.rs          # Socket::{tx_timestamp, next_tx_id, tx_timestamping}; timestamp_info(); docs
src/sys/mod.rs      # wait(fd, timeout, events)
src/sys/linux.rs    # flags, SCM_TS_OPT_ID sends (single, batch, launch time), id-mode fallback, report reader, ts_info
src/sys/bsd.rs      # Unsupported for transmit stamps; timestamp_info (software receive)
src/sys/unsupported.rs
tests/veth.rs       # transmit-timestamp tests
examples/txstamp.rs # send frames and print their transmit timestamps
README.md, CHANGELOG.md, THREAT_MODEL.md (T-16 misattribution, T-12 extended), site timestamps/linux/faq
```

## Complexity Tracking

None.
