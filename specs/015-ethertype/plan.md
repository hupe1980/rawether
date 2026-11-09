# Implementation Plan: Typed EtherType names

**Branch**: `015-ethertype` | **Date**: 2026-11-09 | **Spec**: [spec.md](spec.md)

## Summary

A new `src/ethertype.rs` adds `#[repr(transparent)] pub struct EtherType(pub u16)` with 21
named constants. Each constant is checked against the IEEE registry or the Linux
`<linux/if_ether.h>` header that mirrors it; GOOSE, GSE and SV are IEEE assignments to IEC
TC57. The type gets `name()`, `is_length()`, `Display`/`Debug` (`PTP (0x88f7)`), and
conversions to and from `u16`.

`Config::ethertypes` and `bpf::Program::ethertypes` take
`impl IntoIterator<Item = impl Into<EtherType>>`, so names, numbers and slices all work.
`Filter::EtherTypes` holds `Vec<EtherType>`. `Frame::ethertype()` returns `EtherType`.
`FrameBuilder::new` takes `EtherType` and stays `const`. Examples, tests, README, site and
rustdoc switch to names.

## Constitution Check

Principle I (2.0.0) asks for names only, each citing its source, and no payload items ✅. The
other principles are unaffected. Principle VII: the CHANGELOG records the hard cut ✅.

## Project Structure

`src/ethertype.rs` (new), `src/lib.rs`, `src/config.rs`, `src/bpf.rs`, `src/frame.rs`,
`examples/*`, `tests/*`, `fuzz/fuzz_targets/frame_view.rs`, README, site, CHANGELOG.

## Complexity Tracking

None.
