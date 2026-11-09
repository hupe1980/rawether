# Implementation Plan: Ethernet frame views and frame building

**Branch**: `002-ethernet-frames` (directory identity) | **Date**: 2026-11-09 | **Spec**: [spec.md](spec.md)

## Summary

A new pure module, `src/frame.rs`, adds three things, all without `unsafe`, allocation or
panics, and the same on every platform:

- `Frame<'a>`: a `Copy` view over `&'a [u8]` with `destination`, `source`, `vlan_tags`,
  `ethertype` and `payload`. It parses at most two tags, with the TPIDs the EtherType filter
  uses, so the filter and the view always agree.
- `VlanTag`: a TPID kind plus a checked TCI.
- `FrameBuilder`: writes a frame either into a `Vec<u8>` that is reused (cannot fail) or into a
  fixed `&mut [u8]` (returns the length, or `InvalidInput` when the slice is too small).

`Packet::frame()` returns `Option<Frame<'a>>`. `Frame::reply(from)` returns a `FrameBuilder`
addressed back to the sender, or `None` when the sender's address is a group address. The
examples, README and site guides switch to the new API.

## Technical Context

**Language/Version**: Rust 1.88 (MSRV), edition 2024
**Primary Dependencies**: `libc` 0.2 only; this feature adds none
**Storage**: N/A
**Testing**: `cargo test` (unit, exhaustive small-input, randomised with a fixed-seed xorshift, round trip, filter/view agreement through `bpf::Program::run`), doc tests, the counting-allocator test in `tests/veth.rs` extended with the builder
**Target Platform**: every target (pure code); behaviour identical on Linux, macOS and FreeBSD
**Project Type**: library
**Performance Goals**: a view is O(1), at most three 16-bit reads; building is one `memcpy` of the payload plus header writes; no allocation once the buffer has capacity
**Constraints**: no `unsafe`; no panic on any input (indexing only through `get`/checked lengths); no EtherType or protocol constants (constitution I); public types `Debug`, `Clone`, `Copy` where small; `#[must_use]` on builders
**Scale/Scope**: about 350 lines of code and tests; 4 examples or guides rewritten

## Constitution Check

| Principle | Plan |
|---|---|
| I Generic, nothing above layer 2 | The Ethernet header and 802.1Q/802.1ad tags *are* layer 2. No EtherType constants: the tag kind is an enum (`TagKind::Customer`/`Service`), the EtherType a caller's `u16`. No payload parsing ✅ |
| II `unsafe` confined | `src/frame.rs` has no `unsafe`; it carries `#![forbid(unsafe_code)]` at module level ✅ |
| III Honest | The view reports what is on the wire: a third TPID is reported as the EtherType, an 802.3 length is reported unchanged; nothing is relabelled ✅ |
| IV Real kernel | Pure code, unit-tested everywhere. Agreement with the kernel filter is checked through the interpreter that mirrors it, and the veth suite's flood test reads frames through the view ✅ |
| V No steady-state allocation | View borrows; `write` reuses `Vec` capacity; `write_into` never allocates; the counting-allocator test covers a build-and-send loop ✅ |
| VI Errors say what to do | Out-of-range tag fields: `InvalidInput` naming the field and limit. Slice too small: `InvalidInput` naming the size needed. Short frames: `None`, documented ✅ |
| VII Breaking changes | Additive only. CHANGELOG `Added` ✅ |

Post-design re-check: no change.

## Project Structure

### Documentation (this feature)

```text
specs/002-ethernet-frames/
├── spec.md · plan.md · research.md · data-model.md · quickstart.md
├── contracts/api.md
├── threat-model.yaml · threat-model.md · security/
└── tasks.md   (/speckit-tasks)
```

### Source Code

```text
src/frame.rs          # NEW: Frame<'a>, VlanTag, TagKind, FrameBuilder (pure, forbid(unsafe))
src/lib.rs            # mod frame; re-export Frame, FrameBuilder, TagKind, VlanTag; crate docs example
src/packet.rs         # Packet::frame()
examples/sniff.rs     # read through Frame
examples/lldp.rs      # build with FrameBuilder, read with Frame
examples/echo.rs      # Frame::reply + FrameBuilder::write into reused buffers
tests/veth.rs         # build frames with FrameBuilder; view received ones; allocation test covers build+send
README.md · CHANGELOG.md · THREAT_MODEL.md (T-03 extended; T-10 reply reflection; T-11 stale buffer bytes)
site/content/_index.md · docs/{getting-started,receiving,sending,filtering,threat-model}.md
```

**Structure Decision**: one new module in the existing single library crate, re-exported at the root like `MacAddr` and `Packet`.

## Complexity Tracking

No constitution violations.
