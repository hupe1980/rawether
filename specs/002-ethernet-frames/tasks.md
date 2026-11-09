---
description: "Tasks for 002 — Ethernet frame views and frame building"
---

# Tasks: Ethernet frame views and frame building

**Input**: plan.md, spec.md, research.md, data-model.md, contracts/api.md, quickstart.md
**Tests**: required (spec SC-001…SC-005; SR-001…SR-006; constitution IV, V).
**Markers**: test doc comments cite `Spec 002 SR-00N` so converge finds the evidence.

## Phase 1: Setup

- [X] T001 Create src/frame.rs with module docs and `#![forbid(unsafe_code)]`, declare `pub mod frame;` in src/lib.rs and re-export `Frame`, `FrameBuilder`, `TagKind`, `VlanTag` at the crate root

## Phase 2: Foundational (blocks every story)

- [X] T002 [P] [SR-003] src/frame.rs: `TagKind { Customer, Service }` with `tpid()` (0x8100, 0x88A8, plus a private `from_tpid`); `VlanTag` with `new(kind, pcp, dei, vid) -> io::Result` ("refuses a PCP above 7 or a VID above 4095" with `InvalidInput` naming the field and limit; "VID 0 and 4095 accepted"), `from_tci` (any `u16`), `kind`/`tci`/`pcp`/`dei`/`vid`; unit tests: limits, the TCI bit layout (`pcp << 13 | dei << 12 | vid`), and VID 4095 + PCP 7 + DEI = TCI 0xFFFF
- [X] T003 [P] src/frame.rs: `pub const MIN_FRAME_LEN: usize = 60` (Ethernet minimum without FCS), documented with research R3

## Phase 3: User Story 1 — read a frame's header without slicing (P1) 🎯 MVP

**Goal**: `Frame::new(&[u8])` and `Packet::frame()` give destination, source, tags, EtherType and payload, or `None`.
**Independent test**: `cargo test --lib frame`, with no socket and no privilege.

- [X] T004 [US1] [SR-001] [SR-002] src/frame.rs: `Frame<'a>` (`Copy`) with `new` (None if `len < 14`, or `< 14 + 4 × tags` for each announced tag; at most two tags, TPIDs 0x8100/0x88A8 only, in any order; a third TPID is reported as the EtherType), `destination`, `source`, `vlan_tags` (outer first), `ethertype`, `header_len`, `payload`, `as_bytes`. Read only through `get`/checked slices, with no indexing that can panic
- [X] T005 [US1] [SR-006] src/frame.rs: rustdoc on `Frame` and `payload` saying that the payload includes padding, that for a truncated packet it covers only the captured octets (see `Packet::is_truncated`), and that values below 0x0600 are 802.3 lengths, reported unchanged
- [X] T006 [US1] [SR-006] src/packet.rs: `Packet::frame(&self) -> Option<Frame<'a>>`, with rustdoc pointing to `is_truncated`
- [X] T007 [US1] [SR-001] src/frame.rs tests: exhaustive over every slice length 0..=24 with 0x8100/0x88A8/other at offsets 12 and 16 (no panic; a view exactly when the announced header fits), plus a fixed-seed xorshift run of 100 000 slices up to 1600 octets that reads every accessor and checks the payload lies inside the slice
- [X] T008 [US1] [SR-002] src/frame.rs tests: for frames with 0–3 tags of either TPID and sets S without a TPID, whenever `Program::ethertypes(S).run(frame) != 0` then `Frame::new(frame).ethertype()` is in S, and vice versa for the inner type
- [X] T009 [US1] src/frame.rs tests: acceptance scenarios 1–3 of story 1 (untagged; 802.1ad outer + 802.1Q inner with PCP/DEI/VID; 13 octets and 16 octets announcing a tag give `None`)

## Phase 4: User Story 2 — build a frame into a reusable buffer (P1)

**Goal**: `FrameBuilder` writes header, tags, EtherType and zero-padded payload into a `Vec` or a fixed slice.
**Independent test**: round trip through `Frame::new`; byte-exact comparisons; the allocation test.

- [X] T010 [US2] [SR-004] src/frame.rs: `FrameBuilder` (`Copy`, `#[must_use]`) with `new(dst, src, ethertype)`, `vlan(tag)` and `vlans(outer, inner)` (each replaces the tags set before), `header_len`, `frame_len(payload_len)` = `max(header_len + payload_len, 60)`, a private `fill(&self, out: &mut [u8], payload)` that writes exactly `frame_len` octets and zero padding, `write(&mut Vec<u8>, payload)` (clear, `resize(frame_len, 0)`, fill; no allocation within capacity), and `write_into(&mut [u8], payload) -> io::Result<usize>` (`InvalidInput` naming the size needed when too small, without writing)
- [X] T011 [US2] [SR-004] src/frame.rs tests: a `Vec` prefilled with 1518 × 0xAA and a 5-octet payload gives 60 octets with octets 19..60 zero; the same for `write_into` on a 1518-octet slice (returns 60, `buf[19..60]` zero); a too-small slice gives `InvalidInput` and leaves the slice unchanged
- [X] T012 [US2] src/frame.rs tests: acceptance 1–3 of story 2 (60-octet padded frame; 1500-octet payload + one tag = 1518 octets, unpadded; shrinking reuse), and round trip for 0/1/2 tags and payload lengths 0, 1, 46, 47, 1500 (SC-002)
- [X] T013 [US2] tests/veth.rs: build the suite's test frames with `FrameBuilder` (`frame()` helper), read received ones through `Packet::frame()`, assert in the tagged-frame test that a packet whose tag was restored shows that tag (VID, PCP) through `p.frame().vlan_tags()` (US1 scenario 4), and extend `the_steady_state_does_not_allocate` with a build-into-reused-`Vec`-and-send loop (SC-003)

## Phase 5: User Story 3 — answer a received frame (P2)

**Goal**: `Frame::reply(from)` builds the answer; a group source gives `None`.
**Independent test**: unit tests; the `echo` example.

- [X] T014 [US3] [SR-005] src/frame.rs: `Frame::reply(&self, from: MacAddr) -> Option<FrameBuilder>`: destination = `self.source()`, source = `from`, same tags and EtherType; `None` when `self.source().is_multicast()` (the group bit, which also covers broadcast)
- [X] T015 [US3] [SR-005] src/frame.rs tests: replies to an untagged and to a VID 100 frame (addresses, tags, EtherType, payload); `None` for sources ff:ff:ff:ff:ff:ff and 01:00:5e:00:00:01
- [X] T016 [US3] examples/echo.rs: answer with `p.frame()` → `f.reply(me)` → `write(&mut replies[n], f.payload())`, reusing the 32 buffers; no header index arithmetic

## Phase 6: User Story 4 — examples and guides read like the protocol (P3)

- [X] T017 [P] [US4] examples/sniff.rs: print through `Frame` (addresses, VLAN ids, EtherType), and skip frames without a view instead of the manual length check
- [X] T018 [P] [US4] examples/lldp.rs: build the announcement with `FrameBuilder` and read neighbours with `Frame::payload()`; the TLV code stays in the example (constitution I)
- [X] T019 [P] [US4] src/lib.rs: crate-level docs example and a "Frames" section linking `Frame` and `FrameBuilder`
- [X] T020 [P] [US4] README.md: the receive example prints the source and EtherType through `p.frame()`; a send example uses `FrameBuilder`; the feature list mentions header views and the builder
- [X] T021 [P] [US4] [SR-006] site/content/docs/receiving.md ("Reading the header" section with `Frame`, padding and truncation notes), site/content/docs/sending.md (builder, `write` vs `write_into`, reply), site/content/docs/getting-started.md (receive and send snippets), site/content/_index.md (hero example), site/content/docs/filtering.md (view and filter agree on tags)
- [X] T022 [P] [US4] THREAT_MODEL.md and site/content/docs/threat-model.md: extend T-03 (the view is total); add T-10 "Replying to a group source address" (mitigated, `Frame::reply` returns None) and T-11 "Earlier frame bytes in a reused buffer" (mitigated, zero padding), each with its guarding test name

## Phase 7: Polish & cross-cutting

- [X] T023 CHANGELOG.md `[Unreleased] → Added`: `Frame`, `VlanTag`, `TagKind`, `FrameBuilder`, `Packet::frame`, `MIN_FRAME_LEN`
- [X] T024 Compile-check every site snippet that uses the new API (scratch crate), and run `grep -nE 'd\[(6|12)' examples README.md site/content` to show nothing is left, and compare the line count of the echo example's receive-and-reply loop before and after (at least a third shorter) (SC-004)
- [X] T025 Run `just ci site` and `scripts/veth-test.sh --docker`, and record the results for converge (SC-005)
- [X] T026 specs/README.md: add 002 to the index

## Dependencies

T001 → T002, T003 → US1 (T004–T009) → US2 (T010–T013; round trip needs `Frame`) → US3 (T014–T016;
reply needs both) → US4 (T017–T022) → Polish. Within US1, T004 comes before T005–T009. T017–T022
run in parallel.

## Parallel example

```text
After T010: T011 and T012 together. After T016: T017, T018, T019, T020, T021 and T022 together.
```

## Implementation strategy

MVP = US1 (the read side removes the panics). US2 and US3 complete the developer experience,
and US4 makes it visible. Each phase ends with `cargo test` green.
