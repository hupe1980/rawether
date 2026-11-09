# Tasks: Typed EtherType names

- [X] T001 [SR-001] [SR-002] src/ethertype.rs: `EtherType(pub u16)` (`repr(transparent)`, Copy/Eq/Ord/Hash), the 21 constants of research.md with their source in rustdoc, `name()`, `is_length()`, `Display`/`Debug`, `From<u16>`/`From<EtherType> for u16`; table test against research.md, uniqueness, VLAN/QINQ = TagKind TPIDs; Display/is_length tests
- [X] T002 src/config.rs, src/bpf.rs: `ethertypes(impl IntoIterator<Item = impl Into<EtherType>>)`; `Filter::EtherTypes(Vec<EtherType>)`; test that names and numbers give identical programs
- [X] T003 src/frame.rs: `Frame::ethertype() -> EtherType`; `FrameBuilder::new(.., EtherType)`; tests updated
- [X] T004 src/lib.rs: re-export, crate docs example with names
- [X] T005 examples, tests/veth.rs, tests/drop_capabilities.rs, fuzz/fuzz_targets/frame_view.rs: use the type and names
- [X] T006 README, site (landing, getting-started, filtering, receiving, sending, event-loops, launch-time), CHANGELOG: names in every snippet
- [X] T007 `just ci site`, veth suite, Miri
