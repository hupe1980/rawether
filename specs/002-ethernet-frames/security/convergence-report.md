## Security Convergence — 002-ethernet-frames

Commit `61e3733` · 2026-11-09T11:35:03Z

| Metric | Value |
|---|---|
| Threats (active) | 6 |
| Open blocking threats | 0  |
| Security requirements | 6 |
| verified | 6 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `src/frame.rs::tests::a_view_is_total_over_small_inputs; src/frame.rs::tests::a_view_never_panics_on_random_frames` | Every slice 0..=24 octets with each TPID/other word at offsets 12 and 16 is viewed and asserted to have a view exactly when 14 + 4 x tags fits; 100 000 random slices up to 1600 octets read every accessor and assert the payload lies inside the slice. Both pass (cargo test, 2026-11-09). |
| SR-002 | verified | test | `src/frame.rs::tests::the_view_and_the_ethertype_filter_agree` | For three TPID-free sets and every layout of 0-3 tags of either TPID with four inner types, asserts Program::ethertypes(S).run(frame) != 0 exactly when the view's EtherType is in S. Passes. |
| SR-003 | verified | test | `src/frame.rs::tests::a_tag_refuses_out_of_range_fields_and_lays_out_its_tci` | Asserts VlanTag::new refuses PCP 8 and VID 4096, and that VID 4095 + PCP 7 + DEI gives TCI 0xFFFF. Passes. |
| SR-004 | verified | test | `src/frame.rs::tests::building_replaces_the_buffer_and_pads_with_zeros` | A Vec and a fixed 1518-octet slice prefilled with 0xAA receive a 5-octet-payload frame; asserts length 60, octets 19..60 zero, nothing written past the frame, and a 59-octet slice yields InvalidInput naming 60 with the slice untouched. Passes. |
| SR-005 | verified | test | `src/frame.rs::tests::a_reply_goes_back_to_the_sender_and_never_to_a_group` | Asserts reply() is None for sources ff:ff:ff:ff:ff:ff and 01:00:5e:00:00:01, and that a unicast-sourced tagged frame gets a reply to its sender with the same tags and EtherType. Passes. |
| SR-006 | verified | review | `src/frame.rs (Frame::payload rustdoc); src/packet.rs (Packet::frame rustdoc); site/content/docs/receiving.md#reading-the-header` | The rustdoc of Frame::payload and Packet::frame both name Packet::is_truncated and say a truncated packet's payload is the captured part only; the receiving guide says the same. Acceptance is a documentation read, satisfied by review. |
