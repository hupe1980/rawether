## Security Convergence — 016-low-latency-ring

Commit `4142732` · 2026-11-09T15:30:06Z

| Metric | Value |
|---|---|
| Threats (active) | 2 |
| Open blocking threats | 0  |
| Security requirements | 2 |
| verified | 2 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| covered by decision (not blocking) | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `src/ring.rs::tests::a_frame_ring_slot_is_read_only_when_it_holds_together; fuzz/fuzz_targets/ring_walk.rs (V2 slots, CI fuzz lane)` | Synthetic slots with tp_mac below the header, tp_mac or snaplen past the slot and kernel-owned status form no frame; random slots fuzzed 60 s in CI without panic. |
| SR-002 | verified | test | `tests/veth.rs with RAWETHER_RX=frame (scripts/veth-test.sh): a_hundred_thousand_frames_are_received_or_counted_as_dropped, sparse_frames_wait_in_the_ring_while_the_reader_is_busy` | On the frame ring received plus dropped equals sent for a 100 000-frame flood and later frames keep arriving; the held slot is released on the next receive and on drop. |
