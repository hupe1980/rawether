## Security Convergence — 001-raw-l2-crate

Commit `307f8e8` · 2026-11-09T10:49:21Z

| Metric | Value |
|---|---|
| Threats (active) | 9 |
| Open blocking threats | 0  |
| Security requirements | 9 |
| verified | 8 |
| implemented, unverified | 1 SR-009 |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: NOT CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `src/ring.rs::tests::offsets_that_point_outside_the_block_end_the_walk` | Synthetic blocks with a frame claiming 100000 octets and a first-frame offset past the end end the walk and skip the rest; a block with status 0 yields no cursor (a_block_still_owned_by_the_kernel_is_not_read). The ring path of the veth suite (8/8) reads real blocks through the same walker. |
| SR-002 | verified | test | `src/lib.rs::Socket::recv (compile_fail doctest)` | The doctest calls recv twice while the first Packet is alive and is required not to compile; cargo test --doc reports it compile-fail ok. The ring is released only at the next recv (src/sys/linux.rs ring_next). |
| SR-003 | verified | test | `src/vlan.rs::tests::reinsertion_is_total_over_small_inputs; tests/veth.rs::a_short_snap_length_marks_the_frame_truncated_with_its_wire_length` | Exhaustive over buffers up to 24 octets and every start/length: either the tag lands inside the buffer with the rest intact or the buffer is untouched; no panic. tests/veth.rs::only_the_chosen_ethertypes_arrive_tagged_or_not_each_with_a_timestamp asserts wire length equals captured length and the tag position on real frames, on both receive paths. A filter returning a 20-octet snap length yields data of 20 and a wire length of 60, flagged truncated, on the ring and the plain path. |
| SR-004 | verified | test | `tests/veth.rs::only_the_chosen_ethertypes_arrive_tagged_or_not_each_with_a_timestamp` | A frame of another EtherType sent first is not delivered; src/bpf.rs::tests::the_builder_refuses_what_the_kernel_would rejects empty, oversized, out-of-range-jump, bad-scratch and no-return programs. The open sequence creates the socket with protocol 0 and attaches the filter before bind (src/sys/linux.rs open). |
| SR-005 | verified | test | `tests/veth.rs::dropping_capabilities_keeps_open_sockets_and_names_the_capability_when_opening` | In a child process: after drop_capabilities, CapEff and CapPrm in /proc/thread-self/status are zero, the already open socket sends and receives, and a new open fails PermissionDenied naming CAP_NET_RAW. Passed on ring and plain paths. |
| SR-006 | verified | test | `tests/veth.rs::every_descriptor_is_close_on_exec` | F_GETFD on an open Linux socket has FD_CLOEXEC; the BSD backend opens /dev/bpf with O_CLOEXEC and sets FD_CLOEXEC on its membership socket (src/sys/bsd.rs open_device, join_groups) — reviewed, not run on BSD. |
| SR-007 | verified | test | `src/lib.rs::tests::the_default_configuration_is_neither_promiscuous_nor_all_multicast` | Config::new leaves both flags false; the backends enable them only from those flags. |
| SR-008 | verified | test | `tests/veth.rs::a_hundred_thousand_frames_are_received_or_counted_as_dropped` | 100000 frames sent in batches; received plus stats().dropped equals 100000 and stats().received equals the frames seen, on both receive paths. Sparse traffic is kept: 50 frames 3 ms apart all wait in the ring while the reader is busy (sparse_frames_wait_in_the_ring_while_the_reader_is_busy). |
| SR-009 | implemented-unverified | review | `src/sys/linux.rs:send_at` | Scenario 1 passed (send_at without tx_time is InvalidInput, tests/veth.rs::launch_time_needs_configuration_and_a_qdisc_that_honours_it). Scenario 2 (etf drops a past launch time and tx_errors counts it) is implemented and tested, but the test skipped: the local Docker kernel has no sch_etf. It runs in the ubuntu-24.04 CI lane. |
