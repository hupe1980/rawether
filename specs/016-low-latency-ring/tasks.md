# Tasks: Low-latency frame ring

- [X] T001 src/config.rs: `FrameRingConfig { frame_size, frame_count }` (default 2 048 × 4 096), `RxMode::FrameRing`, `RxMode::low_latency()`; `validate`: frame_size a multiple of 16 in 128..=65 536, frame_count ≥ 1, sizes without overflow (unit tests for each refusal, FR-005); src/packet.rs: `RxPath::FrameRing`
- [X] T002 [SR-001] src/ring.rs: `frame2` layout and `FrameMeta::read_v2(slot)`; unit tests: a good slot, tp_mac below the header, snaplen past the slot, kernel-owned status
- [X] T003 [SR-001] [SR-002] src/sys/linux.rs: `FrameRing` (setup with TPACKET_V2, PACKET_RESERVE, PACKET_TIMESTAMP, tpacket_req, mmap with MAP_LOCKED fallback, free on failure); `frame_ring_next` (acquire status, skip outgoing, VLAN re-insertion in the head-room, timestamps, release on next receive); recv, rx_path; explicit failure → error
- [X] T004 src/sys/bsd.rs: FrameRing uses the BPF path
- [X] T005 [SR-001] src/lib.rs fuzzing hook and fuzz/fuzz_targets/ring_walk.rs read V2 slots too
- [X] T006 [SR-002] tests/veth.rs `RAWETHER_RX=frame`; scripts/veth-test.sh runs ring, plain and frame
- [X] T007 bench: a frame-ring receiver; rerun; site performance page, receiving (paths table, latency guidance), linux.md, how-it-works, README, CHANGELOG, THREAT_MODEL T-01
- [ ] T008 Gates, Miri, fuzz, veth; converge
