## Security Convergence — 003-audit-remediation

Commit `9692423` · 2026-11-09T12:33:51Z

| Metric | Value |
|---|---|
| Threats (active) | 12 |
| Open blocking threats | 0  |
| Security requirements | 12 |
| verified | 12 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `src/bpf_record.rs::tests::records_of_both_layouts_are_read; src/bpf_record.rs::tests::malformed_records_end_the_buffer; src/bpf_record.rs::tests::random_buffers_never_escape; fuzz target bpf_record` | Three FreeBSD (hdrlen 26) and three macOS (hdrlen 18) records are read back; hdrlen below the minimum, caplen past the buffer and every header cut end the parse; a final record shorter than the padded struct is read; 50 000 random buffers with both layouts stay inside; Miri clean; fuzzed 20 s locally without a finding. |
| SR-002 | verified | test | `tests/drop_capabilities.rs (run by scripts/veth-test.sh, Docker, 2026-11-09); src/sys/linux.rs::tests::a_thread_status_shows_whether_it_holds_capabilities` | With a second thread the call returns "1 other thread(s) still hold capabilities"; alone it succeeds, every /proc/self/task/*/status shows zero CapInh/CapPrm/CapEff/CapAmb and NoNewPrivs 1, CapBnd lacks bits 12 and 13 (root in Docker held CAP_SETPCAP), the socket still sends and receives, and a new socket is refused naming CAP_NET_RAW. |
| SR-003 | verified | test | `src/hwtstamp.rs::tests::the_nic_configuration_is_never_lowered; tests/veth.rs::hardware_timestamps_on_a_nic_without_them_report_software` | Exhaustive over flags x tx_type 0..=3 x rx_filter 0..=15 - a write keeps flags and tx_type and only changes NONE to ALL; an unreadable configuration gives Software and no write (decide(None)); on veth (no hwtstamp ioctl) the socket reports Software. The linux backend writes only on Plan::Widen (review of hardware_timestamps). |
| SR-004 | verified | test | `tests/veth.rs::a_link_going_down_ends_a_receive_and_frames_return_after_it_comes_up; tests/veth.rs::deleting_the_interface_ends_a_receive` | On ring and plain paths (Docker, 2026-11-09) a recv with a 5 s timeout returns an error naming the interface within 1 s of link down or deletion; after link up a frame is received; after deletion a later recv does not spin. |
| SR-005 | verified | test | `src/sys/linux.rs::tests::a_short_control_message_is_skipped` | A cmsg whose cmsg_len is shorter than [timespec; 3] is skipped and a full-length one read (Linux unit tests in Docker); MSG_CTRUNC causes every message to be ignored in plain_next and drain_error_queue (review, src/sys/linux.rs). |
| SR-006 | verified | review | `src/sys/linux.rs (Ring::block returns &[u8]; Ring::frame_mut borrows only start-4..start+len; ring_next); Miri on ring and vlan tests` | The walker reads through Ring::block (shared); VLAN re-insertion gets a &mut over the frame and its head-room only; Miri reports no UB on the pure ring/vlan modules. |
| SR-007 | verified | review | `src/sys/bsd.rs hardware_address` | The MAC is copied with ptr::copy_nonoverlapping from ifa_addr.cast::<u8>() + offset_of!(sockaddr_dl, sdl_data) + sdl_nlen, bounded by sdl_len; no &sockaddr_dl spans the read; the macOS lo0 test still opens. |
| SR-008 | verified | test | `src/sys/mod.rs::tests::waits_never_overflow_and_round_up; src/config.rs::tests::a_configuration_is_checked_before_any_system_call; src/bpf.rs::tests::a_far_jump_is_refused_on_every_pointer_width; tests/veth.rs::a_huge_timeout_waits_and_an_impossible_ring_is_refused` | Duration::MAX gives no deadline and recv returns; overflowing ring geometries are InvalidInput; a ja with k = u32::MAX is refused and run uses checked_add; clippy passes on i686. |
| SR-009 | verified | test | `tests/veth.rs::a_huge_timeout_waits_and_an_impossible_ring_is_refused` | RxMode::Ring with a 2 KiB block (not a page multiple) fails open with InvalidInput on both runs; Auto keeps its fallback (review of open). |
| SR-010 | verified | review | `src/sys/bsd.rs open (BIOCSDIRECTION, BPF_D_IN); src/sys/bsd.rs::tests::locally_defined_ioctls_match_the_headers` | On FreeBSD without see_outgoing, BIOCSDIRECTION (0x80044277 = _IOW('B', 119, u_int), checked against FreeBSD's bpf.h) is issued with BPF_D_IN and its error returned; builds with clippy for x86_64-unknown-freebsd. |
| SR-011 | verified | test | `tests/veth.rs::launch_time_needs_configuration_and_a_qdisc_that_honours_it (CI run https://github.com/hupe1980/rawether/actions/runs/42617140283, ubuntu-24.04 with sch_etf, RAWETHER_REQUIRE_ETF=1, both receive paths, commit 9692423); src/sys/linux.rs::tests::only_launch_time_reports_are_counted` | On a kernel with etf, a past launch time makes send_at fail naming the launch time and tx_errors report invalid = 1, missed = 0, then 0 after draining; a future launch time leaves after >= 40 ms; classification ignores non-TXTIME origins (unit test). |
| SR-012 | verified | review | `src/sys/bsd.rs (recv increments delivered; stats returns delivered and bs_drop); src/packet.rs Stats rustdoc` | received counts records handed out by recv, all of which passed the in-kernel filter; dropped is bs_drop; the rustdoc states the meaning and what is excluded. bd_rcount being pre-filter was read in FreeBSD and xnu bpf.c (research R9). |
