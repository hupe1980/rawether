## Security Convergence — 007-ptp-precision

Commit `4142732` · 2026-11-09T15:30:06Z

| Metric | Value |
|---|---|
| Threats (active) | 6 |
| Open blocking threats | 0  |
| Security requirements | 6 |
| verified | 6 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| covered by decision (not blocking) | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `tests/veth.rs::transmit_timestamps_carry_the_announced_ids, ids_stay_exact_after_a_refused_send_and_reports_coexist (CI ubuntu-24.04 with RAWETHER_REQUIRE_ETF=1)` | 1 000 single and batched sends return exactly the announced ids; after an etf refusal the next 10 frames carry the ids announced for them, on all three receive paths in CI. |
| SR-002 | verified | test | `src/hwtstamp.rs::tests::the_nic_configuration_is_never_lowered` | Exhaustive over tx_type 0..=3, rx_filter 0..=15 and all requests: writes only widen rx NONE to ALL and tx OFF to ON. |
| SR-003 | verified | test | `tests/veth.rs::unread_transmit_timestamps_are_bounded_and_receiving_does_not_spin` | 2 000 unread stamps: recv waits about 200 ms with little CPU, at most 1 024 are queued, timestamps_lost counts the rest. |
| SR-004 | verified | test | `tests/veth.rs::ids_stay_exact_after_a_refused_send_and_reports_coexist (CI etf run)` | Through etf one refused launch time gives invalid = 1 and every sent frame keeps its timestamp, reading tx_errors and timestamps in either order. |
| SR-005 | verified | test | `src/sys/linux.rs::tests::a_short_control_message_is_skipped, only_launch_time_reports_are_counted, a_launch_time_and_an_id_fit_one_control_buffer` | Every payload is read through the checked cmsg reader; short and truncated control messages are skipped; the classifier counts only launch-time origins. |
| SR-006 | verified | review | `src/sys/bsd.rs open: tx_timestamping returns Unsupported naming transmit timestamps` | The BSD backend refuses tx_timestamping with ErrorKind::Unsupported and a message naming it; compiled and linted for macOS and FreeBSD in CI. |
