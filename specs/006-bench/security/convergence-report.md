## Security Convergence — 006-bench

Commit `4142732` · 2026-11-09T15:30:05Z

| Metric | Value |
|---|---|
| Threats (active) | 1 |
| Open blocking threats | 0  |
| Security requirements | 1 |
| verified | 1 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| covered by decision (not blocking) | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | review | `site/content/docs/performance.md against scripts/bench.sh --docker output of 2026-11-09` | All five rows equal the recorded harness run (block ring, frame ring, plain, pcap, pnet); the method lists the sender, the traffic shapes, the kernel filters per receiver and the end-of-run frames. |
