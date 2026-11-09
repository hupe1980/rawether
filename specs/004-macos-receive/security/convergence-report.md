## Security Convergence — 004-macos-receive

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
| SR-001 | verified | test | `tests/bpf.rs::pair; CI macos-15, macos-26, FreeBSD 14 with RAWETHER_REQUIRE_PAIR=1` | pair() asserts when RAWETHER_REQUIRE_PAIR is set and no pair is named; CI sets it on all three BSD lanes, and the suite ran (6 tests) on each in PR #2. |
