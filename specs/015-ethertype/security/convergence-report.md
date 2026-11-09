## Security Convergence — 015-ethertype

Commit `8fa8759` · 2026-11-09T14:08:27Z

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
| SR-001 | verified | test | `src/ethertype.rs::tests::every_name_has_its_registry_value` | All 21 constants equal the registry table in research.md (Linux if_ether.h and IEEE assignments for IEC 61850), values are unique, VLAN and QINQ equal TagKind's TPIDs; name() round-trips. |
| SR-002 | verified | test | `src/ethertype.rs::tests::lengths_and_unnamed_values_print_as_numbers` | 0x0000, 0x0050 and 0x05ff report is_length() and no name and print as numbers; 0x0600 is not a length; 0x9100 is unnamed. |
