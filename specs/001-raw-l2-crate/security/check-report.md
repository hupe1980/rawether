## ThreatSpec Check Report

Feature: `001-raw-l2-crate` · Model: `threat-model.yaml` · Enforcement: `warn`

| ID | Check | Severity | Location | Summary | Recommendation |
|---|---|---|---|---|---|
| F1 | C9 | MEDIUM | `plan.md` | plan.md changed since the model was generated | Re-run the model command to refresh the threat model |
| F2 | C9 | MEDIUM | `spec.md` | spec.md changed since the model was generated | Re-run the model command to refresh the threat model |
| F3 | C6 | LOW | `threat-model.yaml#requirements` | 9 requirements have no verification entry yet (implementation not started): SR-001, SR-002, SR-003, SR-004, SR-005, SR-006, SR-007, SR-008, SR-009 | Expected before implementation; run the converge command afterwards |

**Metrics**

- threats: 9
- mitigations: 9
- requirements: 9
- requirements with tasks: 9
- requirements verified: 0
- decisions: 0
- threats by severity: high 2, low 2, medium 5
- findings: medium 2, low 1

**Next actions**

- Resolve HIGH findings before implementation; MEDIUM may proceed with a note.
