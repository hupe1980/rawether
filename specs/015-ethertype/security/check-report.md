## ThreatSpec Check Report

Feature: `015-ethertype` · Model: `threat-model.yaml` · Enforcement: `warn`

| ID | Check | Severity | Location | Summary | Recommendation |
|---|---|---|---|---|---|
| F1 | C6 | LOW | `threat-model.yaml#SR-001` | Requirement 'SR-001' has no verification entry (implementation not started) | Run the converge command after implementation or record evidence |
| F2 | C6 | LOW | `threat-model.yaml#SR-002` | Requirement 'SR-002' has no verification entry (implementation not started) | Run the converge command after implementation or record evidence |
| F3 | C9 | LOW | `plan.md` | plan.md was not hashed when the model was generated | Re-run the model command |

**Metrics**

- threats: 2
- mitigations: 2
- requirements: 2
- requirements with tasks: 2
- requirements verified: 0
- decisions: 0
- threats by severity: low 1, medium 1
- findings: low 3

**Next actions**

- Proceed.
