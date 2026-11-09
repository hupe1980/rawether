# Design records

Every change to rawether is specified, threat-modelled and verified before it ships. This
directory holds the record of each change, one numbered folder per change, written with
[Spec Kit](https://github.com/github/spec-kit) and its
[ThreatSpec](https://github.com/hupe1980/spec-kit-threatspec) extension.

These are **records of each change as it was made**: the state, the numbers and the open items
are those of that day. What rawether promises today is in the [README](../README.md), the
[threat model](../THREAT_MODEL.md), the [API documentation](https://docs.rs/rawether) and the
[website](https://hupe1980.github.io/rawether/). Where a record and those documents differ, the
documents are right.

## What a record holds

| File | What it is |
|---|---|
| `spec.md` | What the change must do and why: user stories, acceptance scenarios, requirements (`FR-…`), success criteria (`SC-…`), the decisions taken during clarification, and the security requirements (`SR-…`) derived from the threat model |
| `research.md` | The kernel interfaces and references the design rests on |
| `plan.md` | How it is built, checked against the [constitution](../.specify/memory/constitution.md) |
| `tasks.md` | The work, in order, each task tied to a story and its security requirements |
| `threat-model.yaml`, `threat-model.md` | The threat model ([Open Threat Model](https://github.com/iriusrisk/OpenThreatModel)-compatible), rendered for reading |
| `security/` | The check report, verdicts and the convergence report: how each security requirement was verified |
| `quickstart.md` | How to run the checks |
| `contracts/`, `data-model.md` | Interfaces and types |

## How a change is made

```text
specify ─▶ threat model ─▶ clarify ─▶ plan ─▶ threat model (from the plan)
        ─▶ tasks ─▶ check ─▶ analyze ─▶ implement ─▶ converge (security, then core)
```

ThreatSpec turns each threat into a chain that must close before a change is done:

```text
asset ─▶ threat ─▶ mitigation ─▶ security requirement (SR-…)
                                    ├──▶ task in tasks.md
                                    └──▶ verification: a test, a review or evidence
```

`check` finds any broken link (a threat without a mitigation, a requirement without a task);
`converge` records how each requirement was verified and is clean only when every one is. A
claim rawether makes about kernel behaviour is backed by a test on a real kernel (a veth pair),
never by the documentation alone.

## Index

### 0.1.0 (first release)

| Record | Change |
|---|---|
| [001-raw-l2-crate](001-raw-l2-crate/spec.md) | rawether 0.1.0 — raw layer-2 Ethernet I/O |
| [002-ethernet-frames](002-ethernet-frames/spec.md) | Ethernet frame views (`Frame`), frame building (`FrameBuilder`) and replies |
| [003-audit-remediation](003-audit-remediation/spec.md) | Audit remediation: FreeBSD receive, a process-wide capability drop, hardware timestamps that never lower the NIC's configuration, link-loss errors, checked arithmetic and control messages, Miri, fuzzing and a FreeBSD lane |

### 0.2.0

| Record | Change |
|---|---|
| [007-ptp-precision](007-ptp-precision/spec.md) | Transmit timestamps with exact ids, PTP hardware clock discovery |
| [015-ethertype](015-ethertype/spec.md) | Typed EtherType names (constitution 2.0.0) |
| [016-low-latency-ring](016-low-latency-ring/spec.md) | TPACKET_V2 frame ring: per-frame wakeup, zero-copy, no loss |
| [004-macos-receive](004-macos-receive/spec.md) | The BPF suite on macOS 15 and 26 and FreeBSD 14 |
| [006-bench](006-bench/spec.md) | Published receive benchmarks |
