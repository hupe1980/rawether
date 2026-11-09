# Feature Specification: Typed EtherType names

**Feature Branch**: `015-ethertype` (directory identity; no git branch)
**Created**: 2026-11-09
**Status**: Draft
**Input**: Maintainer brief (constitution 2.0.0, principle I): filters, frames and logs use bare
numbers (`.ethertypes(&[0x88cc, 0x88f7])`, `type 88f7`). Make EtherTypes a type with names for
the well-known ones, as best-in-class Ethernet crates do, without parsing anything after the
EtherType. Hard cut allowed.

## User Scenarios & Testing

### User Story 1 - Filter and build with names (Priority: P1)

A developer writes `.ethertypes([EtherType::LLDP, EtherType::PTP])` and
`FrameBuilder::new(dst, src, EtherType::GOOSE)`; any other value still works as
`EtherType(0x88b5)` or a plain `0x88b5`.

**Why this priority**: the readability gain, everywhere frames are filtered or built.

**Independent Test**: filters built from names and from numbers are identical programs; built
frames carry the value.

**Acceptance Scenarios**:

1. **Given** names, numbers or a mix, **When** a filter is built, **Then** it accepts exactly
   those EtherTypes, as before.
2. **Given** an unnamed value, **When** it is used anywhere, **Then** it behaves like a named one.

### User Story 2 - Read and log with names (Priority: P1)

`frame.ethertype()` returns the type; printing it shows `PTP (0x88f7)` for a named value and
`0x88b5` for an unnamed one; `is_length()` tells an 802.3 length from a type.

**Why this priority**: logs and test failures become readable; lengths stop masquerading as
types.

**Independent Test**: unit tests of `Display`, `Debug`, `name` and `is_length`.

**Acceptance Scenarios**:

1. **Given** 0x88f7, **When** printed, **Then** `PTP (0x88f7)`; **Given** 0x0050, **Then**
   `is_length()` is true.

### User Story 3 - Names that can be trusted (Priority: P1)

Every named constant has the value the IEEE registry (or the Linux header that mirrors it)
assigns, and the VLAN tag identifiers agree with `TagKind`.

**Why this priority**: a wrong constant would make a filter admit the wrong traffic.

**Independent Test**: a table test of every constant against its registry value and source.

**Acceptance Scenarios**:

1. **Given** the set of named constants, **When** the table test runs, **Then** every value
   matches its cited source and no two names share a value.

### Edge Cases

- Values below 0x0600 are 802.3 lengths, not types: printed as numbers, `is_length()` true.
- 0x9100 (pre-standard Q-in-Q) is not named: it is not a registered type.
- Tag identifiers 0x8100 and 0x88A8 are named (`VLAN`, `QINQ`) and equal `TagKind`'s TPIDs.

## Requirements

### Functional Requirements

- **FR-001**: rawether MUST provide an open EtherType type holding any 16-bit value, with named
  constants for a curated set of well-known types, each citing its registry source.
- **FR-002**: Filters, frame views and frame builders MUST use the type; filters MUST also
  accept plain numbers.
- **FR-003**: The type MUST print as name and value when named, and as value otherwise; it MUST
  say whether a value is an 802.3 length.
- **FR-004**: No item may read or build anything after the EtherType (constitution I).
- **FR-005**: Examples, README, site and rustdoc MUST use the names.

### Key Entities

- **EtherType**: a 16-bit value; optionally a name.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P2): Every named EtherType MUST equal its registry value, no two names MAY share a value, and VLAN/QINQ MUST equal TagKind's TPIDs.
  - Mitigates: `threat.wrong-constant-value` via `mitigation.registry-table-test`
  - Given the table of names, values and sources, when the test runs, then every constant matches, values are unique, VLAN = TagKind::Customer.tpid(), QINQ = TagKind::Service.tpid()
- **SR-002** (P2): A value below 0x0600 MUST report is_length() and MUST NOT print a protocol name.
  - Mitigates: `threat.length-read-as-type` via `mitigation.is-length`
  - Given 0x0050 and 0x05ff, when is_length and Display run, then true, and printed as numbers only
<!-- threatspec:end -->

## Success Criteria

### Measurable Outcomes

- **SC-001**: Every named constant matches its source (table test, 100%).
- **SC-002**: Filters from names and from numbers produce identical programs.
- **SC-003**: No bare EtherType number remains in examples, README and site where a name exists.

## Assumptions

- The curated set covers rawether's audience (IP basics, VLAN tags, discovery and timing,
  industrial and redundancy protocols, security, local experimental). More names are additive.
