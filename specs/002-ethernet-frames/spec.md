# Feature Specification: Ethernet frame views and frame building

**Feature Branch**: `002-ethernet-frames` (directory identity; no git branch)
**Created**: 2026-11-09
**Status**: Clarified
**Input**: Maintainer brief: every rawether user hand-slices the Ethernet header out of
`Packet::data()` (`MacAddr([d[6], d[7], …])`, `u16::from_be_bytes([d[12], d[13]])`) — the
crate's own examples and documentation included. That is verbose, easy to get wrong behind VLAN
tags, and panics on a short or truncated frame (threat model T-03, hostile frame shapes).
Building a frame to send is just as manual. Add a small, allocation-free, panic-free layer-2
view and builder, plus a way to answer a received frame, and use them in the examples and
guides. No parsing above the Ethernet header; no new dependency; identical on every platform.

## Clarifications

### Session 2026-11-09

- Q: How should a received Packet expose its Ethernet header? → A: One accessor that returns
  the optional view (the same view type as for any byte slice); no per-field shortcuts on
  `Packet`.
- Q: Into what kind of buffer should the frame builder write? → A: Both: a growable buffer the
  builder clears and refills (no size error), and a fixed slice that returns the frame's length
  or an error when the slice is too small.

## User Scenarios & Testing

### User Story 1 - Read a frame's Ethernet header without slicing (Priority: P1)

A developer receives a frame and wants its destination, source, VLAN tags, EtherType and
payload. They ask the received packet (or any byte slice holding a frame) for its Ethernet view
and read named fields. A frame too short to hold the header it announces yields "no view"
instead of a panic.

**Why this priority**: every receiving program needs this first; it removes the most common
source of panics on hostile input and the most repeated boilerplate.

**Independent Test**: unit tests over byte arrays — untagged, single-tagged (802.1Q and
802.1ad), double-tagged, and every length from 0 to the full header — with no socket and no
privileges, on any platform.

**Acceptance Scenarios**:

1. **Given** an untagged 60-octet frame, **When** its view is taken, **Then** destination,
   source and EtherType match octets 0–5, 6–11 and 12–13, there are no tags, and the payload is
   octets 14 onwards.
2. **Given** a frame with an 802.1ad outer tag and an 802.1Q inner tag, **When** its view is
   taken, **Then** both tags are reported in wire order with their priority (PCP), drop-eligible
   bit (DEI) and VLAN id (VID), and the EtherType and payload are the ones after the inner tag.
3. **Given** any byte slice shorter than its announced header (for example 13 octets, or 16
   octets announcing a tag), **When** its view is taken, **Then** there is no view and nothing
   panics.
4. **Given** a received packet whose VLAN tag the driver had stripped and rawether restored,
   **When** its view is taken, **Then** the tag is reported as if it had never been stripped.

### User Story 2 - Build a frame to send into a reusable buffer (Priority: P1)

A developer sends frames of their own protocol. They describe destination, source, optional
tags, EtherType and payload, and the builder writes the frame into a buffer they own and reuse,
padded to the Ethernet minimum, ready for `send` or `send_batch`.

**Why this priority**: every sending program needs it; hand-built headers are where byte-order
and padding mistakes happen.

**Independent Test**: build frames into a buffer and compare with hand-written bytes; read them
back through the view of story 1 (round trip); count allocations across a loop that reuses the
buffer.

**Acceptance Scenarios**:

1. **Given** destination, source, EtherType 0x88B5 and a 5-octet payload, **When** the frame is
   built, **Then** it is 60 octets: the 14-octet header, the payload, and zero padding.
2. **Given** a 1500-octet payload and one tag, **When** the frame is built, **Then** it is
   1518 octets and not padded.
3. **Given** a buffer already used for a larger frame, **When** a smaller frame is built into
   it, **Then** the buffer holds exactly the new frame, and no allocation happens.
4. **Given** a VLAN id above 4095 or a priority above 7, **When** a tag is made from those
   fields, **Then** it is refused, not silently truncated.

### User Story 3 - Answer a received frame (Priority: P2)

A developer writes a responder (an echo service, a discovery reply, a test reflector). Given a
received frame and the socket's own address, they build the answer in one call: addressed back
to the sender, from this interface, with the same VLAN tags and EtherType, and their payload.

**Why this priority**: it removes the remaining manual header work from responders; it is
optional for programs that only send or only receive.

**Independent Test**: build replies to untagged and tagged frames and check addresses, tags,
EtherType and payload; the `echo` example uses it and allocates nothing in its loop.

**Acceptance Scenarios**:

1. **Given** a received frame from A to B with tag VID 100 and EtherType X, **When** a reply is
   built from address C with payload P, **Then** it goes from C to A with tag VID 100,
   EtherType X and payload P.
2. **Given** a received frame too short to have a view, **When** a reply is requested, **Then**
   none is built and nothing panics.

### User Story 4 - Examples and guides read like the protocol (Priority: P3)

A developer reading the README, the examples or the website sees named header fields, not
index arithmetic, and copies code that cannot panic on a short frame.

**Why this priority**: the documentation is how most users meet the API; it only follows once
stories 1–3 exist.

**Independent Test**: no example, README snippet or website guide indexes into a frame's
header by hand; every snippet compiles.

**Acceptance Scenarios**:

1. **Given** the examples `sniff`, `lldp` and `echo`, **When** they are read, **Then** they use
   the view and the builder and contain no header index arithmetic.

### Edge Cases

- **Tag count**: at most two tags are interpreted (an outer 802.1ad or 802.1Q tag, then an
  802.1Q tag). A third tag protocol identifier after two tags is reported as the EtherType, as
  it is on the wire; nothing is guessed.
- **802.3 length field**: a value below 0x0600 in the EtherType position is a length, not a
  type. It is reported unchanged; telling the two apart is the caller's protocol knowledge.
- **Padding**: on receive, the payload is everything after the EtherType, including any padding
  the sender added; the Ethernet header does not say how much of it is padding.
- **Truncated packets**: the view covers the captured octets. A packet cut short by a filter
  still has a view if its header was captured; its payload is then the captured part, and
  `Packet::is_truncated()` says so.
- **Tagged minimum size**: the builder pads to 60 octets (64 with the frame check sequence the
  NIC adds), whether or not the frame carries tags.
- **Fixed slice too small**: building into a slice shorter than the frame (header, tags,
  payload, padding) is an error that names the size needed; the caller's slice is not reported
  as holding a frame.
- **Oversized payload**: the builder does not enforce an MTU; the kernel refuses a frame too
  large for the interface when it is sent, as today.

## Requirements

### Functional Requirements

- **FR-001**: rawether MUST provide a borrowed Ethernet view over any byte slice that exposes
  destination and source addresses, the VLAN tags present (zero, one or two), the EtherType
  after them, and the payload slice.
- **FR-002**: Taking a view MUST NOT panic on any input. A slice shorter than the header it
  announces MUST yield no view.
- **FR-003**: Each VLAN tag MUST report its tag protocol identifier (0x8100 or 0x88A8), priority
  (PCP), drop-eligible indicator (DEI) and VLAN id (VID).
- **FR-004**: A received `Packet` MUST give the same view over its data through one accessor
  that returns no view for a too-short frame, borrowing no longer than the packet itself. No
  per-field shortcuts are added to `Packet`.
- **FR-005**: rawether MUST provide a frame builder that writes destination, source, up to two
  tags, EtherType and payload into a caller-owned buffer, replacing its previous contents, and
  pads the result with zeros to 60 octets. It MUST accept both a growable buffer (cleared and
  refilled; cannot fail) and a fixed slice (returns the frame length, or an error naming the
  needed size when the slice is too small, leaving no partial frame claimed as written).
- **FR-006**: Building into a growable buffer whose capacity suffices, or into a fixed slice,
  MUST NOT allocate.
- **FR-007**: A VLAN tag made from fields MUST refuse a VID above 4095 or a PCP above 7. A tag
  may also be made from a raw 16-bit tag control value.
- **FR-008**: rawether MUST provide a way to build a reply to a viewed frame: destination = the
  frame's source, source = a given address, the same tags and EtherType, and a new payload.
- **FR-009**: The view, the builder and the reply MUST behave identically on every platform and
  need no socket and no privilege.
- **FR-010**: The examples `sniff`, `lldp` and `echo`, the README and the website guides MUST
  use the view and builder instead of header index arithmetic.
- **FR-011**: The feature MUST NOT add protocol knowledge above the Ethernet header
  (constitution I): no EtherType constants, no payload parsing, and no new dependency.

### Key Entities

- **Ethernet view**: a borrowed reading of one frame: destination, source, tags, EtherType,
  payload.
- **VLAN tag**: tag protocol identifier, PCP, DEI, VID; its wire form is four octets.
- **Frame builder**: a description of a frame to write (destination, source, tags, EtherType),
  applied with a payload to a caller's buffer.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): Taking an Ethernet view MUST NOT panic for any byte slice, and MUST return no view when the slice is shorter than the header it announces.
  - Mitigates: `threat.view-panic-on-hostile-frame` via `mitigation.total-view`
  - Given every byte slice up to 24 octets with each tag identifier at offsets 12 and 16, when a view is taken, then it returns without panicking, and returns a view only when the announced header fits
  - Given randomised byte slices up to 1600 octets, when a view is taken and every field and the payload are read, then nothing panics and the payload lies inside the slice
- **SR-002** (P1): For every set S containing no tag identifier (0x8100, 0x88A8) and every frame that Program::ethertypes(S) accepts, the view's EtherType MUST be in S, using the same tag identifiers (0x8100, 0x88A8) and the same depth (two tags).
  - Mitigates: `threat.view-filter-disagreement` via `mitigation.shared-tag-rules`
  - Given frames with zero, one, two and three tags of either identifier, when the filter for a set S is run through Program::run and the view is taken, then whenever the filter accepts, the view's EtherType is in S
- **SR-003** (P2): Making a VLAN tag from fields MUST fail for a VID above 4095 or a PCP above 7.
  - Mitigates: `threat.tag-field-truncation` via `mitigation.checked-tag-fields`
  - Given VID 4096 or PCP 8, when a tag is made from fields, then it is refused
  - Given VID 4095, PCP 7, DEI set, when a tag is made and written, then the wire TCI is 0xFFFF
- **SR-004** (P2): Building a frame MUST leave the growable buffer, or the returned prefix of a fixed slice, holding exactly the new frame, with any padding zero, whatever the buffer held before; a fixed slice too small MUST yield an error, not a partial frame.
  - Mitigates: `threat.stale-buffer-disclosure` via `mitigation.replace-and-zero-pad`
  - Given a buffer filled with 1518 octets of 0xAA, when a frame with a 5-octet payload is built into it, then the buffer is 60 octets long and octets 19 to 59 are zero
  - Given a fixed 1518-octet slice filled with 0xAA, when a frame with a 5-octet payload is written into it, then the returned length is 60 and octets 19 to 59 of the slice are zero
  - Given a fixed slice shorter than the frame, when a frame is written into it, then an error names the size needed and no length is returned
- **SR-005** (P2): Building a reply MUST NOT produce a frame when the received frame's source address is a group (multicast or broadcast) address.
  - Mitigates: `threat.reply-reflection` via `mitigation.no-reply-to-groups`
  - Given a received frame whose source is ff:ff:ff:ff:ff:ff or 01:00:5e:00:00:01, when a reply is requested, then none is built
- **SR-006** (P3): The view's documentation MUST state that a truncated packet's payload covers only the captured octets and point to Packet::is_truncated.
  - Mitigates: `threat.truncated-payload-misread` via `mitigation.truncation-visible`
  - Given the rustdoc of the payload accessor and of Packet's view accessor, when it is read, then it names is_truncated
<!-- threatspec:end -->

## Success Criteria

### Measurable Outcomes

- **SC-001**: Taking a view never panics: every byte slice up to 24 octets with every
  combination of tag identifiers at the tag positions, plus a randomised run over longer slices,
  completes without a panic.
- **SC-002**: Building a frame and taking its view returns the same addresses, tags, EtherType
  and payload (round trip) for 0, 1 and 2 tags and payloads from 0 to 1500 octets.
- **SC-003**: A loop that builds and sends 10 000 frames into one reused buffer, and the `echo`
  responder's loop, make zero allocations after the first iteration.
- **SC-004**: The examples, README and website contain no header index arithmetic, and the
  `echo` example's frame handling is at least a third shorter than before.
- **SC-005**: The full gate set (`just ci`) and the veth suite pass; the public API has no
  protocol-specific item.

## Assumptions

- Users write frames in network byte order as Ethernet defines it; the builder takes the
  EtherType and tag fields as numbers and writes them big-endian.
- Ethernet II framing only. 802.3/LLC frames are readable through the same view (the length
  field appears as the EtherType); building them is the caller's job.
- The frame check sequence is never part of a view or a built frame; the NIC handles it.
- The existing `MacAddr` type is the address type for the view and the builder.
- The reply helper does not change the received frame; it builds a new one into the caller's
  buffer.
