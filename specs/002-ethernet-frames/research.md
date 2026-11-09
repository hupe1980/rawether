# Research: Ethernet frame views and frame building

No open technical questions remained after clarification. These are the decisions the design
rests on.

## R1. Which tags the view parses

- **Decision**: up to two tags, each introduced by TPID 0x8100 (802.1Q C-tag) or 0x88A8 (802.1ad
  S-tag), in any order. Parsing stops after two; whatever follows is the EtherType.
- **Rationale**: `bpf::Program::ethertypes` looks for the EtherType at offsets 12, 16 and 20,
  stepping over exactly these two TPIDs (`TPIDS` in `src/bpf.rs`). If the view used other rules,
  a frame could pass the filter as one type and be read as another (threat
  `view-filter-disagreement`). For every set S that contains no TPID, the filter accepts a
  frame only if the view's EtherType is in S (SR-002). A set that contains a TPID is
  degenerate: the filter then accepts any tagged frame at offset 12, by design. This is
  documented, not tested as agreement.
- **Alternatives**: 0x9100/0x9200 (legacy pre-standard QinQ) were rejected, because the filter
  does not know them and they are outside both standards. Unlimited tag depth was rejected for
  the same reason, and because no standard defines more than two.

## R2. Short frames

- **Decision**: `Frame::new` returns `None` if the slice is shorter than 14 octets, or than
  14 + 4 per announced tag. A frame of exactly the header length is valid, with an empty
  payload.
- **Rationale**: on receive, a 14-octet minimum matches `send`'s own `InvalidInput` floor. On
  short frames the kernel's filter loads fail and reject, so `None` matches the filter here
  too.

## R3. Padding and minimum size

- **Decision**: pad with zeros to 60 octets, whether or not the frame carries tags.
- **Rationale**: IEEE 802.3 requires a minimum of 64 octets including the 4-octet FCS that the
  NIC appends. Current 802.1Q accepts tagged frames at that same minimum (early editions
  required 68), so 60 is right with or without tags; a peer that strips a tag re-pads. Zero padding also closes
  `stale-buffer-disclosure` (SR-004).

## R4. Buffers (clarified)

- **Decision**: `write(&self, buf: &mut Vec<u8>, payload)` clears and refills the buffer, so it
  cannot fail. `write_into(&self, buf: &mut [u8], payload) -> io::Result<usize>` returns the
  length, or `InvalidInput` naming the size needed, and writes nothing in that case.
- **Rationale**: the `Vec` form serves almost every caller and allocates only while the buffer
  first grows. The slice form serves stack buffers and callers that avoid the allocator. Both
  share one private routine that writes into a slice of exactly the frame's length.

## R5. Tag constructors and errors

- **Decision**: `VlanTag::new(kind, pcp, dei, vid) -> io::Result<VlanTag>` refuses a PCP above 7
  or a VID above 4095 with `InvalidInput`. `VlanTag::from_tci(kind, tci) -> VlanTag` is
  infallible, because every 16-bit TCI is valid.
- **Rationale**: the crate's errors are `io::Error` (constitution VI), and `?` composes in
  callers' `io::Result` functions. VID 0 (priority-tagged) and 4095 (reserved) are valid on the
  wire, so they are accepted; refusing them is a policy for the caller, not for a layer-2 tool.
- **Alternatives**: `Option` was rejected because it cannot say which field was wrong.
  Silently masking the value was rejected because of threat `tag-field-truncation`.

## R6. Setting tags on the builder

- **Decision**: `vlan(tag)` sets one tag. `vlans(outer, inner)` sets two. Each call replaces the
  tags set before, so a builder can never hold more than two.
- **Rationale**: there is no overflow case to handle and nothing to panic on. Every call states
  the whole tag stack.

## R7. Reply

- **Decision**: `Frame::reply(&self, from: MacAddr) -> Option<FrameBuilder>` addresses the
  reply to the frame's source, from `from`, with the same tags and EtherType. It returns `None`
  when the frame's source has the group bit set.
- **Rationale**: a valid sender never uses a group address as its source (IEEE 802). Answering
  one would multicast or broadcast the reply (threat `reply-reflection`, SR-005). With a
  builder rather than a written frame, the caller still picks the buffer and the payload.

## R8. Payload of received frames

- **Decision**: the payload is everything after the EtherType, padding included. For a
  truncated packet, it is the captured part.
- **Rationale**: Ethernet II does not carry a payload length, so only the upper protocol knows
  where its data ends. The rustdoc says so and points to `Packet::is_truncated` (SR-006).
