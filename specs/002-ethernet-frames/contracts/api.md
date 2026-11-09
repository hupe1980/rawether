# Contract: public API added by 002

```rust
// rawether::frame, re-exported at the crate root.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TagKind { Customer /* 802.1Q, 0x8100 */, Service /* 802.1ad, 0x88A8 */ }
impl TagKind { pub const fn tpid(self) -> u16; }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VlanTag;
impl VlanTag {
    pub fn new(kind: TagKind, pcp: u8, dei: bool, vid: u16) -> io::Result<VlanTag>; // InvalidInput: pcp > 7, vid > 4095
    pub const fn from_tci(kind: TagKind, tci: u16) -> VlanTag;
    pub const fn kind(&self) -> TagKind;
    pub const fn tci(&self) -> u16;
    pub const fn pcp(&self) -> u8;
    pub const fn dei(&self) -> bool;
    pub const fn vid(&self) -> u16;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a>;
impl<'a> Frame<'a> {
    pub fn new(data: &'a [u8]) -> Option<Frame<'a>>;      // None: shorter than the header it announces
    pub fn destination(&self) -> MacAddr;
    pub fn source(&self) -> MacAddr;
    pub fn vlan_tags(&self) -> &[VlanTag];                 // 0..=2, outer first
    pub fn ethertype(&self) -> u16;
    pub fn header_len(&self) -> usize;
    pub fn payload(&self) -> &'a [u8];                     // padding included; captured part if truncated
    pub fn as_bytes(&self) -> &'a [u8];
    pub fn reply(&self, from: MacAddr) -> Option<FrameBuilder>; // None: source is a group address
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FrameBuilder;
impl FrameBuilder {
    pub const fn new(destination: MacAddr, source: MacAddr, ethertype: u16) -> FrameBuilder;
    pub const fn vlan(self, tag: VlanTag) -> FrameBuilder;                    // exactly one tag
    pub const fn vlans(self, outer: VlanTag, inner: VlanTag) -> FrameBuilder; // exactly two tags
    pub const fn header_len(&self) -> usize;
    pub const fn frame_len(&self, payload_len: usize) -> usize;                   // at least 60
    pub fn write(&self, buf: &mut Vec<u8>, payload: &[u8]);
    pub fn write_into(&self, buf: &mut [u8], payload: &[u8]) -> io::Result<usize>; // InvalidInput: too small
}

impl<'a> Packet<'a> {
    pub fn frame(&self) -> Option<Frame<'a>>;
}

/// The Ethernet minimum without the frame check sequence.
pub const MIN_FRAME_LEN: usize = 60; // in rawether::frame
```

Guarantees: no method panics on any input; nothing allocates except `write` growing a `Vec`
beyond its capacity; identical behaviour on every target.
