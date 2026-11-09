//! Ethernet frames: read the header of a frame, and build one to send.
//!
//! [`Frame`] is a view over the octets of one frame, received or not: destination, source, the
//! VLAN tags in front of the EtherType, the EtherType, and the payload. Taking a view never
//! panics; a slice too short for the header it announces has no view.
//!
//! [`FrameBuilder`] writes a frame into a buffer you keep and reuse, zero-padded to the
//! Ethernet minimum, ready for [`Socket::send`](crate::Socket::send).
//!
//! ```
//! use rawether::{Frame, FrameBuilder, MacAddr, TagKind, VlanTag};
//!
//! # fn main() -> std::io::Result<()> {
//! let me = MacAddr([0x02, 0, 0, 0, 0, 1]);
//! let tag = VlanTag::new(TagKind::Customer, 5, false, 100)?;
//! let mut buf = Vec::with_capacity(1518);
//! FrameBuilder::new(MacAddr::BROADCAST, me, 0x88b5).vlan(tag).write(&mut buf, b"hello");
//!
//! let f = Frame::new(&buf).expect("a whole header");
//! assert_eq!((f.source(), f.ethertype()), (me, 0x88b5));
//! assert_eq!(f.vlan_tags()[0].vid(), 100);
//! assert_eq!(buf.len(), 60); // padded to the minimum
//! # Ok(()) }
//! ```
//!
//! Only layer 2 is read: what follows the EtherType is the caller's protocol.

#![forbid(unsafe_code)]

use std::io;

use crate::packet::MacAddr;

/// The shortest Ethernet frame, without the frame check sequence the NIC appends: 64 − 4
/// octets. [`FrameBuilder`] pads to it, with or without VLAN tags.
pub const MIN_FRAME_LEN: usize = 60;

/// Destination, source and EtherType.
const HEADER_LEN: usize = 14;
/// Tag protocol identifier and tag control information.
const TAG_LEN: usize = 4;
/// The tags a view looks through: the same as [`Program::ethertypes`](crate::bpf::Program::ethertypes).
const MAX_TAGS: usize = 2;

/// Which kind of VLAN tag: the tag protocol identifier (TPID) in front of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TagKind {
    /// An IEEE 802.1Q customer tag (C-tag), TPID 0x8100.
    Customer,
    /// An IEEE 802.1ad service tag (S-tag), TPID 0x88A8: the outer tag of a double-tagged
    /// ("Q-in-Q") frame.
    Service,
}

impl TagKind {
    /// The tag protocol identifier.
    pub const fn tpid(self) -> u16 {
        match self {
            TagKind::Customer => 0x8100,
            TagKind::Service => 0x88a8,
        }
    }

    const fn from_tpid(tpid: u16) -> Option<TagKind> {
        match tpid {
            0x8100 => Some(TagKind::Customer),
            0x88a8 => Some(TagKind::Service),
            _ => None,
        }
    }
}

/// One VLAN tag: its kind and its tag control information (priority, drop eligibility, VLAN
/// id).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VlanTag {
    kind: TagKind,
    tci: u16,
}

impl VlanTag {
    /// A tag from its fields: priority code point `pcp` (0–7), drop-eligible indicator `dei`,
    /// VLAN id `vid` (0–4095; 0 marks a priority-only tag). Out-of-range values are refused
    /// with `InvalidInput`, never truncated.
    pub fn new(kind: TagKind, pcp: u8, dei: bool, vid: u16) -> io::Result<VlanTag> {
        if pcp > 7 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("VLAN priority (PCP) {pcp} is above 7"),
            ));
        }
        if vid > 0x0fff {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("VLAN id {vid} is above 4095")));
        }
        Ok(VlanTag { kind, tci: (u16::from(pcp) << 13) | (u16::from(dei) << 12) | vid })
    }

    /// A tag from its raw 16-bit tag control information, as on the wire.
    pub const fn from_tci(kind: TagKind, tci: u16) -> VlanTag {
        VlanTag { kind, tci }
    }

    /// The kind of tag.
    pub const fn kind(&self) -> TagKind {
        self.kind
    }

    /// The tag control information: `pcp << 13 | dei << 12 | vid`.
    pub const fn tci(&self) -> u16 {
        self.tci
    }

    /// The priority code point, 0–7.
    pub const fn pcp(&self) -> u8 {
        (self.tci >> 13) as u8
    }

    /// The drop-eligible indicator.
    pub const fn dei(&self) -> bool {
        self.tci & 0x1000 != 0
    }

    /// The VLAN id, 0–4095.
    pub const fn vid(&self) -> u16 {
        self.tci & 0x0fff
    }
}

/// An unused tag slot.
const NO_TAG: VlanTag = VlanTag::from_tci(TagKind::Customer, 0);

fn be16(data: &[u8], at: usize) -> Option<u16> {
    match data.get(at..at.checked_add(2)?)? {
        &[a, b] => Some(u16::from_be_bytes([a, b])),
        _ => None,
    }
}

fn mac(data: &[u8], at: usize) -> Option<MacAddr> {
    let octets: [u8; 6] = data.get(at..at.checked_add(6)?)?.try_into().ok()?;
    Some(MacAddr(octets))
}

/// A view of one Ethernet frame's header and payload, borrowed from its octets.
///
/// Up to two VLAN tags are looked through, 802.1Q (TPID 0x8100) or 802.1ad (0x88A8) in any
/// order — exactly what [`Program::ethertypes`](crate::bpf::Program::ethertypes) looks through,
/// so a frame the kernel filter accepted for EtherType `x` has `ethertype() == x` here. A
/// third tag's TPID is reported as the EtherType, as it is on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    data: &'a [u8],
    destination: MacAddr,
    source: MacAddr,
    tags: [VlanTag; MAX_TAGS],
    tag_count: usize,
    ethertype: u16,
}

impl<'a> Frame<'a> {
    /// A view of `data`, which starts at the destination address. `None` when `data` is
    /// shorter than the header it announces: 14 octets, plus 4 for each VLAN tag.
    pub fn new(data: &'a [u8]) -> Option<Frame<'a>> {
        let destination = mac(data, 0)?;
        let source = mac(data, 6)?;
        let mut tags = [NO_TAG; MAX_TAGS];
        let mut tag_count = 0;
        let mut at = 12;
        let ethertype = loop {
            let field = be16(data, at)?;
            match (TagKind::from_tpid(field), tags.get_mut(tag_count)) {
                (Some(kind), Some(slot)) => {
                    *slot = VlanTag::from_tci(kind, be16(data, at + 2)?);
                    tag_count += 1;
                    at += TAG_LEN;
                }
                _ => break field,
            }
        };
        Some(Frame { data, destination, source, tags, tag_count, ethertype })
    }

    /// The destination address.
    pub fn destination(&self) -> MacAddr {
        self.destination
    }

    /// The source address, as received: layer 2 does not authenticate it.
    pub fn source(&self) -> MacAddr {
        self.source
    }

    /// The VLAN tags in front of the EtherType, outer first: none, one or two.
    pub fn vlan_tags(&self) -> &[VlanTag] {
        self.tags.get(..self.tag_count).unwrap_or_default()
    }

    /// The EtherType after the tags. A value below 0x0600 is an IEEE 802.3 length rather than
    /// a type; it is reported unchanged.
    pub fn ethertype(&self) -> u16 {
        self.ethertype
    }

    /// The header's length in octets: 14, plus 4 per VLAN tag.
    pub fn header_len(&self) -> usize {
        HEADER_LEN + TAG_LEN * self.tag_count
    }

    /// Everything after the EtherType. That includes any padding the sender added (Ethernet
    /// does not say where the protocol's data ends), and for a truncated packet only the
    /// captured octets: check [`Packet::is_truncated`](crate::Packet::is_truncated).
    pub fn payload(&self) -> &'a [u8] {
        self.data.get(self.header_len()..).unwrap_or_default()
    }

    /// The whole frame.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// A builder for the answer to this frame: back to its source, from `from` (usually
    /// [`Socket::mac_address`](crate::Socket::mac_address)), with the same VLAN tags and
    /// EtherType. Add the payload when writing it.
    ///
    /// `None` when the source is a group (multicast or broadcast) address, which no real
    /// sender uses: answering it would send the reply to every member of the group.
    pub fn reply(&self, from: MacAddr) -> Option<FrameBuilder> {
        if self.source.is_multicast() {
            return None;
        }
        Some(FrameBuilder {
            destination: self.source,
            source: from,
            tags: self.tags,
            tag_count: self.tag_count,
            ethertype: self.ethertype,
        })
    }
}

/// Writes Ethernet frames: destination, source, optional VLAN tags, EtherType, payload, and
/// zero padding to [`MIN_FRAME_LEN`].
///
/// A builder is a small `Copy` value describing the header; [`write`](FrameBuilder::write) and
/// [`write_into`](FrameBuilder::write_into) apply it to a payload. Reusing one buffer for every
/// frame keeps a send loop free of allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FrameBuilder {
    destination: MacAddr,
    source: MacAddr,
    tags: [VlanTag; MAX_TAGS],
    tag_count: usize,
    ethertype: u16,
}

impl FrameBuilder {
    /// An untagged frame from `source` to `destination` of type `ethertype`.
    pub const fn new(destination: MacAddr, source: MacAddr, ethertype: u16) -> FrameBuilder {
        FrameBuilder { destination, source, tags: [NO_TAG; MAX_TAGS], tag_count: 0, ethertype }
    }

    /// One VLAN tag, replacing any set before.
    pub const fn vlan(self, tag: VlanTag) -> FrameBuilder {
        FrameBuilder { tags: [tag, NO_TAG], tag_count: 1, ..self }
    }

    /// Two VLAN tags, outer first (usually an 802.1ad service tag, then an 802.1Q tag),
    /// replacing any set before.
    pub const fn vlans(self, outer: VlanTag, inner: VlanTag) -> FrameBuilder {
        FrameBuilder { tags: [outer, inner], tag_count: 2, ..self }
    }

    /// The header's length in octets: 14, plus 4 per VLAN tag.
    pub const fn header_len(&self) -> usize {
        HEADER_LEN + TAG_LEN * self.tag_count
    }

    /// The length of a frame with `payload_len` octets of payload: the header and payload,
    /// at least [`MIN_FRAME_LEN`].
    pub const fn frame_len(&self, payload_len: usize) -> usize {
        let len = self.header_len().saturating_add(payload_len);
        if len < MIN_FRAME_LEN { MIN_FRAME_LEN } else { len }
    }

    /// Replace the contents of `buf` with the frame carrying `payload`. Allocates only when
    /// `buf`'s capacity is smaller than the frame.
    pub fn write(&self, buf: &mut Vec<u8>, payload: &[u8]) {
        buf.clear();
        buf.resize(self.frame_len(payload.len()), 0);
        self.fill(buf, payload);
    }

    /// Write the frame carrying `payload` to the start of `buf` and return its length. Fails
    /// with `InvalidInput`, writing nothing, when `buf` is too small.
    pub fn write_into(&self, buf: &mut [u8], payload: &[u8]) -> io::Result<usize> {
        let len = self.frame_len(payload.len());
        let available = buf.len();
        let Some(out) = buf.get_mut(..len) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("a frame of {len} octets does not fit in a buffer of {available}"),
            ));
        };
        self.fill(out, payload);
        Ok(len)
    }

    /// Write the frame into `out`, which is exactly `frame_len(payload.len())` octets long.
    fn fill(&self, out: &mut [u8], payload: &[u8]) {
        let mut at = 0;
        let mut put = |bytes: &[u8]| {
            if let Some(dst) = out.get_mut(at..at + bytes.len()) {
                dst.copy_from_slice(bytes);
            }
            at += bytes.len();
        };
        put(&self.destination.0);
        put(&self.source.0);
        for tag in self.tags.get(..self.tag_count).unwrap_or_default() {
            put(&tag.kind.tpid().to_be_bytes());
            put(&tag.tci.to_be_bytes());
        }
        put(&self.ethertype.to_be_bytes());
        put(payload);
        out.get_mut(at..).unwrap_or_default().fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf::Program;

    const A: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x0a]);
    const B: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x0b]);

    fn raw(tpids: &[u16], tci: u16, ethertype: u16, len: usize) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&B.0);
        f.extend_from_slice(&A.0);
        for t in tpids {
            f.extend_from_slice(&t.to_be_bytes());
            f.extend_from_slice(&tci.to_be_bytes());
        }
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.resize(len.max(f.len()), 0x5a);
        f
    }

    /// Spec 002 SR-003: out-of-range fields are refused; the TCI layout is pcp|dei|vid.
    #[test]
    fn a_tag_refuses_out_of_range_fields_and_lays_out_its_tci() {
        assert!(VlanTag::new(TagKind::Customer, 8, false, 1).is_err());
        assert!(VlanTag::new(TagKind::Customer, 0, false, 4096).is_err());
        let t = VlanTag::new(TagKind::Service, 7, true, 4095).expect("in range");
        assert_eq!(t.tci(), 0xffff);
        let t = VlanTag::new(TagKind::Customer, 5, false, 100).expect("in range");
        assert_eq!((t.pcp(), t.dei(), t.vid(), t.tci()), (5, false, 100, 0xa064));
        assert_eq!(
            VlanTag::from_tci(TagKind::Customer, 0x3005),
            VlanTag::new(TagKind::Customer, 1, true, 5).expect("ok")
        );
        assert!(VlanTag::new(TagKind::Customer, 0, false, 0).is_ok(), "priority-only tag");
    }

    /// Spec 002 story 1, scenarios 1–3.
    #[test]
    fn a_view_names_the_header_fields_with_and_without_tags() {
        let f = raw(&[], 0, 0x88b5, 60);
        let v = Frame::new(&f).expect("untagged");
        assert_eq!((v.destination(), v.source(), v.ethertype()), (B, A, 0x88b5));
        assert_eq!(v.vlan_tags(), &[] as &[VlanTag]);
        assert_eq!(v.payload(), &f[14..]);

        let mut f = raw(&[0x88a8, 0x8100], 0, 0x88b6, 64);
        f[14..16].copy_from_slice(&0x2064u16.to_be_bytes()); // outer: PCP 1, VID 100
        f[18..20].copy_from_slice(&0xb007u16.to_be_bytes()); // inner: PCP 5, DEI, VID 7
        let v = Frame::new(&f).expect("double-tagged");
        let tags = v.vlan_tags();
        assert_eq!(tags.len(), 2);
        assert_eq!(
            (tags[0].kind(), tags[0].pcp(), tags[0].dei(), tags[0].vid()),
            (TagKind::Service, 1, false, 100)
        );
        assert_eq!(
            (tags[1].kind(), tags[1].pcp(), tags[1].dei(), tags[1].vid()),
            (TagKind::Customer, 5, true, 7)
        );
        assert_eq!((v.ethertype(), v.header_len(), v.payload()), (0x88b6, 22, &f[22..]));

        assert!(Frame::new(&f[..13]).is_none());
        assert!(Frame::new(&raw(&[0x8100], 1, 0x88b5, 0)[..16]).is_none(), "a tag announced but cut off");
        assert_eq!(Frame::new(&raw(&[], 0, 0x88b5, 0)).expect("header only").payload(), &[] as &[u8]);
    }

    /// Spec 002 SR-001: every slice up to 24 octets, with each TPID at the tag positions, has a
    /// view exactly when its announced header fits, and nothing panics.
    #[test]
    fn a_view_is_total_over_small_inputs() {
        let words = [0x8100u16, 0x88a8, 0x88b5, 0x0000];
        for len in 0..=24 {
            for &w12 in &words {
                for &w16 in &words {
                    let mut f = vec![0x11u8; len];
                    for (at, w) in [(12, w12), (16, w16)] {
                        if let Some(dst) = f.get_mut(at..at + 2) {
                            dst.copy_from_slice(&w.to_be_bytes());
                        }
                    }
                    let tags = match (TagKind::from_tpid(w12), TagKind::from_tpid(w16)) {
                        (None, _) => 0,
                        (Some(_), None) => 1,
                        (Some(_), Some(_)) => 2,
                    };
                    let v = Frame::new(&f);
                    assert_eq!(v.is_some(), len >= 14 + 4 * tags, "len {len}, {w12:04x} {w16:04x}");
                    if let Some(v) = v {
                        assert_eq!(v.header_len() + v.payload().len(), len);
                        assert_eq!(v.vlan_tags().len(), tags);
                    }
                }
            }
        }
    }

    /// Spec 002 SR-001: random slices up to 1600 octets, biased towards tags.
    #[test]
    fn a_view_never_panics_on_random_frames() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let rounds = if cfg!(miri) { 300 } else { 100_000 }; // Miri checks soundness, not volume
        for _ in 0..rounds {
            let len = (next() % 1601) as usize;
            let mut f: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            for at in [12, 16, 20] {
                if next() % 2 == 0
                    && let Some(dst) = f.get_mut(at..at + 2)
                {
                    let tpid = if next() % 2 == 0 { 0x8100u16 } else { 0x88a8 };
                    dst.copy_from_slice(&tpid.to_be_bytes());
                }
            }
            if let Some(v) = Frame::new(&f) {
                let _ = (v.destination(), v.source(), v.ethertype(), v.vlan_tags());
                assert!(v.header_len() <= f.len());
                assert_eq!(v.payload().len(), f.len() - v.header_len());
                assert_eq!(v.as_bytes().len(), f.len());
            }
        }
    }

    /// Spec 002 SR-002: the view and `Program::ethertypes` agree on every tag layout, for sets
    /// that contain no TPID.
    #[test]
    fn the_view_and_the_ethertype_filter_agree() {
        let sets: [&[u16]; 3] = [&[0x88b5], &[0x88b5, 0x0800], &[0x0800, 0x88cc, 0x88f7]];
        let types = [0x88b5u16, 0x0800, 0x88cc, 0x1234];
        let tpids = [0x8100u16, 0x88a8];
        let mut layouts: Vec<Vec<u16>> = vec![vec![]];
        for depth in 1..=3 {
            let mut next = Vec::new();
            for l in layouts.iter().filter(|l| l.len() == depth - 1) {
                for &t in &tpids {
                    let mut l = l.clone();
                    l.push(t);
                    next.push(l);
                }
            }
            layouts.extend(next);
        }
        for set in sets {
            let filter = Program::ethertypes(set).expect("filter");
            for layout in &layouts {
                for &ty in &types {
                    let f = raw(layout, 0x0064, ty, 64);
                    let v = Frame::new(&f).expect("long enough");
                    let accepted = filter.run(&f) != 0;
                    assert_eq!(accepted, set.contains(&v.ethertype()), "{set:x?} {layout:x?} {ty:04x}");
                }
            }
        }
    }

    /// Spec 002 SR-004: a reused buffer holds exactly the new frame, zero-padded.
    #[test]
    fn building_replaces_the_buffer_and_pads_with_zeros() {
        let b = FrameBuilder::new(B, A, 0x88b5);
        let mut buf = vec![0xaa; 1518];
        let cap = buf.capacity();
        b.write(&mut buf, b"hello");
        assert_eq!(buf.len(), 60);
        assert_eq!(&buf[14..19], b"hello");
        assert!(buf[19..].iter().all(|&o| o == 0));
        assert_eq!(buf.capacity(), cap, "no reallocation");

        let mut fixed = [0xaau8; 1518];
        assert_eq!(b.write_into(&mut fixed, b"hello").expect("fits"), 60);
        assert_eq!(&fixed[..60], buf.as_slice());
        assert!(fixed[60..].iter().all(|&o| o == 0xaa), "nothing written past the frame");

        let mut small = [0xaau8; 59];
        let e = b.write_into(&mut small, b"hello").expect_err("too small");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert!(e.to_string().contains("60"), "{e}");
        assert!(small.iter().all(|&o| o == 0xaa), "nothing written");
    }

    /// Spec 002 story 2, scenarios 1–3, and SC-002: built frames round-trip through the view.
    #[test]
    fn built_frames_round_trip_through_the_view() {
        let c = VlanTag::new(TagKind::Customer, 3, false, 42).expect("tag");
        let s = VlanTag::new(TagKind::Service, 0, true, 7).expect("tag");
        let builders = [
            FrameBuilder::new(B, A, 0x88b5),
            FrameBuilder::new(B, A, 0x88b5).vlan(c),
            FrameBuilder::new(B, A, 0x88b5).vlans(s, c),
            FrameBuilder::new(B, A, 0x88b5).vlans(s, c).vlan(c),
        ];
        let mut buf = Vec::new();
        for b in builders {
            for n in [0usize, 1, 46, 47, 1500] {
                let payload: Vec<u8> = (0..n).map(|k| k as u8).collect();
                b.write(&mut buf, &payload);
                assert_eq!(buf.len(), b.frame_len(n));
                let v = Frame::new(&buf).expect("view");
                assert_eq!((v.destination(), v.source(), v.ethertype()), (B, A, 0x88b5));
                assert_eq!(v.vlan_tags().len(), (b.header_len() - 14) / 4);
                assert_eq!(&v.payload()[..n], payload.as_slice());
            }
        }
        assert_eq!(FrameBuilder::new(B, A, 0x88b5).frame_len(5), 60);
        assert_eq!(FrameBuilder::new(B, A, 0x88b5).vlan(c).frame_len(1500), 1518);
        assert_eq!(builders[3].vlan_tags_for_test(), &[c], "vlan() replaces the tags");
    }

    impl FrameBuilder {
        fn vlan_tags_for_test(&self) -> &[VlanTag] {
            self.tags.get(..self.tag_count).unwrap_or_default()
        }
    }

    /// Spec 002 SR-005 and story 3: a reply goes back to the sender with the same tags and type;
    /// a group source gets none.
    #[test]
    fn a_reply_goes_back_to_the_sender_and_never_to_a_group() {
        let me = MacAddr([0x02, 0, 0, 0, 0, 0x0c]);
        let f = raw(&[0x8100], 0x0064, 0x88b5, 60);
        let v = Frame::new(&f).expect("view");
        let mut buf = Vec::new();
        v.reply(me).expect("unicast source").write(&mut buf, b"pong");
        let r = Frame::new(&buf).expect("reply");
        assert_eq!((r.destination(), r.source(), r.ethertype()), (A, me, 0x88b5));
        assert_eq!(r.vlan_tags(), v.vlan_tags());
        assert_eq!(&r.payload()[..4], b"pong");

        for group in [MacAddr::BROADCAST, MacAddr([0x01, 0x00, 0x5e, 0, 0, 1])] {
            let mut f = raw(&[], 0, 0x88b5, 60);
            f[6..12].copy_from_slice(&group.0);
            assert!(Frame::new(&f).expect("view").reply(me).is_none(), "{group}");
        }
    }
}
