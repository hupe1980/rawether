//! Reading TPACKET_V3 ring blocks.
//!
//! The kernel fills a block with frames and hands it to user space by setting
//! `TP_STATUS_USER` in its header. Everything here works on a byte slice holding one block, so
//! it is tested on any platform over synthetic blocks; the Linux backend hands it the block
//! only after it has observed the status bit with acquire ordering. Every offset the kernel
//! wrote is checked against the block's length before it is used.

/// Layout of `struct tpacket_block_desc` / `tpacket_hdr_v1` (`<linux/if_packet.h>`).
pub(crate) mod block {
    pub const STATUS: usize = 8;
    pub const NUM_PKTS: usize = 12;
    pub const FIRST: usize = 16;
    pub const LEN: usize = 48;
}

/// Layout of `struct tpacket3_hdr`.
pub(crate) mod frame {
    pub const NEXT: usize = 0;
    pub const SEC: usize = 4;
    pub const NSEC: usize = 8;
    pub const SNAPLEN: usize = 12;
    pub const LEN: usize = 16;
    pub const STATUS: usize = 20;
    pub const MAC: usize = 24;
    pub const VLAN_TCI: usize = 32;
    pub const VLAN_TPID: usize = 36;
    pub const HDR: usize = 48;
}

/// `TP_STATUS_*` bits the walker reads.
pub(crate) mod status {
    pub const USER: u32 = 1;
    pub const VLAN_VALID: u32 = 1 << 4;
    pub const VLAN_TPID_VALID: u32 = 1 << 6;
    #[cfg_attr(not(test), allow(dead_code))]
    pub const TS_SOFTWARE: u32 = 1 << 29;
    pub const TS_RAW_HARDWARE: u32 = 1 << 31;
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_ne_bytes([s[0], s[1]]))
}

/// The header of one block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BlockHeader {
    pub status: u32,
    pub num_pkts: u32,
    pub first: usize,
}

impl BlockHeader {
    pub(crate) fn read(block: &[u8]) -> Option<BlockHeader> {
        if block.len() < block::LEN {
            return None;
        }
        Some(BlockHeader {
            status: u32_at(block, block::STATUS)?,
            num_pkts: u32_at(block, block::NUM_PKTS)?,
            first: u32_at(block, block::FIRST)? as usize,
        })
    }
}

/// What the kernel says about one frame in a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FrameMeta {
    /// Offset of the next frame from this one; 0 for the last.
    pub next: usize,
    pub sec: u32,
    pub nsec: u32,
    pub status: u32,
    /// Captured octets start here, relative to the frame header.
    pub mac: usize,
    pub snaplen: usize,
    pub len: usize,
    pub vlan_tci: u16,
    pub vlan_tpid: u16,
}

impl FrameMeta {
    /// The frame header at `at` in `block`, if it and the data it describes lie inside.
    pub(crate) fn read(block: &[u8], at: usize) -> Option<FrameMeta> {
        if at.checked_add(frame::HDR)? > block.len() {
            return None;
        }
        let m = FrameMeta {
            next: u32_at(block, at + frame::NEXT)? as usize,
            sec: u32_at(block, at + frame::SEC)?,
            nsec: u32_at(block, at + frame::NSEC)?,
            snaplen: u32_at(block, at + frame::SNAPLEN)? as usize,
            len: u32_at(block, at + frame::LEN)? as usize,
            status: u32_at(block, at + frame::STATUS)?,
            mac: usize::from(u16_at(block, at + frame::MAC)?),
            vlan_tci: u32_at(block, at + frame::VLAN_TCI)? as u16,
            vlan_tpid: u16_at(block, at + frame::VLAN_TPID)?,
        };
        // The data must lie inside the block and after the header.
        let start = at.checked_add(m.mac)?;
        if m.mac < frame::HDR || start.checked_add(m.snaplen)? > block.len() {
            return None;
        }
        Some(m)
    }

    /// The tag the driver stripped, as `(tpid, tci)`, if any.
    pub(crate) fn stripped_vlan(&self) -> Option<(u16, u16)> {
        if self.status & status::VLAN_VALID == 0 {
            return None;
        }
        let tpid = if self.status & status::VLAN_TPID_VALID != 0 && self.vlan_tpid != 0 {
            self.vlan_tpid
        } else {
            0x8100
        };
        Some((tpid, self.vlan_tci))
    }
}

/// Where the reader is inside the current block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Cursor {
    /// Frames left in the block.
    pub remaining: u32,
    /// Offset of the next frame header within the block.
    pub at: usize,
}

impl Cursor {
    /// Start reading a block the kernel has handed over; `None` if its header is unusable.
    pub(crate) fn start(block: &[u8]) -> Option<Cursor> {
        let h = BlockHeader::read(block)?;
        if h.status & status::USER == 0 {
            return None;
        }
        Some(Cursor { remaining: h.num_pkts, at: h.first })
    }

    /// The next frame, advancing the cursor. `None` when the block is exhausted or the kernel's
    /// offsets do not hold together (the rest of the block is then skipped, never trusted).
    pub(crate) fn next(&mut self, block: &[u8]) -> Option<(usize, FrameMeta)> {
        if self.remaining == 0 {
            return None;
        }
        let Some(meta) = FrameMeta::read(block, self.at) else {
            self.remaining = 0;
            return None;
        };
        let here = self.at;
        self.remaining -= 1;
        if self.remaining > 0 {
            if meta.next == 0 {
                self.remaining = 0;
            } else {
                self.at = here.saturating_add(meta.next);
            }
        }
        Some((here, meta))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A synthetic block holding `frames`, laid out the way the kernel does it.
    /// `(data, timestamp status bits, stripped tag)` for each frame.
    pub(crate) type FrameSpec<'a> = (&'a [u8], u32, Option<(u16, u16)>);

    pub(crate) fn synthetic_block(size: usize, frames: &[FrameSpec<'_>]) -> Vec<u8> {
        let mut b = vec![0u8; size];
        let put32 = |b: &mut [u8], at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_ne_bytes());
        put32(&mut b, block::STATUS, status::USER);
        put32(&mut b, block::NUM_PKTS, frames.len() as u32);
        let mut at = 64usize;
        put32(&mut b, block::FIRST, at as u32);
        for (n, (data, ts_status, vlan)) in frames.iter().enumerate() {
            let mac = 80usize; // header (48) + sockaddr_ll (20) + reserve (4), aligned
            let total = (mac + data.len() + 15) & !15;
            let next = if n + 1 == frames.len() { 0 } else { total };
            put32(&mut b, at + frame::NEXT, next as u32);
            put32(&mut b, at + frame::SEC, 1_700_000_000 + n as u32);
            put32(&mut b, at + frame::NSEC, 42);
            put32(&mut b, at + frame::SNAPLEN, data.len() as u32);
            put32(&mut b, at + frame::LEN, data.len() as u32);
            let mut st = *ts_status;
            if let Some((tpid, tci)) = vlan {
                st |= status::VLAN_VALID | status::VLAN_TPID_VALID;
                put32(&mut b, at + frame::VLAN_TCI, u32::from(*tci));
                b[at + frame::VLAN_TPID..at + frame::VLAN_TPID + 2].copy_from_slice(&tpid.to_ne_bytes());
            }
            put32(&mut b, at + frame::STATUS, st);
            b[at + frame::MAC..at + frame::MAC + 2].copy_from_slice(&(mac as u16).to_ne_bytes());
            b[at + mac..at + mac + data.len()].copy_from_slice(data);
            at += total;
        }
        b
    }

    #[test]
    fn a_block_is_walked_frame_by_frame() {
        let a = [1u8; 60];
        let c = [3u8; 100];
        let blk = synthetic_block(
            4096,
            &[(&a, status::TS_SOFTWARE, None), (&c, status::TS_RAW_HARDWARE, Some((0x8100, 5)))],
        );
        let mut cur = Cursor::start(&blk).expect("user block");
        let (at, m) = cur.next(&blk).expect("first");
        assert_eq!(&blk[at + m.mac..at + m.mac + m.snaplen], &a[..]);
        assert_eq!(m.stripped_vlan(), None);
        let (at, m) = cur.next(&blk).expect("second");
        assert_eq!(&blk[at + m.mac..at + m.mac + m.snaplen], &c[..]);
        assert_eq!(m.stripped_vlan(), Some((0x8100, 5)));
        assert!(m.status & status::TS_RAW_HARDWARE != 0);
        assert!(cur.next(&blk).is_none());
    }

    /// Threat model T-01 (SR-001).
    #[test]
    fn a_block_still_owned_by_the_kernel_is_not_read() {
        let mut blk = synthetic_block(4096, &[(&[0u8; 60], 0, None)]);
        blk[block::STATUS..block::STATUS + 4].copy_from_slice(&0u32.to_ne_bytes());
        assert!(Cursor::start(&blk).is_none());
    }

    /// Threat model T-01 (SR-001).
    #[test]
    fn offsets_that_point_outside_the_block_end_the_walk() {
        let mut blk = synthetic_block(4096, &[(&[0u8; 60], 0, None), (&[0u8; 60], 0, None)]);
        // Make the first frame claim more captured data than the block holds.
        blk[64 + frame::SNAPLEN..64 + frame::SNAPLEN + 4].copy_from_slice(&100_000u32.to_ne_bytes());
        let mut cur = Cursor::start(&blk).expect("user block");
        assert!(cur.next(&blk).is_none());
        assert!(cur.next(&blk).is_none(), "the rest of the block is not trusted");

        let mut blk = synthetic_block(256, &[(&[0u8; 60], 0, None)]);
        blk[block::FIRST..block::FIRST + 4].copy_from_slice(&250u32.to_ne_bytes());
        let mut cur = Cursor::start(&blk).expect("user block");
        assert!(cur.next(&blk).is_none());
        assert!(Cursor::start(&blk[..20]).is_none(), "a block shorter than its header");
    }

    #[test]
    fn a_frame_whose_data_overlaps_its_header_is_refused() {
        let mut blk = synthetic_block(4096, &[(&[0u8; 60], 0, None)]);
        blk[64 + frame::MAC..64 + frame::MAC + 2].copy_from_slice(&8u16.to_ne_bytes());
        assert!(FrameMeta::read(&blk, 64).is_none());
    }
}
