//! Putting a stripped 802.1Q/802.1ad tag back where it was.
//!
//! Many drivers — and veth — remove the outer VLAN tag on receive and report it as metadata.
//! The socket reserves four octets of head-room in front of every frame so the tag can be
//! re-inserted in place: the two addresses move four octets earlier and the tag fills the gap.

/// Re-insert `(tpid, tci)` in front of the EtherType of the frame at `buf[start..start + len]`,
/// using the four octets before `start`. Returns the new `(start, len)`, or `None` (and leaves
/// `buf` untouched) when there is no head-room or the frame is shorter than its two addresses.
pub(crate) fn reinsert(
    buf: &mut [u8],
    start: usize,
    len: usize,
    tpid: u16,
    tci: u16,
) -> Option<(usize, usize)> {
    let new_start = start.checked_sub(4)?;
    if len < 12 || start.checked_add(len)? > buf.len() {
        return None;
    }
    buf.copy_within(start..start + 12, new_start);
    buf[new_start + 12..new_start + 14].copy_from_slice(&tpid.to_be_bytes());
    buf[new_start + 14..new_start + 16].copy_from_slice(&tci.to_be_bytes());
    Some((new_start, len + 4))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tag_is_put_back_in_front_of_the_ethertype() {
        let mut buf = vec![0u8; 4];
        let frame: Vec<u8> = (1..=12).chain([0x88, 0xb8, 0xaa, 0xbb]).collect();
        buf.extend_from_slice(&frame);
        let (s, l) = reinsert(&mut buf, 4, frame.len(), 0x8100, 0x8005).expect("room");
        assert_eq!((s, l), (0, frame.len() + 4));
        let expect: Vec<u8> = (1..=12).chain([0x81, 0x00, 0x80, 0x05, 0x88, 0xb8, 0xaa, 0xbb]).collect();
        assert_eq!(&buf[s..s + l], &expect[..]);
    }

    /// SR-003. Every buffer up to 24 octets, every start and length: re-insertion either succeeds inside
    /// the buffer with the tag in place, or refuses and leaves the buffer untouched — never a
    /// panic, never a write outside.
    #[test]
    fn reinsertion_is_total_over_small_inputs() {
        for size in 0..=24usize {
            let original: Vec<u8> = (0..size as u8).collect();
            for start in 0..=size + 2 {
                for len in 0..=size + 2 {
                    let mut buf = original.clone();
                    match reinsert(&mut buf, start, len, 0x88a8, 0x0123) {
                        Some((s, l)) => {
                            assert_eq!((s, l), (start - 4, len + 4));
                            assert!(s + l <= buf.len());
                            assert_eq!(&buf[s..s + 12], &original[start..start + 12]);
                            assert_eq!(&buf[s + 12..s + 16], &[0x88, 0xa8, 0x01, 0x23]);
                            assert_eq!(&buf[s + 16..s + l], &original[start + 12..start + len]);
                        }
                        None => assert_eq!(buf, original),
                    }
                }
            }
        }
    }

    #[test]
    fn without_head_room_nothing_moves() {
        let mut buf = vec![7u8; 20];
        assert!(reinsert(&mut buf, 2, 14, 0x8100, 1).is_none());
        assert!(reinsert(&mut buf, 4, 8, 0x8100, 1).is_none(), "shorter than two addresses");
        assert!(reinsert(&mut buf, 4, 40, 0x8100, 1).is_none(), "past the buffer");
        assert!(buf.iter().all(|&b| b == 7));
    }
}
