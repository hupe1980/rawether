//! Records in a BPF device's read buffer (macOS, FreeBSD).
//!
//! A `read` returns every captured frame, each behind a `struct bpf_hdr` and padded to
//! `BPF_ALIGNMENT`. The header's layout differs by platform (macOS uses a 32-bit `timeval`,
//! FreeBSD a native one), so it is read field by field at offsets taken from the platform's own
//! struct, never as a whole: the kernel writes only `SIZEOF_BPF_HDR` octets, fewer than the
//! padded struct.

#![forbid(unsafe_code)]

/// Where the header's fields are, and how records are aligned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Layout {
    /// Octets of each of `tv_sec` and `tv_usec` in `bh_tstamp`, which starts the header.
    pub ts_width: usize,
    pub caplen: usize,
    pub datalen: usize,
    pub hdrlen: usize,
    /// `SIZEOF_BPF_HDR`: the end of `bh_hdrlen`, the smallest header the kernel writes.
    pub min_header: usize,
    /// `BPF_ALIGNMENT`.
    pub align: usize,
}

impl Layout {
    /// macOS on 64-bit: `struct timeval32`, 4-octet alignment.
    #[cfg_attr(not(any(test, fuzzing)), allow(dead_code))]
    pub(crate) const MACOS: Layout =
        Layout { ts_width: 4, caplen: 8, datalen: 12, hdrlen: 16, min_header: 18, align: 4 };
    /// FreeBSD on 64-bit: `struct timeval` of two `long`s, `sizeof(long)` alignment.
    #[cfg_attr(not(any(test, fuzzing)), allow(dead_code))]
    pub(crate) const FREEBSD_LP64: Layout =
        Layout { ts_width: 8, caplen: 16, datalen: 20, hdrlen: 24, min_header: 26, align: 8 };

    /// This platform's layout, from libc's `bpf_hdr`.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    pub(crate) const fn native() -> Layout {
        use std::mem::{offset_of, size_of};
        Layout {
            // `bh_tstamp` is the two fields in front of `bh_caplen`.
            ts_width: offset_of!(libc::bpf_hdr, bh_caplen) / 2,
            caplen: offset_of!(libc::bpf_hdr, bh_caplen),
            datalen: offset_of!(libc::bpf_hdr, bh_datalen),
            hdrlen: offset_of!(libc::bpf_hdr, bh_hdrlen),
            min_header: offset_of!(libc::bpf_hdr, bh_hdrlen) + 2,
            align: if cfg!(target_os = "macos") { 4 } else { size_of::<libc::c_long>() },
        }
    }
}

/// One record: where its frame is, and what the header says about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    pub start: usize,
    pub caplen: usize,
    pub datalen: usize,
    pub secs: i64,
    pub usecs: i64,
}

fn uint(buf: &[u8], at: usize, width: usize) -> Option<u64> {
    let b = buf.get(at..at.checked_add(width)?)?;
    Some(match *b {
        [a, b] => u64::from(u16::from_ne_bytes([a, b])),
        [a, b, c, d] => u64::from(u32::from_ne_bytes([a, b, c, d])),
        [a, b, c, d, e, f, g, h] => u64::from_ne_bytes([a, b, c, d, e, f, g, h]),
        _ => return None,
    })
}

fn int(buf: &[u8], at: usize, width: usize) -> Option<i64> {
    let b = buf.get(at..at.checked_add(width)?)?;
    Some(match *b {
        [a, b, c, d] => i64::from(i32::from_ne_bytes([a, b, c, d])),
        [a, b, c, d, e, f, g, h] => i64::from_ne_bytes([a, b, c, d, e, f, g, h]),
        _ => return None,
    })
}

/// The record at `*pos` in `buf`, advancing `*pos` past it. `None` at the end of the buffer, or
/// when the kernel's lengths do not hold together; the rest of the buffer is then skipped.
pub(crate) fn next(buf: &[u8], pos: &mut usize, layout: Layout) -> Option<Record> {
    let at = *pos;
    let parsed = (|| {
        if at.checked_add(layout.min_header)? > buf.len() {
            return None;
        }
        let hdrlen = uint(buf, at + layout.hdrlen, 2)? as usize;
        let caplen = uint(buf, at + layout.caplen, 4)? as usize;
        let datalen = uint(buf, at + layout.datalen, 4)? as usize;
        let start = at.checked_add(hdrlen)?;
        let end = start.checked_add(caplen)?;
        if hdrlen < layout.min_header || end > buf.len() {
            return None;
        }
        let secs = int(buf, at, layout.ts_width)?;
        let usecs = int(buf, at + layout.ts_width, layout.ts_width)?;
        let next = end.checked_next_multiple_of(layout.align)?;
        Some((Record { start, caplen, datalen, secs, usecs }, next))
    })();
    if let Some((r, next)) = parsed {
        *pos = next;
        Some(r)
    } else {
        *pos = buf.len();
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Append one record as the kernel writes it: header (only `min_header` octets meaningful),
    /// the frame, padding to the alignment.
    fn push(buf: &mut Vec<u8>, l: Layout, secs: i64, usecs: i64, frame: &[u8], datalen: u32) {
        let at = buf.len();
        let hdrlen = (l.min_header + 14).next_multiple_of(l.align) - 14;
        buf.resize(at + hdrlen, 0);
        let w = l.ts_width;
        if w == 4 {
            buf[at..at + 4].copy_from_slice(&(secs as i32).to_ne_bytes());
            buf[at + 4..at + 8].copy_from_slice(&(usecs as i32).to_ne_bytes());
        } else {
            buf[at..at + 8].copy_from_slice(&secs.to_ne_bytes());
            buf[at + 8..at + 16].copy_from_slice(&usecs.to_ne_bytes());
        }
        buf[at + l.caplen..at + l.caplen + 4].copy_from_slice(&(frame.len() as u32).to_ne_bytes());
        buf[at + l.datalen..at + l.datalen + 4].copy_from_slice(&datalen.to_ne_bytes());
        buf[at + l.hdrlen..at + l.hdrlen + 2].copy_from_slice(&(hdrlen as u16).to_ne_bytes());
        buf.extend_from_slice(frame);
        buf.resize(buf.len().next_multiple_of(l.align), 0);
    }

    fn all(buf: &[u8], l: Layout) -> Vec<Record> {
        let mut pos = 0;
        std::iter::from_fn(|| next(buf, &mut pos, l)).collect()
    }

    /// Spec 003 SR-001: three records of each platform's layout are read back, FreeBSD's
    /// 26-octet minimum header included (the audit's H1).
    #[test]
    fn records_of_both_layouts_are_read() {
        for l in [Layout::MACOS, Layout::FREEBSD_LP64] {
            let mut buf = Vec::new();
            for k in 0..3u8 {
                push(&mut buf, l, 1_700_000_000 + i64::from(k), 250_000, &[k; 61], 61 + u32::from(k));
            }
            let rs = all(&buf, l);
            assert_eq!(rs.len(), 3, "{l:?}");
            for (k, r) in rs.iter().enumerate() {
                assert_eq!(&buf[r.start..r.start + r.caplen], &[k as u8; 61][..]);
                assert_eq!((r.datalen, r.secs, r.usecs), (61 + k, 1_700_000_000 + k as i64, 250_000));
            }
        }
        // The old bound (size_of::<bpf_hdr>() - 2 = 30 on FreeBSD) refused hdrlen 26.
        let mut buf = Vec::new();
        push(&mut buf, Layout::FREEBSD_LP64, 1, 2, &[7; 60], 60);
        assert_eq!(u16::from_ne_bytes([buf[24], buf[25]]), 26);
    }

    /// Spec 003 SR-001: malformed and truncated records end the parse, nothing is read outside.
    #[test]
    fn malformed_records_end_the_buffer() {
        for l in [Layout::MACOS, Layout::FREEBSD_LP64] {
            let mut good = Vec::new();
            push(&mut good, l, 1, 2, &[1; 60], 60);
            let one = good.len();
            push(&mut good, l, 3, 4, &[2; 60], 60);

            let mut low = good.clone();
            low[one + l.hdrlen..one + l.hdrlen + 2]
                .copy_from_slice(&((l.min_header - 1) as u16).to_ne_bytes());
            assert_eq!(all(&low, l).len(), 1, "hdrlen below the minimum");

            let mut long = good.clone();
            long[one + l.caplen..one + l.caplen + 4].copy_from_slice(&10_000u32.to_ne_bytes());
            assert_eq!(all(&long, l).len(), 1, "caplen past the buffer");

            for cut in one..one + l.min_header {
                assert_eq!(all(&good[..cut], l).len(), 1, "header cut at {cut}");
            }
            // A last record shorter than the padded struct (FreeBSD: 26 + 2 = 28 < 32) is read.
            let mut tail = Vec::new();
            push(&mut tail, l, 5, 6, &[9, 9], 2);
            let hdrlen = usize::from(u16::from_ne_bytes([tail[l.hdrlen], tail[l.hdrlen + 1]]));
            assert_eq!(all(&tail[..hdrlen + 2], l).len(), 1);
        }
    }

    /// Spec 003 SR-001: random buffers never panic and every frame lies inside the buffer.
    #[test]
    fn random_buffers_never_escape() {
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let rounds = if cfg!(miri) { 300 } else { 50_000 }; // Miri checks soundness, not volume
        for _ in 0..rounds {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let len = (x % 600) as usize;
            let buf: Vec<u8> = (0..len).map(|k| (x >> (k % 56)) as u8 ^ k as u8).collect();
            for l in [Layout::MACOS, Layout::FREEBSD_LP64] {
                for r in all(&buf, l) {
                    assert!(r.start + r.caplen <= buf.len());
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_native_layout_is_macos() {
        assert_eq!(Layout::native(), Layout::MACOS);
    }

    #[cfg(all(target_os = "freebsd", target_pointer_width = "64"))]
    #[test]
    fn the_native_layout_is_freebsd() {
        assert_eq!(Layout::native(), Layout::FREEBSD_LP64);
    }
}
