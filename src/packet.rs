//! What a socket hands out: frames, timestamps, counters and addresses.

use core::fmt;
use core::str::FromStr;
use std::io;

/// A 48-bit Ethernet hardware address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// `ff:ff:ff:ff:ff:ff`.
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);

    /// The six octets.
    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }

    /// Whether the group bit (the least significant bit of the first octet) is set.
    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 1 == 1
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl FromStr for MacAddr {
    type Err = io::Error;

    /// Six hexadecimal octets separated by `:` or `-`.
    fn from_str(s: &str) -> io::Result<MacAddr> {
        let bad = || io::Error::new(io::ErrorKind::InvalidInput, format!("not a MAC address: {s:?}"));
        let mut out = [0u8; 6];
        let mut parts = s.split([':', '-']);
        for slot in &mut out {
            let part = parts.next().ok_or_else(bad)?;
            if part.is_empty() || part.len() > 2 {
                return Err(bad());
            }
            *slot = u8::from_str_radix(part, 16).map_err(|_| bad())?;
        }
        if parts.next().is_some() {
            return Err(bad());
        }
        Ok(MacAddr(out))
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> MacAddr {
        MacAddr(octets)
    }
}

/// Who stamped a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TimestampSource {
    /// The network interface, on its own clock (a PTP hardware clock where it has one).
    Hardware,
    /// The kernel, on `CLOCK_REALTIME`, when the frame reached the socket layer.
    Software,
    /// rawether, on `CLOCK_REALTIME`, when it read the frame — because the kernel did not stamp
    /// it (Linux enables receive timestamps lazily, so the first frames after opening a socket
    /// can arrive without one). Later than a kernel stamp by the time the frame waited.
    User,
}

/// When a frame was received, and by whose clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Timestamp {
    /// Seconds since the clock's epoch (the Unix epoch for software timestamps).
    pub secs: i64,
    /// Nanoseconds within the second, below 1 000 000 000.
    pub nanos: u32,
    /// Which clock this is.
    pub source: TimestampSource,
}

impl Timestamp {
    /// Nanoseconds since the clock's epoch, saturating.
    pub fn as_nanos(&self) -> i128 {
        i128::from(self.secs) * 1_000_000_000 + i128::from(self.nanos)
    }
}

/// One received frame, borrowed from the socket until the next receive.
#[derive(Debug)]
pub struct Packet<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) original_len: usize,
    pub(crate) timestamp: Option<Timestamp>,
    pub(crate) vlan_restored: bool,
}

impl<'a> Packet<'a> {
    /// The captured octets, starting at the destination MAC address.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// The frame's length on the wire. Larger than `data().len()` when the frame was truncated.
    pub fn original_len(&self) -> usize {
        self.original_len
    }

    /// Whether the captured octets are the whole frame.
    pub fn is_truncated(&self) -> bool {
        self.data.len() < self.original_len
    }

    /// When the frame was received, if the platform said.
    pub fn timestamp(&self) -> Option<Timestamp> {
        self.timestamp
    }

    /// Whether an 802.1Q/802.1ad tag the driver had stripped into metadata was put back, so that
    /// `data()` is the frame as it was on the wire.
    pub fn vlan_restored(&self) -> bool {
        self.vlan_restored
    }
}

/// Counters the kernel keeps for a socket, accumulated since it was opened.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Frames that passed the filter.
    pub received: u64,
    /// Frames that passed the filter and were dropped because the socket's buffer was full.
    pub dropped: u64,
}

/// How frames reach user space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RxPath {
    /// A TPACKET_V3 ring shared with the kernel (Linux).
    Ring,
    /// One `recvmsg` per frame (Linux).
    Plain,
    /// A BPF device read buffer (macOS and the BSDs).
    Bpf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_addresses_parse_with_either_separator_and_print_with_colons() {
        let m: MacAddr = "01-0C-cd-01-00-05".parse().expect("parse");
        assert_eq!(m, MacAddr([1, 0x0c, 0xcd, 1, 0, 5]));
        assert_eq!(m.to_string(), "01:0c:cd:01:00:05");
        assert!(m.is_multicast());
        assert_eq!(
            "aa:bb:cc:dd:ee:ff".parse::<MacAddr>().expect("parse"),
            MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        for bad in ["", "01:02:03:04:05", "01:02:03:04:05:06:07", "001:02:03:04:05:06", "zz:02:03:04:05:06"] {
            assert!(bad.parse::<MacAddr>().is_err(), "{bad}");
        }
    }

    #[test]
    fn a_timestamp_counts_nanoseconds() {
        let t = Timestamp { secs: 2, nanos: 5, source: TimestampSource::Software };
        assert_eq!(t.as_nanos(), 2_000_000_005);
    }
}
