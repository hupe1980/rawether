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

    /// The frame's Ethernet header and payload, or `None` if fewer octets were captured than
    /// the header announces. For a truncated packet the payload is the captured part only: see
    /// [`is_truncated`](Packet::is_truncated).
    ///
    /// ```no_run
    /// # fn f(sock: &mut rawether::Socket) -> std::io::Result<()> {
    /// if let Some(p) = sock.recv(None)? {
    ///     if let Some(f) = p.frame() {
    ///         println!("{} → {} type {:04x}", f.source(), f.destination(), f.ethertype());
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    pub fn frame(&self) -> Option<crate::Frame<'a>> {
        crate::Frame::new(self.data)
    }

    /// Whether an 802.1Q/802.1ad tag the driver had stripped into metadata was put back, so that
    /// `data()` is the frame as it was on the wire.
    pub fn vlan_restored(&self) -> bool {
        self.vlan_restored
    }
}

/// Frame counters for a socket, accumulated since it was opened. They mean the same on every
/// platform; neither counts frames lost before the socket (in the NIC or the kernel's
/// per-CPU backlog).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Frames that passed the filter and reached the socket. Linux counts them when the kernel
    /// queues them; macOS and FreeBSD when rawether reads them from the device.
    pub received: u64,
    /// Frames that passed the filter but found the ring or buffer full.
    pub dropped: u64,
}

/// Launch-time frames the kernel dropped, by reason, since the last
/// [`Socket::tx_errors`](crate::Socket::tx_errors).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxErrors {
    /// The launch time had passed, or would have by the time the frame reached the qdisc.
    pub missed: u64,
    /// The qdisc refused the frame's launch-time parameters, for example a launch time already
    /// past or on another clock.
    pub invalid: u64,
    /// Transmit timestamps rawether dropped because more were waiting unread than it keeps
    /// (1 024 per socket).
    pub timestamps_lost: u64,
}

impl TxErrors {
    /// Launch-time frames dropped, for either reason.
    pub fn dropped(&self) -> u64 {
        self.missed + self.invalid
    }
}

/// When a sent frame left, by its identifier ([`Socket::next_tx_id`](crate::Socket::next_tx_id)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TxTimestamp {
    /// The identifier the socket gave the frame.
    pub id: u32,
    /// When it left: the NIC's clock ([`TimestampSource::Hardware`]) or the kernel's as the
    /// frame reached the driver ([`TimestampSource::Software`]).
    pub timestamp: Timestamp,
}

/// What an interface can timestamp, and which PTP hardware clock stamps it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[allow(clippy::struct_excessive_bools)] // four independent capabilities, as ethtool reports them
pub struct TimestampInfo {
    /// The kernel stamps received frames.
    pub software_rx: bool,
    /// The kernel stamps transmitted frames.
    pub software_tx: bool,
    /// The NIC stamps received frames on its own clock.
    pub hardware_rx: bool,
    /// The NIC stamps transmitted frames on its own clock.
    pub hardware_tx: bool,
    /// The PTP hardware clock (`/dev/ptp<index>`) the NIC's stamps come from, if it has one.
    pub phc_index: Option<u32>,
}

impl TimestampInfo {
    /// The PTP hardware clock's device path, `/dev/ptp<index>`.
    pub fn phc_path(&self) -> Option<std::path::PathBuf> {
        self.phc_index.map(|i| std::path::PathBuf::from(format!("/dev/ptp{i}")))
    }

    /// From `struct ethtool_ts_info`'s `so_timestamping` bits and `phc_index` (−1: none).
    #[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
    pub(crate) fn from_ethtool(so_timestamping: u32, phc_index: i32) -> TimestampInfo {
        // `SOF_TIMESTAMPING_{TX,RX}_{HARDWARE,SOFTWARE}` and `RAW_HARDWARE`.
        let has = |bit: u32| so_timestamping & (1 << bit) != 0;
        TimestampInfo {
            software_rx: has(3),
            software_tx: has(1),
            hardware_rx: has(2) && has(6),
            hardware_tx: has(0) && has(6),
            phc_index: u32::try_from(phc_index).ok(),
        }
    }
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

    /// Spec 007: capability bits and the PHC index are read as ethtool reports them.
    #[test]
    fn timestamp_capabilities_follow_the_ethtool_bits() {
        // veth: SOFTWARE | RX_SOFTWARE | TX_SOFTWARE, no PHC.
        let veth = TimestampInfo::from_ethtool(0b1_1010, -1);
        assert_eq!(veth, TimestampInfo { software_rx: true, software_tx: true, ..TimestampInfo::default() });
        assert_eq!(veth.phc_path(), None);
        // A PTP NIC: all of them plus RAW_HARDWARE, PHC 2.
        let nic = TimestampInfo::from_ethtool(0b101_1111, 2);
        assert!(nic.hardware_rx && nic.hardware_tx && nic.software_rx && nic.software_tx);
        assert_eq!(nic.phc_path(), Some(std::path::PathBuf::from("/dev/ptp2")));
        // Hardware bits without RAW_HARDWARE do not count as hardware stamps.
        assert!(!TimestampInfo::from_ethtool(0b0101, 0).hardware_rx);
    }

    #[test]
    fn a_timestamp_counts_nanoseconds() {
        let t = Timestamp { secs: 2, nanos: 5, source: TimestampSource::Software };
        assert_eq!(t.as_nanos(), 2_000_000_005);
    }
}
