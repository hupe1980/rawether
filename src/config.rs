//! How a socket is opened.

use std::io;

use crate::EtherType;
use crate::Socket;
use crate::bpf::Program;
use crate::packet::MacAddr;

/// Which frames reach the socket.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Filter {
    /// Every frame on the interface.
    #[default]
    All,
    /// Frames whose EtherType is in the set — untagged, or behind one or two 802.1Q/802.1ad
    /// tags. Compiled with [`Program::ethertypes`].
    EtherTypes(Vec<EtherType>),
    /// A classic-BPF program of the caller's.
    Bpf(Program),
}

/// The geometry of a TPACKET_V3 receive ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingConfig {
    /// Octets per block: a power of two, a multiple of the page size.
    pub block_size: u32,
    /// Blocks in the ring.
    pub block_count: u32,
    /// The frame slot size the kernel is told about, in octets. TPACKET_V3 packs frames into a
    /// block by their own length, so this does not cap a frame; a frame is captured short only
    /// when the filter returns a smaller snap length or the frame exceeds a block.
    pub frame_size: u32,
    /// How long the kernel waits before handing over a block that is not full, in milliseconds.
    /// This bounds the latency the ring adds when traffic is light.
    pub retire_ms: u32,
}

impl Default for RingConfig {
    /// 64 blocks of 64 KiB (4 MiB), 2 KiB frame slots, 1 ms block timeout.
    ///
    /// Many small blocks rather than a few large ones: at a low frame rate the kernel retires a
    /// block after `retire_ms` with whatever it holds — often one frame — so the number of
    /// blocks is how many frames the ring keeps while the reader is busy. 64 blocks keep 64
    /// sparse frames, and at line rate a 64 KiB block holds dozens of small frames.
    fn default() -> RingConfig {
        RingConfig { block_size: 1 << 16, block_count: 64, frame_size: 2048, retire_ms: 1 }
    }
}

/// How received frames reach user space.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RxMode {
    /// The ring with the default geometry where the platform has one and the kernel grants it,
    /// else one system call per frame. [`Socket::rx_path`] says which.
    #[default]
    Auto,
    /// A TPACKET_V3 ring with this geometry. Opening fails if the kernel refuses it (Linux);
    /// other platforms have no ring and use their only path.
    Ring(RingConfig),
    /// One `recvmsg` per frame: the lowest latency, the most system calls.
    Plain,
}

/// Receive timestamps.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Timestamping {
    /// None.
    Off,
    /// The kernel's, on `CLOCK_REALTIME`.
    #[default]
    Software,
    /// The NIC's where it stamps received frames, otherwise the kernel's; each frame says which
    /// it got, and [`Socket::timestamping`] what the socket delivers. On Linux the NIC's
    /// device-wide configuration is read first and never lowered: a NIC that already stamps
    /// (for example for `ptp4l`) is used as it is, and only one that stamps nothing is widened,
    /// which needs `CAP_NET_ADMIN`.
    Hardware,
}

/// A clock a launch time is expressed on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Clock {
    /// International Atomic Time — what `etf` and `taprio` expect.
    Tai,
    /// `CLOCK_MONOTONIC`.
    Monotonic,
    /// `CLOCK_REALTIME`.
    Realtime,
}

/// Launch-time transmission (`SO_TXTIME`, Linux).
///
/// A frame sent with [`Socket::send_at`] leaves at the given time on `clock`. The egress queue
/// needs a qdisc that honours it (`etf`, or `taprio` in txtime-assisted mode); without one the
/// launch time is ignored and the frame leaves at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TxTime {
    /// The clock launch times are on.
    pub clock: Clock,
    /// `SOF_TXTIME_DEADLINE_MODE`: the time is a deadline rather than an exact launch time.
    pub deadline: bool,
    /// `SOF_TXTIME_REPORT_ERRORS`: frames the qdisc drops are reported, by reason, through
    /// [`Socket::tx_errors`].
    pub report_errors: bool,
}

impl Default for TxTime {
    fn default() -> TxTime {
        TxTime { clock: Clock::Tai, deadline: false, report_errors: true }
    }
}

/// Everything [`Socket::open`] needs.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // independent switches of a builder, not a state machine
pub struct Config {
    pub(crate) interface: String,
    pub(crate) filter: Filter,
    pub(crate) multicast: Vec<MacAddr>,
    pub(crate) all_multicast: bool,
    pub(crate) promiscuous: bool,
    pub(crate) rx: RxMode,
    pub(crate) timestamping: Timestamping,
    pub(crate) tx_timestamping: Timestamping,
    pub(crate) priority: Option<u32>,
    pub(crate) tx_time: Option<TxTime>,
    pub(crate) qdisc_bypass: bool,
    pub(crate) nonblocking: bool,
    pub(crate) restore_vlan: bool,
    pub(crate) see_outgoing: bool,
    pub(crate) buffer_size: usize,
}

impl Config {
    /// A socket on `interface` that receives every frame.
    pub fn new(interface: impl Into<String>) -> Config {
        Config {
            interface: interface.into(),
            filter: Filter::All,
            multicast: Vec::new(),
            all_multicast: false,
            promiscuous: false,
            rx: RxMode::Auto,
            timestamping: Timestamping::Software,
            tx_timestamping: Timestamping::Off,
            priority: None,
            tx_time: None,
            qdisc_bypass: false,
            nonblocking: false,
            restore_vlan: true,
            see_outgoing: false,
            buffer_size: 1 << 20,
        }
    }

    /// Receive only frames of these EtherTypes, tagged or not: names, numbers or a mix
    /// (`[EtherType::LLDP, EtherType::PTP]`, `&[0x88b5u16]`).
    #[must_use]
    pub fn ethertypes<T: Into<EtherType>>(mut self, types: impl IntoIterator<Item = T>) -> Config {
        self.filter = Filter::EtherTypes(types.into_iter().map(Into::into).collect());
        self
    }

    /// Install a filter.
    #[must_use]
    pub fn filter(mut self, filter: Filter) -> Config {
        self.filter = filter;
        self
    }

    /// Join a multicast group (any MAC with the group bit set).
    #[must_use]
    pub fn join(mut self, group: MacAddr) -> Config {
        if !self.multicast.contains(&group) {
            self.multicast.push(group);
        }
        self
    }

    /// Receive every multicast frame (on BSD this needs promiscuous mode, which it then enables).
    #[must_use]
    pub fn all_multicast(mut self, on: bool) -> Config {
        self.all_multicast = on;
        self
    }

    /// Receive frames addressed to anyone.
    #[must_use]
    pub fn promiscuous(mut self, on: bool) -> Config {
        self.promiscuous = on;
        self
    }

    /// How frames reach user space.
    #[must_use]
    pub fn rx_mode(mut self, mode: RxMode) -> Config {
        self.rx = mode;
        self
    }

    /// Receive timestamps.
    #[must_use]
    pub fn timestamping(mut self, t: Timestamping) -> Config {
        self.timestamping = t;
        self
    }

    /// Transmit timestamps (Linux; off by default): every frame sent gets an identifier
    /// ([`Socket::next_tx_id`]), and [`Socket::tx_timestamp`] hands back when it left.
    /// [`Timestamping::Hardware`] uses the NIC's clock where it stamps transmitted frames, under
    /// the same never-lower rule as receive stamps; otherwise the kernel's.
    #[must_use]
    pub fn tx_timestamping(mut self, t: Timestamping) -> Config {
        self.tx_timestamping = t;
        self
    }

    /// `SO_PRIORITY` for frames sent (Linux): picks the traffic class and, through an egress
    /// QoS map, the VLAN PCP the kernel writes when it adds a tag.
    #[must_use]
    pub fn priority(mut self, priority: u32) -> Config {
        self.priority = Some(priority);
        self
    }

    /// Enable launch-time transmission.
    #[must_use]
    pub fn tx_time(mut self, t: TxTime) -> Config {
        self.tx_time = Some(t);
        self
    }

    /// `PACKET_QDISC_BYPASS` (Linux): frames skip the queueing discipline. Faster, but loses
    /// traffic shaping — and launch times, which need a qdisc.
    #[must_use]
    pub fn qdisc_bypass(mut self, on: bool) -> Config {
        self.qdisc_bypass = on;
        self
    }

    /// Open the socket non-blocking: receives return `Ok(None)` at once when nothing is waiting.
    #[must_use]
    pub fn nonblocking(mut self, on: bool) -> Config {
        self.nonblocking = on;
        self
    }

    /// Put back an 802.1Q/802.1ad tag the driver stripped into metadata (default on).
    #[must_use]
    pub fn restore_vlan(mut self, on: bool) -> Config {
        self.restore_vlan = on;
        self
    }

    /// Also receive the frames this host sends on the interface (default off).
    #[must_use]
    pub fn see_outgoing(mut self, on: bool) -> Config {
        self.see_outgoing = on;
        self
    }

    /// Size of the receive buffer for the plain and BPF paths, in octets.
    #[must_use]
    pub fn buffer_size(mut self, octets: usize) -> Config {
        self.buffer_size = octets.max(4096);
        self
    }

    /// The interface name.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Open the socket. Shorthand for [`Socket::open`].
    pub fn open(&self) -> io::Result<Socket> {
        Socket::open(self)
    }

    /// The filter program this configuration installs, if any.
    pub(crate) fn program(&self) -> io::Result<Option<Program>> {
        match &self.filter {
            Filter::All => Ok(None),
            Filter::EtherTypes(types) => Program::ethertypes(types.iter()).map(Some),
            Filter::Bpf(p) => Ok(Some(p.clone())),
        }
    }

    pub(crate) fn validate(&self) -> io::Result<()> {
        if self.interface.is_empty() || self.interface.len() >= 16 || self.interface.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{:?} is not an interface name (1 to 15 octets, no NUL)", self.interface),
            ));
        }
        if let Some(m) = self.multicast.iter().find(|m| !m.is_multicast()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{m} is not a multicast address"),
            ));
        }
        // The kernel counts frames in a `u32` and the mapping is `block_size × block_count`
        // octets: both must fit, on every pointer width.
        if let RxMode::Ring(r) = self.rx
            && (r.block_count == 0
                || !r.block_size.is_power_of_two()
                || r.frame_size < 128
                || r.frame_size > r.block_size
                || (r.block_size / r.frame_size).checked_mul(r.block_count).is_none()
                || (r.block_size as usize).checked_mul(r.block_count as usize).is_none())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("ring geometry {r:?} is not usable"),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_configuration_is_checked_before_any_system_call() {
        assert!(Config::new("").validate().is_err());
        assert!(Config::new("a-name-that-is-too-long").validate().is_err());
        assert!(Config::new("eth0").join(MacAddr([0, 1, 2, 3, 4, 5])).validate().is_err(), "unicast group");
        assert!(Config::new("eth0").join(MacAddr([1, 0x80, 0xc2, 0, 0, 0xe])).validate().is_ok());
        let ring = RingConfig { block_size: 1000, ..RingConfig::default() };
        assert!(Config::new("eth0").rx_mode(RxMode::Ring(ring)).validate().is_err());
        // Spec 003 SR-008: sizes that overflow are refused before any system call.
        let huge = RingConfig { block_size: 1 << 31, frame_size: 128, block_count: u32::MAX, retire_ms: 1 };
        assert!(Config::new("eth0").rx_mode(RxMode::Ring(huge)).validate().is_err());
        let none = RingConfig { block_count: 0, ..RingConfig::default() };
        assert!(Config::new("eth0").rx_mode(RxMode::Ring(none)).validate().is_err());
        assert!(Config::new("eth0").ethertypes::<EtherType>([]).program().is_err());
        assert!(Config::new("eth0").ethertypes([EtherType::LLDP]).program().expect("program").is_some());
        // Spec 015 SC-002: names, numbers and slices give the same program.
        let named =
            Config::new("eth0").ethertypes([EtherType::LLDP, EtherType::PTP]).program().expect("named");
        let numbered = Config::new("eth0").ethertypes([0x88ccu16, 0x88f7]).program().expect("numbered");
        assert_eq!(named, numbered);
    }

    #[test]
    fn joining_a_group_twice_joins_it_once() {
        let g = MacAddr([1, 0x80, 0xc2, 0, 0, 0xe]);
        assert_eq!(Config::new("eth0").join(g).join(g).multicast, vec![g]);
    }
}
