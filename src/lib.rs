//! Raw layer-2 Ethernet I/O.
//!
//! Open a [`Socket`] on a named interface, choose which frames reach it, and send and receive
//! whole Ethernet frames — with the kernel features that make that fast and precise:
//!
//! | | Linux (AF_PACKET) | macOS, FreeBSD (BPF) |
//! |---|---|---|
//! | EtherType filter, tagged or not; custom classic BPF | ✓ in kernel | ✓ in kernel |
//! | Multicast membership, all-multicast, promiscuous | ✓ | ✓ (all-multicast via promiscuous) |
//! | Receive ring (TPACKET_V3), zero-copy | ✓, `recvmsg` fallback | read buffer |
//! | Receive timestamps | hardware or software, labelled | software |
//! | Stripped VLAN tags put back | ✓ | not needed |
//! | Batched send | `sendmmsg` | loop |
//! | Launch-time send (`SO_TXTIME`), `SO_PRIORITY`, qdisc bypass | ✓ | — |
//! | Drop counters | ✓ | ✓ |
//! | Pollable fd, non-blocking, timed receive | ✓ | ✓ |
//!
//! Other platforms compile, and [`Socket::open`] returns [`std::io::ErrorKind::Unsupported`].
//!
//! ```no_run
//! use std::time::Duration;
//!
//! # fn main() -> std::io::Result<()> {
//! // LLDP and PTP frames, VLAN-tagged or not, with timestamps.
//! use rawether::EtherType;
//! let mut sock = rawether::Config::new("eth0").ethertypes([EtherType::LLDP, EtherType::PTP]).open()?;
//! while let Some(p) = sock.recv(Some(Duration::from_secs(1)))? {
//!     let Some(f) = p.frame() else { continue }; // shorter than a header: skip, never panic
//!     println!("{} sent {} at {:?}", f.source(), f.ethertype(), p.timestamp());
//! }
//! # Ok(()) }
//! ```
//!
//! Receiving hands out a [`Packet`] that borrows the socket's ring or buffer until the next
//! receive, so a steady-state loop never allocates.
//!
//! # Frames
//!
//! [`Packet::frame`] (or [`Frame::new`] on any byte slice) reads the Ethernet header: addresses,
//! up to two VLAN tags, the EtherType and the payload, without index arithmetic and without
//! panicking on a short frame. [`FrameBuilder`] writes a frame into a buffer you reuse, padded
//! to the Ethernet minimum, and [`Frame::reply`] answers a received one:
//!
//! ```no_run
//! # fn f(sock: &mut rawether::Socket) -> std::io::Result<()> {
//! let me = sock.mac_address();
//! let mut buf = Vec::with_capacity(1518);
//! loop {
//!     let Some(p) = sock.recv(None)? else { continue };
//!     let Some(reply) = p.frame().and_then(|f| f.reply(me)) else { continue };
//!     reply.write(&mut buf, b"pong"); // the builder holds no borrow of the packet
//!     sock.send(&buf)?;
//! }
//! # }
//! ```
//!
//! # Privileges
//!
//! Opening a socket needs `CAP_NET_RAW` on Linux and read/write access to `/dev/bpf*` on macOS
//! and FreeBSD. Grant the capability to the binary (`setcap cap_net_raw+ep`) rather than running
//! as root, and call [`drop_capabilities`] once every socket is open: the sockets keep working,
//! and the code that parses untrusted frames no longer holds the privilege.
//!
//! # Security
//!
//! The [threat model](threat_model) states what rawether defends against (the ring shared with
//! the kernel, hostile frame shapes, the privilege, descriptor leaks, silent drops), what it
//! trusts, and the test that guards each claim. Report a vulnerability privately through
//! [GitHub's private vulnerability reporting](https://github.com/hupe1980/rawether/security/advisories/new).
//!
//! More guides, including launch-time transmission, hardware timestamps and event-loop
//! integration, are on the [rawether website](https://hupe1980.github.io/rawether/).

#![deny(unsafe_op_in_unsafe_fn)]

pub mod bpf;
#[cfg(any(target_os = "macos", target_os = "freebsd", test, fuzzing))]
mod bpf_record;
mod config;
mod ethertype;
pub mod frame;
#[cfg(any(target_os = "linux", test))]
mod hwtstamp;
mod packet;
#[cfg(any(target_os = "linux", test, fuzzing))]
mod ring;
mod sys;
pub mod threat_model;
#[cfg(any(target_os = "linux", test, fuzzing))]
mod vlan;

use std::io;
use std::time::Duration;

pub use config::{Clock, Config, Filter, RingConfig, RxMode, Timestamping, TxTime};
pub use ethertype::EtherType;
pub use frame::{Frame, FrameBuilder, TagKind, VlanTag};
pub use packet::{
    MacAddr, Packet, RxPath, Stats, Timestamp, TimestampInfo, TimestampSource, TxErrors, TxTimestamp,
};

/// An open raw socket on one interface.
#[derive(Debug)]
pub struct Socket {
    inner: sys::Inner,
}

impl Socket {
    /// Open a socket as `config` describes.
    ///
    /// The filter is in place before the socket is bound, so no frame it rejects is ever
    /// queued.
    pub fn open(config: &Config) -> io::Result<Socket> {
        config.validate()?;
        let program = config.program()?;
        Ok(Socket { inner: sys::Inner::open(config, program.as_ref())? })
    }

    /// The interface's name.
    pub fn interface(&self) -> &str {
        self.inner.interface()
    }

    /// The interface's index.
    pub fn index(&self) -> u32 {
        self.inner.index()
    }

    /// The interface's hardware address — the source address of frames this host sends.
    pub fn mac_address(&self) -> MacAddr {
        self.inner.mac()
    }

    /// How received frames reach user space.
    pub fn rx_path(&self) -> RxPath {
        self.inner.rx_path()
    }

    /// Wait for the next frame for at most `timeout` (`None`: indefinitely). `Ok(None)` when the
    /// time ran out, or at once on a non-blocking socket with nothing waiting.
    ///
    /// The packet borrows the socket, so its memory cannot be handed back to the kernel while it
    /// is in use (threat model T-02, SR-002):
    ///
    /// ```compile_fail
    /// # fn f(sock: &mut rawether::Socket) -> std::io::Result<()> {
    /// let first = sock.recv(None)?;
    /// let second = sock.recv(None)?; // error: `sock` is still borrowed by `first`
    /// drop(first);
    /// # Ok(()) }
    /// ```
    pub fn recv(&mut self, timeout: Option<Duration>) -> io::Result<Option<Packet<'_>>> {
        self.inner.recv(timeout)
    }

    /// The next frame if one is already waiting.
    pub fn try_recv(&mut self) -> io::Result<Option<Packet<'_>>> {
        self.inner.recv(Some(Duration::ZERO))
    }

    /// Send one frame: destination MAC first, at least 14 octets, no frame check sequence.
    pub fn send(&self, frame: &[u8]) -> io::Result<()> {
        check_frame(frame)?;
        self.inner.send(frame)
    }

    /// Send one frame to leave at `launch_ns` nanoseconds on the configured launch-time clock
    /// ([`Config::tx_time`]; read the clock with [`clock_now`]).
    pub fn send_at(&self, frame: &[u8], launch_ns: u64) -> io::Result<()> {
        check_frame(frame)?;
        self.inner.send_at(frame, launch_ns)
    }

    /// Send several frames with as few system calls as the platform allows. Returns how many
    /// were sent, which is all of them unless an error interrupted the batch.
    pub fn send_batch(&mut self, frames: &[&[u8]]) -> io::Result<usize> {
        for f in frames {
            check_frame(f)?;
        }
        self.inner.send_batch(frames)
    }

    /// Frames received and dropped since the socket was opened.
    pub fn stats(&mut self) -> io::Result<Stats> {
        self.inner.stats()
    }

    /// Launch-time frames the kernel dropped since the last call, by reason (Linux, with
    /// [`TxTime::report_errors`]). Always zero elsewhere.
    pub fn tx_errors(&mut self) -> io::Result<TxErrors> {
        self.inner.tx_errors()
    }

    /// The transmit timestamps this socket delivers: [`Timestamping::Off`] unless
    /// [`Config::tx_timestamping`] asked for them; a request for hardware stamps that the NIC
    /// cannot honour delivers [`Timestamping::Software`].
    pub fn tx_timestamping(&self) -> Timestamping {
        self.inner.tx_timestamping()
    }

    /// The identifier the next frame sent gets; a batch gets consecutive ones (wrapping). On
    /// Linux 6.13 and later identifiers are exact; before, the kernel numbers frames itself and
    /// a send it refuses after numbering (a qdisc drop) shifts later identifiers by one.
    pub fn next_tx_id(&self) -> u32 {
        self.inner.next_tx_id()
    }

    /// The next transmit timestamp, waiting for at most `timeout` (`None`: indefinitely; at once
    /// on a non-blocking socket). Timestamps may arrive out of order; match them by
    /// [`TxTimestamp::id`]. Fails with `InvalidInput` unless [`Config::tx_timestamping`] is on.
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// use rawether::{Config, Timestamping};
    ///
    /// # fn main() -> std::io::Result<()> {
    /// # let frame = [0u8; 60];
    /// let mut sock = Config::new("eth0").tx_timestamping(Timestamping::Hardware).open()?;
    /// let id = sock.next_tx_id();
    /// sock.send(&frame)?;
    /// if let Some(t) = sock.tx_timestamp(Some(Duration::from_millis(10)))? {
    ///     assert_eq!(t.id, id);
    ///     println!("left at {:?} ({:?})", t.timestamp.as_nanos(), t.timestamp.source);
    /// }
    /// # Ok(()) }
    /// ```
    pub fn tx_timestamp(&mut self, timeout: Option<Duration>) -> io::Result<Option<TxTimestamp>> {
        self.inner.tx_timestamp(timeout)
    }

    /// What this socket's interface can timestamp, and its PTP hardware clock: see
    /// [`timestamp_info`].
    pub fn timestamp_info(&self) -> io::Result<TimestampInfo> {
        timestamp_info(self.interface())
    }

    /// The timestamps this socket delivers. [`Timestamping::Hardware`] when the NIC stamps
    /// received frames; a request for hardware timestamps that the NIC cannot honour delivers
    /// [`Timestamping::Software`]. Each frame's [`Timestamp::source`] says which clock stamped
    /// it.
    pub fn timestamping(&self) -> Timestamping {
        self.inner.timestamping()
    }

    /// Switch non-blocking mode.
    pub fn set_nonblocking(&mut self, on: bool) -> io::Result<()> {
        self.inner.set_nonblocking(on)
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for Socket {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

#[cfg(unix)]
impl std::os::fd::AsRawFd for Socket {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.inner.as_fd().as_raw_fd()
    }
}

/// Give up the privilege that opening a socket needed, for the whole process, keeping every
/// socket already open.
///
/// On Linux this clears the calling thread's effective, permitted, inheritable and ambient
/// capability sets, removes every capability from the bounding set where the process may
/// (with `CAP_SETPCAP`), and sets `no_new_privs`, so no later `exec` regains privilege. Open
/// sockets keep working: the kernel checks `CAP_NET_RAW` only when one is created.
///
/// Capabilities are per thread. If any other thread of the process still holds one afterwards,
/// or that cannot be checked (no `/proc`), this returns an error rather than leaving a thread
/// privileged: call it after opening the sockets and before spawning threads. In an async
/// program, that means before building a multi-threaded runtime:
///
/// ```no_run
/// fn main() -> std::io::Result<()> {
///     let sock = rawether::Config::new("eth0").ethertypes([rawether::EtherType::PTP]).open()?;
///     rawether::drop_capabilities()?; // still the only thread
///     // ...then build the runtime (or spawn threads) and move `sock` into it.
///     # drop(sock);
///     Ok(())
/// }
/// ```
///
/// On macOS and FreeBSD the privilege is access to `/dev/bpf*`, which an open descriptor
/// already holds, and this does nothing. A process running as root keeps its user id: drop
/// that separately.
pub fn drop_capabilities() -> io::Result<()> {
    sys::drop_capabilities()
}

/// What `interface` can timestamp, and which PTP hardware clock (`/dev/ptp<index>`) its
/// hardware stamps come from. Needs no privilege. On macOS and FreeBSD, BPF stamps received
/// frames in software and there is no hardware clock.
///
/// ```no_run
/// # fn main() -> std::io::Result<()> {
/// let info = rawether::timestamp_info("eth0")?;
/// if let Some(phc) = info.phc_path() {
///     println!("hardware stamps on {}", phc.display());
/// }
/// # Ok(()) }
/// ```
pub fn timestamp_info(interface: &str) -> io::Result<TimestampInfo> {
    sys::timestamp_info(interface)
}

/// Read `clock` — for computing launch times.
pub fn clock_now(clock: Clock) -> io::Result<Duration> {
    sys::clock_now(clock)
}

fn check_frame(frame: &[u8]) -> io::Result<()> {
    if frame.len() < 14 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("a frame of {} octets has no Ethernet header", frame.len()),
        ));
    }
    Ok(())
}

/// Entry points into the internal parsers for the fuzz targets in `fuzz/`. Not part of the API.
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing {
    /// Walk one TPACKET_V3 block as the receive ring does, re-inserting stripped tags.
    pub fn ring_walk(block: &mut [u8]) {
        let Some(mut cur) = crate::ring::Cursor::start(block) else { return };
        let mut found = Vec::new();
        while let Some((at, meta)) = cur.next(block) {
            assert!(at + meta.mac + meta.snaplen <= block.len());
            found.push((at + meta.mac, meta.snaplen, meta.stripped_vlan()));
        }
        for (start, len, tag) in found {
            if let (Some((tpid, tci)), Some(lo)) = (tag, start.checked_sub(4))
                && let Some(region) = block.get_mut(lo..start + len)
            {
                let _ = crate::vlan::reinsert(region, 4, len, tpid, tci);
            }
        }
    }

    /// Parse a BPF read buffer with both platforms' layouts.
    pub fn bpf_records(buf: &[u8]) {
        for layout in [crate::bpf_record::Layout::MACOS, crate::bpf_record::Layout::FREEBSD_LP64] {
            let mut pos = 0;
            while let Some(r) = crate::bpf_record::next(buf, &mut pos, layout) {
                assert!(r.start + r.caplen <= buf.len());
            }
        }
    }

    /// Re-insert a tag into `buf` at `start` with `len`, as the plain path does.
    pub fn vlan_reinsert(buf: &mut [u8], start: usize, len: usize, tpid: u16, tci: u16) {
        let before = buf.to_vec();
        match crate::vlan::reinsert(buf, start, len, tpid, tci) {
            Some((s, l)) => assert!(s + l <= buf.len()),
            None => assert_eq!(buf, &before[..], "a refused re-insertion leaves the buffer alone"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)] // system calls
    fn opening_a_missing_interface_or_on_an_unsupported_platform_fails_cleanly() {
        let e = Socket::open(&Config::new("no-such-if0")).expect_err("no interface");
        assert!(
            matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
            ),
            "{e:?}"
        );
    }

    /// On macOS a BPF device on the loopback interface opens with access to `/dev/bpf*`, and
    /// without it fails naming what is missing.
    #[cfg(target_os = "macos")]
    #[test]
    #[cfg_attr(miri, ignore)] // system calls
    fn the_loopback_interface_opens_or_says_what_access_is_missing() {
        match Socket::open(&Config::new("lo0")) {
            Ok(s) => assert_eq!(s.rx_path(), RxPath::Bpf),
            Err(e) => {
                assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
                assert!(e.to_string().contains("/dev/bpf"), "{e}");
            }
        }
    }

    /// Threat model T-07 (SR-007).
    #[test]
    fn the_default_configuration_is_neither_promiscuous_nor_all_multicast() {
        let c = Config::new("eth0");
        assert!(!c.promiscuous && !c.all_multicast);
    }

    #[test]
    fn a_frame_without_a_header_is_refused_before_any_system_call() {
        assert_eq!(check_frame(&[0; 13]).expect_err("short").kind(), io::ErrorKind::InvalidInput);
        assert!(check_frame(&[0; 14]).is_ok());
    }
}
