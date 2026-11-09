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
//! let mut sock = rawether::Config::new("eth0").ethertypes(&[0x88cc, 0x88f7]).open()?;
//! while let Some(p) = sock.recv(Some(Duration::from_secs(1)))? {
//!     println!("{} octets at {:?}", p.data().len(), p.timestamp());
//! }
//! # Ok(()) }
//! ```
//!
//! Receiving hands out a [`Packet`] that borrows the socket's ring or buffer until the next
//! receive, so a steady-state loop never allocates. Opening needs `CAP_NET_RAW` on Linux and
//! read/write access to `/dev/bpf*` on the BSDs.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod bpf;
mod config;
mod packet;
#[cfg(any(target_os = "linux", test))]
mod ring;
mod sys;
#[cfg(any(target_os = "linux", test))]
mod vlan;

use std::io;
use std::time::Duration;

pub use config::{Clock, Config, Filter, RingConfig, RxMode, Timestamping, TxTime};
pub use packet::{MacAddr, Packet, RxPath, Stats, Timestamp, TimestampSource};

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
    /// The packet borrows the socket (SR-002), so its memory cannot be handed back to the kernel while
    /// it is in use:
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

    /// Frames the kernel reported it could not send (launch time missed, no qdisc), drained
    /// from the error queue since the last call.
    pub fn tx_errors(&mut self) -> io::Result<u64> {
        self.inner.tx_errors()
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

/// Give up the privilege that opening a socket needed, keeping every socket already open.
///
/// On Linux this clears the process's effective, permitted and inheritable capability sets
/// (so `CAP_NET_RAW` is gone) and sets `no_new_privs`, so no later `exec` regains privilege;
/// sockets keep working because the kernel checks the capability only when one is created.
/// Call it after opening every socket and before handling the first frame. On the BSDs the
/// privilege is access to `/dev/bpf*`, which an open descriptor already holds, and this does
/// nothing. A process running as root keeps its user id: drop that separately.
pub fn drop_capabilities() -> io::Result<()> {
    sys::drop_capabilities()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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
    fn the_loopback_interface_opens_or_says_what_access_is_missing() {
        match Socket::open(&Config::new("lo0")) {
            Ok(s) => assert_eq!(s.rx_path(), RxPath::Bpf),
            Err(e) => {
                assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
                assert!(e.to_string().contains("/dev/bpf"), "{e}");
            }
        }
    }

    /// SR-007.
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
