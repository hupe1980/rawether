//! Linux: AF_PACKET with a TPACKET_V3 block ring or a TPACKET_V2 frame ring.
//!
//! Every `unsafe` block below wraps one system call or one access to the memory the kernel
//! shares through the ring, and says why it is sound.

use std::cell::Cell;
use std::collections::VecDeque;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering, fence};
use std::time::{Duration, Instant};

use super::deadline;
use super::unix::{Ready, ifr_name, interface_index, last_error, set_nonblocking, socket_error, wait};
use crate::bpf::Program;
use crate::config::{Clock, Config, FrameRingConfig, RingConfig, RxMode, Timestamping, TxTime};
use crate::hwtstamp::{self, Plan};
use crate::packet::{MacAddr, Packet, RxPath, Stats, Timestamp, TimestampSource, TxErrors};
use crate::packet::{TimestampInfo, TxTimestamp};
use crate::ring::{self, Cursor};
use crate::vlan;

/// `enum tpacket_versions` — not exported by `libc`.
const TPACKET_V2: libc::c_int = 1;
const TPACKET_V3: libc::c_int = 2;
/// Head-room the kernel leaves in front of every ring frame, for VLAN re-insertion.
const RESERVE: libc::c_uint = 4;
/// `PACKET_TX_TIMESTAMP` (`<linux/if_packet.h>`): the control message carrying error-queue
/// reports on a packet socket. Not exported by `libc`.
const PACKET_TX_TIMESTAMP: libc::c_int = 16;
/// `SO_EE_ORIGIN_TXTIME` and its codes (`<linux/errqueue.h>`). Not exported by `libc`.
const SO_EE_ORIGIN_TXTIME: u8 = 6;
const SO_EE_CODE_TXTIME_INVALID_PARAM: u8 = 1;
const SO_EE_CODE_TXTIME_MISSED: u8 = 2;
/// `SCM_TS_OPT_ID` (`<asm-generic/socket.h>`, Linux 6.13): the transmit timestamp id of one
/// send. Not exported by `libc`.
const SCM_TS_OPT_ID: libc::c_int = 81;
/// `SCM_TSTAMP_SND`: a report that the frame left (`ee_info`).
const SCM_TSTAMP_SND: u32 = 0;
/// Unread transmit timestamps kept per socket.
const TX_QUEUE: usize = 1024;

/// How transmit timestamp ids are assigned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdMode {
    /// rawether passes each id with `SCM_TS_OPT_ID`; not yet accepted by the kernel.
    Explicit,
    /// The kernel accepted an explicit id: ids are exact.
    Confirmed,
    /// The kernel (before 6.13) rejected `SCM_TS_OPT_ID`: it numbers frames itself.
    Implicit,
}
/// `sockaddr_ll` follows the frame header at `TPACKET_ALIGN(sizeof(tpacket3_hdr))`; its
/// `sll_pkttype` is octet 10.
const SLL_PKTTYPE_IN_RING: usize = 48 + 10;
/// Frames handed to `sendmmsg` per system call.
const BATCH: usize = 64;
/// Largest frame the plain path receives in one piece (jumbo frames included).
const PLAIN_MAX: usize = 65_536;

fn setopt<T>(fd: &OwnedFd, level: libc::c_int, name: libc::c_int, value: &T, what: &str) -> io::Result<()> {
    // SAFETY: `value` points to a live `T` and the length passed is exactly its size.
    let r = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            std::ptr::from_ref(value).cast(),
            size_of::<T>() as libc::socklen_t,
        )
    };
    if r < 0 { Err(last_error(what)) } else { Ok(()) }
}

/// The receive ring: a mapping of `block_size × blocks` octets shared with the kernel.
struct Ring {
    base: NonNull<u8>,
    len: usize,
    block_size: usize,
    blocks: usize,
    /// The block being read, if the kernel has handed it over.
    current: usize,
    cursor: Option<Cursor>,
}

// SAFETY: the mapping belongs to this value alone (it is created and unmapped by it, and the
// socket that owns it is not shared), so moving it to another thread moves sole ownership.
unsafe impl Send for Ring {}

impl std::fmt::Debug for Ring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ring")
            .field("block_size", &self.block_size)
            .field("blocks", &self.blocks)
            .finish_non_exhaustive()
    }
}

/// The per-frame receive ring: `frames` slots of `frame_size` octets, `per_block` to a block of
/// `block_size`, in a mapping shared with the kernel.
struct FrameRing {
    base: NonNull<u8>,
    len: usize,
    block_size: usize,
    frame_size: usize,
    per_block: usize,
    frames: usize,
    /// The next slot to read.
    current: usize,
    /// The slot handed out by the last receive, returned to the kernel by the next one.
    held: Option<usize>,
}

// SAFETY: as for `Ring`: the mapping belongs to this value alone.
unsafe impl Send for FrameRing {}

impl std::fmt::Debug for FrameRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrameRing")
            .field("frame_size", &self.frame_size)
            .field("frames", &self.frames)
            .finish_non_exhaustive()
    }
}

impl FrameRing {
    /// Where slot `i` starts in the mapping.
    fn offset(&self, i: usize) -> usize {
        (i / self.per_block) * self.block_size + (i % self.per_block) * self.frame_size
    }

    #[allow(clippy::cast_ptr_alignment)] // the offset is 16-aligned; see the SAFETY comment
    fn status(&self, i: usize) -> &AtomicU32 {
        let offset = self.offset(i) + ring::frame2::STATUS;
        debug_assert!(offset + 4 <= self.len);
        // SAFETY: slot `i < frames` lies inside the mapping; its status word is its first four
        // octets, 16-aligned (blocks are page-aligned, slots multiples of 16), and the kernel
        // accesses it atomically too.
        unsafe { &*self.base.as_ptr().add(offset).cast::<AtomicU32>() }
    }

    /// Slot `i` as a shared slice. Only called for a slot whose `TP_STATUS_USER` bit was observed
    /// with acquire ordering and that has not been released since: the kernel does not write it.
    fn slot(&self, i: usize) -> &[u8] {
        // SAFETY: `[offset, offset + frame_size)` lies inside the mapping, and the slot is in
        // user ownership (see above), so nothing writes it while the shared slice lives.
        unsafe { std::slice::from_raw_parts(self.base.as_ptr().add(self.offset(i)), self.frame_size) }
    }

    /// `range` of user-owned slot `i`, mutably: one frame and its head-room, which only VLAN
    /// re-insertion writes. `None` unless `range` lies inside the slot.
    fn slot_mut(&mut self, i: usize, range: std::ops::Range<usize>) -> Option<&mut [u8]> {
        if range.start > range.end || range.end > self.frame_size {
            return None;
        }
        let offset = self.offset(i) + range.start;
        // SAFETY: the range lies inside the slot (checked) and so inside the mapping; the slot is
        // user-owned and `&mut self` keeps the slice unique on our side.
        Some(unsafe { std::slice::from_raw_parts_mut(self.base.as_ptr().add(offset), range.len()) })
    }

    fn release(&self, i: usize) {
        fence(Ordering::Release);
        self.status(i).store(libc::TP_STATUS_KERNEL, Ordering::Release);
    }
}

impl Drop for FrameRing {
    fn drop(&mut self) {
        // SAFETY: `base`/`len` are exactly what `mmap` returned, and nothing borrows the mapping
        // any more (packets borrow the socket, which is being dropped).
        unsafe {
            libc::munmap(self.base.as_ptr().cast(), self.len);
        }
    }
}

impl Ring {
    #[allow(clippy::cast_ptr_alignment)] // the offset is 4-aligned; see the SAFETY comment
    fn status(&self, block: usize) -> &AtomicU32 {
        let offset = block * self.block_size + ring::block::STATUS;
        debug_assert!(offset + 4 <= self.len);
        // SAFETY: `offset` lies inside the mapping (block < blocks, STATUS + 4 < block_size),
        // is 4-aligned (blocks are page-aligned and STATUS is 8), and the kernel accesses this
        // word atomically too, so viewing it as an `AtomicU32` for the mapping's lifetime is sound.
        unsafe { &*self.base.as_ptr().add(offset).cast::<AtomicU32>() }
    }

    /// The block as a shared slice. Only called for a block whose `TP_STATUS_USER` bit was
    /// observed with acquire ordering and that has not been released since: in that state the
    /// kernel does not write the block (it may still read its descriptor).
    fn block(&self, block: usize) -> &[u8] {
        let offset = block * self.block_size;
        // SAFETY: `[offset, offset + block_size)` lies inside the mapping, and the block is in
        // user ownership (see above), so nothing writes it while the shared slice lives.
        unsafe { std::slice::from_raw_parts(self.base.as_ptr().add(offset), self.block_size) }
    }

    /// `range` of a user-owned block, mutably: one frame and the head-room in front of it, which
    /// only VLAN re-insertion writes. `None` unless `range` lies inside the block.
    fn frame_mut(&mut self, block: usize, range: std::ops::Range<usize>) -> Option<&mut [u8]> {
        if range.start > range.end || range.end > self.block_size {
            return None;
        }
        let offset = block * self.block_size + range.start;
        // SAFETY: the range lies inside the block (checked) and so inside the mapping. The block
        // is user-owned, and the kernel neither reads nor writes a frame's octets in that state;
        // `&mut self` keeps the slice unique on our side.
        Some(unsafe { std::slice::from_raw_parts_mut(self.base.as_ptr().add(offset), range.len()) })
    }

    fn release(&mut self, block: usize) {
        fence(Ordering::Release);
        self.status(block).store(libc::TP_STATUS_KERNEL, Ordering::Release);
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        // SAFETY: `base`/`len` are exactly what `mmap` returned, and nothing borrows the
        // mapping any more (packets borrow the socket, which is being dropped).
        unsafe {
            libc::munmap(self.base.as_ptr().cast(), self.len);
        }
    }
}

/// What the next frame is, as offsets — so the borrow of the ring is taken once, at the end.
struct Found {
    block: usize,
    start: usize,
    len: usize,
    original_len: usize,
    timestamp: Option<Timestamp>,
    vlan_restored: bool,
}

/// An open AF_PACKET socket.
#[derive(Debug)]
pub(crate) struct Inner {
    // Drop order: the rings are unmapped before the socket closes.
    ring: Option<Ring>,
    frame_ring: Option<FrameRing>,
    fd: OwnedFd,
    name: String,
    index: u32,
    mac: MacAddr,
    /// The timestamping this socket delivers (a hardware request may have become software).
    timestamping: Timestamping,
    restore_vlan: bool,
    see_outgoing: bool,
    tx_time: Option<TxTime>,
    nonblocking: bool,
    buf: Vec<u8>,
    /// Ancillary data for `recvmsg`; `u64` elements keep it aligned for `cmsghdr`.
    ctrl: [u64; 64],
    stats: Stats,
    /// Launch-time drops read from the error queue and not yet returned by `tx_errors`.
    tx_pending: TxErrors,
    /// The transmit timestamping this socket delivers.
    tx_timestamping: Timestamping,
    /// The id of the next frame sent, and how ids reach the kernel.
    next_id: Cell<u32>,
    id_mode: Cell<IdMode>,
    /// Transmit timestamps read from the error queue and not yet handed out.
    tx_stamps: VecDeque<TxTimestamp>,
}

impl Inner {
    pub(crate) fn open(cfg: &Config, program: Option<&Program>) -> io::Result<Inner> {
        // SAFETY: plain system call; protocol 0 means the socket receives nothing until it is
        // bound, so no frame can be queued before the filter is in place.
        let raw = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::PermissionDenied {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "opening an AF_PACKET socket needs CAP_NET_RAW (grant it to the binary with `setcap cap_net_raw+ep`, or run in a container that has it)",
                ));
            }
            return Err(io::Error::new(e.kind(), format!("socket(AF_PACKET): {e}")));
        }
        // SAFETY: `raw` is a descriptor we just created and own.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let index = interface_index(&cfg.interface)?;
        let mac = hardware_address(&fd, &cfg.interface)?;

        if let Some(p) = program {
            attach_filter(&fd, p)?;
        }
        // Kernels from 4.20 drop our own transmissions before they reach the socket; older ones
        // are filtered by packet type on receive below.
        if !cfg.see_outgoing {
            let _ = setopt(
                &fd,
                libc::SOL_PACKET,
                libc::PACKET_IGNORE_OUTGOING,
                &1 as &libc::c_int,
                "PACKET_IGNORE_OUTGOING",
            );
        }
        let (want_rx, want_tx) =
            (cfg.timestamping == Timestamping::Hardware, cfg.tx_timestamping == Timestamping::Hardware);
        let (hw_rx, hw_tx) = if want_rx || want_tx {
            hardware_timestamps(&fd, &cfg.interface, want_rx, want_tx)
        } else {
            (false, false)
        };
        let downgrade = |t: Timestamping, hw: bool| {
            if t == Timestamping::Hardware && !hw { Timestamping::Software } else { t }
        };
        let timestamping = downgrade(cfg.timestamping, hw_rx);
        let tx_timestamping = downgrade(cfg.tx_timestamping, hw_tx);
        let hardware = timestamping == Timestamping::Hardware;

        // `Auto` falls back to the plain path (and `rx_path` says so); an explicit ring that the
        // kernel refuses is an error, not a quiet downgrade.
        let (ring, frame_ring) = match cfg.rx {
            RxMode::Plain => (None, None),
            RxMode::Auto => (setup_ring(&fd, RingConfig::default(), hardware).ok(), None),
            RxMode::Ring(r) => (Some(setup_ring(&fd, r, hardware)?), None),
            RxMode::FrameRing(f) => (None, Some(setup_frame_ring(&fd, f, hardware)?)),
        };

        // SAFETY: an all-zero `sockaddr_ll` is a valid value of a C struct of integers.
        let mut sll: libc::sockaddr_ll = unsafe { zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        sll.sll_ifindex = index as libc::c_int;
        // SAFETY: `sll` is a live `sockaddr_ll` and the length passed is its size.
        let r = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const sll).cast(),
                size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if r < 0 {
            return Err(last_error(&format!("bind to {}", cfg.interface)));
        }

        for group in &cfg.multicast {
            membership(&fd, index, libc::PACKET_MR_MULTICAST, Some(*group))?;
        }
        if cfg.all_multicast {
            membership(&fd, index, libc::PACKET_MR_ALLMULTI, None)?;
        }
        if cfg.promiscuous {
            membership(&fd, index, libc::PACKET_MR_PROMISC, None)?;
        }

        // The plain path's metadata: the stripped VLAN tag and the timestamps.
        setopt(&fd, libc::SOL_PACKET, libc::PACKET_AUXDATA, &1 as &libc::c_int, "PACKET_AUXDATA")?;
        let mut flags = 0;
        if timestamping != Timestamping::Off {
            flags |= libc::SOF_TIMESTAMPING_RX_SOFTWARE | libc::SOF_TIMESTAMPING_SOFTWARE;
            if hardware {
                flags |= libc::SOF_TIMESTAMPING_RX_HARDWARE | libc::SOF_TIMESTAMPING_RAW_HARDWARE;
            }
        }
        if tx_timestamping != Timestamping::Off {
            // One report per frame, numbered, without the frame looped back.
            flags |= libc::SOF_TIMESTAMPING_TX_SOFTWARE
                | libc::SOF_TIMESTAMPING_SOFTWARE
                | libc::SOF_TIMESTAMPING_OPT_ID
                | libc::SOF_TIMESTAMPING_OPT_TSONLY;
            if tx_timestamping == Timestamping::Hardware {
                flags |= libc::SOF_TIMESTAMPING_TX_HARDWARE | libc::SOF_TIMESTAMPING_RAW_HARDWARE;
            }
        }
        if flags != 0 {
            setopt(&fd, libc::SOL_SOCKET, libc::SO_TIMESTAMPING, &(flags as libc::c_int), "SO_TIMESTAMPING")?;
        }
        if let Some(p) = cfg.priority {
            setopt(&fd, libc::SOL_SOCKET, libc::SO_PRIORITY, &(p as libc::c_int), "SO_PRIORITY")?;
        }
        if cfg.qdisc_bypass {
            setopt(
                &fd,
                libc::SOL_PACKET,
                libc::PACKET_QDISC_BYPASS,
                &1 as &libc::c_int,
                "PACKET_QDISC_BYPASS",
            )?;
        }
        if let Some(t) = cfg.tx_time {
            let mut flags = 0;
            if t.deadline {
                flags |= libc::SOF_TXTIME_DEADLINE_MODE;
            }
            if t.report_errors {
                flags |= libc::SOF_TXTIME_REPORT_ERRORS;
            }
            let v = libc::sock_txtime { clockid: clock_id(t.clock), flags };
            setopt(&fd, libc::SOL_SOCKET, libc::SO_TXTIME, &v, "SO_TXTIME (needs Linux 4.19)")?;
        }
        if cfg.nonblocking {
            set_nonblocking(fd.as_fd(), true)?;
        }
        let buf = if ring.is_some() || frame_ring.is_some() {
            Vec::new()
        } else {
            vec![0u8; RESERVE as usize + cfg.buffer_size.min(PLAIN_MAX)]
        };

        Ok(Inner {
            ring,
            frame_ring,
            fd,
            name: cfg.interface.clone(),
            index,
            mac,
            timestamping,
            restore_vlan: cfg.restore_vlan,
            see_outgoing: cfg.see_outgoing,
            tx_time: cfg.tx_time,
            nonblocking: cfg.nonblocking,
            buf,
            ctrl: [0; 64],
            stats: Stats::default(),
            tx_pending: TxErrors::default(),
            tx_timestamping,
            next_id: Cell::new(0),
            id_mode: Cell::new(IdMode::Explicit),
            tx_stamps: VecDeque::with_capacity(if tx_timestamping == Timestamping::Off {
                0
            } else {
                TX_QUEUE
            }),
        })
    }

    pub(crate) fn interface(&self) -> &str {
        &self.name
    }

    pub(crate) fn index(&self) -> u32 {
        self.index
    }

    pub(crate) fn mac(&self) -> MacAddr {
        self.mac
    }

    pub(crate) fn rx_path(&self) -> RxPath {
        if self.ring.is_some() {
            RxPath::Ring
        } else if self.frame_ring.is_some() {
            RxPath::FrameRing
        } else {
            RxPath::Plain
        }
    }

    pub(crate) fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub(crate) fn timestamping(&self) -> Timestamping {
        self.timestamping
    }

    pub(crate) fn tx_timestamping(&self) -> Timestamping {
        self.tx_timestamping
    }

    pub(crate) fn next_tx_id(&self) -> u32 {
        self.next_id.get()
    }

    pub(crate) fn tx_timestamp(&mut self, timeout: Option<Duration>) -> io::Result<Option<TxTimestamp>> {
        if self.tx_timestamping == Timestamping::Off {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transmit timestamps are off: turn them on with Config::tx_timestamping",
            ));
        }
        let timeout = if self.nonblocking { Some(Duration::ZERO) } else { timeout };
        let deadline = deadline(timeout);
        loop {
            if let Some(t) = self.tx_stamps.pop_front() {
                return Ok(Some(t));
            }
            if self.drain_error_queue()? > 0 {
                continue;
            }
            let remaining = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            if remaining == Some(Duration::ZERO) {
                return Ok(None);
            }
            // Events 0: woken by the error queue only, not by frames waiting to be received.
            match wait(self.fd.as_fd(), remaining, 0)? {
                Ready::Timeout => return Ok(None),
                Ready::Readable | Ready::Error => self.on_socket_error()?,
            }
        }
    }

    pub(crate) fn recv(&mut self, timeout: Option<Duration>) -> io::Result<Option<Packet<'_>>> {
        let timeout = if self.nonblocking { Some(Duration::ZERO) } else { timeout };
        let deadline = deadline(timeout);
        if self.frame_ring.is_some() {
            let Some(found) = self.frame_ring_next(deadline)? else { return Ok(None) };
            let ring = self.frame_ring.as_ref().ok_or_else(|| io::Error::other("frame ring vanished"))?;
            let data = ring
                .slot(found.block)
                .get(found.start..found.start + found.len)
                .ok_or_else(|| io::Error::other("ring frame out of range"))?;
            return Ok(Some(Packet {
                data,
                original_len: found.original_len,
                timestamp: found.timestamp,
                vlan_restored: found.vlan_restored,
            }));
        }
        if self.ring.is_some() {
            let Some(found) = self.ring_next(deadline)? else { return Ok(None) };
            let ring = self.ring.as_ref().ok_or_else(|| io::Error::other("ring vanished"))?;
            let block = ring.block(found.block);
            let data = block
                .get(found.start..found.start + found.len)
                .ok_or_else(|| io::Error::other("ring frame out of range"))?;
            return Ok(Some(Packet {
                data,
                original_len: found.original_len,
                timestamp: found.timestamp,
                vlan_restored: found.vlan_restored,
            }));
        }
        let Some((start, len, original_len, timestamp, vlan_restored)) = self.plain_next(deadline)? else {
            return Ok(None);
        };
        Ok(Some(Packet { data: &self.buf[start..start + len], original_len, timestamp, vlan_restored }))
    }

    /// The next frame on the per-frame ring. The slot handed out last is returned first; a slot
    /// whose header does not hold together, or that holds this host's own frame, is returned
    /// unread.
    fn frame_ring_next(&mut self, deadline: Option<Instant>) -> io::Result<Option<Found>> {
        let (restore, see_outgoing, timestamping) = (self.restore_vlan, self.see_outgoing, self.timestamping);
        loop {
            let ring = self.frame_ring.as_mut().ok_or_else(|| io::Error::other("no frame ring"))?;
            if let Some(h) = ring.held.take() {
                ring.release(h);
                ring.current = (h + 1) % ring.frames;
            }
            let i = ring.current;
            if ring.status(i).load(Ordering::Acquire) & ring::status::USER != 0 {
                fence(Ordering::Acquire);
                ring.held = Some(i);
                let slot = ring.slot(i);
                let Some(meta) = ring::FrameMeta::read_v2(slot) else { continue };
                if !see_outgoing && slot.get(ring::frame2::SLL_PKTTYPE) == Some(&libc::PACKET_OUTGOING) {
                    continue;
                }
                let (mut start, mut len) = (meta.mac, meta.snaplen);
                let mut original_len = meta.len;
                let mut restored = false;
                // The re-inserted tag needs the reserved octets in front of the frame, which lie
                // after the header and its `sockaddr_ll` (32 + 20).
                if restore
                    && meta.mac >= ring::frame2::HDR + 20 + RESERVE as usize
                    && let Some((tpid, tci)) = meta.stripped_vlan()
                    && let Some(region) = ring.slot_mut(i, start - 4..start + len)
                    && vlan::reinsert(region, 4, len, tpid, tci).is_some()
                {
                    (start, len, restored) = (start - 4, len + 4, true);
                    original_len += 4;
                }
                let timestamp = (timestamping != Timestamping::Off).then(|| Timestamp {
                    secs: i64::from(meta.sec),
                    nanos: meta.nsec,
                    source: if meta.status & ring::status::TS_RAW_HARDWARE != 0 {
                        TimestampSource::Hardware
                    } else {
                        TimestampSource::Software
                    },
                });
                return Ok(Some(Found {
                    block: i,
                    start,
                    len,
                    original_len,
                    timestamp,
                    vlan_restored: restored,
                }));
            }
            let remaining = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            if remaining == Some(Duration::ZERO) {
                return Ok(None);
            }
            match wait(self.fd.as_fd(), remaining, libc::POLLIN)? {
                Ready::Readable => {}
                Ready::Timeout => return Ok(None),
                Ready::Error => self.on_socket_error()?,
            }
        }
    }

    fn ring_next(&mut self, deadline: Option<Instant>) -> io::Result<Option<Found>> {
        let (restore, see_outgoing, timestamping) = (self.restore_vlan, self.see_outgoing, self.timestamping);
        loop {
            let ring = self.ring.as_mut().ok_or_else(|| io::Error::other("no ring"))?;
            let current = ring.current;
            if let Some(mut cur) = ring.cursor {
                let block = ring.block(current);
                let mut next = None;
                while let Some((at, meta)) = cur.next(block) {
                    if see_outgoing || block.get(at + SLL_PKTTYPE_IN_RING) != Some(&libc::PACKET_OUTGOING) {
                        next = Some((at, meta));
                        break;
                    }
                }
                let Some((at, meta)) = next else {
                    // The block is exhausted: hand it back and move on.
                    ring.cursor = None;
                    ring.release(current);
                    ring.current = (current + 1) % ring.blocks;
                    continue;
                };
                ring.cursor = Some(cur);
                let (mut start, mut len) = (at + meta.mac, meta.snaplen);
                let mut original_len = meta.len;
                let mut restored = false;
                // The re-inserted tag needs the reserved octets in front of the frame, which lie
                // after the header and its `sockaddr_ll` (48 + 20).
                if restore
                    && meta.mac >= 48 + 20 + RESERVE as usize
                    && let Some((tpid, tci)) = meta.stripped_vlan()
                    && let Some(region) = ring.frame_mut(current, start - 4..start + len)
                    && vlan::reinsert(region, 4, len, tpid, tci).is_some()
                {
                    (start, len, restored) = (start - 4, len + 4, true);
                    original_len += 4;
                }
                let timestamp = (timestamping != Timestamping::Off).then(|| Timestamp {
                    secs: i64::from(meta.sec),
                    nanos: meta.nsec,
                    source: if meta.status & ring::status::TS_RAW_HARDWARE != 0 {
                        TimestampSource::Hardware
                    } else {
                        TimestampSource::Software
                    },
                });
                return Ok(Some(Found {
                    block: current,
                    start,
                    len,
                    original_len,
                    timestamp,
                    vlan_restored: restored,
                }));
            }
            if ring.status(current).load(Ordering::Acquire) & ring::status::USER != 0 {
                fence(Ordering::Acquire);
                if let Some(c) = Cursor::start(ring.block(current)) {
                    ring.cursor = Some(c);
                } else {
                    ring.release(current);
                    ring.current = (current + 1) % ring.blocks;
                }
                continue;
            }
            let remaining = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            if remaining == Some(Duration::ZERO) {
                return Ok(None);
            }
            match wait(self.fd.as_fd(), remaining, libc::POLLIN)? {
                Ready::Readable => {}
                Ready::Timeout => return Ok(None),
                Ready::Error => self.on_socket_error()?,
            }
        }
    }

    /// The descriptor reported an error or a hang-up. Return the socket's pending error (link
    /// down, interface removed) — or, when it only had launch-time reports queued, count them
    /// for `tx_errors` and carry on waiting.
    fn on_socket_error(&mut self) -> io::Result<()> {
        if let Some(e) = socket_error(self.fd.as_fd()) {
            return Err(io::Error::new(e.kind(), format!("interface {}: {e}", self.name)));
        }
        if self.drain_error_queue()? > 0 {
            return Ok(());
        }
        Err(io::Error::new(io::ErrorKind::BrokenPipe, format!("interface {}: the socket hung up", self.name)))
    }

    #[allow(clippy::type_complexity)]
    fn plain_next(
        &mut self,
        deadline: Option<Instant>,
    ) -> io::Result<Option<(usize, usize, usize, Option<Timestamp>, bool)>> {
        loop {
            let remaining = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            match wait(self.fd.as_fd(), remaining, libc::POLLIN)? {
                Ready::Readable => {}
                Ready::Timeout => return Ok(None),
                Ready::Error => {
                    self.on_socket_error()?;
                    continue;
                }
            }
            let reserve = RESERVE as usize;
            let room = self.buf.len() - reserve;
            // SAFETY: all-zero values are valid for these C structs of integers and pointers.
            let mut sll: libc::sockaddr_ll = unsafe { zeroed() };
            let mut iov = libc::iovec { iov_base: self.buf[reserve..].as_mut_ptr().cast(), iov_len: room };
            // SAFETY: as above.
            let mut msg: libc::msghdr = unsafe { zeroed() };
            msg.msg_name = (&raw mut sll).cast();
            msg.msg_namelen = size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            msg.msg_iov = &raw mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = self.ctrl.as_mut_ptr().cast();
            msg.msg_controllen = size_of::<[u64; 64]>() as _;
            // SAFETY: `msg` points at live buffers (`sll`, `iov` → `buf`, `ctrl`) whose sizes it
            // states; the kernel writes only inside them. MSG_DONTWAIT because readiness was
            // checked above.
            let n = unsafe {
                libc::recvmsg(self.fd.as_raw_fd(), &raw mut msg, libc::MSG_TRUNC | libc::MSG_DONTWAIT)
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => continue,
                    _ => return Err(io::Error::new(e.kind(), format!("interface {}: {e}", self.name))),
                }
            }
            if !self.see_outgoing && sll.sll_pkttype == libc::PACKET_OUTGOING {
                continue;
            }
            let captured = (n as usize).min(room);
            let (mut vlan_tag, mut timestamp, mut wire_len) = (None, None, None);
            // A truncated control buffer may cut a message short: use none of them (the frame is
            // still delivered, labelled by what is known).
            let mut c = if msg.msg_flags & libc::MSG_CTRUNC == 0 {
                // SAFETY: the kernel filled `ctrl` and set `msg_controllen`.
                unsafe { libc::CMSG_FIRSTHDR(&raw const msg) }
            } else {
                std::ptr::null_mut()
            };
            while !c.is_null() {
                // SAFETY: `c` is a header CMSG_FIRSTHDR/CMSG_NXTHDR returned inside `ctrl`.
                let (level, kind) = unsafe { ((*c).cmsg_level, (*c).cmsg_type) };
                if level == libc::SOL_PACKET && kind == libc::PACKET_AUXDATA {
                    // SAFETY: as above.
                    if let Some(aux) = unsafe { cmsg_payload::<libc::tpacket_auxdata>(&msg, c) } {
                        // The length on the wire: a filter's snap length trims the frame before
                        // `recvmsg` sees it, so MSG_TRUNC alone would report the trimmed size.
                        wire_len = Some(aux.tp_len as usize);
                        if aux.tp_status & libc::TP_STATUS_VLAN_VALID != 0 {
                            // Kernels before 4.x do not report the TPID: assume 802.1Q.
                            let tpid = if aux.tp_status & libc::TP_STATUS_VLAN_TPID_VALID != 0
                                && aux.tp_vlan_tpid != 0
                            {
                                aux.tp_vlan_tpid
                            } else {
                                0x8100
                            };
                            vlan_tag = Some((tpid, aux.tp_vlan_tci));
                        }
                    }
                } else if level == libc::SOL_SOCKET && kind == libc::SCM_TIMESTAMPING {
                    // SAFETY: as above.
                    if let Some(ts) = unsafe { cmsg_payload::<[libc::timespec; 3]>(&msg, c) } {
                        timestamp = pick_timestamp(&ts);
                    }
                }
                // SAFETY: `c` is a header inside `msg`'s control buffer.
                c = unsafe { libc::CMSG_NXTHDR(&raw const msg, c) };
            }
            let original_len = wire_len.unwrap_or(n as usize).max(captured);
            if self.timestamping == Timestamping::Off {
                timestamp = None;
            } else if timestamp.is_none() {
                timestamp = clock_now(Clock::Realtime).ok().map(|d| Timestamp {
                    secs: d.as_secs() as i64,
                    nanos: d.subsec_nanos(),
                    source: TimestampSource::User,
                });
            }
            let (mut start, mut len, mut restored, mut orig) = (reserve, captured, false, original_len);
            if self.restore_vlan
                && let Some((tpid, tci)) = vlan_tag
                && let Some((s, l)) = vlan::reinsert(&mut self.buf, start, len, tpid, tci)
            {
                (start, len, restored) = (s, l, true);
                orig += 4;
            }
            return Ok(Some((start, len, orig, timestamp, restored)));
        }
    }

    pub(crate) fn send(&self, frame: &[u8]) -> io::Result<()> {
        self.send_one(frame, None).map_err(|e| io::Error::new(e.kind(), format!("send: {e}")))
    }

    pub(crate) fn send_at(&self, frame: &[u8], launch_ns: u64) -> io::Result<()> {
        if self.tx_time.is_none() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "send_at needs Config::tx_time"));
        }
        self.send_one(frame, Some(launch_ns)).map_err(|e| {
            // The qdisc dropped the frame at enqueue: etf refuses a launch time already past or
            // on another clock, and reports why to `tx_errors`.
            if e.raw_os_error() == Some(libc::ENOBUFS) {
                io::Error::new(
                    e.kind(),
                    "the qdisc refused the launch time (already past, or on another clock); see tx_errors",
                )
            } else {
                io::Error::new(e.kind(), format!("sendmsg with SCM_TXTIME: {e}"))
            }
        })
    }

    /// Send one frame with its launch time and timestamp id, if any, and advance the id.
    fn send_one(&self, frame: &[u8], launch: Option<u64>) -> io::Result<()> {
        let stamping = self.tx_timestamping != Timestamping::Off;
        let mode = self.id_mode.get();
        let id = (stamping && mode != IdMode::Implicit).then(|| self.next_id.get());
        let mut r = self.sendmsg(frame, launch, id);
        if id.is_some() && mode == IdMode::Explicit {
            match &r {
                // Before Linux 6.13 the kernel rejects SCM_TS_OPT_ID before building the frame:
                // send again without it; if that works, the kernel numbers frames itself.
                Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
                    r = self.sendmsg(frame, launch, None);
                    if r.is_ok() {
                        self.id_mode.set(IdMode::Implicit);
                    }
                }
                Ok(()) => self.id_mode.set(IdMode::Confirmed),
                Err(_) => {}
            }
        }
        if r.is_ok() && stamping {
            self.next_id.set(self.next_id.get().wrapping_add(1));
        }
        r
    }

    /// One `sendmsg` with optional control messages; the raw OS error on failure.
    fn sendmsg(&self, frame: &[u8], launch: Option<u64>, id: Option<u32>) -> io::Result<()> {
        let mut ctrl = [0u64; 6];
        let mut iov = libc::iovec { iov_base: frame.as_ptr().cast_mut().cast(), iov_len: frame.len() };
        // SAFETY: all-zero is a valid `msghdr`.
        let mut msg: libc::msghdr = unsafe { zeroed() };
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        send_cmsgs(&mut msg, &mut ctrl, launch, id);
        // SAFETY: `msg` describes live buffers (`iov` → the caller's frame, `ctrl`); the kernel
        // only reads them. The socket is bound, so no address is needed.
        let n = unsafe { libc::sendmsg(self.fd.as_raw_fd(), &raw const msg, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n as usize != frame.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("sent {n} of {} octets", frame.len()),
            ));
        }
        Ok(())
    }

    pub(crate) fn send_batch(&mut self, frames: &[&[u8]]) -> io::Result<usize> {
        let stamping = self.tx_timestamping != Timestamping::Off;
        let mode = self.id_mode.get();
        let explicit = stamping && mode != IdMode::Implicit;
        let base = self.next_id.get();
        let mut sent = 0;
        for chunk in frames.chunks(BATCH) {
            // SAFETY: all-zero values are valid for `iovec` and `mmsghdr`.
            let mut iovs: [libc::iovec; BATCH] = unsafe { zeroed() };
            // SAFETY: as above.
            let mut msgs: [libc::mmsghdr; BATCH] = unsafe { zeroed() };
            let mut ctrls = [[0u64; 6]; BATCH];
            for (k, (f, ctrl)) in chunk.iter().zip(ctrls.iter_mut()).enumerate() {
                iovs[k] = libc::iovec { iov_base: f.as_ptr().cast_mut().cast(), iov_len: f.len() };
                msgs[k].msg_hdr.msg_iov = &raw mut iovs[k];
                msgs[k].msg_hdr.msg_iovlen = 1;
                let id = explicit.then(|| base.wrapping_add((sent + k) as u32));
                send_cmsgs(&mut msgs[k].msg_hdr, ctrl, None, id);
            }
            let mut done = 0;
            while done < chunk.len() {
                // SAFETY: `msgs[done..chunk.len()]` are initialised headers pointing at live
                // iovecs (the caller's frames) and control buffers; the kernel only reads them.
                let n = unsafe {
                    libc::sendmmsg(
                        self.fd.as_raw_fd(),
                        msgs[done..].as_mut_ptr(),
                        (chunk.len() - done) as libc::c_uint,
                        0,
                    )
                };
                if n < 0 {
                    let e = io::Error::last_os_error();
                    if explicit
                        && mode == IdMode::Explicit
                        && sent + done == 0
                        && e.raw_os_error() == Some(libc::EINVAL)
                    {
                        // Before Linux 6.13: no SCM_TS_OPT_ID. Retry once with kernel numbering.
                        self.id_mode.set(IdMode::Implicit);
                        let r = self.send_batch(frames);
                        if r.is_err() {
                            self.id_mode.set(IdMode::Explicit);
                        }
                        return r;
                    }
                    if sent + done > 0 {
                        break;
                    }
                    return Err(io::Error::new(e.kind(), format!("sendmmsg: {e}")));
                }
                done += n as usize;
            }
            sent += done;
            if done < chunk.len() {
                break;
            }
        }
        if stamping {
            if explicit && sent > 0 {
                self.id_mode.set(IdMode::Confirmed);
            }
            self.next_id.set(base.wrapping_add(sent as u32));
        }
        Ok(sent)
    }

    pub(crate) fn stats(&mut self) -> io::Result<Stats> {
        // SAFETY: all-zero is a valid `tpacket_stats_v3`.
        let mut st: libc::tpacket_stats_v3 = unsafe { zeroed() };
        let mut len = size_of::<libc::tpacket_stats_v3>() as libc::socklen_t;
        // SAFETY: `st` and `len` are live and `len` states the buffer's size; the kernel writes
        // at most that many octets (8 for TPACKET_V1/V2 sockets, 12 for V3).
        let r = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                (&raw mut st).cast(),
                &raw mut len,
            )
        };
        if r < 0 {
            return Err(last_error("PACKET_STATISTICS"));
        }
        // The kernel resets its counters on every read, and its `tp_packets` includes the drops.
        let drops = u64::from(st.tp_drops);
        self.stats.dropped += drops;
        self.stats.received += u64::from(st.tp_packets).saturating_sub(drops);
        Ok(self.stats)
    }

    pub(crate) fn tx_errors(&mut self) -> io::Result<TxErrors> {
        self.drain_error_queue()?;
        Ok(std::mem::take(&mut self.tx_pending))
    }

    /// Read every report waiting on the error queue: transmit timestamps into `tx_stamps`,
    /// launch-time drops into `tx_pending`. Returns how many reports were read.
    fn drain_error_queue(&mut self) -> io::Result<u64> {
        let mut read = 0;
        loop {
            let mut data = [0u8; 64];
            let mut ctrl = [0u64; 32];
            let mut iov = libc::iovec { iov_base: data.as_mut_ptr().cast(), iov_len: data.len() };
            // SAFETY: all-zero is a valid `msghdr`.
            let mut msg: libc::msghdr = unsafe { zeroed() };
            msg.msg_iov = &raw mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = ctrl.as_mut_ptr().cast();
            msg.msg_controllen = size_of::<[u64; 32]>() as _;
            // SAFETY: `msg` describes live local buffers of the stated sizes.
            let n = unsafe {
                libc::recvmsg(self.fd.as_raw_fd(), &raw mut msg, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT)
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                return match e.kind() {
                    io::ErrorKind::WouldBlock => Ok(read),
                    io::ErrorKind::Interrupted => continue,
                    _ => Err(io::Error::new(e.kind(), format!("error queue: {e}"))),
                };
            }
            read += 1;
            if msg.msg_flags & libc::MSG_CTRUNC != 0 {
                continue;
            }
            let (mut stamps, mut report) = (None, None);
            // SAFETY: the kernel filled `ctrl` and set `msg_controllen`.
            let mut c = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
            while !c.is_null() {
                // SAFETY: `c` is a header inside `msg`'s control buffer.
                let (level, kind) = unsafe { ((*c).cmsg_level, (*c).cmsg_type) };
                if level == libc::SOL_PACKET && kind == PACKET_TX_TIMESTAMP {
                    // SAFETY: as above.
                    report = unsafe { cmsg_payload::<libc::sock_extended_err>(&msg, c) };
                } else if level == libc::SOL_SOCKET && kind == libc::SCM_TIMESTAMPING {
                    // SAFETY: as above.
                    stamps = unsafe { cmsg_payload::<[libc::timespec; 3]>(&msg, c) };
                }
                // SAFETY: as above.
                c = unsafe { libc::CMSG_NXTHDR(&raw const msg, c) };
            }
            let Some(ee) = report else { continue };
            match classify(ee.ee_origin, ee.ee_code, ee.ee_info, ee.ee_data) {
                Report::Missed => self.tx_pending.missed += 1,
                Report::Invalid => self.tx_pending.invalid += 1,
                Report::Sent(id) => {
                    if let Some(timestamp) = stamps.as_ref().and_then(pick_timestamp) {
                        self.push_stamp(TxTimestamp { id, timestamp });
                    }
                }
                Report::Other => {}
            }
        }
    }

    /// Keep a transmit timestamp for `tx_timestamp`, dropping the oldest when full.
    fn push_stamp(&mut self, t: TxTimestamp) {
        if self.tx_timestamping == Timestamping::Off {
            return;
        }
        if self.tx_stamps.len() == TX_QUEUE {
            self.tx_stamps.pop_front();
            self.tx_pending.timestamps_lost += 1;
        }
        self.tx_stamps.push_back(t);
    }

    pub(crate) fn set_nonblocking(&mut self, on: bool) -> io::Result<()> {
        set_nonblocking(self.fd.as_fd(), on)?;
        self.nonblocking = on;
        Ok(())
    }
}

/// Prefer the raw hardware stamp (`[2]`), else the software one (`[0]`).
fn pick_timestamp(ts: &[libc::timespec; 3]) -> Option<Timestamp> {
    #[allow(clippy::useless_conversion)] // `time_t` is 32-bit on some targets
    let mk =
        |t: &libc::timespec, source| Timestamp { secs: i64::from(t.tv_sec), nanos: t.tv_nsec as u32, source };
    if ts[2].tv_sec != 0 || ts[2].tv_nsec != 0 {
        Some(mk(&ts[2], TimestampSource::Hardware))
    } else if ts[0].tv_sec != 0 || ts[0].tv_nsec != 0 {
        Some(mk(&ts[0], TimestampSource::Software))
    } else {
        None
    }
}

fn attach_filter(fd: &OwnedFd, program: &Program) -> io::Result<()> {
    let mut insns: Vec<libc::sock_filter> = program
        .instructions()
        .iter()
        .map(|i| libc::sock_filter { code: i.code, jt: i.jt, jf: i.jf, k: i.k })
        .collect();
    let prog = libc::sock_fprog { len: insns.len() as libc::c_ushort, filter: insns.as_mut_ptr() };
    // `insns` outlives the call; the kernel copies the program.
    setopt(fd, libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &prog, "SO_ATTACH_FILTER")
}

fn membership(fd: &OwnedFd, index: u32, kind: libc::c_int, mac: Option<MacAddr>) -> io::Result<()> {
    // SAFETY: all-zero is a valid `packet_mreq`.
    let mut m: libc::packet_mreq = unsafe { zeroed() };
    m.mr_ifindex = index as libc::c_int;
    m.mr_type = kind as libc::c_ushort;
    if let Some(mac) = mac {
        m.mr_alen = 6;
        m.mr_address[..6].copy_from_slice(&mac.0);
    }
    setopt(fd, libc::SOL_PACKET, libc::PACKET_ADD_MEMBERSHIP, &m, "PACKET_ADD_MEMBERSHIP")
}

fn hardware_address(fd: &OwnedFd, name: &str) -> io::Result<MacAddr> {
    // SAFETY: all-zero is a valid `ifreq`.
    let mut ifr: libc::ifreq = unsafe { zeroed() };
    ifr.ifr_name = ifr_name(name)?;
    // SAFETY: SIOCGIFHWADDR reads the name and writes the address into `ifr`, which is live.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCGIFHWADDR as _, &raw mut ifr) } < 0 {
        return Err(last_error(&format!("SIOCGIFHWADDR {name}")));
    }
    // SAFETY: the kernel filled the `ifru_hwaddr` member of the union.
    let sa = unsafe { ifr.ifr_ifru.ifru_hwaddr };
    let mut mac = [0u8; 6];
    for (o, b) in mac.iter_mut().zip(sa.sa_data.iter()) {
        // `c_char` is `u8` on some targets and `i8` on others.
        #[allow(clippy::unnecessary_cast)]
        {
            *o = *b as u8;
        }
    }
    Ok(MacAddr(mac))
}

/// Have the NIC stamp received (`rx`) and/or transmitted (`tx`) frames without disturbing
/// anyone else, and say which of them it stamps. See [`hwtstamp`]: read first, never lower,
/// never write blind.
fn hardware_timestamps(fd: &OwnedFd, name: &str, rx: bool, tx: bool) -> (bool, bool) {
    let Ok(current) = hwtstamp_ioctl(fd, name, libc::SIOCGHWTSTAMP, None) else { return (false, false) };
    let now = match hwtstamp::decide(Some(current), rx, tx) {
        Plan::Unreadable => return (false, false),
        Plan::Keep => current,
        Plan::Write(want) => hwtstamp_ioctl(fd, name, libc::SIOCSHWTSTAMP, Some(want)).unwrap_or(current),
    };
    hwtstamp::effective(now, rx, tx)
}

/// What `name` can timestamp: `ETHTOOL_GET_TS_INFO` on a plain datagram socket, unprivileged.
pub(crate) fn timestamp_info(name: &str) -> io::Result<TimestampInfo> {
    /// `struct ethtool_ts_info` (`<linux/ethtool.h>`).
    #[repr(C)]
    struct EthtoolTsInfo {
        cmd: u32,
        so_timestamping: u32,
        phc_index: i32,
        tx_types: u32,
        tx_reserved: [u32; 3],
        rx_filters: u32,
        rx_reserved: [u32; 3],
    }
    const ETHTOOL_GET_TS_INFO: u32 = 0x41;
    let ifr_name = ifr_name(name)?;
    // SAFETY: plain system call.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(last_error("socket for ETHTOOL_GET_TS_INFO"));
    }
    // SAFETY: `raw` was just created and is owned by nobody else.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut info = EthtoolTsInfo {
        cmd: ETHTOOL_GET_TS_INFO,
        so_timestamping: 0,
        phc_index: -1,
        tx_types: 0,
        tx_reserved: [0; 3],
        rx_filters: 0,
        rx_reserved: [0; 3],
    };
    // SAFETY: all-zero is a valid `ifreq`.
    let mut ifr: libc::ifreq = unsafe { zeroed() };
    ifr.ifr_name = ifr_name;
    ifr.ifr_ifru.ifru_data = (&raw mut info).cast();
    // SAFETY: SIOCETHTOOL reads `cmd` and writes the rest of `info` through `ifru_data`; both
    // live for the call, and `info` has the layout of `struct ethtool_ts_info`.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCETHTOOL as _, &raw mut ifr) } < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENODEV) {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("no interface named {name:?}")));
        }
        return Err(io::Error::new(e.kind(), format!("ETHTOOL_GET_TS_INFO on {name}: {e}")));
    }
    Ok(TimestampInfo::from_ethtool(info.so_timestamping, info.phc_index))
}

/// `SIOCGHWTSTAMP` (`set` = None) or `SIOCSHWTSTAMP`; returns the configuration the driver reports.
fn hwtstamp_ioctl(
    fd: &OwnedFd,
    name: &str,
    request: libc::c_ulong,
    set: Option<hwtstamp::Current>,
) -> io::Result<hwtstamp::Current> {
    let c = set.unwrap_or(hwtstamp::Current { flags: 0, tx_type: 0, rx_filter: 0 });
    let mut cfg = libc::hwtstamp_config { flags: c.flags, tx_type: c.tx_type, rx_filter: c.rx_filter };
    // SAFETY: all-zero is a valid `ifreq`.
    let mut ifr: libc::ifreq = unsafe { zeroed() };
    ifr.ifr_name = ifr_name(name)?;
    ifr.ifr_ifru.ifru_data = (&raw mut cfg).cast();
    // SAFETY: SIOC[GS]HWTSTAMP read and write `cfg` through `ifru_data`; both live for the call.
    if unsafe { libc::ioctl(fd.as_raw_fd(), request as _, &raw mut ifr) } < 0 {
        return Err(last_error("hardware timestamp configuration"));
    }
    Ok(hwtstamp::Current { flags: cfg.flags, tx_type: cfg.tx_type, rx_filter: cfg.rx_filter })
}

/// What one error-queue report is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Report {
    /// A launch time missed after the qdisc accepted the frame.
    Missed,
    /// A launch time the qdisc refused.
    Invalid,
    /// The frame with this id left; the timestamp travels in `SCM_TIMESTAMPING`.
    Sent(u32),
    /// Anything else (other timestamp kinds, other origins): not ours.
    Other,
}

/// Classify a `sock_extended_err` by origin, code, info and data.
fn classify(origin: u8, code: u8, info: u32, data: u32) -> Report {
    match origin {
        SO_EE_ORIGIN_TXTIME => match code {
            SO_EE_CODE_TXTIME_MISSED => Report::Missed,
            SO_EE_CODE_TXTIME_INVALID_PARAM => Report::Invalid,
            _ => Report::Other,
        },
        libc::SO_EE_ORIGIN_TIMESTAMPING if info == SCM_TSTAMP_SND => Report::Sent(data),
        _ => Report::Other,
    }
}

/// Control messages for one send, in `ctrl`: a launch time (`SCM_TXTIME`) and/or a transmit
/// timestamp id (`SCM_TS_OPT_ID`). None leaves `msg` without control data.
fn send_cmsgs(msg: &mut libc::msghdr, ctrl: &mut [u64; 6], launch: Option<u64>, id: Option<u32>) {
    // SAFETY: CMSG_SPACE is a pure size computation.
    let space = |n: usize| unsafe { libc::CMSG_SPACE(n as u32) } as usize;
    let len = launch.map_or(0, |_| space(size_of::<u64>())) + id.map_or(0, |_| space(size_of::<u32>()));
    if len == 0 {
        return;
    }
    msg.msg_control = ctrl.as_mut_ptr().cast();
    msg.msg_controllen = len as _;
    // SAFETY: `ctrl` holds 48 octets (≥ CMSG_SPACE(8) + CMSG_SPACE(4) = 48 on 64-bit, less on
    // 32-bit), is zeroed and u64-aligned; each header and payload is written inside the first
    // `msg_controllen` octets, and CMSG_NXTHDR stays inside them. The kernel only reads it.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(msg);
        if let Some(t) = launch
            && !c.is_null()
        {
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_TXTIME;
            (*c).cmsg_len = libc::CMSG_LEN(size_of::<u64>() as u32) as _;
            libc::CMSG_DATA(c).cast::<u64>().write_unaligned(t);
            c = libc::CMSG_NXTHDR(msg, c);
        }
        if let Some(i) = id
            && !c.is_null()
        {
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = SCM_TS_OPT_ID;
            (*c).cmsg_len = libc::CMSG_LEN(size_of::<u32>() as u32) as _;
            libc::CMSG_DATA(c).cast::<u32>().write_unaligned(i);
        }
    }
}

/// The payload of control message `c` as a `T`, if the message holds a whole one inside `msg`'s
/// control buffer.
///
/// # Safety
///
/// `c` must be a header that `CMSG_FIRSTHDR`/`CMSG_NXTHDR` returned for `msg`.
#[allow(clippy::unnecessary_cast)] // `cmsg_len` and `msg_controllen` are `u32` on musl
unsafe fn cmsg_payload<T>(msg: &libc::msghdr, c: *const libc::cmsghdr) -> Option<T> {
    // SAFETY: pure size computation.
    let need = unsafe { libc::CMSG_LEN(size_of::<T>() as u32) } as usize;
    // SAFETY: the caller guarantees `c` is a header inside the control buffer.
    let (len, data) = unsafe { ((*c).cmsg_len as usize, libc::CMSG_DATA(c)) };
    let end = (data as usize).checked_add(size_of::<T>())?;
    let limit = (msg.msg_control as usize).checked_add(msg.msg_controllen as usize)?;
    if len < need || end > limit {
        return None;
    }
    // SAFETY: `size_of::<T>()` octets from `data` lie inside the control buffer (checked) and
    // inside this message (`cmsg_len`); the payload may be unaligned.
    Some(unsafe { data.cast::<T>().read_unaligned() })
}

/// A per-frame (TPACKET_V2) ring: 64 KiB blocks (at least a page), as many slots per block as
/// fit, and enough blocks for `f.frame_count` slots.
fn setup_frame_ring(fd: &OwnedFd, f: FrameRingConfig, hardware: bool) -> io::Result<FrameRing> {
    // SAFETY: sysconf is a plain query.
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(4096);
    let frame_size = f.frame_size as usize;
    let block_size = frame_size.max(1 << 16).next_multiple_of(page);
    let per_block = block_size / frame_size;
    let blocks = (f.frame_count as usize).div_ceil(per_block);
    let frames = per_block * blocks;
    let geometry =
        || io::Error::new(io::ErrorKind::InvalidInput, format!("frame ring geometry {f:?} is too large"));
    let len = block_size.checked_mul(blocks).ok_or_else(geometry)?;
    let req = libc::tpacket_req {
        tp_block_size: u32::try_from(block_size).map_err(|_| geometry())?,
        tp_block_nr: u32::try_from(blocks).map_err(|_| geometry())?,
        tp_frame_size: f.frame_size,
        tp_frame_nr: u32::try_from(frames).map_err(|_| geometry())?,
    };
    setopt(fd, libc::SOL_PACKET, libc::PACKET_VERSION, &TPACKET_V2, "PACKET_VERSION")?;
    setopt(fd, libc::SOL_PACKET, libc::PACKET_RESERVE, &RESERVE, "PACKET_RESERVE")?;
    if hardware {
        let _ = setopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_TIMESTAMP,
            &(libc::SOF_TIMESTAMPING_RAW_HARDWARE as libc::c_int),
            "PACKET_TIMESTAMP",
        );
    }
    setopt(fd, libc::SOL_PACKET, libc::PACKET_RX_RING, &req, "PACKET_RX_RING")?;
    let Some(base) = map_ring(fd, len) else {
        let e = last_error("mmap of the frame ring");
        // Without the mapping the ring must go, or frames would vanish into it.
        // SAFETY: all-zero is a valid `tpacket_req`; a zero block count frees the ring.
        let off: libc::tpacket_req = unsafe { zeroed() };
        let _ = setopt(fd, libc::SOL_PACKET, libc::PACKET_RX_RING, &off, "PACKET_RX_RING off");
        return Err(e);
    };
    Ok(FrameRing { base, len, block_size, frame_size, per_block, frames, current: 0, held: None })
}

/// Map a ring of `len` octets the kernel just allocated for `fd`: locked where the limit
/// allows, unlocked otherwise. `None` (errno set) if the mapping fails.
fn map_ring(fd: &OwnedFd, len: usize) -> Option<NonNull<u8>> {
    let map = |flags| {
        // SAFETY: mapping the ring the kernel just allocated for this socket; the result is
        // checked against MAP_FAILED below.
        unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                fd.as_raw_fd(),
                0,
            )
        }
    };
    let mut p = map(libc::MAP_SHARED | libc::MAP_LOCKED);
    if p == libc::MAP_FAILED {
        p = map(libc::MAP_SHARED);
    }
    NonNull::new(p.cast::<u8>()).filter(|_| p != libc::MAP_FAILED)
}

fn setup_ring(fd: &OwnedFd, r: RingConfig, hardware: bool) -> io::Result<Ring> {
    // SAFETY: sysconf is a plain query.
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(4096);
    let block_size = r.block_size as usize;
    if !block_size.is_multiple_of(page) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ring block size must be a multiple of the page size",
        ));
    }
    let frame_size = (r.frame_size + 15) & !15;
    let geometry =
        || io::Error::new(io::ErrorKind::InvalidInput, format!("ring geometry {r:?} is too large"));
    let frames = (r.block_size / frame_size).checked_mul(r.block_count).ok_or_else(geometry)?;
    let len = block_size.checked_mul(r.block_count as usize).ok_or_else(geometry)?;
    setopt(fd, libc::SOL_PACKET, libc::PACKET_VERSION, &TPACKET_V3, "PACKET_VERSION")?;
    setopt(fd, libc::SOL_PACKET, libc::PACKET_RESERVE, &RESERVE, "PACKET_RESERVE")?;
    if hardware {
        let _ = setopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_TIMESTAMP,
            &(libc::SOF_TIMESTAMPING_RAW_HARDWARE as libc::c_int),
            "PACKET_TIMESTAMP",
        );
    }
    let req = libc::tpacket_req3 {
        tp_block_size: r.block_size,
        tp_block_nr: r.block_count,
        tp_frame_size: frame_size,
        tp_frame_nr: frames,
        tp_retire_blk_tov: r.retire_ms,
        tp_sizeof_priv: 0,
        tp_feature_req_word: 0,
    };
    setopt(fd, libc::SOL_PACKET, libc::PACKET_RX_RING, &req, "PACKET_RX_RING")?;
    let Some(base) = map_ring(fd, len) else {
        let e = last_error("mmap of the receive ring");
        // Without the mapping the ring must go, or frames would vanish into it.
        // SAFETY: all-zero is a valid `tpacket_req3`; a zero block count frees the ring.
        let off: libc::tpacket_req3 = unsafe { zeroed() };
        let _ = setopt(fd, libc::SOL_PACKET, libc::PACKET_RX_RING, &off, "PACKET_RX_RING off");
        return Err(e);
    };
    Ok(Ring { base, len, block_size, blocks: r.block_count as usize, current: 0, cursor: None })
}

fn clock_id(clock: Clock) -> libc::clockid_t {
    match clock {
        Clock::Tai => libc::CLOCK_TAI,
        Clock::Monotonic => libc::CLOCK_MONOTONIC,
        Clock::Realtime => libc::CLOCK_REALTIME,
    }
}

pub(crate) fn clock_now(clock: Clock) -> io::Result<Duration> {
    // SAFETY: all-zero is a valid `timespec`.
    let mut ts: libc::timespec = unsafe { zeroed() };
    // SAFETY: `ts` is live and writable.
    if unsafe { libc::clock_gettime(clock_id(clock), &raw mut ts) } < 0 {
        return Err(last_error("clock_gettime"));
    }
    Ok(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

/// Give up every capability, for good: the ambient set, the bounding set where the process
/// may, and the calling thread's sets, then `no_new_privs`. Fails if another thread still holds
/// a capability (capabilities are per thread), or if that cannot be checked.
pub(crate) fn drop_capabilities() -> io::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    // The ambient set first: an ambient capability survives `exec`. Kernels before 4.3 have
    // none and answer EINVAL.
    // SAFETY: PR_CAP_AMBIENT takes integer arguments only.
    let _ = unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) };
    // The bounding set limits what any later `exec` can gain. Dropping needs CAP_SETPCAP; a
    // binary granted only CAP_NET_RAW gets EPERM, which is expected.
    let last = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse::<libc::c_int>().ok())
        .unwrap_or(63);
    for cap in 0..=last {
        // SAFETY: PR_CAPBSET_DROP takes integer arguments only.
        let _ = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
    }

    let mut header = Header { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let data = [Data { effective: 0, permitted: 0, inheritable: 0 }; 2];
    // SAFETY: capset(2) reads one header and two data words (version 3); both are live, and
    // `pid: 0` means the calling thread.
    if unsafe { libc::syscall(libc::SYS_capset, &raw mut header, data.as_ptr()) } < 0 {
        return Err(last_error("capset"));
    }
    // No later exec may gain privileges either (set-uid or file capabilities).
    // SAFETY: PR_SET_NO_NEW_PRIVS takes integer arguments only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        return Err(last_error("PR_SET_NO_NEW_PRIVS"));
    }
    match privileged_threads() {
        Ok(0) => Ok(()),
        Ok(n) => Err(io::Error::other(format!(
            "{n} other thread(s) still hold capabilities: call drop_capabilities after opening the \
             sockets and before spawning threads or building a multi-threaded runtime"
        ))),
        Err(e) => Err(io::Error::new(e.kind(), format!("cannot check the other threads' capabilities: {e}"))),
    }
}

/// How many other threads of this process hold a capability.
fn privileged_threads() -> io::Result<usize> {
    // SAFETY: gettid takes no arguments.
    let me = unsafe { libc::syscall(libc::SYS_gettid) }.to_string();
    let mut n = 0;
    for entry in std::fs::read_dir("/proc/self/task")? {
        let entry = entry?;
        if entry.file_name().to_str() == Some(me.as_str()) {
            continue;
        }
        match std::fs::read_to_string(entry.path().join("status")) {
            Ok(status) if holds_capabilities(&status) => n += 1,
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {} // the thread just ended
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Whether a `/proc/<pid>/task/<tid>/status` text shows any inheritable, permitted, effective
/// or ambient capability. A set that cannot be read counts as held.
fn holds_capabilities(status: &str) -> bool {
    let sets = ["CapInh", "CapPrm", "CapEff", "CapAmb"];
    let mut seen = 0;
    for (key, value) in status.lines().filter_map(|l| l.split_once(':')) {
        if sets.contains(&key) {
            seen += 1;
            if u64::from_str_radix(value.trim(), 16) != Ok(0) {
                return true;
            }
        }
    }
    seen < 3 // CapAmb is missing before Linux 4.3; the other three always exist
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec 003 SR-002: the status parser sees every set, and an unreadable set counts as held.
    #[test]
    fn a_thread_status_shows_whether_it_holds_capabilities() {
        let none = "Name:\tx\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n";
        assert!(!holds_capabilities(none));
        assert!(holds_capabilities(&none.replace("CapPrm:\t0000000000000000", "CapPrm:\t0000000000002000")));
        assert!(holds_capabilities(&none.replace("CapAmb:\t0000000000000000", "CapAmb:\t0000000000001000")));
        assert!(holds_capabilities(&none.replace("CapEff:\t0000000000000000", "CapEff:\tzz")));
        assert!(holds_capabilities("Name:\tx\n"), "no sets at all");
        assert!(!holds_capabilities(&none.replace("CapAmb:\t0000000000000000\n", "")), "old kernel");
    }

    /// Spec 003 SR-011, spec 007 SR-004: launch-time reports by reason, transmit timestamps by
    /// id, anything else ignored.
    #[test]
    fn only_launch_time_reports_are_counted() {
        assert_eq!(classify(SO_EE_ORIGIN_TXTIME, SO_EE_CODE_TXTIME_MISSED, 0, 0), Report::Missed);
        assert_eq!(classify(SO_EE_ORIGIN_TXTIME, SO_EE_CODE_TXTIME_INVALID_PARAM, 0, 0), Report::Invalid);
        assert_eq!(classify(libc::SO_EE_ORIGIN_TIMESTAMPING, 0, SCM_TSTAMP_SND, 41), Report::Sent(41));
        assert_eq!(classify(libc::SO_EE_ORIGIN_TIMESTAMPING, 0, 1, 41), Report::Other, "SCM_TSTAMP_SCHED");
        assert_eq!(classify(libc::SO_EE_ORIGIN_LOCAL, SO_EE_CODE_TXTIME_MISSED, 0, 0), Report::Other);
    }

    /// Spec 007 SR-001: a launch time and an id share one control buffer.
    #[test]
    fn a_launch_time_and_an_id_fit_one_control_buffer() {
        let mut ctrl = [0u64; 6];
        // SAFETY: all-zero is a valid `msghdr`.
        let mut msg: libc::msghdr = unsafe { zeroed() };
        send_cmsgs(&mut msg, &mut ctrl, Some(7), Some(9));
        // SAFETY: `msg` points at `ctrl`, which `send_cmsgs` filled with two messages.
        unsafe {
            let a = libc::CMSG_FIRSTHDR(&raw const msg);
            assert_eq!(((*a).cmsg_type, cmsg_payload::<u64>(&msg, a)), (libc::SCM_TXTIME, Some(7)));
            let b = libc::CMSG_NXTHDR(&raw const msg, a);
            assert_eq!(((*b).cmsg_type, cmsg_payload::<u32>(&msg, b)), (SCM_TS_OPT_ID, Some(9)));
        }
        // SAFETY: all-zero is a valid `msghdr`.
        let mut none: libc::msghdr = unsafe { zeroed() };
        send_cmsgs(&mut none, &mut ctrl, None, None);
        assert!(none.msg_control.is_null());
    }

    /// Spec 003 SR-005: a control message shorter than its payload type is skipped.
    #[test]
    fn a_short_control_message_is_skipped() {
        let mut ctrl = [0u64; 16];
        // SAFETY: all-zero is a valid `msghdr`.
        let mut msg: libc::msghdr = unsafe { zeroed() };
        msg.msg_control = ctrl.as_mut_ptr().cast();
        msg.msg_controllen = size_of::<[u64; 16]>() as _;
        // SAFETY: the buffer holds at least one header.
        let c = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
        assert!(!c.is_null());
        // SAFETY: `c` points at the start of `ctrl`, which is large enough for a header.
        unsafe {
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_TIMESTAMPING;
            (*c).cmsg_len = libc::CMSG_LEN(4) as _;
        }
        // SAFETY: `c` came from CMSG_FIRSTHDR for `msg`.
        assert!(unsafe { cmsg_payload::<[libc::timespec; 3]>(&msg, c) }.is_none());
        // SAFETY: as above.
        unsafe { (*c).cmsg_len = libc::CMSG_LEN(size_of::<[libc::timespec; 3]>() as u32) as _ };
        // SAFETY: as above.
        assert!(unsafe { cmsg_payload::<[libc::timespec; 3]>(&msg, c) }.is_some());
    }
}
