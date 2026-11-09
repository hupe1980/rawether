//! Linux: AF_PACKET with a TPACKET_V3 receive ring.
//!
//! Every `unsafe` block below wraps one system call or one access to the memory the kernel
//! shares through the ring, and says why it is sound.

use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering, fence};
use std::time::{Duration, Instant};

use super::deadline;
use super::unix::{Ready, ifr_name, interface_index, last_error, set_nonblocking, socket_error, wait};
use crate::bpf::Program;
use crate::config::{Clock, Config, RingConfig, RxMode, Timestamping, TxTime};
use crate::hwtstamp::{self, Plan};
use crate::packet::{MacAddr, Packet, RxPath, Stats, Timestamp, TimestampSource, TxErrors};
use crate::ring::{self, Cursor};
use crate::vlan;

/// `enum tpacket_versions` — not exported by `libc`.
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
    // Drop order: the ring is unmapped before the socket closes.
    ring: Option<Ring>,
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
        let timestamping = match cfg.timestamping {
            Timestamping::Hardware if !hardware_timestamps(&fd, &cfg.interface) => Timestamping::Software,
            t => t,
        };
        let hardware = timestamping == Timestamping::Hardware;

        // `Auto` falls back to the plain path (and `rx_path` says so); an explicit ring that the
        // kernel refuses is an error, not a quiet downgrade.
        let ring = match cfg.rx {
            RxMode::Plain => None,
            RxMode::Auto => setup_ring(&fd, RingConfig::default(), hardware).ok(),
            RxMode::Ring(r) => Some(setup_ring(&fd, r, hardware)?),
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
        if timestamping != Timestamping::Off {
            let mut flags = libc::SOF_TIMESTAMPING_RX_SOFTWARE | libc::SOF_TIMESTAMPING_SOFTWARE;
            if hardware {
                flags |= libc::SOF_TIMESTAMPING_RX_HARDWARE | libc::SOF_TIMESTAMPING_RAW_HARDWARE;
            }
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
        let buf = if ring.is_some() {
            Vec::new()
        } else {
            vec![0u8; RESERVE as usize + cfg.buffer_size.min(PLAIN_MAX)]
        };

        Ok(Inner {
            ring,
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
        if self.ring.is_some() { RxPath::Ring } else { RxPath::Plain }
    }

    pub(crate) fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub(crate) fn timestamping(&self) -> Timestamping {
        self.timestamping
    }

    pub(crate) fn recv(&mut self, timeout: Option<Duration>) -> io::Result<Option<Packet<'_>>> {
        let timeout = if self.nonblocking { Some(Duration::ZERO) } else { timeout };
        let deadline = deadline(timeout);
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
            match wait(self.fd.as_fd(), remaining)? {
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
            match wait(self.fd.as_fd(), remaining)? {
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
        // SAFETY: `frame` is a live slice whose length is passed; the socket is bound, so no
        // address is needed.
        let n = unsafe { libc::send(self.fd.as_raw_fd(), frame.as_ptr().cast(), frame.len(), 0) };
        if n < 0 {
            return Err(last_error("send"));
        }
        if n as usize != frame.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("sent {n} of {} octets", frame.len()),
            ));
        }
        Ok(())
    }

    pub(crate) fn send_at(&self, frame: &[u8], launch_ns: u64) -> io::Result<()> {
        if self.tx_time.is_none() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "send_at needs Config::tx_time"));
        }
        let mut ctrl = [0u64; 4];
        let mut iov = libc::iovec { iov_base: frame.as_ptr().cast_mut().cast(), iov_len: frame.len() };
        // SAFETY: all-zero is a valid `msghdr`.
        let mut msg: libc::msghdr = unsafe { zeroed() };
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl.as_mut_ptr().cast();
        // SAFETY: CMSG_SPACE is a pure size computation.
        msg.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<u64>() as u32) } as _;
        // SAFETY: `ctrl` holds `msg_controllen` octets (32 ≥ CMSG_SPACE(8) = 24) and is aligned;
        // the header and its `u64` payload are written inside it. The kernel only reads `iov`.
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&raw const msg);
            if c.is_null() {
                return Err(io::Error::other("no room for the launch-time control message"));
            }
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_TXTIME;
            (*c).cmsg_len = libc::CMSG_LEN(size_of::<u64>() as u32) as _;
            libc::CMSG_DATA(c).cast::<u64>().write_unaligned(launch_ns);
        }
        // SAFETY: `msg` describes live buffers as above.
        let n = unsafe { libc::sendmsg(self.fd.as_raw_fd(), &raw const msg, 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            // The qdisc dropped the frame at enqueue: etf refuses a launch time already past or
            // on another clock, and reports why to `tx_errors`.
            if e.raw_os_error() == Some(libc::ENOBUFS) {
                return Err(io::Error::new(
                    e.kind(),
                    "the qdisc refused the launch time (already past, or on another clock); see tx_errors",
                ));
            }
            return Err(io::Error::new(e.kind(), format!("sendmsg with SCM_TXTIME: {e}")));
        }
        Ok(())
    }

    pub(crate) fn send_batch(&mut self, frames: &[&[u8]]) -> io::Result<usize> {
        let mut sent = 0;
        for chunk in frames.chunks(BATCH) {
            // SAFETY: all-zero values are valid for `iovec` and `mmsghdr`.
            let mut iovs: [libc::iovec; BATCH] = unsafe { zeroed() };
            // SAFETY: as above.
            let mut msgs: [libc::mmsghdr; BATCH] = unsafe { zeroed() };
            for (k, f) in chunk.iter().enumerate() {
                iovs[k] = libc::iovec { iov_base: f.as_ptr().cast_mut().cast(), iov_len: f.len() };
                msgs[k].msg_hdr.msg_iov = &raw mut iovs[k];
                msgs[k].msg_hdr.msg_iovlen = 1;
            }
            let mut done = 0;
            while done < chunk.len() {
                // SAFETY: `msgs[done..chunk.len()]` are initialised headers pointing at live
                // iovecs that point at the caller's frames; the kernel only reads them.
                let n = unsafe {
                    libc::sendmmsg(
                        self.fd.as_raw_fd(),
                        msgs[done..].as_mut_ptr(),
                        (chunk.len() - done) as libc::c_uint,
                        0,
                    )
                };
                if n < 0 {
                    let e = last_error("sendmmsg");
                    if sent + done > 0 {
                        return Ok(sent + done);
                    }
                    return Err(e);
                }
                done += n as usize;
            }
            sent += done;
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

    /// Read every report waiting on the error queue, counting launch-time drops into
    /// `tx_pending`. Returns how many reports were read.
    fn drain_error_queue(&mut self) -> io::Result<u64> {
        let mut read = 0;
        loop {
            let mut data = [0u8; 256];
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
            // SAFETY: the kernel filled `ctrl` and set `msg_controllen`.
            let mut c = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
            while !c.is_null() {
                // SAFETY: `c` is a header inside `msg`'s control buffer.
                let (level, kind) = unsafe { ((*c).cmsg_level, (*c).cmsg_type) };
                if level == libc::SOL_PACKET
                    && kind == PACKET_TX_TIMESTAMP
                    // SAFETY: as above.
                    && let Some(ee) = unsafe { cmsg_payload::<libc::sock_extended_err>(&msg, c) }
                {
                    count_tx_error(&mut self.tx_pending, ee.ee_origin, ee.ee_code);
                }
                // SAFETY: as above.
                c = unsafe { libc::CMSG_NXTHDR(&raw const msg, c) };
            }
        }
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
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCGIFHWADDR, &raw mut ifr) } < 0 {
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

/// Make the NIC stamp received frames without disturbing anyone else, and say whether its
/// stamps can be asked for. See [`hwtstamp`]: read first, never lower, never write blind.
fn hardware_timestamps(fd: &OwnedFd, name: &str) -> bool {
    let current = hwtstamp_ioctl(fd, name, libc::SIOCGHWTSTAMP, None).ok();
    match hwtstamp::decide(current) {
        Plan::Software => false,
        Plan::Hardware => true,
        Plan::Widen(want) => hwtstamp_ioctl(fd, name, libc::SIOCSHWTSTAMP, Some(want))
            .is_ok_and(|now| now.rx_filter != hwtstamp::FILTER_NONE),
    }
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

/// Count one error-queue report: launch-time drops by reason; anything else is not ours.
fn count_tx_error(t: &mut TxErrors, origin: u8, code: u8) {
    if origin == SO_EE_ORIGIN_TXTIME {
        match code {
            SO_EE_CODE_TXTIME_MISSED => t.missed += 1,
            SO_EE_CODE_TXTIME_INVALID_PARAM => t.invalid += 1,
            _ => {}
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
    let Some(base) = NonNull::new(p.cast::<u8>()).filter(|_| p != libc::MAP_FAILED) else {
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

    /// Spec 003 SR-011: only launch-time reports count, by reason.
    #[test]
    fn only_launch_time_reports_are_counted() {
        let mut t = TxErrors::default();
        count_tx_error(&mut t, SO_EE_ORIGIN_TXTIME, SO_EE_CODE_TXTIME_MISSED);
        count_tx_error(&mut t, SO_EE_ORIGIN_TXTIME, SO_EE_CODE_TXTIME_INVALID_PARAM);
        count_tx_error(&mut t, libc::SO_EE_ORIGIN_LOCAL, SO_EE_CODE_TXTIME_MISSED);
        count_tx_error(&mut t, libc::SO_EE_ORIGIN_TXSTATUS, 0);
        assert_eq!((t.missed, t.invalid, t.total()), (1, 1, 2));
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
