//! macOS and FreeBSD: BPF devices (`/dev/bpf*`).
//!
//! Every `unsafe` block below wraps one system call or one unaligned read of a record the
//! kernel wrote into our buffer, and says why it is sound.

// Every backend offers the same methods, including the ones this one cannot do anything for.
#![allow(clippy::unused_self, clippy::unnecessary_wraps)]

use std::ffi::CStr;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use super::unix::{ifr_name, interface_index, last_error, set_nonblocking, wait_readable};
use crate::bpf::Program;
use crate::config::{Clock, Config, Timestamping};
use crate::packet::{MacAddr, Packet, RxPath, Stats, Timestamp, TimestampSource};

/// `BPF_ALIGNMENT`: records in a read buffer start on this boundary.
#[cfg(target_os = "macos")]
const ALIGN: usize = 4;
#[cfg(not(target_os = "macos"))]
const ALIGN: usize = size_of::<libc::c_long>();

const fn word_align(x: usize) -> usize {
    (x + (ALIGN - 1)) & !(ALIGN - 1)
}

/// `struct bpf_stat`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BpfStat {
    recv: libc::c_uint,
    drop: libc::c_uint,
}

fn ioctl_int(fd: &OwnedFd, request: libc::c_ulong, value: libc::c_uint, what: &str) -> io::Result<()> {
    let mut v = value;
    // SAFETY: the request takes a pointer to a `u_int`, which `v` is.
    if unsafe { libc::ioctl(fd.as_raw_fd(), request, &raw mut v) } < 0 {
        return Err(last_error(what));
    }
    Ok(())
}

/// An open BPF device bound to one interface.
#[derive(Debug)]
pub(crate) struct Inner {
    fd: OwnedFd,
    name: String,
    index: u32,
    mac: MacAddr,
    timestamping: Timestamping,
    nonblocking: bool,
    buf: Vec<u8>,
    /// The unread part of the last read: `buf[pos..end]`.
    pos: usize,
    end: usize,
    /// A datagram socket kept for multicast membership, which BSD holds per socket.
    _membership: Option<OwnedFd>,
}

impl Inner {
    pub(crate) fn open(cfg: &Config, program: Option<&Program>) -> io::Result<Inner> {
        if cfg.tx_time.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "launch-time transmission (SO_TXTIME) is Linux-only",
            ));
        }
        let index = interface_index(&cfg.interface)?;
        let mac = hardware_address(&cfg.interface)?;
        let fd = open_device()?;

        // The buffer length must be set before the interface is attached.
        let want = cfg.buffer_size.clamp(4096, 1 << 21) as libc::c_uint;
        let _ = ioctl_int(&fd, libc::BIOCSBLEN as _, want, "BIOCSBLEN");
        // SAFETY: all-zero is a valid `ifreq`.
        let mut ifr: libc::ifreq = unsafe { zeroed() };
        ifr.ifr_name = ifr_name(&cfg.interface)?;
        // SAFETY: BIOCSETIF reads the name from `ifr`, which is live.
        if unsafe { libc::ioctl(fd.as_raw_fd(), libc::BIOCSETIF as _, &raw mut ifr) } < 0 {
            return Err(last_error(&format!("BIOCSETIF {}", cfg.interface)));
        }
        ioctl_int(&fd, libc::BIOCIMMEDIATE as _, 1, "BIOCIMMEDIATE")?;
        ioctl_int(&fd, libc::BIOCSHDRCMPLT as _, 1, "BIOCSHDRCMPLT")?;
        #[cfg(target_os = "macos")]
        if !cfg.see_outgoing {
            ioctl_int(&fd, libc::BIOCSSEESENT as _, 0, "BIOCSSEESENT")?;
        }
        if let Some(p) = program {
            let mut insns: Vec<libc::bpf_insn> = p
                .instructions()
                .iter()
                .map(|i| libc::bpf_insn { code: i.code, jt: i.jt, jf: i.jf, k: i.k })
                .collect();
            let mut prog =
                libc::bpf_program { bf_len: insns.len() as libc::c_uint, bf_insns: insns.as_mut_ptr() };
            // SAFETY: `prog` points at `insns`, both live for the call; the kernel copies them.
            if unsafe { libc::ioctl(fd.as_raw_fd(), libc::BIOCSETF as _, &raw mut prog) } < 0 {
                return Err(last_error("BIOCSETF"));
            }
        }
        // BPF has no all-multicast mode of its own: promiscuous mode covers it.
        if cfg.promiscuous || cfg.all_multicast {
            // SAFETY: BIOCPROMISC takes no argument.
            if unsafe { libc::ioctl(fd.as_raw_fd(), libc::BIOCPROMISC as _) } < 0 {
                return Err(last_error("BIOCPROMISC"));
            }
        }
        let membership =
            if cfg.multicast.is_empty() { None } else { Some(join_groups(&cfg.interface, &cfg.multicast)?) };
        if cfg.nonblocking {
            set_nonblocking(fd.as_fd(), true)?;
        }
        let mut blen: libc::c_uint = 0;
        // SAFETY: BIOCGBLEN writes a `u_int` into `blen`.
        if unsafe { libc::ioctl(fd.as_raw_fd(), libc::BIOCGBLEN as _, &raw mut blen) } < 0 {
            return Err(last_error("BIOCGBLEN"));
        }
        Ok(Inner {
            fd,
            name: cfg.interface.clone(),
            index,
            mac,
            timestamping: cfg.timestamping,
            nonblocking: cfg.nonblocking,
            buf: vec![0u8; blen as usize],
            pos: 0,
            end: 0,
            _membership: membership,
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
        RxPath::Bpf
    }

    pub(crate) fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub(crate) fn recv(&mut self, timeout: Option<Duration>) -> io::Result<Option<Packet<'_>>> {
        let timeout = if self.nonblocking { Some(Duration::ZERO) } else { timeout };
        let deadline = timeout.map(|t| Instant::now() + t);
        loop {
            if let Some((start, caplen, datalen, ts)) = next_record(&self.buf[..self.end], &mut self.pos) {
                let timestamp = (self.timestamping != Timestamping::Off).then_some(ts);
                return Ok(Some(Packet {
                    data: &self.buf[start..start + caplen],
                    original_len: datalen,
                    timestamp,
                    vlan_restored: false,
                }));
            }
            self.pos = 0;
            self.end = 0;
            let remaining = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            if remaining.is_some() && !wait_readable(self.fd.as_fd(), remaining)? {
                return Ok(None);
            }
            // SAFETY: reads at most `buf.len()` octets into `buf`, as BPF requires.
            let n = unsafe { libc::read(self.fd.as_raw_fd(), self.buf.as_mut_ptr().cast(), self.buf.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                match e.kind() {
                    io::ErrorKind::WouldBlock if remaining == Some(Duration::ZERO) => return Ok(None),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => continue,
                    _ => return Err(io::Error::new(e.kind(), format!("read from BPF: {e}"))),
                }
            }
            self.end = n as usize;
        }
    }

    pub(crate) fn send(&self, frame: &[u8]) -> io::Result<()> {
        // SAFETY: writes `frame.len()` octets from a live slice.
        let n = unsafe { libc::write(self.fd.as_raw_fd(), frame.as_ptr().cast(), frame.len()) };
        if n < 0 {
            return Err(last_error("write to BPF"));
        }
        if n as usize != frame.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("sent {n} of {} octets", frame.len()),
            ));
        }
        Ok(())
    }

    pub(crate) fn send_at(&self, _: &[u8], _: u64) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::InvalidInput, "send_at needs Config::tx_time, which is Linux-only"))
    }

    pub(crate) fn send_batch(&mut self, frames: &[&[u8]]) -> io::Result<usize> {
        for (k, f) in frames.iter().enumerate() {
            if let Err(e) = self.send(f) {
                return if k > 0 { Ok(k) } else { Err(e) };
            }
        }
        Ok(frames.len())
    }

    pub(crate) fn stats(&mut self) -> io::Result<Stats> {
        let mut st = BpfStat::default();
        // SAFETY: BIOCGSTATS writes a `struct bpf_stat` (two `u_int`s) into `st`.
        if unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::BIOCGSTATS as _, &raw mut st) } < 0 {
            return Err(last_error("BIOCGSTATS"));
        }
        // BPF's counters are cumulative; `bs_recv` includes the drops.
        let dropped = u64::from(st.drop);
        Ok(Stats { received: u64::from(st.recv).saturating_sub(dropped), dropped })
    }

    pub(crate) fn tx_errors(&mut self) -> io::Result<u64> {
        Ok(0)
    }

    pub(crate) fn set_nonblocking(&mut self, on: bool) -> io::Result<()> {
        set_nonblocking(self.fd.as_fd(), on)?;
        self.nonblocking = on;
        Ok(())
    }
}

/// The next record in `buf` at `*pos`, as `(data start, captured, wire length, timestamp)`,
/// advancing `*pos`. `None` at the end or when the kernel's lengths do not hold together.
fn next_record(buf: &[u8], pos: &mut usize) -> Option<(usize, usize, usize, Timestamp)> {
    let at = *pos;
    if at.checked_add(size_of::<libc::bpf_hdr>())? > buf.len() {
        return None;
    }
    // SAFETY: `size_of::<bpf_hdr>()` octets from `at` lie inside `buf` (checked above); the
    // record may be unaligned, so it is read unaligned into a value of its own type.
    let h: libc::bpf_hdr = unsafe { buf.as_ptr().add(at).cast::<libc::bpf_hdr>().read_unaligned() };
    let start = at.checked_add(usize::from(h.bh_hdrlen))?;
    let caplen = h.bh_caplen as usize;
    if usize::from(h.bh_hdrlen) < size_of::<libc::bpf_hdr>() - 2 || start.checked_add(caplen)? > buf.len() {
        *pos = buf.len();
        return None;
    }
    *pos = word_align(start + caplen);
    let ts = Timestamp {
        secs: i64::from(h.bh_tstamp.tv_sec),
        nanos: (h.bh_tstamp.tv_usec as u32).saturating_mul(1000).min(999_999_999),
        source: TimestampSource::Software,
    };
    Some((start, caplen, h.bh_datalen as usize, ts))
}

fn open_device() -> io::Result<OwnedFd> {
    let open = |path: &CStr| {
        // SAFETY: `path` is NUL-terminated and outlives the call.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: `fd` was just opened and is owned by nobody else.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    };
    // The cloning device first, then the numbered ones.
    match open(c"/dev/bpf") {
        Ok(fd) => return Ok(fd),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Err(permission()),
        Err(_) => {}
    }
    for n in 0..256 {
        let path = std::ffi::CString::new(format!("/dev/bpf{n}")).map_err(io::Error::other)?;
        match open(&path) {
            Ok(fd) => return Ok(fd),
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {}
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Err(permission()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => break,
            Err(e) => return Err(io::Error::new(e.kind(), format!("open /dev/bpf{n}: {e}"))),
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "no free BPF device"))
}

fn permission() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "opening a BPF device needs read and write access to /dev/bpf* (run as root, or grant the group, e.g. Wireshark's ChmodBPF)",
    )
}

fn hardware_address(name: &str) -> io::Result<MacAddr> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a list and stores its head in `list`.
    if unsafe { libc::getifaddrs(&raw mut list) } < 0 {
        return Err(last_error("getifaddrs"));
    }
    let mut found = None;
    let mut cur = list;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list getifaddrs returned and has not been freed.
        let ifa = unsafe { &*cur };
        // SAFETY: `ifa_name` is a NUL-terminated string owned by the list.
        let this = unsafe { CStr::from_ptr(ifa.ifa_name) };
        if this.to_bytes() == name.as_bytes() && !ifa.ifa_addr.is_null() {
            // SAFETY: `ifa_addr` is non-null and points at a sockaddr owned by the list.
            let family = i32::from(unsafe { (*ifa.ifa_addr).sa_family });
            if family == libc::AF_LINK {
                // SAFETY: an AF_LINK address is a `sockaddr_dl`; its link-level address starts
                // after the name (`sdl_nlen` octets into `sdl_data`), and `sdl_alen` says how
                // long it is. The read is bounded by `sdl_len`, the record's own length.
                let dl = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_dl>() };
                if dl.sdl_alen == 6 && usize::from(dl.sdl_nlen) + 6 + 8 <= usize::from(dl.sdl_len) {
                    let mut mac = [0u8; 6];
                    // SAFETY: as above — the six octets lie inside the record.
                    let p = unsafe { dl.sdl_data.as_ptr().cast::<u8>().add(usize::from(dl.sdl_nlen)) };
                    for (k, o) in mac.iter_mut().enumerate() {
                        // SAFETY: k < 6, inside the bound checked above.
                        *o = unsafe { *p.add(k) };
                    }
                    found = Some(MacAddr(mac));
                }
            }
        }
        cur = ifa.ifa_next;
    }
    // SAFETY: `list` came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(list) };
    // An interface without a link-level address (a tunnel, loopback) still opens; its source
    // address is all zeros.
    Ok(found.unwrap_or_default())
}

fn join_groups(name: &str, groups: &[MacAddr]) -> io::Result<OwnedFd> {
    // SAFETY: plain system call.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc_cloexec(), 0) };
    if raw < 0 {
        return Err(last_error("socket for multicast membership"));
    }
    // SAFETY: `raw` was just created and is owned by nobody else.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    set_cloexec(&fd)?;
    for g in groups {
        // SAFETY: all-zero is a valid `ifreq`.
        let mut ifr: libc::ifreq = unsafe { zeroed() };
        ifr.ifr_name = ifr_name(name)?;
        // SAFETY: writing the `ifru_addr` member of the union, a plain `sockaddr`.
        let sa = unsafe { &mut ifr.ifr_ifru.ifru_addr };
        sa.sa_family = libc::AF_UNSPEC as libc::sa_family_t;
        sa.sa_len = size_of::<libc::sockaddr>() as u8;
        for (o, b) in sa.sa_data.iter_mut().zip(g.0) {
            *o = b as libc::c_char;
        }
        // SAFETY: SIOCADDMULTI reads `ifr`, which is live.
        if unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCADDMULTI as _, &raw mut ifr) } < 0 {
            return Err(last_error(&format!("SIOCADDMULTI {g} on {name}")));
        }
    }
    Ok(fd)
}

/// `SOCK_CLOEXEC` where the platform has it at `socket(2)`; macOS sets it afterwards.
#[cfg(target_os = "macos")]
fn libc_cloexec() -> libc::c_int {
    0
}
#[cfg(not(target_os = "macos"))]
fn libc_cloexec() -> libc::c_int {
    libc::SOCK_CLOEXEC
}

fn set_cloexec(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: F_SETFD with an `int` of descriptor flags.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(last_error("fcntl(F_SETFD)"));
    }
    Ok(())
}

pub(crate) fn clock_now(clock: Clock) -> io::Result<Duration> {
    let id = match clock {
        Clock::Tai => return Err(io::Error::new(io::ErrorKind::Unsupported, "CLOCK_TAI is Linux-only")),
        Clock::Monotonic => libc::CLOCK_MONOTONIC,
        Clock::Realtime => libc::CLOCK_REALTIME,
    };
    // SAFETY: all-zero is a valid `timespec`.
    let mut ts: libc::timespec = unsafe { zeroed() };
    // SAFETY: `ts` is live and writable.
    if unsafe { libc::clock_gettime(id, &raw mut ts) } < 0 {
        return Err(last_error("clock_gettime"));
    }
    Ok(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

/// BSD has no capability sets to drop; privileges are the BPF device's file mode.
pub(crate) fn drop_capabilities() -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_buffer_is_split_into_records_and_bad_lengths_end_it() {
        let hl = size_of::<libc::bpf_hdr>();
        let mut buf = vec![0u8; 256];
        // SAFETY: test-only; writes one header into a buffer large enough for it.
        let mut h: libc::bpf_hdr = unsafe { zeroed() };
        h.bh_caplen = 20;
        h.bh_datalen = 60;
        h.bh_hdrlen = hl as u16;
        h.bh_tstamp.tv_sec = 7;
        // SAFETY: `buf` holds at least `hl` octets at offset 0.
        unsafe { buf.as_mut_ptr().cast::<libc::bpf_hdr>().write_unaligned(h) };
        buf[hl..hl + 20].fill(0xaa);
        let mut pos = 0;
        let (start, cap, wire, ts) = next_record(&buf[..word_align(hl + 20)], &mut pos).expect("record");
        assert_eq!((start, cap, wire, ts.secs), (hl, 20, 60, 7));
        assert!(next_record(&buf[..word_align(hl + 20)], &mut pos).is_none());

        h.bh_caplen = 10_000;
        // SAFETY: as above.
        unsafe { buf.as_mut_ptr().cast::<libc::bpf_hdr>().write_unaligned(h) };
        let mut pos = 0;
        assert!(next_record(&buf, &mut pos).is_none(), "a record longer than the buffer");
        assert_eq!(pos, buf.len());
    }
}
