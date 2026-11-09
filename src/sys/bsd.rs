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

use super::deadline;
use super::unix::{Ready, ifr_name, interface_index, last_error, set_nonblocking, wait};
use crate::bpf::Program;
use crate::bpf_record::{self, Layout};
use crate::config::{Clock, Config, Timestamping};
use crate::packet::{
    MacAddr, Packet, RxPath, Stats, Timestamp, TimestampInfo, TimestampSource, TxErrors, TxTimestamp,
};

/// `SIOCADDMULTI` = `_IOW('i', 49, struct ifreq)` (`<sys/sockio.h>`), the same on macOS and
/// FreeBSD; not exported by `libc` for either.
const SIOCADDMULTI: libc::c_ulong = 0x8000_0000
    | (((size_of::<libc::ifreq>() as libc::c_ulong) & 0x1fff) << 16)
    | ((b'i' as libc::c_ulong) << 8)
    | 0x31; // command 49
/// `SIOCDELMULTI` = `_IOW('i', 50, struct ifreq)`.
const SIOCDELMULTI: libc::c_ulong = SIOCADDMULTI + 1;
/// `BIOCSDIRECTION` (`_IOW('B', 119, u_int)`) and `BPF_D_IN` (FreeBSD `<net/bpf.h>`): see only
/// incoming frames. Not exported by `libc`; FreeBSD's `BIOCSSEESENT` is an alias of it.
#[cfg(target_os = "freebsd")]
const BIOCSDIRECTION: libc::c_ulong = 0x8004_4277;
#[cfg(target_os = "freebsd")]
const BPF_D_IN: libc::c_uint = 0;

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
    /// Frames handed out since the socket opened: `Stats::received`.
    delivered: u64,
    /// The multicast groups this socket joined, left again on drop.
    _membership: Option<Membership>,
}

impl Inner {
    pub(crate) fn open(cfg: &Config, program: Option<&Program>) -> io::Result<Inner> {
        if cfg.tx_timestamping != Timestamping::Off {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "transmit timestamps are Linux-only: BPF devices do not report them",
            ));
        }
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
        #[cfg(target_os = "freebsd")]
        if !cfg.see_outgoing {
            ioctl_int(&fd, BIOCSDIRECTION, BPF_D_IN, "BIOCSDIRECTION")?;
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
            delivered: 0,
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

    pub(crate) fn tx_timestamping(&self) -> Timestamping {
        Timestamping::Off
    }

    pub(crate) fn next_tx_id(&self) -> u32 {
        0
    }

    pub(crate) fn tx_timestamp(&mut self, _: Option<Duration>) -> io::Result<Option<TxTimestamp>> {
        Err(io::Error::new(io::ErrorKind::InvalidInput, "transmit timestamps are off (and Linux-only)"))
    }

    pub(crate) fn timestamping(&self) -> Timestamping {
        // BPF stamps in software; a request for hardware stamps gets those.
        if self.timestamping == Timestamping::Off { Timestamping::Off } else { Timestamping::Software }
    }

    pub(crate) fn recv(&mut self, timeout: Option<Duration>) -> io::Result<Option<Packet<'_>>> {
        let timeout = if self.nonblocking { Some(Duration::ZERO) } else { timeout };
        let deadline = deadline(timeout);
        loop {
            if let Some(r) = bpf_record::next(&self.buf[..self.end], &mut self.pos, Layout::native()) {
                self.delivered += 1;
                let timestamp = (self.timestamping != Timestamping::Off).then(|| Timestamp {
                    secs: r.secs,
                    nanos: (r.usecs.clamp(0, 999_999) as u32) * 1000,
                    source: TimestampSource::Software,
                });
                return Ok(Some(Packet {
                    data: &self.buf[r.start..r.start + r.caplen],
                    original_len: r.datalen,
                    timestamp,
                    vlan_restored: false,
                }));
            }
            self.pos = 0;
            self.end = 0;
            let remaining = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            // On `Ready::Error` the read below returns the device's error.
            if wait(self.fd.as_fd(), remaining, libc::POLLIN)? == Ready::Timeout {
                return Ok(None);
            }
            // SAFETY: reads at most `buf.len()` octets into `buf`, as BPF requires.
            let n = unsafe { libc::read(self.fd.as_raw_fd(), self.buf.as_mut_ptr().cast(), self.buf.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => continue,
                    _ => return Err(io::Error::new(e.kind(), format!("interface {}: {e}", self.name))),
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
        // `bs_recv` counts frames before the filter runs, so `received` is what rawether read;
        // `bs_drop` counts frames that passed the filter and found the buffer full.
        Ok(Stats { received: self.delivered, dropped: u64::from(st.drop) })
    }

    pub(crate) fn tx_errors(&mut self) -> io::Result<TxErrors> {
        Ok(TxErrors::default())
    }

    pub(crate) fn set_nonblocking(&mut self, on: bool) -> io::Result<()> {
        set_nonblocking(self.fd.as_fd(), on)?;
        self.nonblocking = on;
        Ok(())
    }
}

/// BPF stamps received frames in software; there are no transmit stamps and no hardware clock.
pub(crate) fn timestamp_info(name: &str) -> io::Result<TimestampInfo> {
    interface_index(name)?;
    Ok(TimestampInfo { software_rx: true, ..TimestampInfo::default() })
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
                // An AF_LINK address is a `sockaddr_dl`: the link-level address follows the name
                // (`sdl_nlen` octets into `sdl_data`), `sdl_alen` octets long, inside the record's
                // own `sdl_len`. Read it through the raw pointer to the whole record, never through
                // a reference to the fixed-size struct, which a long name would overrun.
                let base = ifa.ifa_addr.cast::<u8>().cast_const();
                // SAFETY: the record starts with `sdl_len`, `sdl_family`, …, `sdl_alen`; these
                // header fields lie inside every `sockaddr_dl` the kernel returns.
                let (len, nlen, alen) = unsafe {
                    let dl = ifa.ifa_addr.cast::<libc::sockaddr_dl>();
                    (usize::from((*dl).sdl_len), usize::from((*dl).sdl_nlen), (*dl).sdl_alen)
                };
                let at = std::mem::offset_of!(libc::sockaddr_dl, sdl_data) + nlen;
                if alen == 6 && at + 6 <= len {
                    let mut mac = [0u8; 6];
                    // SAFETY: `[at, at + 6)` lies inside the record (`sdl_len`, checked), and
                    // `base` carries the provenance of the whole record.
                    unsafe { std::ptr::copy_nonoverlapping(base.add(at), mac.as_mut_ptr(), 6) };
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

/// Link-layer multicast memberships on one interface. `SIOCADDMULTI` joins the interface,
/// not the socket that asked, so the membership outlives a close: drop leaves every group
/// this socket added. A group that was already joined (FreeBSD: `EADDRINUSE`) belongs to
/// whoever joined it and is left alone.
#[derive(Debug)]
struct Membership {
    fd: OwnedFd,
    name: String,
    added: Vec<MacAddr>,
}

impl Drop for Membership {
    fn drop(&mut self) {
        for g in &self.added {
            if let Ok(mut ifr) = group_request(&self.name, *g) {
                // SAFETY: SIOCDELMULTI reads `ifr`, which is live. A failure leaves nothing
                // to do: the interface may be gone.
                unsafe { libc::ioctl(self.fd.as_raw_fd(), SIOCDELMULTI as _, &raw mut ifr) };
            }
        }
    }
}

fn join_groups(name: &str, groups: &[MacAddr]) -> io::Result<Membership> {
    // SAFETY: plain system call.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc_cloexec(), 0) };
    if raw < 0 {
        return Err(last_error("socket for multicast membership"));
    }
    // SAFETY: `raw` was just created and is owned by nobody else.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    set_cloexec(&fd)?;
    // Built first, so a failure part-way leaves the groups already added.
    let mut m = Membership { fd, name: name.to_owned(), added: Vec::new() };
    for g in groups {
        let mut ifr = group_request(name, *g)?;
        // SAFETY: SIOCADDMULTI reads `ifr`, which is live.
        if unsafe { libc::ioctl(m.fd.as_raw_fd(), SIOCADDMULTI as _, &raw mut ifr) } == 0 {
            m.added.push(*g);
            continue;
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EADDRINUSE) => {}
            Some(libc::EPERM | libc::EACCES) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!(
                        "SIOCADDMULTI {g} on {name}: joining a multicast group needs root (access to /dev/bpf* is not enough); run as root, or receive the group with promiscuous(true) and an EtherType filter"
                    ),
                ));
            }
            _ => return Err(io::Error::new(e.kind(), format!("SIOCADDMULTI {g} on {name}: {e}"))),
        }
    }
    Ok(m)
}

/// An `ifreq` naming interface `name` and link-layer group `g`.
fn group_request(name: &str, g: MacAddr) -> io::Result<libc::ifreq> {
    // SAFETY: all-zero is a valid `ifreq`.
    let mut ifr: libc::ifreq = unsafe { zeroed() };
    ifr.ifr_name = ifr_name(name)?;
    {
        // The group as a link-layer `sockaddr_dl` in `ifr_addr`, as FreeBSD's mtest(8) builds
        // it: FreeBSD accepts only AF_LINK here, macOS AF_LINK or AF_UNSPEC. After `sdl_len`
        // and `sdl_family`, `sa_data` holds `sdl_index` (2), `sdl_type`, `sdl_nlen`, `sdl_alen`,
        // `sdl_slen`, then the address (nlen = 0).
        // SAFETY: writing the `ifru_addr` member of the union, a plain `sockaddr`.
        let sa = unsafe { &mut ifr.ifr_ifru.ifru_addr };
        sa.sa_len = size_of::<libc::sockaddr_dl>() as u8;
        sa.sa_family = libc::AF_LINK as libc::sa_family_t;
        sa.sa_data[4] = 6; // sdl_alen
        for (o, b) in sa.sa_data[6..12].iter_mut().zip(g.0) {
            *o = b as libc::c_char;
        }
    }
    Ok(ifr)
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

    /// Spec 007 SR-006: transmit timestamps are refused, naming them; capabilities are known.
    #[test]
    #[cfg_attr(miri, ignore)] // system calls
    fn transmit_timestamps_are_unsupported_and_capabilities_are_reported() {
        let e = Inner::open(&Config::new("lo0").tx_timestamping(Timestamping::Software), None)
            .expect_err("no tx stamps");
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        assert!(e.to_string().contains("transmit timestamps"), "{e}");
        let info = timestamp_info("lo0").expect("lo0 exists");
        assert!(info.software_rx && !info.software_tx && info.phc_index.is_none());
        assert_eq!(timestamp_info("no-such-if0").expect_err("missing").kind(), io::ErrorKind::NotFound);
    }

    /// The ioctl numbers rawether defines itself, against `<sys/sockio.h>` and `<net/bpf.h>`.
    #[test]
    fn locally_defined_ioctls_match_the_headers() {
        assert_eq!((SIOCADDMULTI, SIOCDELMULTI), (0x8020_6931, 0x8020_6932));
        #[cfg(target_os = "freebsd")]
        assert_eq!(BIOCSDIRECTION, 0x8004_4277);
    }
}
