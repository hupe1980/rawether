//! Operating-system backends. Every `unsafe` block of the crate lives below this module.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::{Inner, clock_now, drop_capabilities};

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod bsd;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) use bsd::{Inner, clock_now, drop_capabilities};

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
mod unsupported;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
pub(crate) use unsupported::{Inner, clock_now, drop_capabilities};

/// Shared helpers for the Unix backends.
#[cfg(unix)]
pub(crate) mod unix {
    use std::ffi::CString;
    use std::io;
    use std::os::fd::{AsRawFd, BorrowedFd};
    use std::time::Duration;

    /// The last OS error, with what was being attempted in front of it.
    pub(crate) fn last_error(what: &str) -> io::Error {
        let e = io::Error::last_os_error();
        io::Error::new(e.kind(), format!("{what}: {e}"))
    }

    /// `if_nametoindex`, with the errors a caller can act on.
    pub(crate) fn interface_index(name: &str) -> io::Result<u32> {
        let c = CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL"))?;
        // SAFETY: `c` is a valid NUL-terminated string that outlives the call.
        let index = unsafe { libc::if_nametoindex(c.as_ptr()) };
        if index == 0 {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("no interface named {name:?}")));
        }
        Ok(index)
    }

    /// Wait until `fd` is readable for at most `timeout` (`None`: indefinitely). `Ok(false)` on
    /// timeout. An interrupted wait is retried.
    pub(crate) fn wait_readable(fd: BorrowedFd<'_>, timeout: Option<Duration>) -> io::Result<bool> {
        let ms = timeout.map_or(-1, |t| i32::try_from(t.as_millis()).unwrap_or(i32::MAX));
        let mut p = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        loop {
            // SAFETY: `p` is one valid `pollfd` and the count passed is 1.
            let n = unsafe { libc::poll(&raw mut p, 1, ms) };
            if n >= 0 {
                return Ok(n > 0);
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }

    /// Set or clear `O_NONBLOCK`.
    pub(crate) fn set_nonblocking(fd: BorrowedFd<'_>, on: bool) -> io::Result<()> {
        // SAFETY: F_GETFL takes no argument and reads the descriptor's flags.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(last_error("fcntl(F_GETFL)"));
        }
        let flags = if on { flags | libc::O_NONBLOCK } else { flags & !libc::O_NONBLOCK };
        // SAFETY: F_SETFL with an `int` of flags.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags) } < 0 {
            return Err(last_error("fcntl(F_SETFL)"));
        }
        Ok(())
    }

    /// The name as the fixed-size, NUL-padded array `struct ifreq` holds.
    pub(crate) fn ifr_name(name: &str) -> io::Result<[libc::c_char; libc::IFNAMSIZ]> {
        let mut out = [0 as libc::c_char; libc::IFNAMSIZ];
        if name.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("interface name {name:?} is too long"),
            ));
        }
        for (o, b) in out.iter_mut().zip(name.bytes()) {
            *o = b as libc::c_char;
        }
        Ok(out)
    }
}
