//! Operating-system backends. Every `unsafe` block of the crate lives below this module.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::{Inner, clock_now, drop_capabilities, timestamp_info};

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod bsd;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) use bsd::{Inner, clock_now, drop_capabilities, timestamp_info};

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
mod unsupported;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
pub(crate) use unsupported::{Inner, clock_now, drop_capabilities, timestamp_info};

/// When a wait of `timeout` started now ends. `None` for no timeout, and for one too large to
/// represent, which is the same thing in practice (`Duration::MAX` means "forever").
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn deadline(timeout: Option<std::time::Duration>) -> Option<std::time::Instant> {
    timeout.and_then(|t| std::time::Instant::now().checked_add(t))
}

/// `poll`'s timeout for what is left of a wait: −1 for none, otherwise milliseconds rounded up
/// (so a short wait is not cut to zero) and clamped to `i32::MAX`.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn poll_ms(remaining: Option<std::time::Duration>) -> i32 {
    remaining.map_or(-1, |r| {
        let ms = r.as_nanos().div_ceil(1_000_000);
        i32::try_from(ms).unwrap_or(i32::MAX)
    })
}

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

    /// What a wait ended with.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Ready {
        /// Data is waiting.
        Readable,
        /// The socket has a pending error or hung up (link down, interface removed).
        Error,
        /// The time ran out.
        Timeout,
    }

    /// Wait until `fd` reports `events` (`POLLIN` for frames, 0 for the error queue only) or an
    /// error, for at most `timeout` (`None`: indefinitely). An interrupted wait is retried with
    /// what is left of the timeout.
    pub(crate) fn wait(
        fd: BorrowedFd<'_>,
        timeout: Option<Duration>,
        events: libc::c_short,
    ) -> io::Result<Ready> {
        let deadline = super::deadline(timeout);
        loop {
            let ms = super::poll_ms(deadline.map(|d| d.saturating_duration_since(std::time::Instant::now())));
            let mut p = libc::pollfd { fd: fd.as_raw_fd(), events, revents: 0 };
            // SAFETY: `p` is one valid `pollfd` and the count passed is 1.
            let n = unsafe { libc::poll(&raw mut p, 1, ms) };
            if n > 0 {
                return Ok(if p.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                    Ready::Error
                } else {
                    Ready::Readable
                });
            }
            if n == 0 {
                return Ok(Ready::Timeout);
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }

    /// The socket's pending error (`SO_ERROR`, which reading clears), if it has one.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn socket_error(fd: BorrowedFd<'_>) -> Option<io::Error> {
        let mut err: libc::c_int = 0;
        let mut len = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: SO_ERROR writes one `int` into `err`, whose size `len` states.
        let r = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&raw mut err).cast(),
                &raw mut len,
            )
        };
        (r == 0 && err != 0).then(|| io::Error::from_raw_os_error(err))
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// Spec 003 SR-008: no timeout overflows; a short one is not cut to zero.
    #[test]
    fn waits_never_overflow_and_round_up() {
        assert!(deadline(Some(Duration::MAX)).is_none(), "Duration::MAX means forever");
        assert!(deadline(Some(Duration::from_secs(1))).is_some());
        assert!(deadline(None).is_none());
        assert_eq!(poll_ms(None), -1);
        assert_eq!(poll_ms(Some(Duration::ZERO)), 0);
        assert_eq!(poll_ms(Some(Duration::from_micros(1))), 1);
        assert_eq!(poll_ms(Some(Duration::from_micros(1500))), 2);
        assert_eq!(poll_ms(Some(Duration::MAX)), i32::MAX);
    }
}
