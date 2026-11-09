//! Platforms with neither AF_PACKET nor BPF devices: everything fails with `Unsupported`.

#![allow(clippy::unused_self, clippy::unnecessary_wraps)]

use std::io;
use std::time::Duration;

use crate::bpf::Program;
use crate::config::{Clock, Config, Timestamping};
use crate::packet::{MacAddr, Packet, RxPath, Stats, TimestampInfo, TxErrors, TxTimestamp};

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "raw Ethernet sockets are supported on Linux, macOS and the BSDs only",
    )
}

/// Never constructed.
#[derive(Debug)]
pub(crate) struct Inner(core::convert::Infallible);

impl Inner {
    pub(crate) fn open(_: &Config, _: Option<&Program>) -> io::Result<Inner> {
        Err(unsupported())
    }
    pub(crate) fn interface(&self) -> &str {
        match self.0 {}
    }
    pub(crate) fn index(&self) -> u32 {
        match self.0 {}
    }
    pub(crate) fn mac(&self) -> MacAddr {
        match self.0 {}
    }
    pub(crate) fn rx_path(&self) -> RxPath {
        match self.0 {}
    }
    pub(crate) fn recv(&mut self, _: Option<Duration>) -> io::Result<Option<Packet<'_>>> {
        match self.0 {}
    }
    pub(crate) fn send(&self, _: &[u8]) -> io::Result<()> {
        match self.0 {}
    }
    pub(crate) fn send_at(&self, _: &[u8], _: u64) -> io::Result<()> {
        match self.0 {}
    }
    pub(crate) fn send_batch(&mut self, _: &[&[u8]]) -> io::Result<usize> {
        match self.0 {}
    }
    pub(crate) fn stats(&mut self) -> io::Result<Stats> {
        match self.0 {}
    }
    pub(crate) fn tx_timestamping(&self) -> Timestamping {
        match self.0 {}
    }
    pub(crate) fn next_tx_id(&self) -> u32 {
        match self.0 {}
    }
    pub(crate) fn tx_timestamp(&mut self, _: Option<Duration>) -> io::Result<Option<TxTimestamp>> {
        match self.0 {}
    }
    pub(crate) fn timestamping(&self) -> Timestamping {
        match self.0 {}
    }

    pub(crate) fn tx_errors(&mut self) -> io::Result<TxErrors> {
        match self.0 {}
    }
    pub(crate) fn set_nonblocking(&mut self, _: bool) -> io::Result<()> {
        match self.0 {}
    }
    #[cfg(unix)]
    pub(crate) fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        match self.0 {}
    }
}

pub(crate) fn clock_now(_: Clock) -> io::Result<Duration> {
    Err(unsupported())
}

pub(crate) fn drop_capabilities() -> io::Result<()> {
    Ok(())
}

pub(crate) fn timestamp_info(_: &str) -> io::Result<TimestampInfo> {
    Err(unsupported())
}
