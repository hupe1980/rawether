//! Deciding what to do with a NIC's hardware timestamping configuration.
//!
//! The configuration (`SIOCGHWTSTAMP`/`SIOCSHWTSTAMP`) is device-wide: other programs on the
//! host, `ptp4l` above all, rely on it. rawether reads it first and never lowers it. Transmit
//! stamping stays as it is, a receive filter that already stamps frames is used as it is, and
//! only a NIC that stamps nothing is widened to stamp every received frame. A configuration that
//! could not be read is never written.

#![forbid(unsafe_code)]

/// `HWTSTAMP_FILTER_NONE` (`<linux/net_tstamp.h>`).
pub(crate) const FILTER_NONE: i32 = 0;
/// `HWTSTAMP_FILTER_ALL`.
pub(crate) const FILTER_ALL: i32 = 1;

/// A NIC's timestamping configuration (`struct hwtstamp_config`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Current {
    pub flags: i32,
    pub tx_type: i32,
    pub rx_filter: i32,
}

/// What to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Plan {
    /// Leave the NIC alone and deliver software timestamps.
    Software,
    /// The NIC already stamps received frames: leave it alone and ask for its stamps.
    Hardware,
    /// The NIC stamps nothing: write this configuration, then ask for its stamps if the write
    /// succeeds and the driver reports a filter other than none.
    Widen(Current),
}

/// The plan for a NIC whose configuration read as `current` (`None`: it could not be read).
pub(crate) fn decide(current: Option<Current>) -> Plan {
    match current {
        None => Plan::Software,
        Some(c) if c.rx_filter != FILTER_NONE => Plan::Hardware,
        Some(c) => Plan::Widen(Current { rx_filter: FILTER_ALL, ..c }),
    }
}

#[cfg(test)]
#[allow(clippy::unreachable)]
mod tests {
    use super::*;

    /// Spec 003 SR-003: for every transmit mode and receive filter, a write keeps the transmit
    /// mode and the flags and only ever changes the filter from none to all; an unreadable
    /// configuration is never written.
    #[test]
    fn the_nic_configuration_is_never_lowered() {
        assert_eq!(decide(None), Plan::Software);
        for flags in [0, 1] {
            for tx_type in 0..=3 {
                for rx_filter in 0..=15 {
                    let current = Current { flags, tx_type, rx_filter };
                    match decide(Some(current)) {
                        Plan::Software => unreachable!("a readable configuration is used or widened"),
                        Plan::Hardware => assert_ne!(rx_filter, FILTER_NONE),
                        Plan::Widen(w) => {
                            assert_eq!(rx_filter, FILTER_NONE, "only a NIC that stamps nothing is widened");
                            assert_eq!((w.flags, w.tx_type, w.rx_filter), (flags, tx_type, FILTER_ALL));
                        }
                    }
                }
            }
        }
    }
}
