//! Deciding what to do with a NIC's hardware timestamping configuration.
//!
//! The configuration (`SIOCGHWTSTAMP`/`SIOCSHWTSTAMP`) is device-wide: other programs on the
//! host, `ptp4l` above all, rely on it. rawether reads it first and never lowers it: a receive
//! filter that already stamps frames and a transmit mode that already stamps (on, or a one-step
//! PTP mode) are used as they are; only none is widened to all, and off to on. A configuration
//! that could not be read is never written.

#![forbid(unsafe_code)]

/// `HWTSTAMP_FILTER_NONE` (`<linux/net_tstamp.h>`).
pub(crate) const FILTER_NONE: i32 = 0;
/// `HWTSTAMP_FILTER_ALL`.
pub(crate) const FILTER_ALL: i32 = 1;
/// `HWTSTAMP_TX_OFF` and `HWTSTAMP_TX_ON`. Values above ON are one-step PTP modes, which stamp
/// as well and are left alone.
pub(crate) const TX_OFF: i32 = 0;
pub(crate) const TX_ON: i32 = 1;

/// A NIC's timestamping configuration (`struct hwtstamp_config`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Current {
    pub flags: i32,
    pub tx_type: i32,
    pub rx_filter: i32,
}

/// What to do with the configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Plan {
    /// It could not be read: write nothing, deliver software timestamps.
    Unreadable,
    /// It already stamps what was asked for: write nothing.
    Keep,
    /// Write this, which only widens what the NIC stamps.
    Write(Current),
}

/// The plan for a NIC whose configuration read as `current` (`None`: it could not be read),
/// when hardware stamps are wanted for received (`rx`) and/or transmitted (`tx`) frames. A write
/// only raises the receive filter from none to all and the transmit mode from off to on.
pub(crate) fn decide(current: Option<Current>, rx: bool, tx: bool) -> Plan {
    let Some(c) = current else { return Plan::Unreadable };
    let mut w = c;
    if rx && c.rx_filter == FILTER_NONE {
        w.rx_filter = FILTER_ALL;
    }
    if tx && c.tx_type == TX_OFF {
        w.tx_type = TX_ON;
    }
    if w == c { Plan::Keep } else { Plan::Write(w) }
}

/// Which stamps the NIC delivers with configuration `c`, for what was wanted: `(rx, tx)`.
pub(crate) fn effective(c: Current, rx: bool, tx: bool) -> (bool, bool) {
    (rx && c.rx_filter != FILTER_NONE, tx && c.tx_type != TX_OFF)
}

#[cfg(test)]
#[allow(clippy::unreachable)]
mod tests {
    use super::*;

    /// Spec 003 SR-003, spec 007 SR-002: for every configuration and request, a write keeps the
    /// flags, raises the receive filter only from none to all and the transmit mode only from off
    /// to on, and touches only what was asked for; an unreadable configuration is never written.
    #[test]
    fn the_nic_configuration_is_never_lowered() {
        for (rx, tx) in [(false, false), (true, false), (false, true), (true, true)] {
            assert_eq!(decide(None, rx, tx), Plan::Unreadable);
            for flags in [0, 1] {
                for tx_type in 0..=3 {
                    for rx_filter in 0..=15 {
                        let c = Current { flags, tx_type, rx_filter };
                        let after = match decide(Some(c), rx, tx) {
                            Plan::Unreadable => unreachable!("a readable configuration"),
                            Plan::Keep => c,
                            Plan::Write(w) => {
                                assert_ne!(w, c);
                                w
                            }
                        };
                        assert_eq!(after.flags, flags);
                        let rx_up = rx && rx_filter == FILTER_NONE;
                        assert_eq!(after.rx_filter, if rx_up { FILTER_ALL } else { rx_filter });
                        let tx_up = tx && tx_type == TX_OFF;
                        assert_eq!(after.tx_type, if tx_up { TX_ON } else { tx_type });
                        assert_eq!(effective(after, rx, tx), (rx, tx), "everything asked for is stamped");
                    }
                }
            }
        }
    }
}
