//! EtherTypes: the 16-bit field that says what follows the Ethernet header.
//!
//! [`EtherType`] holds any value; the well-known ones have names, each checked against the
//! IEEE registry or the Linux header that mirrors it. Nothing after the EtherType is parsed.
//!
//! ```
//! use rawether::EtherType;
//!
//! assert_eq!(EtherType::PTP.to_string(), "PTP (0x88f7)");
//! assert_eq!(EtherType(0x88b5).to_string(), "LOCAL_EXPERIMENTAL_1 (0x88b5)");
//! assert_eq!(EtherType(0x1234).to_string(), "0x1234");
//! assert!(EtherType(0x0050).is_length()); // an IEEE 802.3 length, not a type
//! ```

#![forbid(unsafe_code)]

use core::fmt;

/// An EtherType. Any 16-bit value works; the constants name the well-known ones.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct EtherType(pub u16);

macro_rules! names {
    ($($(#[$doc:meta])* $name:ident = $value:literal;)*) => {
        impl EtherType {
            $($(#[$doc])* pub const $name: EtherType = EtherType($value);)*

            /// The constant's name, if this value has one.
            pub const fn name(self) -> Option<&'static str> {
                match self.0 {
                    $($value => Some(stringify!($name)),)*
                    _ => None,
                }
            }
        }

        #[cfg(test)]
        const NAMED: &[(EtherType, &str)] = &[$((EtherType::$name, stringify!($name)),)*];
    };
}

names! {
    /// IPv4 (`ETH_P_IP`).
    IPV4 = 0x0800;
    /// ARP (`ETH_P_ARP`).
    ARP = 0x0806;
    /// IEEE 1722 Audio Video Transport Protocol, TSN streams (`ETH_P_TSN`).
    AVTP = 0x22F0;
    /// An IEEE 802.1Q customer VLAN tag (`ETH_P_8021Q`); see [`TagKind`](crate::TagKind).
    VLAN = 0x8100;
    /// IPv6 (`ETH_P_IPV6`).
    IPV6 = 0x86DD;
    /// IEEE 802.1X port access control (`ETH_P_PAE`).
    EAPOL = 0x888E;
    /// PROFINET real-time (`ETH_P_PROFINET`).
    PROFINET = 0x8892;
    /// EtherCAT (`ETH_P_ETHERCAT`).
    ETHERCAT = 0x88A4;
    /// An IEEE 802.1ad service VLAN tag, Q-in-Q (`ETH_P_8021AD`); see [`TagKind`](crate::TagKind).
    QINQ = 0x88A8;
    /// IEEE 802 Local Experimental EtherType 1 (`ETH_P_802_EX1`): for your own test traffic.
    LOCAL_EXPERIMENTAL_1 = 0x88B5;
    /// IEEE 802 Local Experimental EtherType 2.
    LOCAL_EXPERIMENTAL_2 = 0x88B6;
    /// IEC 61850-8-1 GOOSE.
    GOOSE = 0x88B8;
    /// IEC 61850-8-1 GSE management.
    GSE = 0x88B9;
    /// IEC 61850-9-2 Sampled Values.
    SAMPLED_VALUES = 0x88BA;
    /// IEEE 802.1AB Link Layer Discovery Protocol (`ETH_P_LLDP`).
    LLDP = 0x88CC;
    /// IEC 62439-2 Media Redundancy Protocol (`ETH_P_MRP`).
    MRP = 0x88E3;
    /// IEEE 802.1AE MACsec (`ETH_P_MACSEC`).
    MACSEC = 0x88E5;
    /// IEEE 1588 Precision Time Protocol over Ethernet (`ETH_P_1588`).
    PTP = 0x88F7;
    /// IEC 62439-3 PRP (and HSRv0) supervision (`ETH_P_PRP`).
    PRP = 0x88FB;
    /// IEEE 802.1ag Connectivity Fault Management (`ETH_P_CFM`).
    CFM = 0x8902;
    /// IEC 62439-3 HSR (`ETH_P_HSR`).
    HSR = 0x892F;
}

impl EtherType {
    /// The value.
    pub const fn value(self) -> u16 {
        self.0
    }

    /// Whether this is an IEEE 802.3 length (below 0x0600) rather than a type.
    pub const fn is_length(self) -> bool {
        self.0 < 0x0600
    }
}

impl From<u16> for EtherType {
    fn from(v: u16) -> EtherType {
        EtherType(v)
    }
}

impl From<&u16> for EtherType {
    fn from(v: &u16) -> EtherType {
        EtherType(*v)
    }
}

impl From<&EtherType> for EtherType {
    fn from(t: &EtherType) -> EtherType {
        *t
    }
}

impl From<EtherType> for u16 {
    fn from(t: EtherType) -> u16 {
        t.0
    }
}

impl fmt::Display for EtherType {
    /// `PTP (0x88f7)` for a named value, `0x1234` otherwise.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} ({:#06x})", self.0),
            None => write!(f, "{:#06x}", self.0),
        }
    }
}

impl fmt::LowerHex for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

impl fmt::Debug for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TagKind;

    /// Spec 015 SR-001: every name has its registry value (research.md), values are unique, and
    /// the VLAN tag identifiers agree with `TagKind`.
    #[test]
    fn every_name_has_its_registry_value() {
        let registry: &[(&str, u16)] = &[
            ("IPV4", 0x0800),
            ("ARP", 0x0806),
            ("AVTP", 0x22F0),
            ("VLAN", 0x8100),
            ("IPV6", 0x86DD),
            ("EAPOL", 0x888E),
            ("PROFINET", 0x8892),
            ("ETHERCAT", 0x88A4),
            ("QINQ", 0x88A8),
            ("LOCAL_EXPERIMENTAL_1", 0x88B5),
            ("LOCAL_EXPERIMENTAL_2", 0x88B6),
            ("GOOSE", 0x88B8),
            ("GSE", 0x88B9),
            ("SAMPLED_VALUES", 0x88BA),
            ("LLDP", 0x88CC),
            ("MRP", 0x88E3),
            ("MACSEC", 0x88E5),
            ("PTP", 0x88F7),
            ("PRP", 0x88FB),
            ("CFM", 0x8902),
            ("HSR", 0x892F),
        ];
        assert_eq!(NAMED.len(), registry.len());
        for ((t, name), (rname, rvalue)) in NAMED.iter().zip(registry) {
            assert_eq!((*name, t.0), (*rname, *rvalue));
            assert_eq!(t.name(), Some(*name));
            assert!(!t.is_length());
        }
        let mut values: Vec<u16> = NAMED.iter().map(|(t, _)| t.0).collect();
        values.sort_unstable();
        values.dedup();
        assert_eq!(values.len(), NAMED.len(), "no two names share a value");
        assert_eq!(EtherType::VLAN.0, TagKind::Customer.tpid());
        assert_eq!(EtherType::QINQ.0, TagKind::Service.tpid());
    }

    /// Spec 015 SR-002: lengths are lengths, printed as numbers.
    #[test]
    fn lengths_and_unnamed_values_print_as_numbers() {
        for v in [0x0000, 0x0050, 0x05ff] {
            assert!(EtherType(v).is_length());
            assert_eq!(EtherType(v).name(), None);
        }
        assert!(!EtherType(0x0600).is_length());
        assert_eq!(format!("{}", EtherType(0x0050)), "0x0050");
        assert_eq!(format!("{:?}", EtherType::PTP), "PTP (0x88f7)");
        assert_eq!(format!("{}", EtherType(0x9100)), "0x9100", "pre-standard Q-in-Q is not named");
        assert_eq!(u16::from(EtherType::from(0x88cc)), 0x88cc);
        assert_eq!(format!("{:04x} {:04X}", EtherType::LLDP, EtherType::LLDP), "88cc 88CC");
    }
}
