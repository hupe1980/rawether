//! Announce this host with one LLDP frame and print the system names of LLDP neighbours.
//!
//! ```sh
//! cargo run --example lldp -- eth0
//! ```
//!
//! LLDP (IEEE 802.1AB) is sent to the nearest-bridge group 01:80:c2:00:00:0e with EtherType
//! 0x88cc; its payload is a list of type-length-value records. rawether handles the Ethernet
//! header; the records are this example's business.

use std::time::{Duration, Instant};

use rawether::{Config, EtherType, FrameBuilder, MacAddr};

const NEAREST_BRIDGE: MacAddr = MacAddr([0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]);

fn tlv(out: &mut Vec<u8>, kind: u8, value: &[u8]) {
    let header = (u16::from(kind) << 9) | (value.len() as u16 & 0x1ff);
    out.extend_from_slice(&header.to_be_bytes());
    out.extend_from_slice(value);
}

/// The LLDP records announcing this host.
fn announcement(chassis: MacAddr, port: &str, name: &str) -> Vec<u8> {
    let mut d = Vec::new();
    tlv(&mut d, 1, &[[4u8].as_slice(), &chassis.0].concat()); // chassis id: MAC address
    tlv(&mut d, 2, &[[5u8].as_slice(), port.as_bytes()].concat()); // port id: interface name
    tlv(&mut d, 3, &120u16.to_be_bytes()); // time to live, seconds
    tlv(&mut d, 5, name.as_bytes()); // system name
    tlv(&mut d, 0, &[]); // end of LLDPDU
    d
}

/// The system name in LLDP records, if they have one.
fn system_name(mut rest: &[u8]) -> Option<String> {
    while rest.len() >= 2 {
        let header = u16::from_be_bytes([rest[0], rest[1]]);
        let (kind, len) = ((header >> 9) as u8, usize::from(header & 0x1ff));
        let value = rest.get(2..2 + len)?;
        match kind {
            0 => return None,
            5 => return Some(String::from_utf8_lossy(value).into_owned()),
            _ => rest = &rest[2 + len..],
        }
    }
    None
}

fn main() -> std::io::Result<()> {
    let Some(iface) = std::env::args().nth(1) else {
        eprintln!("usage: lldp <interface>");
        std::process::exit(2);
    };
    let mut sock = Config::new(&iface).ethertypes([EtherType::LLDP]).join(NEAREST_BRIDGE).open()?;
    rawether::drop_capabilities()?;
    let me = std::env::var("HOSTNAME").unwrap_or_else(|_| String::from("rawether"));
    let mut frame = Vec::with_capacity(1518);
    FrameBuilder::new(NEAREST_BRIDGE, sock.mac_address(), EtherType::LLDP)
        .write(&mut frame, &announcement(sock.mac_address(), &iface, &me));
    sock.send(&frame)?;
    println!("announced {me} on {iface}; listening for 60 s");
    let end = Instant::now() + Duration::from_secs(60);
    while Instant::now() < end {
        let Some(p) = sock.recv(Some(Duration::from_secs(1)))? else { continue };
        let Some(f) = p.frame() else { continue };
        let name = system_name(f.payload()).unwrap_or_else(|| String::from("(no system name)"));
        println!("{}: {name}", f.source());
    }
    Ok(())
}
