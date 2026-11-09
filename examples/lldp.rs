//! Announce this host with one LLDP frame and print the system names of LLDP neighbours.
//!
//! ```sh
//! cargo run --example lldp -- eth0
//! ```
//!
//! LLDP (IEEE 802.1AB) is sent to the nearest-bridge group 01:80:c2:00:00:0e with EtherType
//! 0x88cc; a frame is a list of type-length-value records.

use std::time::{Duration, Instant};

use rawether::{Config, MacAddr};

const LLDP: u16 = 0x88cc;
const NEAREST_BRIDGE: MacAddr = MacAddr([0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]);

fn tlv(out: &mut Vec<u8>, kind: u8, value: &[u8]) {
    let header = (u16::from(kind) << 9) | (value.len() as u16 & 0x1ff);
    out.extend_from_slice(&header.to_be_bytes());
    out.extend_from_slice(value);
}

fn announcement(src: MacAddr, port: &str, name: &str) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&NEAREST_BRIDGE.0);
    f.extend_from_slice(&src.0);
    f.extend_from_slice(&LLDP.to_be_bytes());
    tlv(&mut f, 1, &[[4u8].as_slice(), &src.0].concat()); // chassis id: MAC address
    tlv(&mut f, 2, &[[5u8].as_slice(), port.as_bytes()].concat()); // port id: interface name
    tlv(&mut f, 3, &120u16.to_be_bytes()); // time to live, seconds
    tlv(&mut f, 5, name.as_bytes()); // system name
    tlv(&mut f, 0, &[]); // end of LLDPDU
    f.resize(f.len().max(60), 0);
    f
}

/// The system name in an LLDP frame, if it has one.
fn system_name(frame: &[u8]) -> Option<String> {
    let mut rest = frame.get(14..)?;
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
    let mut sock = Config::new(&iface).ethertypes(&[LLDP]).join(NEAREST_BRIDGE).open()?;
    rawether::drop_capabilities()?;
    let me = std::env::var("HOSTNAME").unwrap_or_else(|_| String::from("rawether"));
    sock.send(&announcement(sock.mac_address(), &iface, &me))?;
    println!("announced {me} on {iface}; listening for 60 s");
    let end = Instant::now() + Duration::from_secs(60);
    while Instant::now() < end {
        if let Some(p) = sock.recv(Some(Duration::from_secs(1)))? {
            let d = p.data();
            let from = MacAddr([d[6], d[7], d[8], d[9], d[10], d[11]]);
            println!("{from}: {}", system_name(d).unwrap_or_else(|| String::from("(no system name)")));
        }
    }
    Ok(())
}
