//! Send frames and print when each one left — the transmit timestamps PTP and Sampled Values
//! need.
//!
//! ```sh
//! cargo run --example txstamp -- eth0 10
//! ```
//!
//! Uses the NIC's clock where it stamps transmitted frames, the kernel's otherwise. Needs
//! `CAP_NET_RAW` (and `CAP_NET_ADMIN` only to switch on a NIC that stamps nothing yet).

use std::time::Duration;

use rawether::{Config, EtherType, FrameBuilder, MacAddr, Timestamping};

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(iface) = args.next() else {
        eprintln!("usage: txstamp <interface> [count]");
        std::process::exit(2);
    };
    let count: u32 = args.next().and_then(|n| n.parse().ok()).unwrap_or(10);
    let info = rawether::timestamp_info(&iface)?;
    println!("{iface}: {info:?}, clock {:?}", info.phc_path());

    let mut sock = Config::new(&iface)
        .ethertypes([EtherType::LOCAL_EXPERIMENTAL_1])
        .tx_timestamping(Timestamping::Hardware)
        .open()?;
    rawether::drop_capabilities()?;
    println!("transmit timestamps: {:?}", sock.tx_timestamping());

    let mut frame = Vec::with_capacity(64);
    let header = FrameBuilder::new(MacAddr::BROADCAST, sock.mac_address(), EtherType::LOCAL_EXPERIMENTAL_1);
    for seq in 0..count {
        header.write(&mut frame, &seq.to_be_bytes());
        let id = sock.next_tx_id();
        sock.send(&frame)?;
        match sock.tx_timestamp(Some(Duration::from_millis(100)))? {
            Some(t) => println!(
                "frame {id}: left at {} ns ({:?}), as id {}",
                t.timestamp.as_nanos(),
                t.timestamp.source,
                t.id
            ),
            None => println!("frame {id}: no timestamp within 100 ms"),
        }
    }
    let lost = sock.tx_errors()?.timestamps_lost;
    if lost > 0 {
        println!("{lost} timestamps lost");
    }
    Ok(())
}
