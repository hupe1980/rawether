//! Reflect every frame of one EtherType back to its sender — a layer-2 ping responder.
//!
//! ```sh
//! cargo run --example echo -- eth0 88b5
//! ```
//!
//! Frames are answered in batches of up to 32, with one system call per batch on Linux. A frame
//! from a group (multicast or broadcast) source address is never answered.

use std::time::Duration;

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let (Some(iface), Some(ty)) = (args.next(), args.next()) else {
        eprintln!("usage: echo <interface> <ethertype-hex>");
        std::process::exit(2);
    };
    let ethertype = u16::from_str_radix(ty.trim_start_matches("0x"), 16)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let mut sock = rawether::Config::new(iface).ethertypes(&[ethertype]).open()?;
    rawether::drop_capabilities()?;
    let me = sock.mac_address();
    // Reused for every batch: the steady state allocates nothing.
    let mut replies: Vec<Vec<u8>> = (0..32).map(|_| Vec::with_capacity(1518)).collect();
    loop {
        let mut n = 0;
        let mut wait = Some(Duration::from_secs(1));
        while n < replies.len() {
            let Some(p) = sock.recv(wait)? else { break };
            wait = Some(Duration::ZERO); // the rest of the batch: only what is already waiting
            let Some(f) = p.frame() else { continue };
            let Some(reply) = f.reply(me) else { continue }; // never answer a group address
            reply.write(&mut replies[n], f.payload());
            n += 1;
        }
        if n > 0 {
            let frames: [&[u8]; 32] = std::array::from_fn(|k| replies[k].as_slice());
            sock.send_batch(&frames[..n])?;
        }
    }
}
