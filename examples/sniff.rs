//! Print every frame on an interface — or only some EtherTypes — with its timestamp.
//!
//! ```sh
//! cargo run --example sniff -- eth0            # everything
//! cargo run --example sniff -- eth0 88cc 88f7  # LLDP and PTP only
//! ```
//!
//! Needs `CAP_NET_RAW` on Linux (`sudo setcap cap_net_raw+ep target/debug/examples/sniff`) or
//! access to `/dev/bpf*` on macOS. The capability is dropped once the socket is open.

use std::time::Duration;

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(iface) = args.next() else {
        eprintln!("usage: sniff <interface> [ethertype-hex]…");
        std::process::exit(2);
    };
    let types: Vec<u16> =
        args.filter_map(|a| u16::from_str_radix(a.trim_start_matches("0x"), 16).ok()).collect();
    let mut cfg = rawether::Config::new(iface);
    if !types.is_empty() {
        cfg = cfg.ethertypes(&types);
    }
    let mut sock = cfg.open()?;
    rawether::drop_capabilities()?;
    eprintln!("{} ({}), receive path {:?}", sock.interface(), sock.mac_address(), sock.rx_path());
    loop {
        let Some(p) = sock.recv(Some(Duration::from_secs(1)))? else { continue };
        // A frame shorter than its header has no view: skip it rather than index into it.
        let Some(f) = p.frame() else { continue };
        let when =
            p.timestamp().map_or_else(String::new, |t| format!("{}.{:09} {:?}", t.secs, t.nanos, t.source));
        print!("{when}  {} → {}", f.source(), f.destination());
        for tag in f.vlan_tags() {
            print!("  vlan {}", tag.vid());
        }
        println!(
            "  type {:04x}  {} octets{}",
            f.ethertype(),
            p.original_len(),
            if p.is_truncated() { " (truncated)" } else { "" },
        );
    }
}
