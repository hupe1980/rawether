+++
title = "rawether"
description = "rawether sends and receives raw Ethernet frames from Rust: AF_PACKET with a zero-copy TPACKET_V3 ring, in-kernel BPF filters, hardware timestamps and SO_TXTIME launch times on Linux; BPF devices on macOS and FreeBSD. For PTP, LLDP, TSN, PROFINET and other protocols below IP."
template = "index.html"
+++

```rust
use std::time::Duration;

// LLDP and PTP frames, VLAN-tagged or not.
let mut sock = rawether::Config::new("eth0")
    .ethertypes(&[0x88cc, 0x88f7])
    .open()?;

// CAP_NET_RAW is no longer needed.
rawether::drop_capabilities()?;

// Receive until a second passes without a frame.
while let Some(p) = sock.recv(Some(Duration::from_secs(1)))? {
    let Some(f) = p.frame() else { continue };
    let tags = f.vlan_tags().len();
    println!("{} sent {:04x}, {tags} tag(s), at {:?}",
        f.source(), f.ethertype(), p.timestamp());
}
```

The filter runs in the kernel; `p` borrows the ring until the next `recv`, and `p.frame()` reads the header without ever panicking.
