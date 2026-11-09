+++
title = "rawether"
description = "rawether sends and receives raw Ethernet frames from Rust: AF_PACKET with a zero-copy TPACKET_V3 ring, in-kernel BPF filters, hardware timestamps and SO_TXTIME launch times on Linux; BPF devices on macOS and FreeBSD. For PTP, LLDP, TSN, PROFINET and other protocols below IP."
template = "index.html"
+++

```rust
use std::time::Duration;
use rawether::EtherType;

// LLDP and PTP frames, VLAN-tagged or not.

let mut sock = rawether::Config::new("eth0")
    .ethertypes([EtherType::LLDP, EtherType::PTP])
    .open()?;

// CAP_NET_RAW is no longer needed.
rawether::drop_capabilities()?;

// Receive until a second passes without a frame.
while let Some(p) = sock.recv(Some(Duration::from_secs(1)))? {
    let Some(f) = p.frame() else { continue };
    let tags = f.vlan_tags().len();
    println!("{} sent {}, {tags} tag(s), at {:?}",
        f.source(), f.ethertype(), p.timestamp());
}
```

The filter runs in the kernel; `p` borrows the ring until the next `recv`, and `p.frame()` reads the header without ever panicking.
