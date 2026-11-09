+++
title = "Timestamps"
description = "Receive timestamps in rawether: software timestamps from the kernel, hardware timestamps from the NIC's PTP clock on Linux, and the label on every frame that says which clock stamped it."
weight = 50

[extra]
group = "Guides"
+++

Protocols such as PTP, or latency measurements, care about when a frame arrived. rawether attaches a `Timestamp` to every frame and says whose clock produced it, because the clocks differ.

## Choosing

```rust
use rawether::{Config, Timestamping};

let sock = Config::new("eth0").timestamping(Timestamping::Hardware).open()?;
```

| `Timestamping` | What you get |
|---|---|
| `Off` | No timestamps |
| `Software` (default) | The kernel's, on `CLOCK_REALTIME` |
| `Hardware` | The NIC's where it has them, otherwise the kernel's |

## Reading

```rust
if let Some(t) = p.timestamp() {
    println!("{}.{:09} by {:?}", t.secs, t.nanos, t.source);
    let ns: i128 = t.as_nanos();
}
```

`TimestampSource` tells you which clock it is:

| Source | Clock | When it is used |
|---|---|---|
| `Hardware` | The NIC's clock (its PTP hardware clock, `/dev/ptp*`) | `Timestamping::Hardware` on a NIC that supports it |
| `Software` | `CLOCK_REALTIME`, read by the kernel as the frame reached the socket layer | The default, and the fallback for `Hardware` |
| `User` | `CLOCK_REALTIME`, read by rawether when it read the frame | Only for frames the kernel did not stamp |

Do not compare stamps from different sources directly. A hardware stamp is on the NIC's clock, which is not the system clock unless something like `phc2sys` keeps them in step.

### Why `User` exists

Linux turns on receive timestamping lazily, so the first frames after a socket opens can arrive without a stamp. On the plain path, rawether fills the gap with its own reading and marks it `User`, so you always get a timestamp but are never misled about its precision. It is later than a kernel stamp by however long the frame waited in the socket.

## Hardware timestamps on Linux

`Timestamping::Hardware` makes rawether configure the NIC (`SIOCSHWTSTAMP`, all received frames) when the socket opens, and ask the kernel for raw hardware stamps. Two things decide whether you get them:

- **The NIC and driver must support it.** `ethtool -T eth0` lists `hardware-receive` and `hardware-raw-clock` if they do.
- **The process needs `CAP_NET_ADMIN`** to configure the NIC.

If either is missing, the socket still opens and frames get `Software` stamps. Check `t.source` on the first frames if you need hardware precision.

> [!WARNING]
> The NIC's timestamping configuration is device-wide, not per socket. rawether sets it to "stamp every received frame, no transmit stamps", and does not restore it on close. On a host where `ptp4l` uses the same NIC, that switches off the transmit stamps `ptp4l` needs. Use `Timestamping::Hardware` only on NICs that no other time-sync program is using.

## macOS and FreeBSD

BPF stamps each frame in the kernel. rawether reports these as `Software` stamps on the system clock. The BPF header carries microseconds, so `nanos` is a multiple of 1000. Hardware timestamps are not available.
