+++
title = "Timestamps"
description = "Receive and transmit timestamps in rawether: the kernel's or the NIC's clock, labelled per frame, transmit timestamps matched to their frame by id, the PTP hardware clock behind an interface, and a NIC configuration that is never lowered."
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

A NIC's timestamping configuration is device-wide: `ptp4l` and other programs rely on it. So with `Timestamping::Hardware`, rawether reads it first and **never lowers it**:

| The NIC currently | rawether |
|---|---|
| Stamps what you asked for (received frames: all or PTP only; transmitted frames: on or a one-step mode), as `ptp4l` sets it | Leaves it alone and asks for its stamps. No `CAP_NET_ADMIN` needed |
| Stamps nothing in the direction you asked for | Widens only that: the receive filter from none to all, transmit stamping from off to on. Needs `CAP_NET_ADMIN` |
| Has no hardware stamping, or its configuration cannot be read | Writes nothing; frames get `Software` stamps |

`sock.timestamping()` tells you what the socket delivers, and each frame's `t.source` says what it got. With a PTP-only filter, PTP frames are stamped `Hardware` and the others `Software`. `ethtool -T eth0` lists what a NIC supports.

## Transmit timestamps

PTP, Sampled Values publishers and latency measurements need the time a frame *left*. Turn on transmit timestamps (Linux), note each frame's id, and read the timestamps back:

```rust
use std::time::Duration;
use rawether::{Config, Timestamping};

let mut sock = Config::new("eth0").tx_timestamping(Timestamping::Hardware).open()?;
let id = sock.next_tx_id();
sock.send(&sync_frame)?;
if let Some(t) = sock.tx_timestamp(Some(Duration::from_millis(10)))? {
    assert_eq!(t.id, id);
    println!("left at {} ns, {:?} clock", t.timestamp.as_nanos(), t.timestamp.source);
}
```

- **Ids.** Every frame sent gets the next id, singly or in a batch (consecutive ids), with or without a launch time. On Linux 6.13 and later rawether passes each id to the kernel (`SCM_TS_OPT_ID`), so ids stay exact even when a send fails. On older kernels the kernel numbers frames itself, and a send refused after numbering (a qdisc drop) shifts later ids by one. rawether detects which applies.
- **Order.** Timestamps may come back out of order: match them by `id`.
- **Clock.** `Hardware` is the NIC's clock where it stamps transmitted frames, otherwise you get `Software` (the kernel's, as the frame reaches the driver). `sock.tx_timestamping()` says which.
- **Read as you go.** The kernel holds only a few hundred unread reports (bounded by the socket's receive buffer) and drops the rest silently. rawether keeps up to 1 024 that it has read; beyond that it drops the oldest and counts them in `tx_errors().timestamps_lost`.
- **Launch times.** Timestamps and launch-time drop reports share the kernel's error queue; rawether separates them, so neither loses the other.

## Which clock

A hardware timestamp is only useful next to the clock that made it. `rawether::timestamp_info(interface)` (or `sock.timestamp_info()`) says what an interface stamps, and which PTP hardware clock (`/dev/ptpN`) its hardware stamps come from. Compare those with the clock that `ptp4l`/`phc2sys` disciplines. It needs no privilege:

```rust
let info = rawether::timestamp_info("eth0")?;
println!("hardware rx {} tx {}, clock {:?}", info.hardware_rx, info.hardware_tx, info.phc_path());
```

## macOS and FreeBSD

BPF stamps each received frame in the kernel. rawether reports these as `Software` stamps on the system clock. The BPF header carries microseconds, so `nanos` is a multiple of 1000. There are no hardware or transmit timestamps: asking for transmit timestamps makes `open` fail with `Unsupported`, and `timestamp_info` reports software receive stamps and no hardware clock.
