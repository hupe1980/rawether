+++
title = "Receiving frames"
description = "Receive raw Ethernet frames with rawether: blocking, timed and non-blocking receive, the zero-copy TPACKET_V3 ring and how to size it, the plain recvmsg path, truncated frames, VLAN tag restoration and counting drops."
weight = 40

[extra]
group = "Guides"
+++

## Receive calls

| Call | Waits |
|---|---|
| `sock.recv(None)` | Until a frame arrives |
| `sock.recv(Some(timeout))` | At most `timeout`; `Ok(None)` if nothing arrived |
| `sock.try_recv()` | Not at all; `Ok(None)` if nothing is waiting |

A socket opened with `.nonblocking(true)`, or switched with `set_nonblocking(true)`, never waits, whatever timeout you pass. That is the mode for [event loops](@/docs/event-loops.md).

## What a packet tells you

| Method | Returns |
|---|---|
| `data()` | The captured octets, from the destination MAC address, without the FCS |
| `original_len()` | The frame's length on the wire |
| `is_truncated()` | Whether `data()` is shorter than the frame |
| `timestamp()` | When it was received, and by whose clock (see [Timestamps](@/docs/timestamps.md)) |
| `vlan_restored()` | Whether a VLAN tag the driver stripped was put back |

A `Packet` borrows the socket until the next receive. Copy what you need to keep (`p.data().to_vec()`), or process the frame in place, which is what makes the loop allocation-free.

## Reading the header

`p.frame()` returns the frame's Ethernet header as named fields, or `None` when fewer octets were captured than the header announces:

```rust
if let Some(f) = p.frame() {
    let src = f.source();          // MacAddr
    let dst = f.destination();
    for tag in f.vlan_tags() {     // outer first: none, one or two
        println!("vlan {} pcp {} dei {}", tag.vid(), tag.pcp(), tag.dei());
    }
    match f.ethertype() {
        0x88f7 => handle_ptp(f.payload()),
        other => eprintln!("{src} → {dst}: type {other:04x}"),
    }
}
```

`Frame::new(bytes)` gives the same view over any byte slice, which keeps your protocol code testable without a socket. Some details:

- **Tags.** The view steps over up to two 802.1Q (0x8100) or 802.1ad (0x88A8) tags. Those are exactly the tags the [EtherType filter](@/docs/filtering.md) steps over, so a frame the filter let through for type `x` has `ethertype() == x`.
- **Payload.** It is everything after the EtherType, *including padding*: Ethernet does not say where your protocol's data ends, so short frames carry zeros up to 60 octets. For a truncated packet, it is only the captured part; check `p.is_truncated()`.
- **802.3 lengths.** A value below 0x0600 in the EtherType position is a length (802.3/LLC framing). It is reported unchanged.

## Receive paths

`Socket::rx_path()` tells you how frames reach your process:

| `RxPath` | Platform | How |
|---|---|---|
| `Ring` | Linux | A TPACKET_V3 ring shared with the kernel. Frames are read in place, many per wake-up. The default |
| `Plain` | Linux | One `recvmsg` per frame. Used when you ask for it, or when `Auto` finds the kernel refusing the ring |
| `Bpf` | macOS, FreeBSD | A BPF device's read buffer. Each `read` returns every frame waiting |

Choose with `Config::rx_mode`:

```rust
use rawether::{Config, RingConfig, RxMode};

// The default: the ring where possible.
let a = Config::new("eth0").rx_mode(RxMode::Auto);
// One system call per frame: the lowest latency for a lone frame, the most system calls.
let b = Config::new("eth0").rx_mode(RxMode::Plain);
// A bigger ring for bursts: 256 blocks of 64 KiB (16 MiB).
let c = Config::new("eth0").rx_mode(RxMode::Ring(RingConfig { block_count: 256, ..RingConfig::default() }));
```

With `Auto`, a ring the kernel refuses (for example under a memory limit) becomes the plain path; check `rx_path()` if it matters to you. An explicit `RxMode::Ring` the kernel refuses fails `open` with the reason instead. A geometry that cannot work, or whose size overflows, is refused before any system call.

At low frame rates the ring adds up to `retire_ms` (1 ms by default) before a lone frame is handed over. If your budget is tighter than that, use `RxMode::Plain`, or lower `retire_ms`.

## Sizing the ring

The defaults are 64 blocks of 64 KiB (4 MiB), with a 1 ms block timeout:

- **`block_count` is how many bursts the ring absorbs.** At low rates the kernel hands over a block after `retire_ms`, often holding a single frame. So the block count, not the byte size, is how many sparse frames wait while your code is busy.
- **`block_size` sets how many frames one wake-up delivers** at high rates. A 64 KiB block holds about a thousand minimum-size frames. It must be a power of two and a multiple of the page size.
- **`retire_ms` bounds the latency the ring adds** when traffic is light.
- **`frame_size` does not cap a frame.** TPACKET_V3 packs frames by their own length. A frame is cut short only by a filter's snap length, or if it is larger than a block.

The ring is locked into memory where the limit (`RLIMIT_MEMLOCK`) allows, and mapped normally otherwise.

On the plain and BPF paths, `Config::buffer_size` sets the receive buffer (1 MiB by default; at least 4 KiB).

## VLAN tags

Many Linux drivers strip the outer 802.1Q or 802.1ad tag and pass it to the kernel as metadata (VLAN offload). Without help, your program would see a frame that never existed on the wire. rawether puts the tag back by default. On the ring it uses 4 octets of head-room reserved in front of each frame, so there is still no copy. `vlan_restored()` tells you when this happened, and `original_len()` includes the tag.

Kernels that do not report the tag's TPID (before Linux 4.x) put an 802.1ad outer tag back as 802.1Q. Turn restoration off with `.restore_vlan(false)` if you want the frame as the kernel delivered it. On macOS and FreeBSD, BPF delivers tags in place, so nothing needs restoring.

## When the link goes down

If the link goes down or the interface is removed while you wait, `recv` returns an error naming the interface (`ENETDOWN`). Once the link is up again, frames arrive on the same socket. A removed interface stays gone for that socket, even if one with the same name comes back, so open a new socket for it.

Timeouts never overflow: `recv(Some(Duration::MAX))` waits as long as `recv(None)`.

## Drops

When frames arrive faster than you read them, the ring or buffer fills and the kernel drops what does not fit. `stats()` reports it:

```rust
let s = sock.stats()?;
if s.dropped > 0 {
    eprintln!("{} of {} frames dropped", s.dropped, s.received + s.dropped);
}
```

The counters are totals since the socket opened, and mean the same on every platform. `received` counts frames that passed the filter and reached the socket (on macOS and FreeBSD, once rawether has read them from the device), and `dropped` counts those that passed the filter and found no room. To drop less, enlarge the ring (more blocks), read on a dedicated thread, or filter more tightly.

Frames lost before the socket, in the NIC's queues or the kernel's per-CPU backlog, are not in `stats()`. Look at `ethtool -S` and `/proc/net/softnet_stat` for those.
