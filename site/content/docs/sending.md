+++
title = "Sending frames"
description = "Send raw Ethernet frames with rawether: frame layout and padding, batched transmission with sendmmsg, traffic priority and VLAN PCP with SO_PRIORITY, and bypassing the queueing discipline on Linux."
weight = 60

[extra]
group = "Guides"
+++

## Building a frame

`FrameBuilder` describes the header once and writes frames into a buffer you keep:

```rust
use rawether::{EtherType, FrameBuilder, MacAddr, TagKind, VlanTag};

let dst: MacAddr = "01:1b:19:00:00:00".parse()?;
let tag = VlanTag::new(TagKind::Customer, 4, false, 100)?; // PCP 4, VLAN 100
let header = FrameBuilder::new(dst, sock.mac_address(), EtherType::LOCAL_EXPERIMENTAL_1).vlan(tag);

let mut buf = Vec::with_capacity(1518);
for payload in payloads {
    header.write(&mut buf, payload); // replaces buf's contents; no allocation after the first
    sock.send(&buf)?;
}
```

- **Padding.** Frames are zero-padded to 60 octets (64 with the frame check sequence the NIC appends), with or without tags. Bytes from an earlier, longer frame in the same buffer never leak into the padding.
- **Tags.** `.vlan(tag)` sets one tag; `.vlans(outer, inner)` sets two, usually an 802.1ad service tag and then an 802.1Q tag. `VlanTag::new` refuses a priority above 7 or a VLAN id above 4095 instead of truncating it; `VlanTag::from_tci` takes the raw 16-bit value.
- **No allocator at all.** `write_into(&mut [u8], payload)` writes into any slice, such as a stack array, and returns the frame's length. If the slice is too small, it returns `InvalidInput` naming the size needed.

```rust
let mut stack = [0u8; 1518];
let len = header.write_into(&mut stack, b"hello")?;
sock.send(&stack[..len])?;
```

## Answering a frame

`Frame::reply` turns a received frame into the header of the answer: back to its source, from your address, with the same VLAN tags and EtherType.

```rust
let me = sock.mac_address();
let mut buf = Vec::with_capacity(1518);
if let Some(p) = sock.recv(None)? {
    if let Some(reply) = p.frame().and_then(|f| f.reply(me)) {
        reply.write(&mut buf, b"pong");
    }
}
sock.send(&buf)?;
```

`reply` returns `None` when the frame's source is a multicast or broadcast address. No real sender uses one, and answering it would send your reply to the whole group, which makes it easy to trigger a reply storm.

## Sending

```rust
sock.send(&frame)?;
```

`frame` is the whole frame as it goes on the wire: destination MAC, source MAC, optional VLAN tags, EtherType, payload. Do not include a frame check sequence; the NIC appends it.

- **At least 14 octets.** A shorter frame is refused with `InvalidInput` before any system call.
- **Padding.** Neither rawether's `send` nor the kernel pads; most NICs pad in hardware, but not all. `FrameBuilder` pads for you.
- **The source address is yours to write.** `sock.mac_address()` is the interface's own address. rawether does not overwrite it, so frames may also claim another source (as some redundancy protocols need).
- **At most the interface MTU plus the header**, or the kernel refuses the frame.

`send` takes `&self`. A received `Packet` borrows the socket mutably, though, so build the reply first and send it after you are done with the packet, as the `echo` example does. A `FrameBuilder` holds no borrow, so this falls out naturally.

## Batches

```rust
let frames: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
let sent = sock.send_batch(&frames)?;
```

On Linux, `send_batch` uses `sendmmsg`, up to 64 frames per system call. On macOS and FreeBSD it writes the frames one by one. It returns how many frames were sent, which is all of them unless an error interrupted the batch. An error on the very first frame is returned as an error; one later in the batch shortens the count.

The `echo` example answers frames in batches and allocates nothing in its loop: it reuses a fixed set of reply buffers.

## Priority and VLAN PCP

```rust
let sock = rawether::Config::new("eth0").priority(6).open()?;
```

`SO_PRIORITY` (Linux) puts every frame from the socket in a traffic class. Queueing disciplines such as `mqprio` and `taprio` map priorities to hardware queues. If the kernel adds the VLAN tag (on a VLAN sub-interface), the interface's egress QoS map turns the priority into the tag's PCP bits:

```sh
ip link add link eth0 name eth0.100 type vlan id 100 egress-qos-map 6:6
```

If you write the VLAN tag into the frame yourself, you set the PCP bits directly in the TCI.

## Bypassing the qdisc

```rust
let sock = rawether::Config::new("eth0").qdisc_bypass(true).open()?;
```

`PACKET_QDISC_BYPASS` (Linux) hands frames straight to the driver, skipping the queueing discipline. That is a little faster, but traffic shaping, priorities mapped by a qdisc, and [launch times](@/docs/launch-time.md) no longer apply, because those all live in the qdisc.
