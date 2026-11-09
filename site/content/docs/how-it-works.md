+++
title = "How it works"
description = "What rawether does when it opens a raw Ethernet socket and receives a frame: the open sequence that keeps unfiltered frames out, the TPACKET_V3 ring shared with the kernel, borrowed packets and the allocation-free steady state."
weight = 20

[extra]
group = "Start"
+++

Background for using rawether well. You do not need it to get started, but it explains the guarantees the other pages rely on.

## Layer 2 in one paragraph

An Ethernet frame is a destination MAC address (6 octets), a source MAC address (6), an EtherType (2) and a payload. Optional VLAN tags (4 octets each, TPID `0x8100` for 802.1Q or `0x88a8` for 802.1ad) sit before the EtherType. The NIC adds the frame check sequence on transmit and removes it on receive. Normal sockets work above this, at IP or above. A raw socket works on the frames themselves, and that is what protocols such as PTP, LLDP or PROFINET need, because they have no IP header.

## Opening a socket

On Linux, `Socket::open` follows an order chosen so that no frame slips past the filter:

1. **Create the socket with protocol 0.** An AF_PACKET socket with protocol 0 receives nothing until it is bound.
2. **Attach the filter.** The EtherType set is compiled to classic BPF and attached with `SO_ATTACH_FILTER`.
3. **Set up the ring.** `PACKET_VERSION` TPACKET_V3, head-room for VLAN tags, `PACKET_RX_RING`, then `mmap`. If the kernel refuses, `RxMode::Auto` uses the plain path; an explicit `RxMode::Ring` fails.
4. **Bind to the interface.** Only now do frames start arriving, all of them already filtered.
5. **Join groups and modes.** Multicast membership, all-multicast and promiscuous mode, if requested.
6. **Socket options.** Timestamping, `SO_PRIORITY`, qdisc bypass, `SO_TXTIME`, non-blocking mode.

Every descriptor is created close-on-exec, so a program you `exec` never inherits the socket.

On macOS and FreeBSD, the sequence opens a free `/dev/bpf*` device, sets the buffer size, attaches it to the interface, and installs the filter with `BIOCSETF`, which also discards anything buffered before it.

## The receive ring

A TPACKET_V3 ring is a region of memory shared between the kernel and your process, split into **blocks**. The kernel fills a block with frames, packed one after another, then hands it over by setting a status word. rawether reads the block in place and hands it back when every frame in it has been read.

```text
 block 0          block 1          block 2         …  block 63
┌──────────────┐┌──────────────┐┌──────────────┐    ┌──────────────┐
│ frame frame  ││ frame        ││  (kernel is  │    │  (free)      │
│ frame …      ││              ││   filling)   │    │              │
└──────────────┘└──────────────┘└──────────────┘    └──────────────┘
  user owns       user owns       kernel owns         kernel owns
```

A block that is not full is handed over after `retire_ms` (1 ms by default), so light traffic still arrives promptly. Every offset and length the kernel writes is checked against the block before a slice is formed. If a block's metadata does not hold together, rawether skips the block rather than trusting it.

## Borrowed packets

`recv` returns `Packet<'_>`, which borrows the socket mutably. The next `recv` is what returns the block to the kernel, and it cannot be called while a packet is alive:

```rust
let first = sock.recv(None)?;
let second = sock.recv(None)?; // error[E0499]: `sock` is still borrowed by `first`
```

So a packet can never point into memory the kernel is writing again. If you need a frame beyond the next receive, copy it: `p.data().to_vec()`.

## No allocation in the steady state

The ring, the plain-path buffer and the control-message buffers are allocated when the socket opens. After that, receiving, filtering, VLAN re-insertion and sending allocate nothing. The test suite checks this with a counting global allocator on both receive paths.

## Errors

Every fallible call returns `std::io::Result`. The error kinds you can act on are used consistently:

| Kind | Meaning |
|---|---|
| `NotFound` | No interface by that name, or no free BPF device |
| `PermissionDenied` | Missing `CAP_NET_RAW` or `/dev/bpf*` access; the message says which |
| `InvalidInput` | A configuration or frame that cannot work: a bad name, a unicast "group", an impossible ring geometry, a frame shorter than 14 octets, `send_at` without `tx_time` |
| `NetworkDown` and others | The link went down or the interface disappeared while you waited; the message names the interface |
| `Unsupported` | A feature the platform lacks, such as launch time on macOS, or any socket on Windows |

A configuration is checked before any system call, so a mistake costs nothing and leaves nothing half-open.
