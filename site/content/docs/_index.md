+++
title = "rawether documentation"
description = "How to send and receive raw Ethernet frames from Rust with rawether: filters, the receive ring, timestamps, batched and launch-time transmission, event loops, Linux and BSD backends, privileges and the threat model."
sort_by = "weight"
template = "docs.html"
page_template = "doc.html"

[extra]
seo_title = "Documentation · rawether"
+++

rawether is a Rust library for **raw layer-2 Ethernet I/O**. You open a `Socket` on a named interface and choose which frames reach it. You then receive whole frames, starting at the destination MAC address, and send frames you built yourself. rawether uses the kernel's own mechanisms for this: AF_PACKET on Linux, BPF devices on macOS and FreeBSD.

> [!NOTE]
> rawether is pre-1.0: the API may change between minor versions. The [API reference on docs.rs](https://docs.rs/rawether) is the authority on signatures.

## How it works

1. **Configure.** `Config::new("eth0")` describes the socket: a filter, multicast groups, the receive path, timestamping, send options.
2. **Open.** `Config::open` needs `CAP_NET_RAW` on Linux and `/dev/bpf*` access on macOS and FreeBSD. The filter is in place before the socket is bound, so nothing unwanted is ever queued.
3. **Drop the privilege.** `drop_capabilities()` sheds `CAP_NET_RAW`. The open socket keeps working.
4. **Receive and send.** `recv` hands out a `Packet` borrowed from the ring or buffer; `send`, `send_batch` and `send_at` take frames as byte slices.

## Core concepts

- **Kernel filtering.** An [EtherType set or a classic-BPF program](@/docs/filtering.md) decides in the kernel which frames reach the socket.
- **Receive paths.** On Linux, a zero-copy [TPACKET_V3 ring](@/docs/receiving.md), or one `recvmsg` per frame. On the BSDs, a BPF read buffer. `Socket::rx_path` says which one you have.
- **Borrowed packets.** A `Packet` borrows the socket until the next receive; the compiler stops you from keeping it longer. See [How it works](@/docs/how-it-works.md).
- **Labelled timestamps.** Each frame says whether the [NIC, the kernel or rawether](@/docs/timestamps.md) stamped it.
- **Transmission.** [Single, batched and prioritised sends](@/docs/sending.md), and [launch times](@/docs/launch-time.md) for TSN schedules.
- **Event loops.** A socket is a file descriptor: use it [with poll, mio or tokio](@/docs/event-loops.md).
- **Security.** The [threat model](@/docs/threat-model.md) lists every class rawether defends against and the [test](@/docs/testing.md) that guards it.
