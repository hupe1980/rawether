+++
title = "macOS and FreeBSD"
description = "rawether on macOS and FreeBSD: BPF devices, access to /dev/bpf, in-kernel filters, multicast membership, software timestamps, and what differs from Linux."
weight = 100

[extra]
group = "Platforms"
+++

On macOS and FreeBSD, a rawether socket is a **BPF device** (`/dev/bpf` or `/dev/bpf0`, `/dev/bpf1`, …) attached to one interface. BPF is the facility `tcpdump` and Wireshark use. It reads and writes whole Ethernet frames and runs classic-BPF filters in the kernel, so the same `bpf::Program` works on both systems and on Linux.

> [!NOTE]
> CI sends and receives real frames through BPF on macOS 15 and macOS 26 (a `feth` pair) and on FreeBSD 14 (an `epair`): filtering, timestamps, own-frame suppression, counters, truncation and timeouts. On macOS the suite runs as an ordinary user with access to `/dev/bpf*`.

## Access

Opening needs read and write access to a BPF device. By default only root has it. Options:

- **macOS:** Wireshark's installer adds a `ChmodBPF` launch daemon that gives the `access_bpf` group access at boot. Add your user to that group.
- **FreeBSD:** a `devfs` rule, for example in `/etc/devfs.rules`: `add path 'bpf*' mode 0660 group network`.
- **Either:** run the tool with `sudo`.

Without access, `open` fails with `PermissionDenied`. If every BPF device is busy, it fails with `NotFound` ("no free BPF device").

## How it is set up

1. Open the cloning `/dev/bpf`, or the first free numbered device.
2. Set the buffer size (`Config::buffer_size`, 4 KiB to 2 MiB), then attach the interface (`BIOCSETIF`).
3. Turn on immediate mode (`BIOCIMMEDIATE`), so frames are delivered as they arrive rather than when the buffer fills. Set `BIOCSHDRCMPLT`, so the source address you write is sent unchanged.
4. Unless `see_outgoing` is set, stop seeing the host's own transmissions (`BIOCSSEESENT` on macOS, `BIOCSDIRECTION` on FreeBSD).
5. Install the filter (`BIOCSETF`), which also discards anything buffered before it.
6. Promiscuous mode if requested (`BIOCPROMISC`), and multicast memberships.

## Differences from Linux

| | macOS and FreeBSD |
|---|---|
| Receive | A read returns every frame waiting in the buffer; rawether hands them out one at a time. `rx_path()` is `RxPath::Bpf` |
| Timestamps | Software only, from the BPF header, with microsecond resolution |
| All-multicast | Not a separate mode: `all_multicast(true)` turns on promiscuous mode |
| Multicast groups | BPF has no membership call. rawether keeps a datagram socket that holds the memberships for as long as the socket is open |
| Own transmissions | Hidden unless `see_outgoing(true)` |
| VLAN tags | Delivered in place; nothing to restore |
| Batched send | One `write` per frame |
| Launch time | Not available: `tx_time` makes `open` fail with `Unsupported` |
| Priority, qdisc bypass | Ignored: these tune Linux's queueing and have no BPF equivalent |
| `tx_errors()` | Always 0 |
| `drop_capabilities()` | Does nothing. The open descriptor already holds the access |
| Counters | `received` counts frames rawether read from the device; `dropped` comes from `BIOCGSTATS` |
