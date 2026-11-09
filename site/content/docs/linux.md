+++
title = "Linux"
description = "rawether on Linux: AF_PACKET sockets, the TPACKET_V3 receive ring and recvmsg fallback, kernel version requirements, CAP_NET_RAW and containers, and the kernel facilities each feature uses."
weight = 90

[extra]
group = "Platforms"
+++

On Linux, a rawether socket is an `AF_PACKET`, `SOCK_RAW` socket bound to one interface.

## Requirements

| Feature | Needs |
|---|---|
| Opening a socket | `CAP_NET_RAW` |
| TPACKET_V3 receive ring | Linux 3.2 |
| Own transmissions filtered in the kernel (`PACKET_IGNORE_OUTGOING`) | Linux 4.20; older kernels filter by packet type on receive |
| Launch time (`SO_TXTIME`) | Linux 4.19, and an `etf` or `taprio` qdisc |
| Hardware timestamps | A NIC that supports them, and `CAP_NET_ADMIN` |

## Kernel facilities by feature

| rawether | Linux |
|---|---|
| `Config::ethertypes`, `Filter::Bpf` | `SO_ATTACH_FILTER` (classic BPF), attached before `bind` |
| `RxMode::Ring` | `PACKET_VERSION` = `TPACKET_V3`, `PACKET_RESERVE`, `PACKET_RX_RING`, `mmap` (`MAP_LOCKED` where allowed) |
| `RxMode::Plain` | `recvmsg` with `PACKET_AUXDATA` and `SCM_TIMESTAMPING` control messages |
| `join`, `all_multicast`, `promiscuous` | `PACKET_ADD_MEMBERSHIP` with `PACKET_MR_MULTICAST`, `_ALLMULTI`, `_PROMISC` |
| `Timestamping` | `SO_TIMESTAMPING`; `SIOCSHWTSTAMP` for hardware |
| `priority` | `SO_PRIORITY` |
| `qdisc_bypass` | `PACKET_QDISC_BYPASS` |
| `tx_time`, `send_at`, `tx_errors` | `SO_TXTIME`, `SCM_TXTIME`, `MSG_ERRQUEUE` |
| `send_batch` | `sendmmsg` |
| `stats` | `PACKET_STATISTICS` |
| `drop_capabilities` | `capset`, `PR_SET_NO_NEW_PRIVS` |

Memberships taken through `PACKET_ADD_MEMBERSHIP` belong to the socket. The kernel counts them per interface and removes them when the last socket that asked closes, so promiscuous mode does not outlive your program.

## Containers

A container needs `CAP_NET_RAW` and an interface to bind to:

```sh
docker run --cap-add NET_RAW --network host …          # the host's interfaces
docker run --cap-add NET_RAW --cap-add NET_ADMIN …       # plus hardware timestamps
```

Docker's default capability set includes `NET_RAW`, but many hardened runtimes and Kubernetes policies drop it. Add it explicitly rather than running privileged. Inside the container's own network namespace, rawether sees the container's interfaces (typically one end of a veth pair).

## Locked memory

The ring is 4 MiB per socket by default. rawether asks for it to be locked into memory (`MAP_LOCKED`) so that frames are never paged out. If `RLIMIT_MEMLOCK` is too low it maps the ring normally, which works the same, and only risks page faults under memory pressure. Raise the limit (`ulimit -l`, or `LimitMEMLOCK=` in a systemd unit) if you open many sockets or large rings.

## VLAN sub-interfaces

You can bind to a VLAN sub-interface such as `eth0.100`. The kernel then removes and adds the tag for you. Bind to the parent `eth0` instead to see every VLAN with its tag, which rawether puts back in place.
