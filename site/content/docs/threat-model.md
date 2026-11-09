+++
title = "Threat model"
description = "What rawether defends against when it opens raw Ethernet sockets: the ring shared with the kernel, hostile frames, the CAP_NET_RAW privilege, descriptor leaks and silent drops. What it trusts, what is out of scope, and the test that guards each class."
weight = 110

[extra]
group = "Security"
+++

This page summarises rawether's threat model. The canonical text, with the test behind every claim, is [**THREAT_MODEL.md**](https://github.com/hupe1980/rawether/blob/main/THREAT_MODEL.md). It ships with the crate and is rendered on docs.rs as the [`rawether::threat_model`](https://docs.rs/rawether/latest/rawether/threat_model/index.html) module. Where they differ, the file is right.

## Why a raw-socket library needs one

A raw socket sits at an unusual point. It holds a privilege that can read and forge any traffic on the link. It shares memory with the kernel. And it hands bytes from an **unauthenticated network** straight to your code. A bug in any of these is a security bug.

## Adversary

Anyone who can put frames on the link the socket is bound to. Layer 2 has no sender identity: any frame can claim any source address, any EtherType and any VLAN.

## Assets

- **Your process's memory safety.** The receive ring is memory the kernel writes.
- **The raw-socket privilege.** Whoever holds it can read and forge traffic on the link.
- **The frames delivered:** their bytes, lengths and timestamps.
- **Other hosts' traffic** on the segment.

## Trusted

The kernel and its drivers. Even so, rawether does not let inconsistent ring metadata make it read outside the mapping.

## Classes

| Id | Threat | Defence | Status |
|---|---|---|---|
| T-01 | Ring offsets pointing outside the mapping | A block is read only once handed over, with acquire ordering. Every offset and length is checked before a slice is formed, and an inconsistent block is skipped | mitigated |
| T-02 | Using a frame after its memory goes back to the kernel | `Packet` borrows the socket; the next receive releases the block. Enforced by the compiler | mitigated |
| T-03 | Hostile frame shapes: truncated, oversized, crafted tags | VLAN re-insertion, length reporting and the header view `p.frame()` are total. Wire and captured lengths are separate, truncation is flagged, and a frame too short for its header has no view | mitigated |
| T-04 | Frames the filter should have excluded | Socket created with protocol 0, filter attached, then bound. `Program::new` refuses what the kernel refuses | mitigated |
| T-05 | The privilege kept while parsing untrusted frames | `drop_capabilities()` clears the capability sets and sets `no_new_privs`. Capabilities are per thread: call it before spawning threads | mitigated (Linux, for the calling thread) |
| T-06 | The socket inherited by a program you execute | Every descriptor is close-on-exec | mitigated |
| T-07 | Other hosts' traffic exposed by default | Promiscuous and all-multicast modes are off unless requested | mitigated |
| T-08 | A flood that fills the ring unnoticed | Bounded ring and buffers; the kernel's drop counter is readable through `stats()` | detected |
| T-09 | Launch-time frames held or dropped silently | `send_at` refuses without `tx_time`; dropped frames are counted by `tx_errors()` | detected |
| T-10 | A forged group source address turning a responder into a reply storm | `Frame::reply` refuses to answer a multicast or broadcast source | mitigated |
| T-11 | Earlier frame bytes leaking into the padding of a frame built in a reused buffer | `FrameBuilder` replaces the buffer's contents and pads with zeros | mitigated |

"Detected" means rawether cannot prevent the loss, but it makes sure you can see it.

## Out of scope

- **Frame authenticity.** rawether delivers what arrived. Authenticating it is the protocol's job: MACsec, IEC 62351-6, PTP authentication TLVs.
- **The user id.** `drop_capabilities()` sheds capabilities, not uid 0. A process started as root keeps root's file access, so grant `CAP_NET_RAW` to the binary instead.
- **Frames lost before the socket**, in the NIC or the kernel's per-CPU backlog.
- **Kernel and driver defects**, and the accuracy of hardware timestamps.

## Deploying safely

1. Grant `CAP_NET_RAW` to the binary (`setcap cap_net_raw+ep`), or add only that capability to a container. Do not run as root or privileged.
2. Open every socket, then call `drop_capabilities()` before spawning threads or reading the first frame.
3. Filter on the EtherTypes you use and leave promiscuous mode off, so the kernel discards everything else.
4. Treat each frame as untrusted input. Read the header through `p.frame()` rather than indexing, check `is_truncated()`, and use `get(..)` rather than `[..]` when you parse the payload.
5. Watch `stats().dropped`, and `tx_errors()` with launch times, if a lost frame matters.
6. Keep `Timestamping::Hardware` off NICs that `ptp4l` or another time-sync program uses: the NIC's timestamp configuration is device-wide.

## Reporting a vulnerability

Report it **privately** through GitHub's [private vulnerability reporting](https://github.com/hupe1980/rawether/security/advisories/new). Do not open a public issue. Include the OS and version (kernel release or macOS build), the rawether version, the configuration, and the smallest program and frames that show the problem. See the [security policy](https://github.com/hupe1980/rawether/blob/main/SECURITY.md).
