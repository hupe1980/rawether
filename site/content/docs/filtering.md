+++
title = "Filtering frames"
description = "Choose which Ethernet frames reach a rawether socket: EtherType filters that see through 802.1Q and 802.1ad VLAN tags, multicast groups, promiscuous mode, your own classic-BPF programs and how to test them without a kernel."
weight = 30

[extra]
group = "Guides"
+++

A busy link carries far more frames than one protocol needs. rawether filters in the kernel, so frames you do not want cost no system call, no copy and no ring space.

## By EtherType

```rust
use rawether::EtherType;

// PTP and LLDP; untagged, single-tagged or double-tagged.
let sock = rawether::Config::new("eth0").ethertypes([EtherType::PTP, EtherType::LLDP]).open()?;
```

`ethertypes` compiles to a classic-BPF program that checks the EtherType at offset 12 (untagged), 16 (behind one 802.1Q or 802.1ad tag) and 20 (behind two). It is also correct when the driver has stripped the outer tag into metadata, because the inner EtherType is then at offset 12. A set holds 1 to 64 types; for more, write your own program. Names, numbers or a mix all work: `.ethertypes([EtherType::GOOSE, EtherType(0x88b5)])` or `.ethertypes(&[0x88b5u16])`. When you read a received frame with `p.frame()`, it steps over the same tags, so `ethertype()` is always one of the types you filtered for.

The default, `Filter::All`, receives every frame on the interface that the NIC accepts. Which frames the NIC accepts is decided by the address filter below.

## EtherType names

`EtherType` holds any 16-bit value and names the well-known ones, each checked against the IEEE registry:

| Name | Value | Protocol |
|---|---|---|
| `IPV4`, `ARP`, `IPV6` | 0x0800, 0x0806, 0x86DD | IP |
| `VLAN`, `QINQ` | 0x8100, 0x88A8 | 802.1Q and 802.1ad tags |
| `LLDP`, `PTP` | 0x88CC, 0x88F7 | Discovery, IEEE 1588 |
| `AVTP` | 0x22F0 | IEEE 1722 (TSN streams) |
| `GOOSE`, `GSE`, `SAMPLED_VALUES` | 0x88B8, 0x88B9, 0x88BA | IEC 61850 |
| `PROFINET`, `ETHERCAT` | 0x8892, 0x88A4 | Industrial Ethernet |
| `PRP`, `HSR`, `MRP` | 0x88FB, 0x892F, 0x88E3 | Redundancy (IEC 62439) |
| `MACSEC`, `EAPOL`, `CFM` | 0x88E5, 0x888E, 0x8902 | Security, 802.1X, fault management |
| `LOCAL_EXPERIMENTAL_1`, `_2` | 0x88B5, 0x88B6 | Your own test traffic |

Printed, a named type reads `PTP (0x88f7)` and any other `0x1234`. `is_length()` tells an IEEE 802.3 length (below 0x0600) from a type. Names identify protocols; rawether parses nothing after the EtherType.

## Which addresses the NIC accepts

A NIC normally drops frames that are not addressed to it. Three settings widen that:

| Setting | Receives | Notes |
|---|---|---|
| `.join(group)` | Frames to one multicast MAC | For example `01:80:c2:00:00:0e` for LLDP or `01:1b:19:00:00:00` for PTP. `open` fails with `InvalidInput` if the address does not have the group bit set |
| `.all_multicast(true)` | Every multicast frame | On macOS and FreeBSD this turns on promiscuous mode, because BPF has no separate all-multicast mode |
| `.promiscuous(true)` | Every frame on the segment | Including other hosts' unicast traffic |

All three are off by default. Join only the groups your protocol uses: other hosts' traffic is none of your program's business, and the [threat model](@/docs/threat-model.md) counts exposing it as a class (T-07).

```rust
use rawether::{Config, EtherType, MacAddr};

const LLDP_NEAREST_BRIDGE: MacAddr = MacAddr([0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]);
let sock = Config::new("eth0").ethertypes([EtherType::LLDP]).join(LLDP_NEAREST_BRIDGE).open()?;
```

Group addresses can also be parsed: `"01-1b-19-00-00-00".parse::<MacAddr>()?`.

## Your own frames

By default a socket does not receive the frames this host sends on the interface. Turn that on with `.see_outgoing(true)`, for example to timestamp your own transmissions. On FreeBSD, BPF always delivers outgoing frames, so filter them yourself by source address there.

## Your own BPF program

`Filter::Bpf` installs any classic-BPF program. `bpf::Program::new` checks it the way the kernel does: 1 to 4096 instructions, every jump inside the program, scratch memory indices below 16, and a return as the last instruction. So a program that would be refused at `open` is refused when you build it, with a clear message.

```rust
use rawether::bpf::{Insn, Program, op};
use rawether::{Config, Filter};

// PTP over Ethernet, keeping only the first 64 octets of each frame.
let ptp_headers = Program::new(vec![
    Insn::new(op::LD | op::H | op::ABS, 0, 0, 12),      // A = EtherType
    Insn::new(op::JMP | op::JEQ | op::K, 0, 1, 0x88f7), // PTP?
    Insn::new(op::RET | op::K, 0, 0, 64),               // keep 64 octets
    Insn::new(op::RET | op::K, 0, 0, 0),                // drop
])?;
let sock = Config::new("eth0").filter(Filter::Bpf(ptp_headers)).open()?;
```

A filter's return value is the number of octets to keep: 0 drops the frame, `bpf::ACCEPT` keeps all of it. A frame cut short this way arrives with `is_truncated()` set and its full length in `original_len()`.

> [!TIP]
> `tcpdump -dd 'ether proto 0x88f7'` prints a compiled program as `{ code, jt, jf, k }` lines that map one-to-one onto `Insn::new`. Programs from `tcpdump` are compiled for one link type; check them on sample frames before you use them.

## Testing a filter without a kernel

`Program::run` interprets a program the way the kernel does, so filters can be unit-tested on any platform, without privileges:

```rust
let mut frame = vec![0u8; 60];
frame[12..14].copy_from_slice(&0x88f7u16.to_be_bytes());
assert_eq!(ptp_headers.run(&frame), 64);

frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4
assert_eq!(ptp_headers.run(&frame), 0);
```

A load beyond the end of the frame ends the program with 0, as in the kernel. Linux's ancillary loads (offsets from `SKF_AD_OFF`, such as `vlan_tci`) are not modelled and also return 0. `Program::instructions` returns the program, for example to inspect what `Program::ethertypes` built.
