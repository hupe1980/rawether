# Research: rawether 0.1.0

Sources: packet(7); kernel `Documentation/networking/packet_mmap.rst`, `timestamping.rst`,
`filter.rst`; tc-etf(8) and `include/uapi/linux/net_tstamp.h` (`SO_TXTIME`, kernel 4.19);
FreeBSD/macOS bpf(4); libpcap's `pcap-linux.c` and `pcap-bpf.c` (the reference user of both
backends); the `libc` 0.2.191 bindings (all structs and constants used exist there except the
`TPACKET_V3` enum value, 2).

## Linux open sequence

`socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0)` — protocol 0 receives nothing, so no frame
can be queued before the filter is in place → `SO_ATTACH_FILTER` (`sock_fprog`) →
`PACKET_VERSION = TPACKET_V3` → `PACKET_RESERVE = 4` (head-room for VLAN re-insertion) →
`PACKET_TIMESTAMP` (`SOF_TIMESTAMPING_RAW_HARDWARE` when hardware is asked for) →
`PACKET_RX_RING` (`tpacket_req3`: block size a power-of-two multiple of the page size, frame
size `TPACKET_ALIGN`ed, `tp_retire_blk_tov` ms) → `mmap(MAP_SHARED | MAP_LOCKED fallback to
MAP_SHARED)` → `bind(sockaddr_ll { AF_PACKET, htons(ETH_P_ALL), ifindex })` →
`PACKET_ADD_MEMBERSHIP` (`packet_mreq` `PACKET_MR_MULTICAST` per MAC, `PACKET_MR_ALLMULTI`,
`PACKET_MR_PROMISC`) → `PACKET_AUXDATA` (plain path) → `SO_TIMESTAMPING` (plain path) →
`SO_PRIORITY`, `PACKET_QDISC_BYPASS`, `SO_TXTIME` as configured. Interface index and MAC by
`SIOCGIFINDEX`/`SIOCGIFHWADDR`. `SIOCSHWTSTAMP` (`hwtstamp_config{rx_filter =
HWTSTAMP_FILTER_ALL}`) best-effort when hardware timestamps are requested; failure falls back.

## Ring walk (TPACKET_V3)

Blocks of `tp_block_size`; a block belongs to user space when `hdr.bh1.block_status &
TP_STATUS_USER`. Inside, `num_pkts` frames starting at `offset_to_first_pkt`, each a
`tpacket3_hdr` linked by `tp_next_offset`; data at `tp_mac` with `tp_snaplen` captured and
`tp_len` on the wire; `tp_sec`/`tp_nsec`; status bits `TP_STATUS_TS_RAW_HARDWARE`,
`TP_STATUS_TS_SOFTWARE`, `TP_STATUS_VLAN_VALID` (+ `tp_vlan_tci`), `TP_STATUS_VLAN_TPID_VALID`
(+ `tp_vlan_tpid`, else 0x8100). Every offset is checked against the block size before a slice
is formed. Release: write `TP_STATUS_KERNEL` to `block_status` (with a release fence). Wait
with `poll(POLLIN)`.

## VLAN re-insertion

With `PACKET_RESERVE = 4`, `tp_mac ≥ tp_net`-headroom of 4 octets exists before the frame:
move the 12 address octets 4 earlier and write TPID + TCI in the gap. Plain path: receive into
a buffer at offset 4 and do the same from `tpacket_auxdata`.

## Timestamps

Plain path: `SO_TIMESTAMPING` with `RX_HARDWARE | RAW_HARDWARE | RX_SOFTWARE | SOFTWARE`;
`SCM_TIMESTAMPING` cmsg holds three `timespec` — `[0]` software, `[2]` raw hardware; prefer
hardware when non-zero. Ring: per-frame status bits. BPF: `bh_tstamp` (`timeval32` on macOS,
`timeval` elsewhere) — software, microseconds.

## Transmit

`sendto` with `sockaddr_ll{ifindex, halen 6, addr = dst}`; `sendmmsg` with reused
`mmsghdr`/`iovec` arrays; `SO_TXTIME` (`sock_txtime{clockid, flags: DEADLINE_MODE?,
REPORT_ERRORS?}`) + per-message `SCM_TXTIME` cmsg (`u64` ns on that clock). Needs an `etf`
qdisc; errors arrive on the error queue (`MSG_ERRQUEUE`), surfaced by `Socket::take_tx_errors`.
`PACKET_TX_RING` rejected (spec clarification).

## BSD/macOS

`/dev/bpf` (cloning on FreeBSD/macOS ≥ 10.x) or first free `/dev/bpfN`; `BIOCSBLEN` before
`BIOCSETIF`; `BIOCIMMEDIATE 1`; `BIOCSHDRCMPLT 1`; `BIOCSSEESENT 0`; `BIOCSETF` (`bpf_program`,
same `{code, jt, jf, k}` layout); `BIOCPROMISC`; read buffer of `bpf_hdr` records aligned by
`BPF_WORDALIGN` (alignment `size_of::<c_long>()` on macOS/FreeBSD, kept as a constant per OS);
`write` to send; timeout via `poll`. Multicast: `SIOCADDMULTI` on an `AF_INET` datagram socket
with `ifr_addr = {AF_UNSPEC, mac}`; MAC from `getifaddrs` (`AF_LINK`, `sockaddr_dl`).

## Classic BPF for EtherType sets

```
ldh [12]
jeq #T1, accept ; … one per type
jeq #0x8100, tagged ; jeq #0x88a8, tagged ; ret #0
tagged: ldh [16] ; jeq #T1, accept … ; ret #0
accept: ret #0x40000
```
Stripped tags make the inner type appear at 12, so the first block covers them. Verified by the
crate's interpreter in unit tests and by the kernel in the veth suite.
