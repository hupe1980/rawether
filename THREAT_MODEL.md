# Threat model

rawether opens raw layer-2 sockets: it holds a privilege (`CAP_NET_RAW` on Linux, access to
`/dev/bpf*` on the BSDs), shares memory with the kernel, and hands frames from an
unauthenticated network to its caller. This page says what it defends against, what it does
not, and which test guards each claim. The design record behind it is
[specs/001-raw-l2-crate](https://github.com/hupe1980/rawether/blob/main/specs/001-raw-l2-crate/threat-model.md).

## Adversary

Anyone who can put frames on the link the socket is bound to. Layer 2 has no sender identity:
any frame can claim any source address and any EtherType.

## Assets

- **The caller's memory safety** — the receive ring is memory the kernel writes.
- **The raw-socket privilege** — whoever holds it can read and forge traffic on the link.
- **The frames delivered** — their bytes, lengths and timestamps.
- **Other hosts' traffic** on the segment.

## Trusted

The kernel and its drivers. A kernel that writes inconsistent ring metadata is still not allowed
to make rawether read outside the mapping (T-01), but a kernel that writes into a block it has
handed over is out of scope.

## Classes

| Id | Class | Defence | Status | Guarded by |
|---|---|---|---|---|
| T-01 | Ring offsets outside the mapping | A block is read only after `TP_STATUS_USER` is seen with acquire ordering; every frame offset and length is checked against the block before a slice is formed; a block whose offsets do not hold together is skipped, never trusted. | mitigated | `ring::tests::offsets_that_point_outside_the_block_end_the_walk`, `ring::tests::a_block_still_owned_by_the_kernel_is_not_read` |
| T-02 | A frame used after its memory is returned to the kernel | `Packet` borrows the socket mutably; the block is released only by the next receive. | mitigated | compile-fail example on `Socket::recv` |
| T-03 | Hostile frame shapes (truncated, oversized, crafted tags) | VLAN re-insertion and length reporting are total: wire length and captured length are reported separately, truncation is flagged, no input panics. | mitigated | `vlan::tests::reinsertion_is_total_over_small_inputs`, `tests/veth.rs::only_the_chosen_ethertypes_arrive_tagged_or_not_each_with_a_timestamp`, `tests/veth.rs::a_short_snap_length_marks_the_frame_truncated_with_its_wire_length` |
| T-04 | Frames the filter should have excluded | The socket is created with protocol 0, the filter attached, then bound; `Program::new` refuses what the kernel refuses. | mitigated | `bpf::tests::*`, `tests/veth.rs::only_the_chosen_ethertypes_arrive_tagged_or_not_each_with_a_timestamp` |
| T-05 | The privilege kept while parsing untrusted frames | `drop_capabilities()` clears the capability sets and sets `no_new_privs`; open sockets keep working. Capabilities are per thread on Linux: call it before spawning threads. | mitigated (Linux) | `tests/veth.rs::dropping_capabilities_keeps_open_sockets_and_names_the_capability_when_opening` |
| T-06 | The socket inherited by an executed program | Every descriptor is close-on-exec. | mitigated | `tests/veth.rs::every_descriptor_is_close_on_exec` |
| T-07 | Other hosts' traffic exposed by default | Promiscuous and all-multicast modes are off unless asked for. | mitigated | `tests::the_default_configuration_is_neither_promiscuous_nor_all_multicast` |
| T-08 | A flood that fills the ring unnoticed | The ring and buffers are bounded; the kernel's drop counter is accumulated and readable. | detected | `tests/veth.rs::a_hundred_thousand_frames_are_received_or_counted_as_dropped`, `tests/veth.rs::sparse_frames_wait_in_the_ring_while_the_reader_is_busy` |
| T-09 | Launch-time frames held or dropped silently | `send_at` refuses without `Config::tx_time`; frames `etf` drops are drained from the error queue and counted. | detected | `tests/veth.rs::launch_time_needs_configuration_and_a_qdisc_that_honours_it` (the `etf` half runs where the kernel has `sch_etf`) |

## Out of scope

- **Frame authenticity.** rawether delivers what arrived. Authenticating it is the protocol's job
  (MACsec, IEC 62351-6, PTP authentication TLVs).
- **The user id.** `drop_capabilities()` sheds capabilities, not uid 0; a process started as root
  keeps root's file access. Grant `CAP_NET_RAW` to the binary (`setcap cap_net_raw+ep`) instead.
- **Frames lost before the socket.** On a busy host the kernel's per-CPU backlog can drop frames
  before any socket sees them; those appear in `/proc/net/softnet_stat`, not in `stats()`.
- **Kernel and driver defects**, and the accuracy of hardware timestamps.
