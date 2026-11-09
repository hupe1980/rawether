# Threat model

rawether opens raw layer-2 sockets: it holds a privilege (`CAP_NET_RAW` on Linux, access to
`/dev/bpf*` on macOS and FreeBSD), shares memory with the kernel, and hands frames from an
unauthenticated network to its caller. This document says what rawether defends against, what
it does not, and which test guards each claim. It ships with the crate and is rendered on
docs.rs as the `rawether::threat_model` module. The design record behind it is
[specs/001-raw-l2-crate](https://github.com/hupe1980/rawether/blob/main/specs/001-raw-l2-crate/threat-model.md).

## Adversary

Anyone who can put frames on the link the socket is bound to. Layer 2 has no sender identity:
any frame can claim any source address and any EtherType.

## Assets

- **The caller's memory safety** — the receive ring is memory the kernel writes.
- **The raw-socket privilege** — whoever holds it can read and forge traffic on the link.
- **The frames delivered** — their bytes, lengths and timestamps.
- **Other hosts' traffic** on the segment.
- **Host-wide NIC state** that other programs rely on, such as the timestamping configuration
  `ptp4l` needs.

## Trusted

The kernel and its drivers. A kernel that writes inconsistent ring metadata, BPF records or
control messages is still not allowed to make rawether read outside its buffers (T-01, T-13,
T-14), but a kernel that writes into a block it has handed over is out of scope.

## Classes

| Id | Class | Defence | Status | Guarded by |
|---|---|---|---|---|
| T-01 | Ring offsets outside the mapping | A block is read only after `TP_STATUS_USER` is seen with acquire ordering; every frame offset and length is checked against the block before a slice is formed; a block whose offsets do not hold together is skipped, never trusted. | mitigated | `ring::tests::offsets_that_point_outside_the_block_end_the_walk`, `ring::tests::a_block_still_owned_by_the_kernel_is_not_read`, Miri on the pure modules, fuzz target `ring_walk` |
| T-02 | A frame used after its memory is returned to the kernel | `Packet` borrows the socket mutably; the block is released only by the next receive. | mitigated | compile-fail example on `Socket::recv` |
| T-03 | Hostile frame shapes (truncated, oversized, crafted tags) | VLAN re-insertion, length reporting and the header view (`Packet::frame`, `Frame::new`) are total: wire length and captured length are reported separately, truncation is flagged, a frame shorter than its announced header has no view, no input panics. The view steps over exactly the tags the EtherType filter steps over. | mitigated | `vlan::tests::reinsertion_is_total_over_small_inputs`, `frame::tests::a_view_is_total_over_small_inputs`, `frame::tests::a_view_never_panics_on_random_frames`, `frame::tests::the_view_and_the_ethertype_filter_agree`, `tests/veth.rs::only_the_chosen_ethertypes_arrive_tagged_or_not_each_with_a_timestamp`, `tests/veth.rs::a_short_snap_length_marks_the_frame_truncated_with_its_wire_length`, fuzz targets `frame_view`, `vlan_reinsert` |
| T-04 | Frames the filter should have excluded | The socket is created with protocol 0, the filter attached, then bound; `Program::new` refuses what the kernel refuses. | mitigated | `bpf::tests::*`, `tests/veth.rs::only_the_chosen_ethertypes_arrive_tagged_or_not_each_with_a_timestamp`, fuzz target `bpf_program`, `bpf::tests::a_far_jump_is_refused_on_every_pointer_width` |
| T-05 | The privilege kept while parsing untrusted frames | `drop_capabilities()` clears the ambient, inheritable, permitted and effective sets, empties the bounding set where `CAP_SETPCAP` allows, and sets `no_new_privs`; open sockets keep working. Capabilities are per thread, so it refuses (`Err`) while any other thread still holds one, instead of leaving it privileged. | mitigated (Linux) | `tests/drop_capabilities.rs` (a single-threaded program: refusal with a second thread, every task's sets empty after the drop, the socket still working) |
| T-06 | The socket inherited by an executed program | Every descriptor is close-on-exec. | mitigated | `tests/veth.rs::every_descriptor_is_close_on_exec` |
| T-07 | Other hosts' traffic exposed by default | Promiscuous and all-multicast modes are off unless asked for. | mitigated | `tests::the_default_configuration_is_neither_promiscuous_nor_all_multicast` |
| T-08 | A flood that fills the ring unnoticed | The ring and buffers are bounded; the kernel's drop counter is accumulated and readable. | detected | `tests/veth.rs::a_hundred_thousand_frames_are_received_or_counted_as_dropped`, `tests/veth.rs::sparse_frames_wait_in_the_ring_while_the_reader_is_busy` |
| T-09 | Launch-time frames held or dropped silently | `send_at` refuses without `Config::tx_time`; a launch time `etf` refuses fails `send_at`; every drop `etf` reports is counted by reason (`tx_errors`). | detected | `tests/veth.rs::launch_time_needs_configuration_and_a_qdisc_that_honours_it` (the `etf` half runs where the kernel has `sch_etf`) |
| T-10 | A reply sent to a group address: a peer forges a multicast or broadcast source so that a responder answers the whole segment | `Frame::reply` returns `None` for a group source address. | mitigated | `frame::tests::a_reply_goes_back_to_the_sender_and_never_to_a_group` |
| T-11 | Bytes of an earlier frame sent in the padding of a later, shorter one built in the same buffer | `FrameBuilder::write` replaces the buffer's contents and `write_into` writes only the frame's length; padding is always zero. | mitigated | `frame::tests::building_replaces_the_buffer_and_pads_with_zeros` |
| T-12 | The NIC's device-wide timestamp configuration changed under other programs (`ptp4l` losing its transmit stamps) | With hardware receive or transmit stamps requested, the configuration is read first and never lowered: a receive filter or transmit mode that already stamps is used as it is; only none is widened to all and off to on; nothing is written if the read fails. | mitigated (Linux) | `hwtstamp::tests::the_nic_configuration_is_never_lowered`, `tests/veth.rs::hardware_timestamps_on_a_nic_without_them_report_software` |
| T-13 | BPF read-buffer records misparsed (FreeBSD's header layout differs from macOS's) | Records are read field by field at the platform's own offsets, bounded by `SIZEOF_BPF_HDR` and the buffer; a malformed record ends the buffer. | mitigated (macOS, FreeBSD) | `bpf_record::tests::*` (both layouts), fuzz target `bpf_record`, the FreeBSD CI lane |
| T-14 | A control message shorter than what is read from it | A truncated control buffer (`MSG_CTRUNC`) is ignored; every message is checked to hold its whole payload inside the buffer. | mitigated (Linux) | `sys::linux::tests::a_short_control_message_is_skipped` |
| T-15 | A receive spinning a CPU core when the link goes down or the interface disappears | A socket error ends the wait: `recv` returns it (`ENETDOWN`, naming the interface); frames flow again once the link is up. | mitigated | `tests/veth.rs::a_link_going_down_ends_a_receive_and_frames_return_after_it_comes_up`, `tests/veth.rs::deleting_the_interface_ends_a_receive` |
| T-16 | A transmit timestamp attributed to the wrong frame (a PTP clock then computes a wrong offset) | Each frame's id is passed to the kernel (`SCM_TS_OPT_ID`, Linux 6.13+), so a refused send cannot shift later ids; unread timestamps are bounded and their loss counted; reports are read through the length-checked control-message reader, and launch-time reports and timestamps are kept apart. | mitigated (Linux 6.13+); documented before | `tests/veth.rs::transmit_timestamps_carry_the_announced_ids`, `tests/veth.rs::ids_stay_exact_after_a_refused_send_and_reports_coexist`, `tests/veth.rs::unread_transmit_timestamps_are_bounded_and_receiving_does_not_spin` |

## Out of scope

- **Frame authenticity.** rawether delivers what arrived. Authenticating it is the protocol's job
  (MACsec, IEC 62351-6, PTP authentication TLVs).
- **The user id.** `drop_capabilities()` sheds capabilities, not uid 0; a process started as root
  keeps root's file access. Grant `CAP_NET_RAW` to the binary (`setcap cap_net_raw+ep`) instead.
- **Frames lost before the socket.** On a busy host the kernel's per-CPU backlog can drop frames
  before any socket sees them; those appear in `/proc/net/softnet_stat`, not in `stats()`.
- **Kernel and driver defects**, and the accuracy of hardware timestamps.

## Deployment

- Grant `CAP_NET_RAW` to the binary (`setcap cap_net_raw+ep`), or add only that capability to a
  container (`--cap-add NET_RAW`), rather than running as root or privileged.
- Open every socket first, then call `drop_capabilities()` before spawning threads, building an
  async runtime or handling the first frame; it refuses if another thread is already running.
- Use `Timestamping::Hardware` freely next to `ptp4l`: rawether never lowers the NIC's
  timestamping configuration.
- Leave promiscuous and all-multicast modes off unless the protocol needs them, and filter on
  the EtherTypes it uses, so the kernel discards everything else.
- Treat every frame as untrusted input: read the header through `Packet::frame()`, check
  `is_truncated()`, and check lengths before parsing the payload.
- Watch `stats().dropped` (and `tx_errors()` with launch times) if losing a frame matters.

## Reporting

Report a suspected vulnerability privately through
[GitHub's private vulnerability reporting](https://github.com/hupe1980/rawether/security/advisories/new);
the [security policy](https://github.com/hupe1980/rawether/blob/main/SECURITY.md) says what to
include and what to expect. A confirmed vulnerability gets a fix, a class in this document and a
test that guards it.
