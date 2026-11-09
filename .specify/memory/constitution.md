<!--
Sync Impact Report
- Version: 1.0.0 → 1.1.0 (2026-11-09). MINOR: the design records become public (tracked
  specs/ and .specify/, as in the sibling procage), and every change gains the ThreatSpec steps.
  No principle changed.
- Version: (template) → 1.0.0 (2026-11-09). MAJOR: first ratification, with the 0.1.0 crate.
  Principles are taken from the sibling iec61850-rs (sans-IO cores, panic-free parsing, outside
  oracles, say what was read) and adapted to a crate whose whole job is the system call.
- Templates: plan-template.md's "Constitution Check" reads this file as it is.
- Specs: 001 (the 0.1.0 crate) is written against this version.
- Follow-up TODOs: none.
-->

# rawether Constitution

Raw layer-2 Ethernet I/O for Rust: send and receive whole frames on a named interface, with
the kernel features that make it fast and precise — packet rings, kernel and hardware
timestamps, in-kernel filters, launch-time transmit — behind one small, safe API. Linux
(AF_PACKET) is the reference; macOS/BSD (BPF) is supported; other platforms fail cleanly.

## Core Principles

### I. Generic, and nothing above layer 2

The crate moves frames, timestamps and counters. It knows no protocol: no EtherType constants
in its API, no parsing of payloads, no opinion about PTP, LLDP or industrial protocols. A filter
is a set of EtherTypes or a caller's classic-BPF program, never a protocol name.

*Checked by:* review; the public API has no protocol-specific item.

### II. `unsafe` is confined, justified and small

Every `unsafe` block lives in an OS backend module, carries a `// SAFETY:` comment stating the
invariant it relies on, and wraps one system call or one read of kernel-shared memory. The
public API is safe; nothing the caller does through it can cause undefined behaviour. Memory
shared with the kernel (the mmap ring) is read with bounds checked against the ring's own
geometry before any slice is formed.

*Checked by:* `clippy::undocumented_unsafe_blocks` at `deny`; `unsafe_op_in_unsafe_fn`;
review of every backend change. **Not checked:** that each SAFETY comment is true.

### III. The kernel's best path by default, and an honest fallback

The fastest correct mechanism the platform has is the default (TPACKET_V3 ring, batched send),
and its absence is a fallback, not an error (plain `recvmsg`). Whatever is reported is what
happened: which receive path is in use, which timestamp source stamped a frame, how many frames
the kernel dropped. Nothing is silently relabelled.

*Checked by:* the Linux veth suite runs on both receive paths; timestamp-source tests.

### IV. Tested against a real kernel

Unit tests cover what is pure (filter generation through a classic-BPF interpreter, ring
walking over synthetic blocks, VLAN re-insertion). Behaviour that depends on the kernel is
tested on a real one: a veth pair in a network namespace, in CI and locally in Docker.

*Checked by:* the `linux-veth` CI job; the macOS build-and-test job.

### V. No allocation in the steady state

Receiving from the ring hands out borrowed slices; sending takes borrowed slices; batched send
reuses its buffers. A caller who has opened a socket can run for ever without the allocator.

*Checked by:* a counting-allocator test over a steady-state loop on the veth pair.

### VI. Errors say what to do

A missing capability names the capability (`CAP_NET_RAW`); an unknown interface names it; an
unsupported platform or feature returns `ErrorKind::Unsupported` with the reason. Never a
panic.

*Checked by:* error-path tests.

### VII. Breaking changes are said out loud

Pre-1.0 a minor release may break the API. Every break gets a `CHANGELOG.md` entry.

*Checked by:* review.

## Development workflow

- **The design records are public.** One `specs/NNN-slug/` per change, indexed in
  `specs/README.md`; `specs/` and `.specify/` are tracked. Private notes and agent configuration
  are gitignored (see `.gitignore`), and neither the crate nor the records point into them
  (`just planning-paths`). The published crate contains neither the records nor the Spec
  Kit machinery.
- `/speckit-plan` checks against I–VII and `/speckit-analyze` runs before `/speckit-implement`.
- **Every change carries a threat model** (ThreatSpec): `/speckit-threatspec-model` after
  specify/clarify and again `--from-plan`, `/speckit-threatspec-check` after tasks (no CRITICAL or
  HIGH finding is implemented over), `/speckit-threatspec-converge` after implement. The
  reader-facing summary is `THREAT_MODEL.md`, kept current with the records.
- A change is done when `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test`, the veth suite and `cargo doc` with `-D warnings` pass, and the MSRV builds.

## Governance

This constitution outranks every other practice in the repository. An amendment states its
version bump in the Sync Impact Report. MAJOR removes or redefines a principle, MINOR adds or
materially expands one, PATCH clarifies wording. A principle is never renumbered.

**Version**: 1.1.0 | **Ratified**: 2026-11-09 | **Last Amended**: 2026-11-09
