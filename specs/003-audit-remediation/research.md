# Research: audit remediation

Sources were read on 2026-11-09: FreeBSD `sys/net/bpf.h`; Linux `include/uapi/linux/{errqueue,
net_tstamp,if_packet}.h` and `net/packet/af_packet.c`; libc 0.2.191.

## R1. BSD record layouts (H1)

- **Decision**: a pure `bpf_record` module parses records field by field. A per-platform
  `Layout` gives the timestamp field width, the field offsets, the minimum header and the
  alignment. Constants for macOS and FreeBSD LP64 make the parser testable everywhere. On a BSD
  target the layout is derived from `libc::bpf_hdr` with `offset_of!`, and a test asserts it
  equals the constant.
- **Facts**:

  | | `bh_tstamp` | caplen | datalen | hdrlen | minimum header (`SIZEOF_BPF_HDR`) | `BPF_ALIGNMENT` |
  |---|---|---|---|---|---|---|
  | macOS (64-bit) | `timeval32`, 2 × 4 | 8 | 12 | 16 | 18 | 4 |
  | FreeBSD LP64 | `timeval`, 2 × 8 | 16 | 20 | 24 | 26 | 8 (`sizeof(long)`) |

  The kernel writes `bh_hdrlen = BPF_WORDALIGN(SIZEOF_BPF_HDR + 14) − 14` (Ethernet). The old
  bound `size_of::<bpf_hdr>() − 2` is 18 on macOS but 30 on FreeBSD (the struct pads to 32), so
  every FreeBSD record was refused.
- **Also**: the old code read `size_of::<bpf_hdr>()` octets, which FreeBSD's final record need
  not have. The new parser needs only `SIZEOF_BPF_HDR` octets.

## R2. Capabilities (M1)

- **Decision**: the order is ambient clear (`PR_CAP_AMBIENT_CLEAR_ALL`; `EINVAL` before Linux
  4.3 is ignored); then drop every bounding capability up to `/proc/sys/kernel/cap_last_cap`
  (`PR_CAPBSET_DROP`; `EPERM` without `CAP_SETPCAP` is expected and ignored); then `capset` all
  zero; then `PR_SET_NO_NEW_PRIVS` (an error fails the call). After that, scan
  `/proc/self/task/*/status` (`CapInh`, `CapPrm`, `CapEff`, `CapAmb`): any other task with a
  non-zero set → `Err` naming the count. An unreadable `/proc` → `Err`.
- **Rationale**: capabilities and `no_new_privs` are per thread. Changing another thread's sets
  needs signal broadcasting (`libpsx`), which is out of scope for a one-dependency crate. Refusing
  is honest (D-034, Q-02). The bounding set limits what any later `exec` can regain.
- **Async**: tokio's multi-thread runtime spawns its workers inside `Runtime::new`, so with
  `#[tokio::main]` they exist before the body runs. The documented order is: open the sockets
  and drop in a plain `fn main`, then build the runtime.

## R3. Hardware timestamp configuration (M2)

- **Decision**: `SIOCGHWTSTAMP` first (Linux ≥ 3.14). If it fails, write nothing and deliver
  software stamps. If `rx_filter != NONE`, write nothing and request hardware stamps
  (`SOF_TIMESTAMPING_RAW_HARDWARE`); this needs no `CAP_NET_ADMIN`. If `rx_filter == NONE`,
  write `{flags, tx_type unchanged, rx_filter: ALL}`; on success use the filter the driver
  returns, and if that is still NONE deliver software stamps. On failure (`EPERM`) deliver
  software stamps.
- **Facts**: `tx_type` ∈ {OFF, ON, ONESTEP_SYNC, ONESTEP_P2P}; `rx_filter` 0–15 (NONE = 0,
  ALL = 1, SOME = 2, PTP filters 3–14, NTP_ALL = 15). The setting is device-wide (`ptp4l` sets
  `tx_type = ON` and often a PTP-only filter).
- **Rationale**: "never lower" means a driver may still widen a filter it is asked for, which is
  harmless to other readers. A pure `decide(current)` is unit-tested over 4 × 16 states.
- **Alternatives**: restoring the configuration on close was rejected: another program may have
  changed it in the meantime, and a crash would leave it changed anyway.

## R4. Link loss (found during this work)

- **Facts**: `packet_notifier` sets `sk_err = ENETDOWN` and calls `sk_error_report` on
  `NETDEV_DOWN` and `NETDEV_UNREGISTER`, and registers the socket again on `NETDEV_UP`. `poll`
  then reports `POLLERR`. The ring path re-polls while no block is user-owned, so it spun.
- **Decision**: `wait` returns `Readable`, `Error` or `Timeout`. On `Error`, read `SO_ERROR`
  (which clears it) and return it as `io::Error` naming the interface. The plain path gets the
  same error from `recvmsg`. After `NETDEV_UP`, frames flow again. After unregister, the socket
  stays unbound (`ifindex = −1`); every later receive waits or errors, and the docs say to
  reopen.

## R5. Waiting arithmetic (L4)

- **Decision**: `deadline(timeout) = Instant::now().checked_add(t)`. `None` (overflow) means no
  deadline. Poll milliseconds round *up* (`(nanos + 999_999) / 1_000_000`, clamped to
  `i32::MAX`), so a 0.5 ms wait does not return at once.

## R6. Ring geometry (L5, L7)

- **Decision**: `validate`: `block_count` 1..=`u32::MAX`; `frames_per_block × block_count` and
  `block_size × block_count` computed with `checked_mul` in `u32` and `usize` respectively; an
  overflow is `InvalidInput`. Page-multiple and kernel refusals happen at open. For explicit
  `Ring`, open fails with the error; for `Auto`, fall back and report `RxPath::Plain`.

## R7. Control messages and the error queue (L2, L8)

- **Decision**: if `msg.msg_flags & MSG_CTRUNC` is set, ignore every control message (the frame
  is still delivered, without a timestamp or restored tag, and is labelled accordingly). Each
  read checks `cmsg_len >= CMSG_LEN(size_of::<T>())`.
- **Error queue**: the cmsg is `SOL_PACKET`/`PACKET_TX_TIMESTAMP` (16, not in libc) carrying
  `sock_extended_err`. Only `ee_origin == SO_EE_ORIGIN_TXTIME` (6) is counted, as `missed` for
  code 2 (`SO_EE_CODE_TXTIME_MISSED`) and `invalid` for code 1 (`INVALID_PARAM`).
  `tx_errors() -> io::Result<TxErrors>`.

## R8. `send_at` without `etf` (Q-06, R-28)

- **Decision**: measured on veth (default qdisc `noqueue`), test
  `a_launch_time_without_etf_is_sent_at_once`. Without a qdisc that honours `skb->tstamp`, the
  launch time is ignored and the frame leaves at once. `fq` also honours it as a pacing time.
  `Config::tx_time`'s rustdoc said "the kernel drops the frame"; that is corrected.

## R9. BSD statistics (Q-05, R-27)

- **Facts**: in xnu's and FreeBSD's `bpf.c`, `bd_rcount` is incremented for every packet tapped,
  before the filter runs; `bd_dcount` only for packets that matched but did not fit.
- **Decision**: BSD `received` = records rawether parsed from the device (all of them passed the
  filter); `dropped` = `bs_drop`. Documented: frames still in the kernel buffer are counted once
  read.

## R10. FreeBSD own-frame suppression (L8)

- **Decision**: `BIOCSDIRECTION` = `_IOW('B', 119, u_int)` = `0x8004_4277`, value `BPF_D_IN` = 0.
  FreeBSD's `BIOCSSEESENT` is an alias of it. Not in libc, so it is defined locally under
  `cfg(target_os = "freebsd")`.

## R11. CI evidence

- **Decision**: Miri runs `cargo +nightly miri test --lib`, with device tests marked
  `cfg_attr(miri, ignore)`. Fuzzing uses cargo-fuzz in `fuzz/`, with targets built against
  `rawether` with `--cfg fuzzing`, which exposes `#[doc(hidden)] pub mod fuzzing` hooks to the
  internal parsers; each target runs `-max_total_time=60` in CI. FreeBSD uses
  `vmactions/freebsd-vm` v1.5.9 at commit `c46abacb49f09938ca4e1702d15d836285d694cc`
  (`pkg install rust`, `cargo test`). 32-bit adds `cargo clippy --target i686-unknown-linux-gnu`
  to `just lint`, as a check only.
