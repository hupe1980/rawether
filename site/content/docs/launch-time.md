+++
title = "Launch-time transmission (TSN)"
description = "Send Ethernet frames at a precise time with rawether on Linux: SO_TXTIME, the etf and taprio qdiscs for Time-Sensitive Networking, the TAI clock, deadline mode, and counting frames the kernel dropped for missing their launch time."
weight = 70

[extra]
group = "Guides"
+++

Time-Sensitive Networking (TSN) schedules frames on the wire: a sampled-value stream every 250 µs, a control frame inside its time slot. Linux supports this with **`SO_TXTIME`**: each frame carries a launch time, and a queueing discipline holds it until then, in software or by programming the NIC.

Launch time is Linux-only, from 4.19. On macOS and FreeBSD, opening a socket with `tx_time` fails with `Unsupported`.

## 1. Install a qdisc that honours launch times

Without one, the kernel drops timed frames. For a single-queue interface (or for testing on a veth pair):

```sh
sudo tc qdisc replace dev eth0 root etf clockid CLOCK_TAI delta 200000
```

`delta` is how many nanoseconds before its launch time the qdisc releases a frame to the driver. Set it to cover the driver's own latency. For a multi-queue NIC, put `etf` under `mqprio` on the queue your socket's priority maps to, and add `offload` if the NIC can launch frames in hardware:

```sh
sudo tc qdisc replace dev eth0 parent root handle 100 mqprio num_tc 3 \
    map 2 2 1 0 2 2 2 2 2 2 2 2 2 2 2 2 queues 1@0 1@1 2@2 hw 0
sudo tc qdisc replace dev eth0 parent 100:1 etf clockid CLOCK_TAI delta 200000 offload
```

`taprio` in txtime-assisted mode also honours launch times, in addition to its gate schedule.

## 2. Open the socket with `tx_time`

```rust
use rawether::{Clock, Config, TxTime};

let sock = Config::new("eth0")
    .priority(3) // the traffic class mqprio maps to the etf queue
    .tx_time(TxTime::default())
    .open()?;
```

`TxTime::default()` is `Clock::Tai`, exact launch times, and error reporting on. The fields:

| Field | Meaning |
|---|---|
| `clock` | The clock launch times are on: `Tai` (what `etf` and `taprio` expect), `Monotonic` or `Realtime`. Must match the qdisc's `clockid` |
| `deadline` | `SOF_TXTIME_DEADLINE_MODE`: the time is a latest-by deadline, and the qdisc may send earlier |
| `report_errors` | `SOF_TXTIME_REPORT_ERRORS`: frames the qdisc drops are reported on the error queue |

## 3. Send with a launch time

```rust
use std::time::Duration;

let now = rawether::clock_now(Clock::Tai)?;
let launch = now + Duration::from_micros(500);
sock.send_at(&frame, launch.as_nanos() as u64)?;
```

`send_at` takes nanoseconds on the configured clock. `clock_now` reads that clock, so schedules can be computed from it. Calling `send_at` on a socket opened without `tx_time` is refused with `InvalidInput`.

`CLOCK_TAI` differs from `CLOCK_REALTIME` by the TAI–UTC offset, which the kernel only knows once something sets it (`ptp4l`/`phc2sys`, or chrony with `leapsectz`). Until then the two clocks read the same, which is fine for local scheduling, but not for agreeing on times with other hosts.

## 4. Count what missed its slot

`etf` refuses a frame whose launch time is already past, or on another clock, at once: `send_at` returns an error, and the notice counts as `invalid`. A frame accepted but dequeued too late to make its slot is dropped later and counts as `missed`. With `report_errors`, `tx_errors()` drains both:

```rust
let errors = sock.tx_errors()?;
if errors.dropped() > 0 {
    eprintln!("{} missed their launch time, {} had invalid parameters", errors.missed, errors.invalid);
}
```

The counts cover the notices since the last call, and only launch-time notices are counted. Check it periodically: a growing number means the schedule is too tight for the `delta`, or the sender is falling behind.

## Without `etf`

Without a qdisc that honours launch times, the kernel ignores the launch time and the frame leaves at once (measured on the veth suite). `fq` also honours it, as a pacing time.

## Things that break launch times

- **`qdisc_bypass(true)`.** It skips the qdisc that holds the frames.
- **A priority that maps to a queue without `etf`.** The frame is then sent at once.
- **A clock mismatch** between `TxTime::clock` and the qdisc's `clockid`. The kernel drops every frame and counts it as `invalid`.
