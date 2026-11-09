# Data model: audit remediation

## Layout (bpf_record, pure)

| Field | macOS | FreeBSD LP64 |
|---|---|---|
| `ts_width` (octets per timestamp field) | 4 | 8 |
| `caplen`, `datalen`, `hdrlen` offsets | 8, 12, 16 | 16, 20, 24 |
| `min_header` (`SIZEOF_BPF_HDR`) | 18 | 26 |
| `align` (`BPF_ALIGNMENT`) | 4 | 8 |

`Record { start, caplen, datalen, secs, usecs }`. Invariant: `start + caplen <= buf.len()`,
`hdrlen >= min_header`. Otherwise parsing ends.

## HwTstampPlan (hwtstamp, pure)

Input: `Option<Current { flags, tx_type, rx_filter }>` (None = could not read).

| Current | Write | Request hardware stamps |
|---|---|---|
| None | nothing | no |
| `rx_filter != NONE` | nothing | yes |
| `rx_filter == NONE` | `{flags, tx_type, rx_filter: ALL}` | if the write succeeds and the returned filter != NONE |

Invariant (tested exhaustively): a write never changes `tx_type` and only changes `rx_filter`
from NONE.

## TxErrors (public)

`{ missed: u64, invalid: u64 }` with `total()`: launch-time drops since the last call, by reason.

## Timestamping in effect

`Socket::timestamping() -> Timestamping`: `Off`; `Software`; `Hardware` when raw hardware stamps
were requested from a NIC that stamps (each frame's `TimestampSource` still says what it got).

## Stats (unchanged type, one meaning)

`received`: frames that passed the filter and reached the socket (Linux: queued; BSD: read from
the device). `dropped`: frames that passed the filter but found no room. Neither counts frames
lost before the socket.

## RingConfig validation

`block_count >= 1`; `block_size` a power of two ≥ the page size at open; `frame_size` 128..=
`block_size`; `(block_size / frame_size) × block_count` fits `u32`; `block_size × block_count`
fits `usize`.
