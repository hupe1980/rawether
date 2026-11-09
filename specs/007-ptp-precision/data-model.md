# Data model: 007

- **Id mode** (per socket): `Explicit { confirmed: bool }` → `Implicit` on the kernel's `EINVAL`
  for `SCM_TS_OPT_ID`. `next_tx_id` wraps at 2³².
- **Report queue**: `VecDeque<TxTimestamp>` with capacity 1 024, preallocated when transmit
  stamping is on; full → pop the front, `timestamps_lost += 1`.
- **Hardware decision**: `decide(current: Option<Current>, want_rx, want_tx) -> Plan`.
  `None` → software only. Otherwise the written configuration (if any) differs only by
  rx_filter NONE→ALL (want_rx) and tx_type OFF→ON (want_tx). After any write, rx is hardware
  if rx_filter != NONE, and tx is hardware if tx_type != OFF.
