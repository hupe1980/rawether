# Research: transmit timestamps and clock discovery

Read on 2026-11-09: Linux `net/packet/af_packet.c`, `include/net/sock.h`,
`Documentation/networking/timestamping.rst`, `include/uapi/linux/{net_tstamp,errqueue,ethtool}.h`,
`include/uapi/asm-generic/socket.h`.

## R1. Identifiers

- **Facts**: with `SOF_TIMESTAMPING_OPT_ID`, `packet_snd` numbers a frame in
  `skb_setup_tx_timestamp`, after the frame is built but before the size re-check and
  `packet_xmit`. An `EMSGSIZE` (VLAN allowance) or a qdisc drop (`ENOBUFS`, for example `etf`
  refusing a launch time) has already used a number, so a user-space mirror of the counter
  drifts. Since Linux 6.13, a `SOL_SOCKET`/`SCM_TS_OPT_ID` (81) control message with a `u32`
  sets the frame's id. Older kernels reject the unknown cmsg with `EINVAL` in
  `sock_cmsg_send`, before any frame is built.
- **Decision**: rawether numbers frames itself (`next_tx_id`, wrapping `u32`, incremented per
  frame the kernel accepted) and passes each number with `SCM_TS_OPT_ID`. The first time the
  kernel answers `EINVAL`, rawether retries once without the message. If the retry succeeds,
  the socket switches to the kernel's own numbering for good; if the retry fails the same way,
  the error was not about the message and the mode is unchanged. No version sniffing; backports
  work.
- **CI and Docker** run Linux 7.0 (`7.0.0-azure`, `7.0.14-linuxkit`), so the exact path is the
  tested one.

## R2. Reports

- `OPT_TSONLY`: no frame payload is looped back (smaller, and works with
  `tstamp_allow_data=0`). Each report is one error-queue message carrying `SCM_TIMESTAMPING`
  (`[timespec; 3]`: software in `[0]`, raw hardware in `[2]`) and `SOL_PACKET`/
  `PACKET_TX_TIMESTAMP` with `sock_extended_err` (`ee_origin = SO_EE_ORIGIN_TIMESTAMPING` (4),
  `ee_info = SCM_TSTAMP_SND` (0), `ee_data = id`).
- Launch-time drops use the same queue (`ee_origin = SO_EE_ORIGIN_TXTIME`), so one reader
  classifies both: timestamps go to a preallocated `VecDeque` of 1 024 (the oldest dropped and
  counted in `TxErrors::timestamps_lost`), launch-time reports go to the counts.
- **Waiting**: `poll` with `events = 0` returns only on `POLLERR`/`POLLHUP`, so waiting for a
  timestamp is not woken by received frames.

## R3. Hardware transmit stamping and the NIC

- `tx_type` values: OFF 0, ON 1, ONESTEP_SYNC 2, ONESTEP_P2P 3. Only OFF → ON is a widening;
  one-step modes already stamp (the NIC inserts the time) and are left alone. `ptp4l` sets ON
  or a one-step mode, so the usual station needs no write and no `CAP_NET_ADMIN`.
- Socket flags: `TX_SOFTWARE | SOFTWARE` always when transmit stamping is on, plus
  `TX_HARDWARE | RAW_HARDWARE` when the NIC stamps transmissions. Drivers that stamp in hardware
  set `SKBTX_IN_PROGRESS`, which suppresses the software stamp (no `OPT_TX_SWHW`), so there is
  one report per frame, labelled by which array slot is set.

## R4. Clock discovery

- `SIOCETHTOOL` with `ETHTOOL_GET_TS_INFO` (0x41) on any `AF_INET` datagram socket, without
  privilege: `struct ethtool_ts_info { cmd, so_timestamping, phc_index (s32, −1 = none),
  tx_types, tx_reserved[3], rx_filters, rx_reserved[3] }`. The capability bits are
  `SOF_TIMESTAMPING_{TX,RX}_{HARDWARE,SOFTWARE}` and `RAW_HARDWARE`. The PHC is `/dev/ptp<index>`.
- veth reports software stamping and no PHC. macOS and FreeBSD have no such call: BPF stamps
  received frames in software and there is no PHC, which is reported as such.
