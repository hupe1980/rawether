# Data model: rawether 0.1.0

| Entity | Fields | Rules |
|---|---|---|
| `Config` | `interface: String`, `filter: Filter`, `multicast: Vec<MacAddr>`, `all_multicast`, `promiscuous`, `rx: RxMode`, `timestamping: Timestamping`, `priority: Option<u32>`, `tx_time: Option<TxTime>`, `qdisc_bypass`, `nonblocking`, `restore_vlan` (default true), `buffer_size` | builder; validated in `Socket::open` |
| `Filter` | `All` · `EtherTypes(Vec<u16>)` (tagged or not) · `Bpf(bpf::Program)` | an empty EtherType set is `InvalidInput` |
| `RxMode` | `Auto` · `Ring { block_size, block_count, frame_size, retire_ms }` · `Plain` | `Auto` = ring of 4 blocks × 1 MiB, 2 KiB frame slots, block retire timeout 1 ms (the worst-case added latency at low traffic), falling back to plain; `Plain` has no added latency |
| `RxPath` | `Ring` · `Plain` · `Bpf` | what `Socket::rx_path()` reports |
| `Timestamping` | `Off` · `Software` (default) · `Hardware` | hardware falls back to software, never mislabelled |
| `TxTime` | `clock: Clock (Tai, Monotonic, Realtime)`, `deadline: bool`, `report_errors: bool` | Linux only; elsewhere `Unsupported` at open |
| `Socket` | backend state (fd, ring mapping, cursor, buffers), `mac`, `index`, `name` | `!Sync` receive (`&mut self`), sends take `&self` |
| `Packet<'a>` | `data: &'a [u8]`, `original_len`, `timestamp: Option<Timestamp>`, `vlan_restored` | valid until the next `recv` |
| `Timestamp` | `secs: i64`, `nanos: u32`, `source: TimestampSource (Hardware, Software)` | |
| `Stats` | `received: u64`, `dropped: u64` | Linux: `PACKET_STATISTICS` (reset on read; accumulated); BPF: `BIOCGSTATS` |
| `MacAddr` | `[u8; 6]` | `Display` as `aa:bb:cc:dd:ee:ff`; `FromStr` accepts `:` or `-` |
| `bpf::Insn` / `bpf::Program` | `{code: u16, jt: u8, jf: u8, k: u32}`; `Vec<Insn>` | `Program::ethertypes(&[u16])`, `Program::run(&[u8]) -> u32` |
