# Contract: API added in 007

```rust
impl Config { pub fn tx_timestamping(self, t: Timestamping) -> Config; }   // Off by default

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxTimestamp { pub id: u32, pub timestamp: Timestamp }

impl Socket {
    pub fn tx_timestamping(&self) -> Timestamping;                       // what is delivered
    pub fn next_tx_id(&self) -> u32;                                     // id of the next frame sent
    pub fn tx_timestamp(&mut self, timeout: Option<Duration>) -> io::Result<Option<TxTimestamp>>;
}

pub struct TxErrors { pub missed: u64, pub invalid: u64, pub timestamps_lost: u64 }

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimestampInfo {
    pub software_rx: bool, pub software_tx: bool,
    pub hardware_rx: bool, pub hardware_tx: bool,
    pub phc_index: Option<u32>,                       // /dev/ptp<index>
}
impl TimestampInfo { pub fn phc_path(&self) -> Option<std::path::PathBuf>; }
pub fn timestamp_info(interface: &str) -> io::Result<TimestampInfo>;  // unprivileged
impl Socket { pub fn timestamp_info(&self) -> io::Result<TimestampInfo>; }
```
