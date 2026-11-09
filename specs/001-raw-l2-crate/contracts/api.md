# Contract: public API

```rust
pub struct Config;
impl Config {
    pub fn new(interface: impl Into<String>) -> Config;
    pub fn ethertypes(self, types: &[u16]) -> Self;     // Filter::EtherTypes
    pub fn filter(self, f: Filter) -> Self;
    pub fn join(self, mac: MacAddr) -> Self;            // multicast membership
    pub fn all_multicast(self, on: bool) -> Self;
    pub fn promiscuous(self, on: bool) -> Self;
    pub fn rx_mode(self, m: RxMode) -> Self;
    pub fn timestamping(self, t: Timestamping) -> Self;
    pub fn priority(self, p: u32) -> Self;
    pub fn tx_time(self, t: TxTime) -> Self;
    pub fn qdisc_bypass(self, on: bool) -> Self;
    pub fn nonblocking(self, on: bool) -> Self;
    pub fn restore_vlan(self, on: bool) -> Self;
    pub fn open(&self) -> io::Result<Socket>;
}

pub struct Socket;
impl Socket {
    pub fn open(cfg: &Config) -> io::Result<Socket>;
    pub fn interface(&self) -> &str; pub fn index(&self) -> u32; pub fn mac_address(&self) -> MacAddr;
    pub fn rx_path(&self) -> RxPath;
    pub fn recv(&mut self, timeout: Option<Duration>) -> io::Result<Option<Packet<'_>>>;
    pub fn try_recv(&mut self) -> io::Result<Option<Packet<'_>>>;
    pub fn send(&self, frame: &[u8]) -> io::Result<()>;
    pub fn send_at(&self, frame: &[u8], launch_ns: u64) -> io::Result<()>;
    pub fn send_batch(&mut self, frames: &[&[u8]]) -> io::Result<usize>;
    pub fn stats(&mut self) -> io::Result<Stats>;
    pub fn set_nonblocking(&self, on: bool) -> io::Result<()>;
}
impl AsFd for Socket; impl AsRawFd for Socket;

pub fn clock_now(clock: Clock) -> io::Result<Duration>;   // read the launch-time clock
pub mod bpf { pub struct Insn; pub struct Program; impl Program { pub fn ethertypes(&[u16]) -> Program; pub fn run(&self, &[u8]) -> u32; } }
```

Errors: `PermissionDenied` naming `CAP_NET_RAW` (Linux) or BPF device access (BSD);
`NotFound` naming the interface; `Unsupported` naming the feature or platform; `InvalidInput`
for a frame under 14 octets or an empty EtherType set.
