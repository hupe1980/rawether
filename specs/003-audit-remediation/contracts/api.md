# Contract: public API changes in 003 (hard cut)

```rust
/// Launch-time frames the kernel dropped since the last call, by reason.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxErrors {
    /// The launch time had passed, or would pass, before the frame could leave (`SO_EE_CODE_TXTIME_MISSED`).
    pub missed: u64,
    /// The qdisc rejected the frame's launch-time parameters, e.g. a clock mismatch (`SO_EE_CODE_TXTIME_INVALID_PARAM`).
    pub invalid: u64,
}
impl TxErrors { pub fn total(&self) -> u64; }

impl Socket {
    pub fn tx_errors(&mut self) -> io::Result<TxErrors>;      // was io::Result<u64>
    pub fn timestamping(&self) -> Timestamping;              // NEW: what this socket delivers
    // recv/try_recv: a pending socket error (link down, interface removed) is returned as Err.
}

/// Linux: clears the calling thread's capability sets (including ambient), drops the bounding
/// set where allowed, sets no_new_privs; Err if any other thread still holds a capability or if
/// that cannot be checked. macOS/FreeBSD: Ok(()) (no-op).
pub fn drop_capabilities() -> io::Result<()>;              // may now fail

impl Config {
    // validate(): ring geometry overflow and limits → InvalidInput.
    // open(): RxMode::Ring that cannot be set up → Err (Auto falls back).
}

#[cfg(fuzzing)] #[doc(hidden)] pub mod fuzzing; // ring_walk, bpf_record(layout), vlan_reinsert
```
