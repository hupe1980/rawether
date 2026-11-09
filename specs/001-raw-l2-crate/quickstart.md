# Quickstart: validating rawether 0.1.0

1. `cargo test` (any OS) — BPF builder/interpreter, ring walker, VLAN re-insertion, config
   validation, error mapping.
2. `scripts/veth-test.sh` (Linux with sudo, or `--docker` from macOS) — creates a veth pair and
   runs `tests/veth.rs` twice (`RAWETHER_RX=ring`, `RAWETHER_RX=plain`). Expected: filtering
   tagged/untagged, multicast membership, timestamps on every frame, timeouts, non-blocking,
   batched send of 100 000 frames with received + dropped = sent, zero steady-state
   allocations.
3. `cargo run --example sniff -- eth0` (privileged) prints frames with timestamps.
4. `cargo publish --dry-run` and `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps` are clean.
