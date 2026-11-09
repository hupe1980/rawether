# Quickstart: validating 007

| Check | Command | Expect |
|---|---|---|
| Decision, classification and info unit tests | `cargo test` | pass (Linux tests in Docker) |
| veth: ids exact, refused send, bounded queue, etf coexistence | `scripts/veth-test.sh --docker` | both paths pass |
| Example | `cargo run --example txstamp -- eth0` | one line per frame: id, source, time |
| Everything | `just ci site`, `just miri` | pass |
