# Quickstart: validating 002

Prerequisites: Rust 1.88+. Linux with Docker or sudo for the veth half.

| Check | Command | Expect |
|---|---|---|
| Unit, exhaustive, randomised, round-trip and filter-agreement tests | `cargo test --lib frame` | all pass, on macOS and Linux |
| Doc examples | `cargo test --doc` | all pass |
| Examples build without header index arithmetic | `cargo build --examples` and `grep -nE 'd\[(6|12)' examples/` | build passes, grep finds nothing |
| Allocation-free build-and-send loop, flood through the view | `scripts/veth-test.sh --docker` | both receive paths pass, including `the_steady_state_does_not_allocate` |
| Gates | `just ci site` | every gate passes |

Manual check (Linux, two shells, `CAP_NET_RAW`):

```sh
cargo run --example echo -- veth0 88b5      # responder
cargo run --example sniff -- veth1 88b5     # watch the replies come back from veth0's address
```
