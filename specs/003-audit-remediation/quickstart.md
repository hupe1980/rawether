# Quickstart: validating 003

| Check | Command | Expect |
|---|---|---|
| Unit tests, including both BSD record layouts and the exhaustive hwtstamp decision | `cargo test` | pass on macOS and Linux |
| Miri on the pure modules | `just miri` | no UB |
| Fuzz every parser 60 s | `just fuzz 60` | no crash |
| Cross-checks: Linux, macOS, Windows, FreeBSD, i686 | `just lint doc` | clean |
| Kernel suite: link down/up, interface deleted, launch-time reasons, `send_at` without etf, capability drop | `scripts/veth-test.sh --docker` | both receive paths pass; `drop_capabilities` binary passes |
| Everything | `just ci site` | every gate passes |
| FreeBSD runtime | CI job `freebsd` | unit tests pass in the VM |
