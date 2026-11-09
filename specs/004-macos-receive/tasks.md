# Tasks: BSD receive proven

- [X] T001 [SR-001] tests/bpf.rs: env pair (`RAWETHER_TEST_IFACE`/`PEER`), `RAWETHER_REQUIRE_PAIR` fails on a missing pair; tests: EtherType filter tagged/untagged with software timestamps; own frames hidden; 1 000 frames received + dropped = sent; 20-octet snap length → truncated with wire length; timeout; multicast join outcome without root (Q-15) printed and checked for a clear error
- [X] T002 scripts/bpf-test.sh (POSIX sh): macOS feth pair with sudo, `/dev/bpf*` opened to the user, suite as the user; FreeBSD epair as root; cleanup on exit
- [X] T003 .github/workflows/ci.yml: macOS matrix `macos-15`, `macos-26` running `scripts/bpf-test.sh` with `RAWETHER_REQUIRE_PAIR=1`; FreeBSD job runs it as root; justfile `bpf`
- [X] T004 README lanes table and versions; site macos-freebsd.md (versions, non-root, multicast finding), testing.md; CHANGELOG
- [ ] T005 Run CI; record the multicast finding (Q-15) in the docs and concepts
