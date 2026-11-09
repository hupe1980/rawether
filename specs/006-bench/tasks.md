# Tasks: Published benchmarks

- [X] T001 bench/Cargo.toml (own workspace, publish = false), bench/src/main.rs: throughput and latency for rawether ring, rawether plain, pcap (immediate, `ether proto` filter) and pnet_datalink (user-space filter); Markdown table; non-zero exit on a failed receiver
- [X] T002 [P] scripts/bench.sh (`--docker`: rust:latest with libpcap-dev and iproute2); justfile `bench`; bench/ in .gitignore for target/
- [X] T003 [SR-001] Run it; site/content/docs/performance.md with the table, date, kernel, CPU, command and method; README and landing link
- [X] T004 CHANGELOG
