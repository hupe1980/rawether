# Implementation Plan: Published benchmarks

**Branch**: `006-bench` | **Date**: 2026-11-09 | **Spec**: [spec.md](spec.md)

## Summary

`bench/` is a crate of its own, in its own workspace, outside the package and not built by CI.
It depends on `rawether` (by path), `pnet_datalink` and `pcap`.

- **Throughput:** a rawether sender floods 500 000 64-octet frames in batches of 64 over a veth
  pair. Each receiver counts the frames of the test EtherType and reports frames per second
  between the first and the last frame, plus loss.
- **Latency:** 5 000 frames, one every 200 µs, each carrying its `CLOCK_MONOTONIC` send time;
  the receiver records receipt minus send. Reported as p50, p99 and max.
- **Receivers:**
  - rawether ring (default geometry) and rawether plain, both with an in-kernel EtherType filter;
  - `pcap` in immediate mode, with the compiled filter `ether proto 0x88b5`;
  - `pnet_datalink`, which has no kernel filter and filters in user space.
- **Running it:** `scripts/bench.sh --docker` installs `libpcap-dev` and `iproute2` in
  `rust:latest`, creates the pair, runs the harness and prints a Markdown table.
  `site/content/docs/performance.md` publishes the table, environment, method and command.

## Constitution Check

The published crate gains no dependency ✅. IV: the numbers come from a real kernel ✅.

## Project Structure

`bench/{Cargo.toml,src/main.rs}`, `scripts/bench.sh`, `site/content/docs/performance.md`,
`justfile` (`bench`), README link, `.gitignore`.

## Complexity Tracking

| Deviation | Why | Rejected alternative |
|---|---|---|
| `pnet_datalink` and `pcap` as benchmark dependencies | The comparison is the point | Comparing against nothing |
