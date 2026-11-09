# Implementation Plan: BSD receive proven

**Branch**: `004-macos-receive` | **Date**: 2026-11-09 | **Spec**: [spec.md](spec.md)

## Summary

The new `tests/bpf.rs` (macOS and FreeBSD only) mirrors the core of the veth suite on an
interface pair. `scripts/bpf-test.sh` (POSIX sh) sets the pair up and runs the suite:

- **macOS:** it creates `feth` interfaces with `sudo`, opens `/dev/bpf*` to the CI user, and runs
  the suite as that user.
- **FreeBSD:** it creates an `epair` and runs the suite as root.

CI runs the macOS job on a `macos-15` / `macos-26` matrix. The FreeBSD VM job runs the script
too. `RAWETHER_REQUIRE_PAIR=1` turns a missing pair into a failure.

## Constitution Check

IV (tested against a real kernel) is extended to the BSDs ✅. No source changes are planned
unless the suite finds a bug (principle III: report what happened).

## Project Structure

`tests/bpf.rs`, `scripts/bpf-test.sh`, `.github/workflows/ci.yml`, `justfile` (`just bpf`),
README (lanes, versions), site `macos-freebsd.md` and `testing.md`, CHANGELOG.

## Complexity Tracking

None.
