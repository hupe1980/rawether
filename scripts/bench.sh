#!/usr/bin/env bash
# Receive throughput and latency of rawether, pcap and pnet_datalink over a veth pair.
#
#   scripts/bench.sh --docker   # anywhere with Docker (rust:latest + libpcap-dev)
#   scripts/bench.sh            # Linux with libpcap-dev; the harness runs with sudo
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "${1:-}" == "--docker" ]]; then
    exec docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
        -v "$PWD":/src -w /src \
        -v rawether-cargo:/usr/local/cargo/registry -v rawether-bench-target:/target -e CARGO_TARGET_DIR=/target \
        rust:latest bash -c 'apt-get -qq update && apt-get -qq install -y iproute2 libpcap-dev >/dev/null; scripts/bench.sh --inside'
fi

run() { local mode=$1; shift; if [[ "$mode" == "--inside" ]]; then "$@"; else sudo -E "$@"; fi; }
mode="${1:-}"
run "$mode" ip link add rwbench0 type veth peer name rwbench1 2>/dev/null || true
run "$mode" ip link set rwbench0 up
run "$mode" ip link set rwbench1 up
trap 'run "$mode" ip link del rwbench0 2>/dev/null || true' EXIT

(cd bench && cargo build --release -q)
bin="${CARGO_TARGET_DIR:-bench/target}/release/rawether-bench"
echo "<!-- $(date -u +%Y-%m-%d) · Linux $(uname -r) · $(nproc) CPUs · $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || uname -m) · rustc $(rustc -V | cut -d' ' -f2) -->"
run "$mode" "$bin" rwbench0 rwbench1
