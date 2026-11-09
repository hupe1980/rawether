#!/usr/bin/env bash
# Run the kernel-behaviour suite (tests/veth.rs) on a veth pair, on the ring and on the plain
# receive path.
#
#   scripts/veth-test.sh           # Linux: builds as you, runs the test binary with sudo
#   scripts/veth-test.sh --docker  # anywhere with Docker: the same inside a Linux container
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "${1:-}" == "--docker" ]]; then
    exec docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
        -v "$PWD":/src -w /src \
        -v rawether-cargo:/usr/local/cargo/registry -v rawether-target:/target -e CARGO_TARGET_DIR=/target \
        rust:latest bash -c 'command -v ip >/dev/null || { apt-get -qq update && apt-get -qq install -y iproute2 >/dev/null; }; scripts/veth-test.sh --inside'
fi

run() { if [[ "${1}" == "--inside" ]]; then shift; "$@"; else sudo -E "$@"; fi; }
mode="${1:-}"

run "$mode" ip link add rawether0 type veth peer name rawether1 2>/dev/null || true
run "$mode" ip link set rawether0 up
run "$mode" ip link set rawether1 up
trap 'run "$mode" ip link del rawether0 2>/dev/null || true' EXIT

built() { cargo test --test "$1" --no-run --message-format=json 2>/dev/null \
    | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -1; }
bin=$(built veth)
caps=$(built drop_capabilities)
[[ -n "$bin" && -n "$caps" ]] || { echo "could not build the kernel tests" >&2; exit 1; }

export RAWETHER_TEST_IFACE=rawether0 RAWETHER_TEST_PEER=rawether1
for rx in ring plain; do
    echo "==> veth suite, receive path: $rx"
    run "$mode" env RAWETHER_TEST_IFACE=rawether0 RAWETHER_TEST_PEER=rawether1 RAWETHER_RX="$rx" "$bin" --test-threads=1
    run "$mode" env RAWETHER_TEST_IFACE=rawether0 RAWETHER_TEST_PEER=rawether1 RAWETHER_RX="$rx" RAWETHER_ALLOC_ALONE=1 \
        "$bin" --exact the_steady_state_does_not_allocate
done
# A program of its own: dropping capabilities is process-wide and cannot be undone.
echo "==> capability drop"
run "$mode" env RAWETHER_TEST_IFACE=rawether0 RAWETHER_TEST_PEER=rawether1 "$caps"
