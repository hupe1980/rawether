#!/bin/sh
# Run the BPF kernel suite (tests/bpf.rs) on an interface pair: feth on macOS, epair on FreeBSD.
#
#   scripts/bpf-test.sh    # macOS: sudo creates the pair and opens /dev/bpf* to you; the suite
#                          # runs as you. FreeBSD: run as root.
set -eu
cd "$(dirname "$0")/.."

if [ "$(id -u)" = 0 ]; then SUDO=; else SUDO=sudo; fi

case "$(uname -s)" in
Darwin)
    a=feth4700 b=feth4701
    $SUDO ifconfig "$a" destroy 2>/dev/null || true
    $SUDO ifconfig "$b" destroy 2>/dev/null || true
    $SUDO ifconfig "$a" create
    $SUDO ifconfig "$b" create
    $SUDO ifconfig "$a" peer "$b"
    $SUDO ifconfig "$a" up
    $SUDO ifconfig "$b" up
    trap '$SUDO ifconfig "$a" destroy 2>/dev/null || true; $SUDO ifconfig "$b" destroy 2>/dev/null || true' EXIT
    # As ChmodBPF does: BPF devices for this user, so the suite runs without root.
    $SUDO chmod o+rw /dev/bpf*
    ;;
FreeBSD)
    a=$($SUDO ifconfig epair create)
    b="${a%a}b"
    $SUDO ifconfig "$a" up
    $SUDO ifconfig "$b" up
    trap '$SUDO ifconfig "$a" destroy 2>/dev/null || true' EXIT
    ;;
*)
    echo "bpf-test.sh: macOS or FreeBSD only" >&2
    exit 1
    ;;
esac
sleep 1

bin=$(cargo test --test bpf --no-run --message-format=json 2>/dev/null \
    | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -1)
[ -n "$bin" ] || { echo "could not build tests/bpf.rs" >&2; exit 1; }
echo "==> BPF suite on $a/$b as uid $(id -u)"
RAWETHER_TEST_IFACE=$a RAWETHER_TEST_PEER=$b "$bin" --test-threads=1 --nocapture
