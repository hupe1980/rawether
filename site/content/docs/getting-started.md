+++
title = "Getting started"
description = "Install rawether, give a binary the privilege to open raw sockets without running as root, and receive and send your first Ethernet frames on Linux, macOS or FreeBSD."
weight = 10

[extra]
group = "Start"
+++

## Install

```sh
cargo add rawether
```

rawether needs Rust 1.88 or later and depends only on `libc`. It builds on every target; on platforms other than Linux, macOS and FreeBSD, `Socket::open` returns `ErrorKind::Unsupported`.

## Get the privilege to open a socket

A raw socket can read and forge any traffic on the link, so the operating system guards it.

### Linux

Opening an AF_PACKET socket needs the `CAP_NET_RAW` capability. Grant it to the binary instead of running as root:

```sh
cargo build
sudo setcap cap_net_raw+ep target/debug/my-tool
./target/debug/my-tool
```

`setcap` has to be repeated after every build, because a new binary has no capabilities. In a container, add only this capability:

```sh
docker run --cap-add NET_RAW …
```

Two features may need more. `Timestamping::Hardware` needs `CAP_NET_ADMIN` only to switch on a NIC that stamps nothing yet; see [Timestamps](@/docs/timestamps.md). Launch times need an `etf` or `taprio` qdisc, which you install with `tc`, outside your program.

After opening your sockets, call `rawether::drop_capabilities()`. It sheds every capability for the whole process, and refuses with an error if another thread is already running, so call it before spawning threads or building an async runtime.

### macOS and FreeBSD

A socket is a BPF device, `/dev/bpf*`, opened for reading and writing. By default only root can do that. The usual way to grant it to a group is the `ChmodBPF` launch daemon that Wireshark installs on macOS, or a `devfs` rule on FreeBSD. Running the tool with `sudo` also works.

If access is missing, `open` fails with `ErrorKind::PermissionDenied` and an error message that names what is missing.

## Receive frames

```rust
use std::time::Duration;

fn main() -> std::io::Result<()> {
    // Only LLDP frames, tagged or not.
    let mut sock = rawether::Config::new("eth0").ethertypes([rawether::EtherType::LLDP]).open()?;
    rawether::drop_capabilities()?;

    println!("{} ({}) on the {:?} path", sock.interface(), sock.mac_address(), sock.rx_path());
    loop {
        let Some(p) = sock.recv(Some(Duration::from_secs(1)))? else { continue };
        let Some(f) = p.frame() else { continue }; // shorter than a header
        println!("{} octets from {}", p.original_len(), f.source());
    }
}
```

`recv` returns `Ok(None)` when the timeout runs out, and a `Packet` otherwise. `p.frame()` reads its Ethernet header (addresses, VLAN tags, EtherType, payload) and returns `None` for a frame too short to have one, so a hostile frame cannot make your program panic. `p.data()` has the raw octets, from the destination MAC address, without the frame check sequence.

## Send a frame

```rust
use rawether::{Config, EtherType, FrameBuilder, MacAddr};

fn main() -> std::io::Result<()> {
    let sock = Config::new("eth0").open()?;
    let mut frame = Vec::with_capacity(1518);
    // To everyone, from this interface, with a local experimental EtherType.
    FrameBuilder::new(MacAddr::BROADCAST, sock.mac_address(), EtherType::LOCAL_EXPERIMENTAL_1)
        .write(&mut frame, b"hello, layer 2"); // padded to the 60-octet minimum
    sock.send(&frame)
}
```

The builder writes the header and pads the frame. The NIC appends the frame check sequence. See [Sending frames](@/docs/sending.md) for VLAN tags, replies and stack buffers.

## Run the examples

The repository has three examples:

```sh
cargo run --example sniff -- eth0 88cc 88f7  # print frames with timestamps
cargo run --example lldp  -- eth0            # announce over LLDP, list neighbours
cargo run --example echo  -- eth0 88b5       # reflect one EtherType, in batches
```

On Linux, run `cargo build --examples` first, then `sudo setcap cap_net_raw+ep target/debug/examples/sniff` (or the example you want).

## Next steps

- [How it works](@/docs/how-it-works.md): what happens when you open a socket and receive a frame.
- [Filtering frames](@/docs/filtering.md): EtherTypes, VLANs, multicast and your own BPF.
- [Threat model](@/docs/threat-model.md): what to keep in mind when you parse frames from the network.
