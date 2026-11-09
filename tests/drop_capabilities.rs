//! `drop_capabilities` on a real kernel, as its own single-threaded program (`harness = false`):
//! under libtest, the harness's own threads would keep their capabilities.
//!
//! Spec 003 SR-002 (threat model T-05). Needs the veth pair from `scripts/veth-test.sh` and
//! `CAP_NET_RAW`; otherwise it reports a skip and passes.

#[cfg(target_os = "linux")]
fn main() {
    use std::sync::mpsc;
    use std::time::Duration;

    use rawether::{Config, EtherType, FrameBuilder, RxMode};

    let (Ok(iface), Ok(peer)) = (std::env::var("RAWETHER_TEST_IFACE"), std::env::var("RAWETHER_TEST_PEER"))
    else {
        println!("drop_capabilities: skipped (no veth pair)");
        return;
    };
    let tx = Config::new(&iface).ethertypes([0xffffu16]).rx_mode(RxMode::Plain).open();
    let Ok(tx) = tx else {
        println!("drop_capabilities: skipped (no CAP_NET_RAW)");
        return;
    };
    let mut rx = Config::new(&peer)
        .ethertypes([EtherType::LOCAL_EXPERIMENTAL_1])
        .open()
        .expect("open the receiving socket");
    let status = |what: &str| -> u64 {
        let s = std::fs::read_to_string("/proc/self/status").expect("status");
        let line = s.lines().find(|l| l.starts_with(what)).expect(what);
        u64::from_str_radix(line[what.len()..].trim(), 16).expect("hex")
    };
    let had_setpcap = status("CapEff:") & (1 << 8) != 0;

    // A second thread that holds capabilities: the drop must refuse, naming it.
    let (release, wait) = mpsc::channel::<()>();
    let other = std::thread::spawn(move || wait.recv());
    let e = rawether::drop_capabilities().expect_err("another thread holds capabilities");
    assert!(e.to_string().starts_with("1 other thread(s)"), "{e}");
    release.send(()).expect("release");
    other.join().expect("join").expect("released");

    // Alone now: the drop succeeds and holds for every thread of the process.
    rawether::drop_capabilities().expect("the only thread");
    for task in std::fs::read_dir("/proc/self/task").expect("tasks") {
        let s = std::fs::read_to_string(task.expect("task").path().join("status")).expect("status");
        for set in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
            let line = s.lines().find(|l| l.starts_with(set)).expect(set);
            assert_eq!(u64::from_str_radix(line[set.len()..].trim(), 16), Ok(0), "{set} {line}");
        }
        assert!(s.lines().any(|l| l == "NoNewPrivs:\t1"), "no_new_privs");
    }
    if had_setpcap {
        // Root in a container: the bounding set lost CAP_NET_ADMIN (12) and CAP_NET_RAW (13).
        assert_eq!(status("CapBnd:") & (1 << 12 | 1 << 13), 0, "bounding set");
    }

    // The open sockets keep working; a new one is refused, naming the capability.
    let mut frame = Vec::new();
    FrameBuilder::new(rx.mac_address(), tx.mac_address(), EtherType::LOCAL_EXPERIMENTAL_1)
        .write(&mut frame, b"after the drop");
    tx.send(&frame).expect("send after the drop");
    let p = rx.recv(Some(Duration::from_secs(2))).expect("recv").expect("a frame after the drop");
    assert!(p.data().windows(14).any(|w| w == b"after the drop"));
    let e = Config::new(&iface).open().expect_err("no capability left");
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(e.to_string().contains("CAP_NET_RAW"), "{e}");
    println!("drop_capabilities: ok");
}

#[cfg(not(target_os = "linux"))]
fn main() {
    rawether::drop_capabilities().expect("a no-op off Linux");
    println!("drop_capabilities: ok (no-op)");
}
