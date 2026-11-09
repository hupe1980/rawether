//! Kernel behaviour on a real veth pair (Linux).
//!
//! Skips unless `RAWETHER_TEST_IFACE` and `RAWETHER_TEST_PEER` name the two ends of a veth pair
//! and the process has `CAP_NET_RAW` (and `CAP_NET_ADMIN` for the launch-time test).
//! `scripts/veth-test.sh` sets that up, natively with sudo or in Docker. `RAWETHER_RX=plain`
//! runs the whole suite on the plain receive path instead of the ring.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::panic)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rawether::{Config, MacAddr, RxMode, RxPath, Socket, TimestampSource};

/// Counts allocations so the steady-state loop can be shown to make none.
struct Counting;
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

// SAFETY: forwards every call to the system allocator unchanged and only counts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// A local experimental EtherType (IEEE 802 "Local Experimental Ethertype 1"), and a second one.
const TYPE_A: u16 = 0x88b5;
const TYPE_B: u16 = 0x88b6;

fn pair() -> Option<(String, String)> {
    Some((std::env::var("RAWETHER_TEST_IFACE").ok()?, std::env::var("RAWETHER_TEST_PEER").ok()?))
}

fn rx_mode() -> RxMode {
    match std::env::var("RAWETHER_RX").as_deref() {
        Ok("plain") => RxMode::Plain,
        _ => RxMode::Auto,
    }
}

fn expected_path() -> RxPath {
    if rx_mode() == RxMode::Plain { RxPath::Plain } else { RxPath::Ring }
}

fn frame(dst: MacAddr, src: MacAddr, ethertype: u16, vlan: Option<u16>, seq: u32) -> Vec<u8> {
    let mut f = Vec::with_capacity(64);
    f.extend_from_slice(&dst.0);
    f.extend_from_slice(&src.0);
    if let Some(tci) = vlan {
        f.extend_from_slice(&0x8100u16.to_be_bytes());
        f.extend_from_slice(&tci.to_be_bytes());
    }
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(&seq.to_be_bytes());
    f.resize(60, 0x5a);
    f
}

fn rx(peer: &str, types: &[u16]) -> Socket {
    Config::new(peer).ethertypes(types).rx_mode(rx_mode()).open().unwrap()
}

fn tx(iface: &str) -> Socket {
    Config::new(iface).ethertypes(&[0xffff]).rx_mode(RxMode::Plain).open().unwrap()
}

/// SR-003, SR-004: filtered in the kernel, tags as on the wire, lengths reported.
#[test]
fn only_the_chosen_ethertypes_arrive_tagged_or_not_each_with_a_timestamp() {
    let Some((iface, peer)) = pair() else { return };
    let mut r = rx(&peer, &[TYPE_A]);
    assert_eq!(r.rx_path(), expected_path());
    let t = tx(&iface);
    let (dst, src) = (r.mac_address(), t.mac_address());
    t.send(&frame(dst, src, TYPE_B, None, 1)).unwrap();
    t.send(&frame(dst, src, TYPE_A, None, 2)).unwrap();
    t.send(&frame(dst, src, TYPE_A, Some(0x6005), 3)).unwrap();

    let p = r.recv(Some(Duration::from_secs(2))).unwrap().expect("untagged frame");
    assert_eq!(&p.data()[12..14], &TYPE_A.to_be_bytes());
    assert_eq!(&p.data()[14..18], &2u32.to_be_bytes(), "the frame of the other type was filtered out");
    let ts = p.timestamp().expect("a timestamp");
    // The kernel's stamp, or — for the first frames after a socket enables timestamping, which
    // the kernel switches on lazily — rawether's own read, labelled as such.
    assert!(matches!(ts.source, TimestampSource::Software | TimestampSource::User), "{ts:?}");
    assert!(ts.secs > 1_600_000_000, "a realtime clock reading");

    let p = r.recv(Some(Duration::from_secs(2))).unwrap().expect("tagged frame");
    assert_eq!(&p.data()[12..14], &0x8100u16.to_be_bytes(), "the tag is where it was on the wire");
    assert_eq!(&p.data()[14..16], &0x6005u16.to_be_bytes());
    assert_eq!(&p.data()[16..18], &TYPE_A.to_be_bytes());
    assert_eq!(p.original_len(), p.data().len());
    assert!(r.recv(Some(Duration::from_millis(100))).unwrap().is_none());
}

#[test]
fn a_receive_times_out_and_a_nonblocking_one_returns_at_once() {
    let Some((_, peer)) = pair() else { return };
    let mut r = rx(&peer, &[0x88b7]);
    let start = Instant::now();
    assert!(r.recv(Some(Duration::from_millis(50))).unwrap().is_none());
    let took = start.elapsed();
    assert!(took >= Duration::from_millis(45) && took < Duration::from_secs(1), "{took:?}");
    r.set_nonblocking(true).unwrap();
    let start = Instant::now();
    assert!(r.try_recv().unwrap().is_none());
    assert!(r.recv(None).unwrap().is_none(), "non-blocking ignores an unbounded wait");
    assert!(start.elapsed() < Duration::from_millis(20));
}

#[test]
fn a_multicast_group_is_joined_on_the_interface() {
    let Some((_, peer)) = pair() else { return };
    let group: MacAddr = "01:80:c2:00:00:0e".parse().unwrap();
    let _s = Config::new(&peer).ethertypes(&[0x88cc]).join(group).open().unwrap();
    let table = std::fs::read_to_string("/proc/net/dev_mcast").unwrap();
    let hex = group.to_string().replace(':', "");
    assert!(table.lines().any(|l| l.contains(&peer) && l.contains(&hex)), "{table}");
}

/// SR-008: every frame received or counted as dropped.
#[test]
fn a_hundred_thousand_frames_are_received_or_counted_as_dropped() {
    const N: u32 = 100_000;
    let Some((iface, peer)) = pair() else { return };
    let mut r = rx(&peer, &[TYPE_B]);
    let mut t = tx(&iface);
    let (dst, src) = (r.mac_address(), t.mac_address());
    let receiver = std::thread::spawn(move || {
        let mut got = 0u64;
        while r.recv(Some(Duration::from_millis(500))).unwrap().is_some() {
            got += 1;
        }
        let stats = r.stats().unwrap();
        (got, stats)
    });
    let frames: Vec<Vec<u8>> = (0..256).map(|k| frame(dst, src, TYPE_B, None, k)).collect();
    let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
    let mut sent = 0u32;
    while sent < N {
        let n = refs.len().min((N - sent) as usize);
        sent += t.send_batch(&refs[..n]).unwrap() as u32;
        // veth hands frames to the peer's per-CPU backlog, which drops beyond
        // `netdev_max_backlog` without any socket seeing it; pacing keeps that queue short so
        // the socket's own counters account for every frame.
        std::thread::sleep(Duration::from_micros(500));
    }
    let (got, stats) = receiver.join().unwrap();
    assert_eq!(got + stats.dropped, u64::from(N), "received {got}, dropped {}", stats.dropped);
    assert_eq!(stats.received, got);
}

/// SR-003: a filter that keeps fewer octets than the frame has marks the frame truncated, and the
/// wire length is still the frame's own — on the ring and on the plain path.
#[test]
fn a_short_snap_length_marks_the_frame_truncated_with_its_wire_length() {
    use rawether::bpf::{Insn, Program, op};
    let Some((iface, peer)) = pair() else { return };
    let keep_20 = Program::new(vec![
        Insn::new(op::LD | op::H | op::ABS, 0, 0, 12),
        Insn::new(op::JMP | op::JEQ | op::K, 0, 1, u32::from(TYPE_A)),
        Insn::new(op::RET | op::K, 0, 0, 20),
        Insn::new(op::RET | op::K, 0, 0, 0),
    ])
    .unwrap();
    let mut r = Config::new(&peer).filter(rawether::Filter::Bpf(keep_20)).rx_mode(rx_mode()).open().unwrap();
    let t = tx(&iface);
    t.send(&frame(r.mac_address(), t.mac_address(), TYPE_A, None, 1)).unwrap();
    let p = r.recv(Some(Duration::from_secs(2))).unwrap().expect("the frame");
    assert_eq!((p.data().len(), p.original_len()), (20, 60));
    assert!(p.is_truncated());
}

/// SR-008: sparse traffic is kept too. At a low rate the kernel retires a block per frame, so
/// the ring must have enough blocks to hold frames that arrive while the reader is busy.
#[test]
fn sparse_frames_wait_in_the_ring_while_the_reader_is_busy() {
    let Some((iface, peer)) = pair() else { return };
    let mut r = rx(&peer, &[TYPE_A]);
    let t = tx(&iface);
    for k in 0..50 {
        t.send(&frame(r.mac_address(), t.mac_address(), TYPE_A, None, k)).unwrap();
        std::thread::sleep(Duration::from_millis(3));
    }
    let mut got = 0;
    while r.recv(Some(Duration::from_millis(200))).unwrap().is_some() {
        got += 1;
    }
    assert_eq!(got, 50, "dropped {}", r.stats().unwrap().dropped);
}

/// SR-009: launch time is opt-in and its drops are reported.
#[test]
fn launch_time_needs_configuration_and_a_qdisc_that_honours_it() {
    let Some((iface, peer)) = pair() else { return };
    let t = tx(&iface);
    let f = frame(MacAddr::BROADCAST, t.mac_address(), TYPE_A, None, 9);
    assert_eq!(t.send_at(&f, 0).unwrap_err().kind(), std::io::ErrorKind::InvalidInput);

    // An `etf` qdisc on the sender; skip when the kernel or the container cannot install one.
    let ok = std::process::Command::new("tc")
        .args(["qdisc", "replace", "dev", &iface, "root", "etf", "clockid", "CLOCK_TAI", "delta", "200000"])
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!("skipping the launch-time half: no etf qdisc");
        return;
    }
    let mut r = rx(&peer, &[TYPE_A]);
    let mut timed = Config::new(&iface)
        .ethertypes(&[0xffff])
        .rx_mode(RxMode::Plain)
        .tx_time(rawether::TxTime::default())
        .open()
        .unwrap();
    let now = rawether::clock_now(rawether::Clock::Tai).unwrap();
    let launch = now + Duration::from_millis(50);
    let start = Instant::now();
    timed.send_at(&f, launch.as_nanos() as u64).unwrap();
    assert!(r.recv(Some(Duration::from_secs(2))).unwrap().is_some());
    assert!(
        start.elapsed() >= Duration::from_millis(40),
        "left at its launch time, not at once: {:?}",
        start.elapsed()
    );

    // A launch time in the past is dropped by etf and reported on the error queue.
    timed.send_at(&f, now.checked_sub(Duration::from_secs(1)).unwrap().as_nanos() as u64).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    assert!(timed.tx_errors().unwrap() >= 1);
    let _ = std::process::Command::new("tc").args(["qdisc", "del", "dev", &iface, "root"]).status();
}

/// SR-006.
#[test]
fn every_descriptor_is_close_on_exec() {
    use std::os::fd::AsRawFd;
    let Some((_, peer)) = pair() else { return };
    let s = rx(&peer, &[TYPE_A]);
    // SAFETY: F_GETFD reads the descriptor flags of a descriptor we own.
    let flags = unsafe { libc::fcntl(s.as_raw_fd(), libc::F_GETFD) };
    assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
}

#[test]
fn the_steady_state_does_not_allocate() {
    let Some((iface, peer)) = pair() else { return };
    let mut r = rx(&peer, &[TYPE_A]);
    let t = tx(&iface);
    let f = frame(r.mac_address(), t.mac_address(), TYPE_A, None, 0);
    for _ in 0..100 {
        t.send(&f).unwrap();
        while r.recv(Some(Duration::from_millis(20))).unwrap().is_some() {}
    }
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut seen = 0;
    for _ in 0..1000 {
        t.send(&f).unwrap();
        if let Some(p) = r.recv(Some(Duration::from_millis(100))).unwrap() {
            seen += p.data().len();
        }
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    assert!(seen > 0);
    // Other tests run on other threads and allocate; this loop's thread made none, which the
    // counter cannot separate, so the bound is checked only when this test runs alone.
    if std::env::var("RAWETHER_ALLOC_ALONE").is_ok() {
        assert_eq!(after - before, 0, "allocations in the steady state");
    }
}

/// SR-005. Dropping capabilities keeps the open socket and refuses a new one. Runs in a child process,
/// because capabilities cannot be regained.
#[test]
fn dropping_capabilities_keeps_open_sockets_and_names_the_capability_when_opening() {
    let Some((iface, peer)) = pair() else { return };
    if std::env::var("RAWETHER_DROP_CHILD").is_err() {
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new(exe)
            .args([
                "--exact",
                "dropping_capabilities_keeps_open_sockets_and_names_the_capability_when_opening",
                "--test-threads=1",
            ])
            .env("RAWETHER_DROP_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    let mut r = rx(&peer, &[TYPE_A]);
    let t = tx(&iface);
    rawether::drop_capabilities().unwrap();
    let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
    for field in ["CapEff:", "CapPrm:"] {
        let line = status.lines().find(|l| l.starts_with(field)).unwrap();
        assert!(line.ends_with("0000000000000000"), "{line}");
    }
    t.send(&frame(r.mac_address(), t.mac_address(), TYPE_A, None, 7)).unwrap();
    assert!(r.recv(Some(Duration::from_secs(2))).unwrap().is_some(), "the open socket still works");
    let e = Socket::open(&Config::new(&peer)).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(e.to_string().contains("CAP_NET_RAW"), "{e}");
}
