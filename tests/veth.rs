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

use rawether::{Config, FrameBuilder, MacAddr, RxMode, RxPath, Socket, TagKind, TimestampSource, VlanTag};

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
    let mut b = FrameBuilder::new(dst, src, ethertype);
    if let Some(tci) = vlan {
        b = b.vlan(VlanTag::from_tci(TagKind::Customer, tci));
    }
    let mut f = Vec::with_capacity(64);
    b.write(&mut f, &seq.to_be_bytes());
    f
}

fn rx(peer: &str, types: &[u16]) -> Socket {
    Config::new(peer).ethertypes(types).rx_mode(rx_mode()).open().unwrap()
}

fn tx(iface: &str) -> Socket {
    Config::new(iface).ethertypes(&[0xffff]).rx_mode(RxMode::Plain).open().unwrap()
}

/// Threat model T-03, T-04 (SR-003, SR-004): filtered in the kernel, tags as on the wire, lengths reported.
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
    // Spec 002 story 1, scenario 4: the view reports the tag even when the driver stripped it
    // and rawether put it back.
    let f = p.frame().expect("a whole header");
    assert_eq!((f.source(), f.destination(), f.ethertype()), (src, dst, TYPE_A));
    assert_eq!(f.vlan_tags(), &[VlanTag::from_tci(TagKind::Customer, 0x6005)]);
    assert_eq!((f.vlan_tags()[0].pcp(), f.vlan_tags()[0].vid()), (3, 5));
    assert_eq!(&f.payload()[..4], &3u32.to_be_bytes());
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

/// Threat model T-08 (SR-008): every frame received or counted as dropped.
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

/// Threat model T-03 (SR-003).
///
/// A filter that keeps fewer octets than the frame has marks the frame truncated, and the
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

/// Threat model T-08 (SR-008).
///
/// Sparse traffic is kept too. At a low rate the kernel retires a block per frame, so
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

/// Threat model T-09 (SR-009): launch time is opt-in and its drops are reported.
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
        // CI's kernel has sch_etf and sets RAWETHER_REQUIRE_ETF, so the half cannot skip there.
        assert!(
            std::env::var_os("RAWETHER_REQUIRE_ETF").is_none(),
            "no etf qdisc, but RAWETHER_REQUIRE_ETF is set"
        );
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
    // Spec 003 SR-011: counted as a missed deadline, nothing else.
    let errors = timed.tx_errors().unwrap();
    assert!(errors.missed >= 1, "{errors:?}");
    let _ = std::process::Command::new("tc").args(["qdisc", "del", "dev", &iface, "root"]).status();
}

/// Threat model T-06 (SR-006).
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
    // Spec 002 SC-003: a frame built into one reused buffer for every send.
    let builder = FrameBuilder::new(r.mac_address(), t.mac_address(), TYPE_A);
    let mut built = Vec::with_capacity(1518);
    for _ in 0..100 {
        t.send(&f).unwrap();
        while r.recv(Some(Duration::from_millis(20))).unwrap().is_some() {}
    }
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut seen = 0;
    for k in 0..1000u32 {
        t.send(&f).unwrap();
        builder.write(&mut built, &k.to_be_bytes());
        t.send(&built).unwrap();
        while let Some(p) = r.recv(Some(Duration::from_millis(100))).unwrap() {
            seen += p.frame().map_or(0, |f| f.payload().len());
            if p.frame().is_some_and(|f| f.payload().starts_with(&k.to_be_bytes())) {
                break;
            }
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

/// A private veth pair for tests that take links down or delete them; removed on drop.
struct Pair(String, String);

impl Pair {
    fn new(tag: &str) -> Option<Pair> {
        let (a, b) = (format!("rwt{tag}0"), format!("rwt{tag}1"));
        let ip =
            |args: &[&str]| std::process::Command::new("ip").args(args).status().is_ok_and(|s| s.success());
        let _ = ip(&["link", "del", &a]);
        (ip(&["link", "add", &a, "type", "veth", "peer", "name", &b])
            && ip(&["link", "set", &a, "up"])
            && ip(&["link", "set", &b, "up"]))
        .then_some(Pair(a, b))
    }

    fn up(&self) {
        let s = std::process::Command::new("ip").args(["link", "set", &self.1, "up"]).status().unwrap();
        assert!(s.success());
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        let _ = std::process::Command::new("ip").args(["link", "del", &self.0]).status();
    }
}

/// Spec 003 SR-004 (threat model T-15): a link going down ends a waiting receive with an error
/// instead of spinning; frames flow again once it is back up.
#[test]
fn a_link_going_down_ends_a_receive_and_frames_return_after_it_comes_up() {
    let Some(_) = pair() else { return };
    let p = Pair::new("d").expect("a private veth pair (the main pair exists, so ip link works)");
    let t = tx(&p.0);
    let mut r = rx(&p.1, &[TYPE_A]);
    let f = frame(MacAddr::BROADCAST, t.mac_address(), TYPE_A, None, 1);
    let flip = {
        let name = p.1.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            std::process::Command::new("ip").args(["link", "set", &name, "down"]).status().unwrap();
        })
    };
    let start = Instant::now();
    let e = r.recv(Some(Duration::from_secs(5))).expect_err("the link went down");
    let took = start.elapsed();
    flip.join().unwrap();
    assert!(took < Duration::from_secs(1), "returned after {took:?}: {e}");
    assert!(e.to_string().contains(&p.1), "names the interface: {e}");
    p.up();
    std::thread::sleep(Duration::from_millis(100));
    t.send(&f).unwrap();
    assert!(r.recv(Some(Duration::from_secs(2))).unwrap().is_some(), "frames flow again");
}

/// Spec 003 SR-004: deleting the interface ends a waiting receive with an error, and later
/// receives wait out their timeout instead of spinning.
#[test]
fn deleting_the_interface_ends_a_receive() {
    let Some(_) = pair() else { return };
    let p = Pair::new("x").expect("a private veth pair (the main pair exists, so ip link works)");
    let mut r = rx(&p.1, &[TYPE_A]);
    let name = p.0.clone();
    let del = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        std::process::Command::new("ip").args(["link", "del", &name]).status().unwrap();
    });
    let start = Instant::now();
    assert!(r.recv(Some(Duration::from_secs(5))).is_err(), "the interface went away");
    assert!(start.elapsed() < Duration::from_secs(1));
    del.join().unwrap();
    let start = Instant::now();
    let later = r.recv(Some(Duration::from_millis(200)));
    assert!(later.is_err() || start.elapsed() >= Duration::from_millis(190), "{later:?}");
}

/// Spec 003 SR-008, SR-009: no timeout overflows, and an explicit ring the kernel refuses is an
/// error, not a quiet fallback.
#[test]
fn a_huge_timeout_waits_and_an_impossible_ring_is_refused() {
    let Some((_, peer)) = pair() else { return };
    let mut r = Config::new(&peer).ethertypes(&[0x88b7]).nonblocking(true).open().unwrap();
    assert!(r.recv(Some(Duration::MAX)).unwrap().is_none());
    let odd = rawether::RingConfig { block_size: 1 << 11, ..rawether::RingConfig::default() };
    let e = Config::new(&peer).rx_mode(RxMode::Ring(odd)).open().expect_err("not a page multiple");
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}");
}

/// Spec 003 FR-007: veth has no hardware timestamping, so a request for it reports software.
#[test]
fn hardware_timestamps_on_a_nic_without_them_report_software() {
    let Some((_, peer)) = pair() else { return };
    let r = Config::new(&peer).timestamping(rawether::Timestamping::Hardware).open().unwrap();
    assert_eq!(r.timestamping(), rawether::Timestamping::Software);
}

/// Spec 003 FR-016 (Q-06): without a qdisc that honours launch times, the launch time is ignored
/// and the frame leaves at once.
#[test]
fn a_launch_time_without_etf_is_sent_at_once() {
    let Some(_) = pair() else { return };
    let p = Pair::new("t").expect("a private veth pair (the main pair exists, so ip link works)");
    let mut r = rx(&p.1, &[TYPE_A]);
    let timed = Config::new(&p.0)
        .ethertypes(&[0xffff])
        .rx_mode(RxMode::Plain)
        .tx_time(rawether::TxTime::default())
        .open()
        .unwrap();
    let f = frame(MacAddr::BROADCAST, timed.mac_address(), TYPE_A, None, 1);
    let launch = rawether::clock_now(rawether::Clock::Tai).unwrap() + Duration::from_millis(300);
    let start = Instant::now();
    timed.send_at(&f, launch.as_nanos() as u64).unwrap();
    assert!(r.recv(Some(Duration::from_secs(2))).unwrap().is_some());
    assert!(start.elapsed() < Duration::from_millis(100), "held for {:?}", start.elapsed());
}
