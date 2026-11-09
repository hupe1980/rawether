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

use rawether::{
    Config, EtherType, FrameBuilder, MacAddr, RxMode, RxPath, Socket, TagKind, TimestampSource, VlanTag,
};

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
const TYPE_A: EtherType = EtherType::LOCAL_EXPERIMENTAL_1;
const TYPE_B: EtherType = EtherType::LOCAL_EXPERIMENTAL_2;

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

fn frame(dst: MacAddr, src: MacAddr, ethertype: EtherType, vlan: Option<u16>, seq: u32) -> Vec<u8> {
    let mut b = FrameBuilder::new(dst, src, ethertype);
    if let Some(tci) = vlan {
        b = b.vlan(VlanTag::from_tci(TagKind::Customer, tci));
    }
    let mut f = Vec::with_capacity(64);
    b.write(&mut f, &seq.to_be_bytes());
    f
}

fn rx(peer: &str, types: &[EtherType]) -> Socket {
    Config::new(peer).ethertypes(types).rx_mode(rx_mode()).open().unwrap()
}

fn tx(iface: &str) -> Socket {
    Config::new(iface).ethertypes([0xffffu16]).rx_mode(RxMode::Plain).open().unwrap()
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
    assert_eq!(&p.data()[12..14], &TYPE_A.0.to_be_bytes());
    assert_eq!(&p.data()[14..18], &2u32.to_be_bytes(), "the frame of the other type was filtered out");
    let ts = p.timestamp().expect("a timestamp");
    // The kernel's stamp, or — for the first frames after a socket enables timestamping, which
    // the kernel switches on lazily — rawether's own read, labelled as such.
    assert!(matches!(ts.source, TimestampSource::Software | TimestampSource::User), "{ts:?}");
    assert!(ts.secs > 1_600_000_000, "a realtime clock reading");

    let p = r.recv(Some(Duration::from_secs(2))).unwrap().expect("tagged frame");
    assert_eq!(&p.data()[12..14], &0x8100u16.to_be_bytes(), "the tag is where it was on the wire");
    assert_eq!(&p.data()[14..16], &0x6005u16.to_be_bytes());
    assert_eq!(&p.data()[16..18], &TYPE_A.0.to_be_bytes());
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
    let mut r = rx(&peer, &[EtherType(0x88b7)]);
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
    let _s = Config::new(&peer).ethertypes([0x88ccu16]).join(group).open().unwrap();
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
        Insn::new(op::JMP | op::JEQ | op::K, 0, 1, u32::from(TYPE_A.0)),
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

/// An `etf` qdisc on an interface, removed on drop.
struct Etf<'a>(&'a str);
impl Drop for Etf<'_> {
    fn drop(&mut self) {
        let _ = std::process::Command::new("tc").args(["qdisc", "del", "dev", self.0, "root"]).status();
    }
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
    // Remove the qdisc even if an assertion fails: etf refuses untimed frames, which would break
    // every later test on this interface.
    let _etf = Etf(&iface);
    let mut r = rx(&peer, &[TYPE_A]);
    let mut timed = Config::new(&iface)
        .ethertypes([0xffffu16])
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

    // Spec 003 SR-011: a launch time already past is refused at once. etf drops it at enqueue,
    // so send_at fails, and the error queue reports invalid parameters (not a missed slot).
    let past = now.checked_sub(Duration::from_secs(1)).unwrap().as_nanos() as u64;
    let e = timed.send_at(&f, past).expect_err("etf refuses a launch time in the past");
    assert!(e.to_string().contains("launch time"), "{e}");
    let errors = timed.tx_errors().unwrap();
    assert_eq!((errors.invalid, errors.missed), (1, 0), "{errors:?}");
    assert_eq!(timed.tx_errors().unwrap().dropped(), 0, "drained");
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
    // Spec 007 FR-011: sending with transmit timestamps and reading them allocates nothing.
    let mut st = stamped(&iface);
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
        let id = st.next_tx_id();
        st.send(&f).unwrap();
        assert_eq!(st.tx_timestamp(Some(Duration::from_secs(1))).unwrap().map(|t| t.id), Some(id));
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
    let mut r = Config::new(&peer).ethertypes([0x88b7u16]).nonblocking(true).open().unwrap();
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
        .ethertypes([0xffffu16])
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

/// A socket on `iface` that sends with software transmit timestamps and receives nothing.
fn stamped(iface: &str) -> Socket {
    Config::new(iface)
        .ethertypes([0xffffu16])
        .rx_mode(rx_mode())
        .tx_timestamping(rawether::Timestamping::Software)
        .open()
        .unwrap()
}

/// CPU time this thread has used, in clock ticks (`/proc/thread-self/stat`, utime + stime).
fn cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/thread-self/stat").unwrap();
    let fields: Vec<&str> = stat.rsplit_once(')').unwrap().1.split_whitespace().collect();
    fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
}

/// Spec 007 SR-001: every frame, sent alone or in a batch, gets the transmit timestamp of the
/// identifier the socket announced for it.
#[test]
fn transmit_timestamps_carry_the_announced_ids() {
    let Some((iface, _)) = pair() else { return };
    let mut s = stamped(&iface);
    assert_eq!(s.tx_timestamping(), rawether::Timestamping::Software);
    let f = frame(MacAddr::BROADCAST, s.mac_address(), TYPE_B, None, 0);
    let before = rawether::clock_now(rawether::Clock::Realtime).unwrap();
    let mut announced = Vec::new();
    let mut got = Vec::new();
    // Read as you go: the kernel keeps only a few hundred unread reports (its receive buffer).
    let collect = |s: &mut Socket, got: &mut Vec<u32>, upto: usize| {
        while got.len() < upto {
            let t = s.tx_timestamp(Some(Duration::from_secs(2))).unwrap().expect("a timestamp per frame");
            assert_eq!(t.timestamp.source, TimestampSource::Software);
            assert!(t.timestamp.as_nanos() >= before.as_nanos() as i128, "not before the sends");
            got.push(t.id);
        }
    };
    for k in 0..1000u32 {
        if k % 100 < 50 {
            announced.push(s.next_tx_id());
            s.send(&f).unwrap();
        } else if k % 100 == 50 {
            let batch = [f.as_slice(); 50];
            let first = s.next_tx_id();
            assert_eq!(s.send_batch(&batch).unwrap(), 50);
            announced.extend((0..50).map(|i| first.wrapping_add(i)));
            assert_eq!(s.next_tx_id(), first.wrapping_add(50));
            collect(&mut s, &mut got, announced.len());
        }
    }
    assert_eq!(announced.len(), 1000);
    collect(&mut s, &mut got, 1000);
    got.sort_unstable();
    announced.sort_unstable();
    assert_eq!(got, announced);
    // Spec 007 US1 scenario 4: nothing waiting → None after the timeout, at once when non-blocking.
    let start = Instant::now();
    assert!(s.tx_timestamp(Some(Duration::from_millis(50))).unwrap().is_none());
    assert!(start.elapsed() >= Duration::from_millis(45));
    s.set_nonblocking(true).unwrap();
    let start = Instant::now();
    assert!(s.tx_timestamp(None).unwrap().is_none());
    assert!(start.elapsed() < Duration::from_millis(20));
    // Without transmit timestamps the call says how to turn them on.
    let mut plain = tx(&iface);
    assert_eq!(plain.tx_timestamp(None).unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
}

/// Spec 007 SR-003: unread timestamps are bounded and counted, and a receive does not spin while
/// timestamps wait.
#[test]
fn unread_transmit_timestamps_are_bounded_and_receiving_does_not_spin() {
    let Some((iface, _)) = pair() else { return };
    let mut s = stamped(&iface);
    let f = frame(MacAddr::BROADCAST, s.mac_address(), TYPE_B, None, 0);
    for _ in 0..15 {
        let batch = [f.as_slice(); 100];
        s.send_batch(&batch).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        // A receive drains the error queue into the socket's own queue as it waits.
        assert!(s.recv(Some(Duration::from_millis(1))).unwrap().is_none());
    }
    let batch = [f.as_slice(); 100];
    s.send_batch(&batch).unwrap(); // left on the kernel's error queue
    std::thread::sleep(Duration::from_millis(5));
    let (start, cpu) = (Instant::now(), cpu_ticks());
    assert!(s.recv(Some(Duration::from_millis(200))).unwrap().is_none());
    assert!(start.elapsed() >= Duration::from_millis(190), "{:?}", start.elapsed());
    assert!(cpu_ticks() - cpu <= 5, "receiving spun: {} ticks", cpu_ticks() - cpu);
    let mut kept = 0;
    while s.tx_timestamp(Some(Duration::ZERO)).unwrap().is_some() {
        kept += 1;
    }
    assert_eq!(kept, 1024);
    assert_eq!(s.tx_errors().unwrap().timestamps_lost, 1600 - 1024);
}

/// Spec 007 SR-001 scenario 2, SR-004: a launch time the qdisc refuses does not shift later
/// identifiers, and launch-time reports and timestamps are both kept, whichever is read first.
#[test]
fn ids_stay_exact_after_a_refused_send_and_reports_coexist() {
    let Some(_) = pair() else { return };
    let p = Pair::new("s").expect("a private veth pair (the main pair exists, so ip link works)");
    let ok = std::process::Command::new("tc")
        .args(["qdisc", "replace", "dev", &p.0, "root", "etf", "clockid", "CLOCK_TAI", "delta", "200000"])
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        assert!(
            std::env::var_os("RAWETHER_REQUIRE_ETF").is_none(),
            "no etf qdisc, but RAWETHER_REQUIRE_ETF is set"
        );
        return;
    }
    let _etf = Etf(&p.0);
    for timestamps_first in [true, false] {
        let mut s = Config::new(&p.0)
            .ethertypes([0xffffu16])
            .rx_mode(RxMode::Plain)
            .tx_time(rawether::TxTime::default())
            .tx_timestamping(rawether::Timestamping::Software)
            .open()
            .unwrap();
        let f = frame(MacAddr::BROADCAST, s.mac_address(), TYPE_A, None, 0);
        let now = rawether::clock_now(rawether::Clock::Tai).unwrap();
        let refused = s.next_tx_id();
        assert!(s.send_at(&f, now.checked_sub(Duration::from_secs(1)).unwrap().as_nanos() as u64).is_err());
        assert_eq!(s.next_tx_id(), refused, "a refused frame uses no identifier");
        let mut announced = Vec::new();
        for k in 0..10u64 {
            announced.push(s.next_tx_id());
            s.send_at(&f, (now + Duration::from_millis(5 + k)).as_nanos() as u64).unwrap();
        }
        std::thread::sleep(Duration::from_millis(50));
        let read_stamps = |s: &mut Socket| {
            let mut ids: Vec<u32> =
                std::iter::from_fn(|| s.tx_timestamp(Some(Duration::from_secs(1))).unwrap())
                    .take(10)
                    .map(|t| t.id)
                    .collect();
            ids.sort_unstable();
            ids
        };
        let (ids, errors) = if timestamps_first {
            let ids = read_stamps(&mut s);
            (ids, s.tx_errors().unwrap())
        } else {
            let errors = s.tx_errors().unwrap();
            (read_stamps(&mut s), errors)
        };
        assert_eq!(ids, announced, "timestamps first: {timestamps_first}");
        assert_eq!((errors.invalid, errors.missed), (1, 0), "timestamps first: {timestamps_first}");
    }
}

/// Spec 007 SR-002, FR-006/FR-007: veth stamps in software only, and says so.
#[test]
fn veth_reports_software_timestamping_and_no_hardware_clock() {
    let Some((iface, _)) = pair() else { return };
    let info = rawether::timestamp_info(&iface).unwrap();
    assert!(info.software_rx && info.software_tx, "{info:?}");
    assert!(!info.hardware_rx && !info.hardware_tx && info.phc_index.is_none(), "{info:?}");
    assert_eq!(rawether::timestamp_info("no-such-if0").unwrap_err().kind(), std::io::ErrorKind::NotFound);
    let s = Config::new(&iface).tx_timestamping(rawether::Timestamping::Hardware).open().unwrap();
    assert_eq!(s.tx_timestamping(), rawether::Timestamping::Software);
    assert_eq!(s.timestamp_info().unwrap(), info);
}
