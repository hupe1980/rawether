//! Receive throughput and latency over a veth pair, for rawether's ring and plain paths,
//! `pcap` and `pnet_datalink`, with the same rawether sender and traffic for each.
//!
//! Usage: `rawether-bench <sender-iface> <receiver-iface>` (needs CAP_NET_RAW).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use rawether::{Clock, Config, EtherType, FrameBuilder, MacAddr, RxMode};

const TYPE: EtherType = EtherType::LOCAL_EXPERIMENTAL_1;
const FLOOD: u64 = 500_000;
const PINGS: u64 = 5_000;
const PACE: Duration = Duration::from_micros(200);

#[derive(Clone, Copy, Debug)]
enum Receiver {
    RawetherRing,
    RawetherFrameRing,
    RawetherPlain,
    Pcap,
    Pnet,
}

impl Receiver {
    fn name(self) -> &'static str {
        match self {
            Receiver::RawetherRing => "rawether, block ring (default)",
            Receiver::RawetherFrameRing => "rawether, frame ring (`RxMode::low_latency()`)",
            Receiver::RawetherPlain => "rawether, plain (`recvmsg`)",
            Receiver::Pcap => "pcap 2 (libpcap, immediate mode)",
            Receiver::Pnet => "pnet_datalink 0.35",
        }
    }
}

fn now_ns() -> u64 {
    rawether::clock_now(Clock::Monotonic).expect("CLOCK_MONOTONIC").as_nanos() as u64
}

/// The payload of the frames that end a run: every receiver wakes on a frame, whatever its
/// timeout semantics (libpcap ignores its timeout in immediate mode).
const END: [u8; 8] = [0xff; 8];

/// Send end frames until the receiver thread has finished.
fn end(tx: &rawether::Socket, receiver: &std::thread::JoinHandle<impl Send>) {
    let mut f = Vec::new();
    FrameBuilder::new(MacAddr::BROADCAST, tx.mac_address(), TYPE).write(&mut f, &END);
    while !receiver.is_finished() {
        let _ = tx.send(&f);
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Calls `on_frame(payload)` for every frame of `TYPE` until an end frame arrives, or `stop`
/// is set and nothing has arrived for 300 ms.
fn receive(kind: Receiver, iface: &str, ready: &Barrier, stop: &AtomicBool, mut on_frame: impl FnMut(&[u8])) {
    let idle = Duration::from_millis(300);
    let mut last = Instant::now();
    let ended = std::cell::Cell::new(false);
    let mut handle = |d: &[u8], last: &mut Instant| {
        if d.len() >= 22 && d[12..14] == TYPE.0.to_be_bytes() {
            if d[14..22] == END {
                ended.set(true);
            } else {
                on_frame(&d[14..22]);
                *last = Instant::now();
            }
        }
    };
    let done = |last: Instant, ended: bool| ended || (stop.load(Ordering::Acquire) && last.elapsed() > idle);
    match kind {
        Receiver::RawetherRing | Receiver::RawetherFrameRing | Receiver::RawetherPlain => {
            let mode = match kind {
                Receiver::RawetherRing => RxMode::Auto,
                Receiver::RawetherFrameRing => RxMode::low_latency(),
                _ => RxMode::Plain,
            };
            let mut s = Config::new(iface).ethertypes([TYPE]).rx_mode(mode).open().expect("rawether");
            ready.wait();
            loop {
                match s.recv(Some(Duration::from_millis(50))).expect("recv") {
                    Some(p) => handle(p.data(), &mut last),
                    None => {}
                }
                if done(last, ended.get()) {
                    break;
                }
            }
        }
        Receiver::Pcap => {
            let mut c = pcap::Capture::from_device(iface)
                .expect("pcap device")
                .immediate_mode(true)
                .snaplen(256)
                .buffer_size(4 << 20)
                .timeout(50)
                .open()
                .expect("pcap open");
            c.filter(&format!("ether proto {:#06x}", TYPE.0), true).expect("pcap filter");
            ready.wait();
            loop {
                match c.next_packet() {
                    Ok(p) => handle(p.data, &mut last),
                    Err(pcap::Error::TimeoutExpired) => {}
                    Err(e) => panic!("pcap: {e}"),
                }
                if done(last, ended.get()) {
                    break;
                }
            }
        }
        Receiver::Pnet => {
            let ni = pnet_datalink::interfaces().into_iter().find(|i| i.name == iface).expect("pnet interface");
            let cfg = pnet_datalink::Config {
                read_timeout: Some(Duration::from_millis(50)),
                read_buffer_size: 1 << 16,
                ..Default::default()
            };
            let pnet_datalink::Channel::Ethernet(_tx, mut rx) = pnet_datalink::channel(&ni, cfg).expect("pnet") else {
                panic!("pnet: not an Ethernet channel")
            };
            ready.wait();
            loop {
                match rx.next() {
                    Ok(d) => handle(d, &mut last),
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) => {}
                    Err(e) => panic!("pnet: {e}"),
                }
                if done(last, ended.get()) {
                    break;
                }
            }
        }
    }
}

struct Throughput {
    received: u64,
    per_second: f64,
}

fn throughput(kind: Receiver, tx_if: &str, rx_if: &str) -> Throughput {
    let ready = Arc::new(Barrier::new(2));
    let stop = Arc::new(AtomicBool::new(false));
    let (r, s, rx_if) = (ready.clone(), stop.clone(), rx_if.to_owned());
    let receiver = std::thread::spawn(move || {
        let (mut n, mut first, mut last) = (0u64, None, Instant::now());
        receive(kind, &rx_if, &r, &s, |_| {
            n += 1;
            first.get_or_insert_with(Instant::now);
            last = Instant::now();
        });
        (n, first.map_or(Duration::ZERO, |f| last - f))
    });
    let mut tx = Config::new(tx_if).ethertypes([EtherType(0xffff)]).rx_mode(RxMode::Plain).open().expect("sender");
    let mut frames = vec![Vec::new(); 64];
    for f in &mut frames {
        FrameBuilder::new(MacAddr::BROADCAST, tx.mac_address(), TYPE).write(f, &[0; 8]);
    }
    let batch: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
    ready.wait();
    std::thread::sleep(Duration::from_millis(100));
    let mut sent = 0;
    while sent < FLOOD {
        sent += tx.send_batch(&batch).unwrap_or(0) as u64;
    }
    stop.store(true, Ordering::Release);
    std::thread::sleep(Duration::from_millis(400));
    end(&tx, &receiver);
    let (received, span) = receiver.join().expect("receiver");
    Throughput { received, per_second: received as f64 / span.as_secs_f64().max(1e-9) }
}

fn latency(kind: Receiver, tx_if: &str, rx_if: &str) -> Vec<u64> {
    let ready = Arc::new(Barrier::new(2));
    let stop = Arc::new(AtomicBool::new(false));
    let (r, s, rx_if) = (ready.clone(), stop.clone(), rx_if.to_owned());
    let receiver = std::thread::spawn(move || {
        let mut v = Vec::with_capacity(PINGS as usize);
        receive(kind, &rx_if, &r, &s, |p| {
            let sent = u64::from_be_bytes(p.try_into().expect("8 octets"));
            v.push(now_ns().saturating_sub(sent));
        });
        v
    });
    let tx = Config::new(tx_if).ethertypes([EtherType(0xffff)]).rx_mode(RxMode::Plain).open().expect("sender");
    let header = FrameBuilder::new(MacAddr::BROADCAST, tx.mac_address(), TYPE);
    let mut f = Vec::with_capacity(64);
    ready.wait();
    std::thread::sleep(Duration::from_millis(100));
    let mut next = Instant::now();
    for _ in 0..PINGS {
        while Instant::now() < next {
            std::hint::spin_loop();
        }
        next += PACE;
        header.write(&mut f, &now_ns().to_be_bytes());
        tx.send(&f).expect("send");
    }
    stop.store(true, Ordering::Release);
    std::thread::sleep(Duration::from_millis(400));
    end(&tx, &receiver);
    let mut v = receiver.join().expect("receiver");
    v.sort_unstable();
    v
}

fn pct(v: &[u64], p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v[((v.len() - 1) as f64 * p).round() as usize] as f64 / 1000.0
}

fn main() {
    let mut a = std::env::args().skip(1);
    let (Some(tx_if), Some(rx_if)) = (a.next(), a.next()) else {
        eprintln!("usage: rawether-bench <sender-iface> <receiver-iface>");
        std::process::exit(2);
    };
    let kinds =
        [Receiver::RawetherRing, Receiver::RawetherFrameRing, Receiver::RawetherPlain, Receiver::Pcap, Receiver::Pnet];
    println!("| Receiver | Frames/s received | Received of {FLOOD} | Latency p50 | p99 | max |");
    println!("|---|---|---|---|---|---|");
    let mut failed = false;
    for kind in kinds {
        let t = throughput(kind, &tx_if, &rx_if);
        let l = latency(kind, &tx_if, &rx_if);
        failed |= t.received == 0 || l.len() < PINGS as usize * 9 / 10;
        println!(
            "| {} | {:.0} k | {:.1} % | {:.0} µs | {:.0} µs | {:.0} µs |",
            kind.name(),
            t.per_second / 1000.0,
            t.received as f64 * 100.0 / FLOOD as f64,
            pct(&l, 0.5),
            pct(&l, 0.99),
            pct(&l, 1.0),
        );
    }
    if failed {
        eprintln!("a receiver missed most of its frames");
        std::process::exit(1);
    }
}
