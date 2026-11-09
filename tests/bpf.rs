//! Kernel behaviour through BPF devices on a real interface pair (macOS `feth`, FreeBSD
//! `epair`).
//!
//! Skips unless `RAWETHER_TEST_IFACE` and `RAWETHER_TEST_PEER` name the two ends of a pair;
//! `RAWETHER_REQUIRE_PAIR` turns the skip into a failure (CI). `scripts/bpf-test.sh` sets it up.
//! Spec 004.

#![cfg(any(target_os = "macos", target_os = "freebsd"))]
#![allow(clippy::unwrap_used, clippy::panic)]

use std::time::{Duration, Instant};

use rawether::bpf::{Insn, Program, op};
use rawether::{Config, EtherType, Filter, FrameBuilder, MacAddr, Socket, TagKind, TimestampSource, VlanTag};

const TYPE_A: EtherType = EtherType::LOCAL_EXPERIMENTAL_1;
const TYPE_B: EtherType = EtherType::LOCAL_EXPERIMENTAL_2;

/// Spec 004 SR-001: in CI a missing pair is a failure, not a skip.
fn pair() -> Option<(String, String)> {
    let p = std::env::var("RAWETHER_TEST_IFACE").ok().zip(std::env::var("RAWETHER_TEST_PEER").ok());
    assert!(
        p.is_some() || std::env::var_os("RAWETHER_REQUIRE_PAIR").is_none(),
        "RAWETHER_REQUIRE_PAIR is set but RAWETHER_TEST_IFACE/RAWETHER_TEST_PEER name no pair"
    );
    p
}

fn frame(src: MacAddr, ethertype: EtherType, vlan: Option<u16>, seq: u32) -> Vec<u8> {
    let mut b = FrameBuilder::new(MacAddr::BROADCAST, src, ethertype);
    if let Some(tci) = vlan {
        b = b.vlan(VlanTag::from_tci(TagKind::Customer, tci));
    }
    let mut f = Vec::new();
    b.write(&mut f, &seq.to_be_bytes());
    f
}

fn open(name: &str, types: &[EtherType]) -> Socket {
    Config::new(name).ethertypes(types).open().unwrap()
}

/// The next frame of ours, skipping anything else the interface sees.
fn next(r: &mut Socket) -> Option<(Vec<u8>, usize, Option<rawether::Timestamp>)> {
    let p = r.recv(Some(Duration::from_secs(2))).unwrap()?;
    Some((p.data().to_vec(), p.original_len(), p.timestamp()))
}

#[test]
fn only_the_chosen_ethertypes_arrive_tagged_or_not_with_timestamps() {
    let Some((iface, peer)) = pair() else { return };
    let mut r = open(&peer, &[TYPE_A]);
    let t = open(&iface, &[EtherType(0xffff)]);
    t.send(&frame(t.mac_address(), TYPE_B, None, 1)).unwrap();
    t.send(&frame(t.mac_address(), TYPE_A, None, 2)).unwrap();
    t.send(&frame(t.mac_address(), TYPE_A, Some(0x6005), 3)).unwrap();

    let (d, _, ts) = next(&mut r).expect("the untagged frame");
    let f = rawether::Frame::new(&d).unwrap();
    assert_eq!(
        (f.ethertype(), &f.payload()[..4]),
        (TYPE_A, &2u32.to_be_bytes()[..]),
        "type B was filtered out"
    );
    let ts = ts.expect("a timestamp");
    assert_eq!(ts.source, TimestampSource::Software);
    assert!(ts.secs > 1_600_000_000);

    let (d, _, _) = next(&mut r).expect("the tagged frame");
    let f = rawether::Frame::new(&d).unwrap();
    assert_eq!(f.vlan_tags(), &[VlanTag::from_tci(TagKind::Customer, 0x6005)], "the tag as on the wire");
    assert_eq!(f.ethertype(), TYPE_A);
    assert!(r.recv(Some(Duration::from_millis(100))).unwrap().is_none());
}

#[test]
fn a_socket_does_not_see_its_own_frames() {
    let Some((iface, _)) = pair() else { return };
    let mut s = open(&iface, &[TYPE_A]);
    s.send(&frame(s.mac_address(), TYPE_A, None, 9)).unwrap();
    assert!(s.recv(Some(Duration::from_millis(200))).unwrap().is_none());
}

#[test]
fn a_thousand_frames_are_received_or_counted_as_dropped() {
    let Some((iface, peer)) = pair() else { return };
    let mut r = open(&peer, &[TYPE_A]);
    let mut t = open(&iface, &[EtherType(0xffff)]);
    let frames: Vec<Vec<u8>> = (0..1000).map(|k| frame(t.mac_address(), TYPE_A, None, k)).collect();
    let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
    // Sent and drained in batches so the device buffer is read as it fills.
    let mut got = 0u64;
    for chunk in refs.chunks(100) {
        assert_eq!(t.send_batch(chunk).unwrap(), chunk.len());
        while r.recv(Some(Duration::from_millis(50))).unwrap().is_some() {
            got += 1;
        }
    }
    while r.recv(Some(Duration::from_millis(200))).unwrap().is_some() {
        got += 1;
    }
    let stats = r.stats().unwrap();
    assert_eq!(stats.received, got, "received counts what was read");
    assert_eq!(got + stats.dropped, 1000, "received {got}, dropped {}", stats.dropped);
}

#[test]
fn a_short_snap_length_marks_the_frame_truncated_with_its_wire_length() {
    let Some((iface, peer)) = pair() else { return };
    let keep_20 = Program::new(vec![
        Insn::new(op::LD | op::H | op::ABS, 0, 0, 12),
        Insn::new(op::JMP | op::JEQ | op::K, 0, 1, u32::from(TYPE_A.0)),
        Insn::new(op::RET | op::K, 0, 0, 20),
        Insn::new(op::RET | op::K, 0, 0, 0),
    ])
    .unwrap();
    let mut r = Config::new(&peer).filter(Filter::Bpf(keep_20)).open().unwrap();
    let t = open(&iface, &[EtherType(0xffff)]);
    t.send(&frame(t.mac_address(), TYPE_A, None, 1)).unwrap();
    let (d, wire, _) = next(&mut r).expect("the frame");
    assert_eq!((d.len(), wire), (20, 60));
}

#[test]
fn a_receive_times_out() {
    let Some((_, peer)) = pair() else { return };
    let mut r = open(&peer, &[EtherType(0x88b7)]);
    let start = Instant::now();
    assert!(r.recv(Some(Duration::from_millis(100))).unwrap().is_none());
    let took = start.elapsed();
    assert!(took >= Duration::from_millis(95) && took < Duration::from_secs(1), "{took:?}");
}

/// Spec 004 US2 (Q-15): whether a user with `/dev/bpf*` access but not root can join a
/// multicast group. Either outcome is recorded; a failure must name what was refused.
#[test]
fn joining_a_multicast_group_works_or_says_why() {
    let Some((_, peer)) = pair() else { return };
    let group: MacAddr = "01:80:c2:00:00:0e".parse().unwrap();
    let root = std::process::Command::new("id").arg("-u").output().is_ok_and(|o| o.stdout.starts_with(b"0"));
    match Config::new(&peer).ethertypes([EtherType::LLDP]).join(group).open() {
        Ok(_) => println!("multicast join: ok (root: {root})"),
        Err(e) => {
            println!("multicast join: {e} (root: {root})");
            assert!(e.to_string().contains("SIOCADDMULTI"), "{e}");
        }
    }
}
