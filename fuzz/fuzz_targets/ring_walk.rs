//! A TPACKET_V3 block as the kernel might (mis)write it: walk it and re-insert stripped tags.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut block = data.to_vec();
    rawether::fuzzing::ring_walk(&mut block);
    // The same octets as one slot of the per-frame ring.
    rawether::fuzzing::frame_slot(data);
});
