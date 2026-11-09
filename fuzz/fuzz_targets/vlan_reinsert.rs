//! VLAN tag re-insertion at arbitrary offsets and lengths.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [a, b, c, d, rest @ ..] = data else { return };
    let mut buf = rest.to_vec();
    rawether::fuzzing::vlan_reinsert(&mut buf, usize::from(*a), usize::from(*b), 0x8100, u16::from_be_bytes([*c, *d]));
});
