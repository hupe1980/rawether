//! `Frame::new` and every accessor, plus `reply` and a rebuild, on arbitrary octets.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rawether::{Frame, MacAddr};

fuzz_target!(|data: &[u8]| {
    let Some(f) = Frame::new(data) else { return };
    assert!(f.header_len() <= data.len());
    assert_eq!(f.header_len() + f.payload().len(), data.len());
    assert!(f.vlan_tags().len() <= 2);
    let _ = (f.destination(), f.source(), f.ethertype());
    if let Some(reply) = f.reply(MacAddr([2, 0, 0, 0, 0, 1])) {
        let mut buf = Vec::new();
        reply.write(&mut buf, f.payload());
        let r = Frame::new(&buf).expect("a built frame has a header");
        assert_eq!((r.destination(), r.ethertype()), (f.source(), f.ethertype()));
    }
});
