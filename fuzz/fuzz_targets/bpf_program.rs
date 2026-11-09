//! `Program::new` on arbitrary instructions, and `run` of every accepted program.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rawether::bpf::{Insn, Program};

fuzz_target!(|data: &[u8]| {
    let (code, frame) = data.split_at(data.len().min(8 * 64));
    let insns: Vec<Insn> = code
        .chunks_exact(8)
        .map(|c| Insn::new(u16::from_le_bytes([c[0], c[1]]), c[2], c[3], u32::from_le_bytes([c[4], c[5], c[6], c[7]])))
        .collect();
    if let Ok(p) = Program::new(insns) {
        let _ = p.run(frame);
    }
});
