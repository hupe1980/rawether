//! Classic BPF: the in-kernel filter language both backends run.
//!
//! A program is attached before the socket is bound, so a frame the filter rejects never
//! reaches user space. [`Program::ethertypes`] builds the common case; [`Program::new`] takes
//! any program, and [`Program::run`] interprets one, so a filter can be tested without a
//! kernel. The instruction layout is the same on Linux (`struct sock_filter`) and on the BSDs
//! (`struct bpf_insn`).

use std::io;

/// One classic-BPF instruction: `{ code, jt, jf, k }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Insn {
    /// Opcode: class | size | mode, or class | op | source.
    pub code: u16,
    /// Jump offset when the condition holds, relative to the next instruction.
    pub jt: u8,
    /// Jump offset when the condition fails, relative to the next instruction.
    pub jf: u8,
    /// The constant operand.
    pub k: u32,
}

impl Insn {
    /// An instruction from its four fields.
    pub const fn new(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
        Insn { code, jt, jf, k }
    }
}

/// Opcode constants, as in `<linux/bpf_common.h>` and `<net/bpf.h>`.
#[allow(missing_docs)]
pub mod op {
    pub const LD: u16 = 0x00;
    pub const LDX: u16 = 0x01;
    pub const ST: u16 = 0x02;
    pub const STX: u16 = 0x03;
    pub const ALU: u16 = 0x04;
    pub const JMP: u16 = 0x05;
    pub const RET: u16 = 0x06;
    pub const MISC: u16 = 0x07;

    pub const W: u16 = 0x00;
    pub const H: u16 = 0x08;
    pub const B: u16 = 0x10;

    pub const IMM: u16 = 0x00;
    pub const ABS: u16 = 0x20;
    pub const IND: u16 = 0x40;
    pub const MEM: u16 = 0x60;
    pub const LEN: u16 = 0x80;
    pub const MSH: u16 = 0xa0;

    pub const ADD: u16 = 0x00;
    pub const SUB: u16 = 0x10;
    pub const MUL: u16 = 0x20;
    pub const DIV: u16 = 0x30;
    pub const OR: u16 = 0x40;
    pub const AND: u16 = 0x50;
    pub const LSH: u16 = 0x60;
    pub const RSH: u16 = 0x70;
    pub const NEG: u16 = 0x80;
    pub const MOD: u16 = 0x90;
    pub const XOR: u16 = 0xa0;

    pub const JA: u16 = 0x00;
    pub const JEQ: u16 = 0x10;
    pub const JGT: u16 = 0x20;
    pub const JGE: u16 = 0x30;
    pub const JSET: u16 = 0x40;

    pub const K: u16 = 0x00;
    pub const X: u16 = 0x08;
    pub const A: u16 = 0x10;

    pub const TAX: u16 = 0x00;
    pub const TXA: u16 = 0x80;
}

/// The largest program the kernel accepts (`BPF_MAXINSNS`).
pub const MAX_INSNS: usize = 4096;

/// How many octets an accepting filter asks the kernel to keep: everything.
pub const ACCEPT: u32 = 0x0004_0000;

/// The two VLAN tag protocol identifiers a filter looks through: 802.1Q and 802.1ad.
const TPIDS: [u16; 2] = [0x8100, 0x88a8];

/// A validated classic-BPF program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    insns: Vec<Insn>,
}

impl Program {
    /// A program from its instructions, checked the way the kernel checks it: not empty, not
    /// longer than [`MAX_INSNS`], every jump inside the program, every scratch-memory index
    /// below 16, and the last instruction a return.
    pub fn new(insns: Vec<Insn>) -> io::Result<Program> {
        let invalid =
            |why: String| io::Error::new(io::ErrorKind::InvalidInput, format!("BPF program: {why}"));
        if insns.is_empty() || insns.len() > MAX_INSNS {
            return Err(invalid(format!("{} instructions; 1 to {MAX_INSNS} allowed", insns.len())));
        }
        for (pc, i) in insns.iter().enumerate() {
            let class = i.code & 0x07;
            if class == op::JMP {
                // Checked: on a 32-bit target `next + k` can wrap for a large `k`.
                let next = pc + 1;
                let target = |off: usize| next.checked_add(off).filter(|&t| t < insns.len());
                let ok = if i.code & 0xf0 == op::JA {
                    target(i.k as usize).is_some()
                } else {
                    target(usize::from(i.jt)).is_some() && target(usize::from(i.jf)).is_some()
                };
                if !ok {
                    return Err(invalid(format!("instruction {pc} jumps past the end")));
                }
            }
            let mem = matches!(class, op::ST | op::STX)
                || (matches!(class, op::LD | op::LDX) && i.code & 0xe0 == op::MEM);
            if mem && i.k >= 16 {
                return Err(invalid(format!("instruction {pc} uses scratch memory slot {}", i.k)));
            }
        }
        if insns.last().is_some_and(|i| i.code & 0x07 != op::RET) {
            return Err(invalid(String::from("the last instruction must be a return")));
        }
        Ok(Program { insns })
    }

    /// Accept frames whose EtherType is one of `types`, untagged, single-tagged (802.1Q or
    /// 802.1ad) or double-tagged; reject everything else.
    ///
    /// A driver that strips the outer tag into metadata leaves the inner EtherType at offset 12,
    /// which the first test covers, so the program is right whether or not tags are stripped.
    pub fn ethertypes(types: &[u16]) -> io::Result<Program> {
        if types.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an EtherType filter needs at least one type",
            ));
        }
        // Each block is `ldh [off]; jeq T1 …; jeq TPID…` and every jump is relative, so the
        // longest jump grows with the set; 64 types keeps every offset well inside a `u8`.
        if types.len() > 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at most 64 EtherTypes; use Filter::Bpf for more",
            ));
        }
        let mut b = Builder::default();
        // Untagged (or tag stripped): the type at 12.
        b.block(12, types, Some(Label::Tagged), Label::Reject);
        b.label(Label::Tagged);
        // One tag: the type at 16, or a second tag there.
        b.block(16, types, Some(Label::Double), Label::Reject);
        b.label(Label::Double);
        b.block(20, types, None, Label::Reject);
        b.label(Label::Reject);
        b.push(Insn::new(op::RET | op::K, 0, 0, 0), None);
        b.label(Label::Accept);
        b.push(Insn::new(op::RET | op::K, 0, 0, ACCEPT), None);
        Program::new(b.finish())
    }

    /// The instructions.
    pub fn instructions(&self) -> &[Insn] {
        &self.insns
    }

    /// Run the program over `frame` the way the kernel does, and return what it returns: 0 to
    /// drop, otherwise the number of octets to keep.
    ///
    /// A load beyond the end of the frame ends the program with 0, as in the kernel. Linux's
    /// ancillary loads (offsets from `SKF_AD_OFF`) are not modelled and also return 0.
    pub fn run(&self, frame: &[u8]) -> u32 {
        let (mut a, mut x) = (0u32, 0u32);
        let mut mem = [0u32; 16];
        let mut pc = 0usize;
        let len = frame.len() as u32;
        let load = |at: u32, size: u16| -> Option<u32> {
            let at = at as usize;
            match size {
                op::W => {
                    frame.get(at..at.checked_add(4)?).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                }
                op::H => {
                    frame.get(at..at.checked_add(2)?).map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
                }
                _ => frame.get(at).map(|&b| u32::from(b)),
            }
        };
        // `new` checked every jump target, so `pc` stays in range; the bound is belt and braces.
        while let Some(&i) = self.insns.get(pc) {
            pc += 1;
            let src = if i.code & op::X == op::X { x } else { i.k };
            match i.code & 0x07 {
                op::LD => {
                    let size = i.code & 0x18;
                    a = match i.code & 0xe0 {
                        op::IMM => i.k,
                        op::ABS => match load(i.k, size) {
                            Some(v) => v,
                            None => return 0,
                        },
                        op::IND => match x.checked_add(i.k).and_then(|at| load(at, size)) {
                            Some(v) => v,
                            None => return 0,
                        },
                        op::MEM => mem[(i.k & 15) as usize],
                        op::LEN => len,
                        _ => return 0,
                    };
                }
                op::LDX => {
                    x = match i.code & 0xe0 {
                        op::IMM => i.k,
                        op::MEM => mem[(i.k & 15) as usize],
                        op::LEN => len,
                        op::MSH => match load(i.k, op::B) {
                            Some(v) => (v & 0x0f) * 4,
                            None => return 0,
                        },
                        _ => return 0,
                    };
                }
                op::ST => mem[(i.k & 15) as usize] = a,
                op::STX => mem[(i.k & 15) as usize] = x,
                op::ALU => {
                    a = match i.code & 0xf0 {
                        op::ADD => a.wrapping_add(src),
                        op::SUB => a.wrapping_sub(src),
                        op::MUL => a.wrapping_mul(src),
                        op::DIV => match a.checked_div(src) {
                            Some(v) => v,
                            None => return 0,
                        },
                        op::MOD => match a.checked_rem(src) {
                            Some(v) => v,
                            None => return 0,
                        },
                        op::OR => a | src,
                        op::AND => a & src,
                        op::XOR => a ^ src,
                        op::LSH => a.checked_shl(src).unwrap_or(0),
                        op::RSH => a.checked_shr(src).unwrap_or(0),
                        op::NEG => a.wrapping_neg(),
                        _ => return 0,
                    };
                }
                op::JMP => {
                    let taken = match i.code & 0xf0 {
                        op::JA => {
                            let Some(to) = pc.checked_add(i.k as usize) else { return 0 };
                            pc = to;
                            continue;
                        }
                        op::JEQ => a == src,
                        op::JGT => a > src,
                        op::JGE => a >= src,
                        op::JSET => a & src != 0,
                        _ => return 0,
                    };
                    pc += usize::from(if taken { i.jt } else { i.jf });
                }
                op::RET => {
                    return match i.code & 0x18 {
                        op::A => a,
                        op::X => x,
                        _ => i.k,
                    };
                }
                op::MISC => {
                    if i.code & 0xf8 == op::TXA {
                        a = x;
                    } else {
                        x = a;
                    }
                }
                _ => return 0,
            }
        }
        0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Label {
    Accept,
    Reject,
    Tagged,
    Double,
}

/// A tiny assembler: instructions with symbolic jump targets, resolved at the end.
#[derive(Default)]
struct Builder {
    insns: Vec<(Insn, Option<(Label, Label)>)>,
    labels: Vec<(Label, usize)>,
}

impl Builder {
    fn push(&mut self, insn: Insn, targets: Option<(Label, Label)>) {
        self.insns.push((insn, targets));
    }

    fn label(&mut self, l: Label) {
        self.labels.push((l, self.insns.len()));
    }

    /// `ldh [offset]`, then accept on any of `types`, continue to `tagged` on a TPID (when
    /// given), and go to `otherwise` when nothing matched.
    fn block(&mut self, offset: u32, types: &[u16], tagged: Option<Label>, otherwise: Label) {
        self.push(Insn::new(op::LD | op::H | op::ABS, 0, 0, offset), None);
        for &t in types {
            self.push(
                Insn::new(op::JMP | op::JEQ | op::K, 0, 0, u32::from(t)),
                Some((Label::Accept, Label::Reject)),
            );
            // `jf` falls through to the next test: patched below by marking it "next".
            if let Some(last) = self.insns.last_mut() {
                last.1 = Some((Label::Accept, otherwise));
                last.0.jf = u8::MAX; // sentinel: fall through
            }
        }
        match tagged {
            Some(next) => {
                let n = TPIDS.len();
                for (k, tpid) in TPIDS.iter().enumerate() {
                    self.push(
                        Insn::new(op::JMP | op::JEQ | op::K, 0, 0, u32::from(*tpid)),
                        Some((next, otherwise)),
                    );
                    if k + 1 < n
                        && let Some(last) = self.insns.last_mut()
                    {
                        last.0.jf = u8::MAX;
                    }
                }
            }
            None => self.push(Insn::new(op::JA | op::JMP, 0, 0, 0), Some((otherwise, otherwise))),
        }
    }

    fn finish(self) -> Vec<Insn> {
        let at = |l: Label| self.labels.iter().find(|(x, _)| *x == l).map_or(0, |(_, pc)| *pc);
        self.insns
            .iter()
            .enumerate()
            .map(|(pc, (insn, targets))| {
                let mut insn = *insn;
                if let Some((t, f)) = targets {
                    let rel = |target: usize| target.saturating_sub(pc + 1);
                    if insn.code & 0xf0 == op::JA && insn.code & 0x07 == op::JMP {
                        insn.k = rel(at(*t)) as u32;
                    } else {
                        insn.jt = rel(at(*t)) as u8;
                        insn.jf = if insn.jf == u8::MAX { 0 } else { rel(at(*f)) as u8 };
                    }
                }
                insn
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(types: &[u16]) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        for t in types {
            f.extend_from_slice(&t.to_be_bytes());
            f.extend_from_slice(&[0, 5]); // a TCI, or payload after the final type
        }
        f.resize(64, 0xab);
        f
    }

    #[test]
    fn an_ethertype_filter_accepts_its_types_tagged_untagged_and_double_tagged() {
        let p = Program::ethertypes(&[0x88cc, 0x88f7]).expect("program");
        for accepted in
            [&[0x88cc][..], &[0x88f7], &[0x8100, 0x88cc], &[0x88a8, 0x88f7], &[0x88a8, 0x8100, 0x88cc]]
        {
            assert_eq!(p.run(&frame(accepted)), ACCEPT, "{accepted:x?}");
        }
        for rejected in
            [&[0x0800][..], &[0x8100, 0x0800], &[0x88a8, 0x8100, 0x86dd], &[0x8100, 0x8100, 0x8100, 0x88cc]]
        {
            assert_eq!(p.run(&frame(rejected)), 0, "{rejected:x?}");
        }
    }

    #[test]
    fn a_frame_too_short_to_hold_a_type_is_rejected() {
        let p = Program::ethertypes(&[0x88cc]).expect("program");
        assert_eq!(p.run(&[0u8; 13]), 0);
        assert_eq!(p.run(&[]), 0);
    }

    /// Spec 003 SR-008: a jump as far as `u32::MAX` is refused, never wrapped.
    #[test]
    fn a_far_jump_is_refused_on_every_pointer_width() {
        let far = vec![Insn::new(op::JMP | op::JA, 0, 0, u32::MAX), Insn::new(op::RET | op::K, 0, 0, 1)];
        assert!(Program::new(far).is_err());
    }

    /// Threat model T-04 (SR-004).
    #[test]
    fn the_builder_refuses_what_the_kernel_would() {
        assert!(Program::ethertypes(&[]).is_err());
        assert!(Program::ethertypes(&[1u16; 65]).is_err());
        assert!(Program::ethertypes(&[1u16; 64]).is_ok());
        assert!(Program::new(vec![]).is_err());
        assert!(
            Program::new(vec![Insn::new(op::JMP | op::JEQ, 5, 0, 0), Insn::new(op::RET, 0, 0, 0)]).is_err()
        );
        assert!(Program::new(vec![Insn::new(op::LD | op::IMM, 0, 0, 1)]).is_err(), "no return");
        assert!(Program::new(vec![Insn::new(op::ST, 0, 0, 16), Insn::new(op::RET, 0, 0, 0)]).is_err());
    }

    #[test]
    fn a_custom_program_runs_as_written() {
        // Accept frames whose source MAC (offset 6) starts 02:00:00:00 — "from one vendor".
        let p = Program::new(vec![
            Insn::new(op::LD | op::W | op::ABS, 0, 0, 6),
            Insn::new(op::JMP | op::JEQ | op::K, 0, 1, 0x0200_0000),
            Insn::new(op::RET | op::K, 0, 0, ACCEPT),
            Insn::new(op::RET | op::K, 0, 0, 0),
        ])
        .expect("program");
        let mut f = vec![0u8; 60];
        f[6] = 2;
        assert_eq!(p.run(&f), ACCEPT);
        f[6] = 4;
        assert_eq!(p.run(&f), 0);
    }

    #[test]
    fn arithmetic_and_scratch_memory_behave_like_the_kernel() {
        let p = Program::new(vec![
            Insn::new(op::LD | op::LEN, 0, 0, 0),
            Insn::new(op::ST, 0, 0, 3),
            Insn::new(op::LDX | op::MEM, 0, 0, 3),
            Insn::new(op::ALU | op::DIV | op::K, 0, 0, 0), // division by zero ends with 0
            Insn::new(op::RET | op::A, 0, 0, 0),
        ])
        .expect("program");
        assert_eq!(p.run(&[0; 10]), 0);
        let q = Program::new(vec![
            Insn::new(op::LD | op::LEN, 0, 0, 0),
            Insn::new(op::ALU | op::MUL | op::K, 0, 0, 3),
            Insn::new(op::MISC | op::TAX, 0, 0, 0),
            Insn::new(op::RET | op::X, 0, 0, 0),
        ])
        .expect("program");
        assert_eq!(q.run(&[0; 10]), 30);
    }
}
