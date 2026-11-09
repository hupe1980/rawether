//! A BPF device read buffer, parsed with the macOS and the FreeBSD record layout.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| rawether::fuzzing::bpf_records(data));
