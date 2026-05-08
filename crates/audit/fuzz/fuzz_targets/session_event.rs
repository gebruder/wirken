#![no_main]

//! Fuzz `SessionEvent` JSON deserialization.
//!
//! `SessionEvent` is the on-disk schema for every row in the audit
//! log. Its serde derive accepts whatever JSON the deserializer is
//! handed; the harness checks that arbitrary byte input produces
//! either a parse error or a valid `SessionEvent` without panicking,
//! aborting, or running unbounded.

use libfuzzer_sys::fuzz_target;
use wirken_audit::SessionEvent;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<SessionEvent>(data);
});
