//! Coverage-guided fuzzing: `cargo +nightly fuzz run analyze`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use pasteproof_engine::{analyze, Options};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let r = analyze(s, &Options { pasted: data.len() % 2 == 0, ..Default::default() });
        assert!(r.score <= 100);
        let _ = r.to_json();
    }
});
