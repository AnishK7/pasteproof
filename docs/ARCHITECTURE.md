# Architecture

```
rules/*.toml ──build.rs──▶ static Rule table (bitmasks) ─┐
crates/engine/signals.txt ─┘                              │
                                                          ▼
 command line ─▶ normalize ─▶ lex/parse ─▶ analyze ─▶ signals (u64) ─▶ rules ─▶ Report
                 (Unicode)    (pipes,      (pipelines,      + text heuristics      (verdict, plain-
                               quotes,      substitutions,    (PowerShell,          language reasons,
                               $(), <(),    -c/-e/-enc,       Windows tools,        decoded content,
                               comments,    download→run,     obfuscation)          JSON)
                               padding)     persistence,
                                            uploads)
```

## Components
| Path | Role |
|---|---|
| `crates/engine` | The pure library: no I/O, no unsafe, no runtime dependencies. `analyze(&str, &Options) -> Report`. |
| `crates/engine/build.rs` | Rule compiler. Validates every rule (ids, signals, at least one positive and one negative test) and generates static data. Build-time dependencies only (`toml`, `serde`). |
| `rules/` | Detection rules as data. Each rule combines signals with `all` / `any` / `none` and optional `match_any` substrings. |
| `corpus/` | Defanged attacks, everyday commands and official installers. Accuracy gates run in CI. |
| `crates/cli` | The `pasteproof` binary: `check`, `why`, `guard`, `init`, `allow`, `rules`. Hand-written argument parsing, no other dependencies. |
| `crates/cli/shell` | bash and zsh integrations. |
| `tests/shell/pty_test.py` | End-to-end tests in a real pseudo-terminal. |

## Why Rust
A single small static binary with ~1 ms startup and no runtime; memory safety for a
parser that reads attacker-controlled input; and the same core can compile to
WebAssembly for browser extensions and to a C ABI for other languages.

## How the budgets are met
- **Rules are compiled, not interpreted.** Matching a rule is three bitmask tests.
- **Fast paths:** ASCII input skips Unicode normalisation, and the text heuristics exit early unless a short list of markers is present.
- **The shell pre-filter** is pure bash/zsh pattern matching, so ordinary lines start no process at all (~46 µs per Enter).
- **No disk I/O on the hot path:** the allowlist file is read only when it could change the verdict.
- **Bounded recursion and decoding** keep the worst case under 5 ms at 64 KiB.
- **Release profile:** `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, stripped symbols.

## The guard protocol
The shell calls `pasteproof guard [--pasted] -- "<line>"` with the terminal on
stdin and stdout. Exit `10` means the user cancelled and the shell clears the line.
**Any other outcome runs the line** (fail open).

| Verdict | Typed | Pasted |
|---|---|---|
| allow | runs | runs |
| caution | runs (set `PASTEPROOF_STRICT=1` to ask) | asks y/N |
| danger | must type `run` | must type `run` |
