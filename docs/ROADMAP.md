# Roadmap

## Milestone 1: engine and terminal guard on Linux ✅ (this release)
- Engine, rule schema and build-time compiler, 26 signals, 20 rules
- Corpus with CI accuracy gates; robustness tests; benchmarks with budgets
- `pasteproof check | why | guard | init | allow | rules`
- bash and zsh integration with pseudo-terminal tests

## Milestone 2: "I think I ran something bad"
- `pasteproof incident`: suspicious processes and connections, a timeline of recent file changes, persistence entries, an inventory of exposed credentials (never printing values), a prioritised rotation checklist with provider links, and a redacted shareable report
- `pasteproof hygiene`: unencrypted SSH keys, tokens in history, live `.env` keys, clipboard managers keeping secrets

## Milestone 3: persistence monitor
- Optional user daemon, event-driven (inotify), under 10 MB RSS, 0% CPU when idle; systemd user unit with resource limits and sandboxing
- "Stop it" (suspend and quarantine, never delete) and "This was me"

## Milestone 4: fish and macOS
- fish integration; FSEvents monitor; LaunchAgents; Homebrew formula

## Milestone 5: Windows
- PowerShell (PSReadLine) integration; winget and Scoop packages

## Milestone 6: reach
- WebAssembly build plus npm package, and outreach to existing ClickFix browser extensions to share the rule set
- C ABI and Python bindings
- Sigma rule export for EDR/SIEM users
- Optional Linux clipboard watcher (an event-driven approach for GNOME and KDE on Wayland)

## Milestone 7: upstream
- A design proposal and reference patch for a built-in paste warning in at least one terminal (VTE/Ptyxis, Konsole, Windows Terminal, iTerm2 or fish)

## Release engineering (before the first public binary)
- Signed artefacts (Sigstore/cosign), checksums, SBOM, SLSA provenance
- deb/rpm/AUR packages; reproducible builds where feasible
- Rules packaged inside the engine crate for crates.io publishing
