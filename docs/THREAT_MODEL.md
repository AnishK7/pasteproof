# Threat model

## Assets
Everything a process running as you can read: SSH keys, shell history, `.env`
files, cloud/CLI/AI-tool tokens, password-manager files, browser cookies and
saved passwords (decryptable through the unlocked OS keyring), crypto wallets,
and your keystrokes.

## Attacker
- Controls (or has compromised) a website you visit, and can show any page and write to your clipboard.
- Can make you believe that pasting a command is a normal verification or repair step.
- Can host payloads anywhere, rotate domains, and find their server through a blockchain contract ("EtherHiding").
- Can obfuscate commands: encoding, splitting strings, hidden whitespace, invisible or lookalike Unicode.
- Does **not** have code running on your machine yet. The pasted command is that first step.

## What pasteproof defends against
1. **The paste-and-run moment.** Any line run from an interactive bash/zsh prompt is checked before it executes. Pasted lines get stricter treatment than typed ones.
2. **Obfuscation aimed at humans.** Hidden padding, invisible characters, lookalikes and encoding are revealed, and they count against the command.
3. **Common delivery forms** on Linux, macOS and Windows: see the rules and the corpus.

## Explicitly out of scope
- **Code already running on the machine**, including root-level malware. Malware can disable any user-level tool. Persistence monitoring and incident mode (later milestones) help after the fact.
- **Users who override every warning.** pasteproof is a speed bump with an explanation, not a jail.
- **Supply-chain attacks inside trusted packages** (a compromised npm package, or a malicious update to a real installer). A trusted installer origin is trusted.
- **Attacks that never touch an interactive shell prompt:** double-clicked files, the Windows Run dialog (until the Windows milestone), commands typed into GUI apps, scripts run non-interactively.
- **Determined evasion of static analysis.** Shell and PowerShell are too dynamic for any static checker to be complete, so pasteproof errs towards plain-language caution.
- **Network-level protection.** Pair pasteproof with an application firewall (e.g. OpenSnitch) for defence in depth.

## Design consequences
- **Fail open:** if pasteproof crashes, times out or is missing, the command runs. A security tool that breaks your shell gets uninstalled.
- **No network, no telemetry:** the check never leaks your commands.
- **Bounded work:** input is capped at 64 KiB, recursion depth at 4, and decoded data at 64 KiB per check, so a crafted line can't hang your shell.
- **No hard-coded "trusted vendors":** lookalike domains could imitate them. Trust is per-user and uses exact origins.
