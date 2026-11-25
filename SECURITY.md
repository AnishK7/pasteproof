# Security policy

pasteproof is a security tool, so bugs in it matter. Thank you for helping.

## Reporting a vulnerability
Please **don't open a public issue** for:
- a way to make a malicious command pass as `allow` that you believe is broadly exploitable (a "bypass"),
- anything that makes pasteproof crash, hang or misbehave on crafted input,
- anything in the shell integration that could run a command the user cancelled.

Instead, use GitHub's **private vulnerability reporting** (the Security tab → "Report a vulnerability").
Include the input, the expected and actual verdict, and your OS and shell.

You can expect an acknowledgement within 7 days and a fix or plan within 30 days.
We'll credit you in the changelog unless you prefer otherwise.

## Scope notes
- Ordinary detection gaps (a new ClickFix variant isn't caught) are welcome as **public** issues or rule pull requests. Please defang samples first (see CONTRIBUTING.md).
- Please never send live malware or real attacker URLs. Describe the pattern and defang the sample.

## Supported versions
Only the latest release receives fixes until 1.0.
