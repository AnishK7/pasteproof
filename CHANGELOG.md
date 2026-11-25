# Changelog

All notable changes are documented here. This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `pasteproof-engine`: dependency-free detection engine with a shell-aware parser, de-obfuscation
  (base64, PowerShell `-EncodedCommand`, hex/printf escapes), Unicode normalisation, URL and host
  classification, and 20 rules compiled from `rules/*.toml` at build time.
- `pasteproof` CLI: `check`, `why`, `guard`, `init bash|zsh`, `allow`, `rules`.
- bash (4.0+) and zsh integrations with paste detection and fail-open behaviour. On bash 3 (stock macOS) the hook prints a notice and stays inactive.
- Corpus accuracy gates, robustness tests, pseudo-terminal tests and benchmarks with budgets.
