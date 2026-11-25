//! Corpus metrics: detection rate on defanged attacks, false positives on
//! everyday commands, and "never danger" for official installers.
//! Fails CI if quality regresses.

use pasteproof_engine::{analyze, Options, Verdict};
use std::path::PathBuf;

fn corpus(name: &str) -> Vec<(Verdict, String)> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(name);
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (v, cmd) = l
                .split_once('\t')
                .unwrap_or_else(|| panic!("missing TAB in {name}: {l}"));
            let v = match v {
                "allow" => Verdict::Allow,
                "caution" => Verdict::Caution,
                "danger" => Verdict::Danger,
                other => panic!("bad verdict {other} in {name}"),
            };
            (v, unescape(cmd))
        })
        .collect()
}

/// `\u{XXXX}` -> character.
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find("\\u{") {
        out.push_str(&rest[..p]);
        let after = &rest[p + 3..];
        match after
            .find('}')
            .and_then(|e| u32::from_str_radix(&after[..e], 16).ok().map(|c| (e, c)))
        {
            Some((e, c)) => {
                out.push(char::from_u32(c).unwrap_or('?'));
                rest = &after[e + 1..];
            }
            None => {
                out.push_str("\\u{");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

fn report(
    name: &str,
    rows: &[(Verdict, String)],
    ok: impl Fn(Verdict, Verdict) -> bool,
) -> Vec<String> {
    let mut bad = Vec::new();
    for (want, cmd) in rows {
        let r = analyze(cmd, &Options::default());
        if !ok(*want, r.verdict) {
            bad.push(format!(
                "[{name}] want {} got {} {:?}\n    {:?}\n    signals={:?}",
                want.as_str(),
                r.verdict.as_str(),
                r.matched.iter().map(|m| m.id).collect::<Vec<_>>(),
                cmd.chars().take(140).collect::<String>(),
                r.signal_names()
            ));
        }
    }
    bad
}

#[test]
fn malicious_detected_at_least_expected_level() {
    let rows = corpus("malicious.tsv");
    assert!(
        rows.len() >= 60,
        "malicious corpus too small: {}",
        rows.len()
    );
    let bad = report("malicious", &rows, |want, got| got >= want);
    let rate = 1.0 - bad.len() as f64 / rows.len() as f64;
    eprintln!(
        "malicious: {} samples, {:.1}% at or above expected verdict",
        rows.len(),
        rate * 100.0
    );
    assert!(
        bad.is_empty(),
        "{} miss(es):\n{}",
        bad.len(),
        bad.join("\n")
    );
}

#[test]
fn benign_never_flagged() {
    let rows = corpus("benign.tsv");
    assert!(rows.len() >= 100, "benign corpus too small: {}", rows.len());
    let bad = report("benign", &rows, |_, got| got == Verdict::Allow);
    eprintln!(
        "benign: {} samples, {} false positive(s)",
        rows.len(),
        bad.len()
    );
    // False-positive budget: zero.
    assert!(
        bad.is_empty(),
        "{} false positive(s):\n{}",
        bad.len(),
        bad.join("\n")
    );
}

#[test]
fn installers_never_danger() {
    let rows = corpus("installers.tsv");
    let bad = report("installers", &rows, |max, got| got <= max);
    assert!(
        bad.is_empty(),
        "{} installer(s) over-flagged:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

/// Enforces the defanging policy: only fictitious hosts in attack samples.
#[test]
fn malicious_corpus_is_defanged() {
    let rows = corpus("malicious.tsv");
    let allowed_real = ["script.google.com", "bit.ly", "transfer.sh"];
    for (_, cmd) in &rows {
        for u in analyze(cmd, &Options::default()).urls {
            let host = u
                .split("://")
                .nth(1)
                .unwrap_or("")
                .split(['/', ':', '?', '@'])
                .next()
                .unwrap_or("")
                .to_lowercase();
            let host = host.trim_start_matches('[');
            let ok = host.ends_with(".example")
                || host.ends_with(".invalid")
                || host.ends_with(".test")
                || host.starts_with("pp-fixture-")
                || host.contains(".pp-fixture-")
                || host.starts_with("192.0.2.")
                || host.starts_with("198.51.100.")
                || host.starts_with("203.0.113.")
                || host.starts_with("xn--pple-43d.example")
                || allowed_real.contains(&host);
            assert!(
                ok,
                "non-fictitious host {host:?} in malicious corpus: {cmd}"
            );
        }
    }
}
