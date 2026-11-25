//! Runs every inline test case from rules/*.toml.
use pasteproof_engine::{analyze, Options, RULE_TESTS};

#[test]
fn inline_rule_tests() {
    let mut failures = Vec::new();
    for (id, input, should) in RULE_TESTS {
        let r = analyze(input, &Options::default());
        let hit = r.matched.iter().any(|m| m.id == *id);
        if hit != *should {
            failures.push(format!(
                "{id}: expected {} for {:?}\n    verdict={} rules={:?} signals={:?}",
                if *should { "match" } else { "no-match" },
                input.chars().take(120).collect::<String>(),
                r.verdict.as_str(),
                r.matched.iter().map(|m| m.id).collect::<Vec<_>>(),
                r.signal_names()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} rule test(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
