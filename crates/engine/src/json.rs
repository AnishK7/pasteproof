//! Minimal JSON writer (keeps the engine dependency-free).

use crate::Report;
use std::fmt::Write as _;

fn esc(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{2028}' || c == '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn list<'a>(out: &mut String, items: impl Iterator<Item = &'a str>) {
    out.push('[');
    for (i, s) in items.enumerate() {
        if i > 0 {
            out.push(',');
        }
        esc(out, s);
    }
    out.push(']');
}

pub fn report(r: &Report) -> String {
    let mut o = String::with_capacity(512);
    o.push_str("{\"verdict\":");
    esc(&mut o, r.verdict.as_str());
    let _ = write!(o, ",\"score\":{}", r.score);
    o.push_str(",\"rules\":[");
    for (i, m) in r.matched.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push_str("{\"id\":");
        esc(&mut o, m.id);
        o.push_str(",\"severity\":");
        esc(&mut o, m.severity.as_str());
        o.push_str(",\"title\":");
        esc(&mut o, m.title);
        o.push('}');
    }
    o.push_str("],\"explanations\":");
    let ex = r.explanations();
    list(&mut o, ex.iter().map(String::as_str));
    o.push_str(",\"advice\":");
    list(&mut o, r.advice().into_iter());
    o.push_str(",\"signals\":");
    list(&mut o, r.signal_names().into_iter());
    o.push_str(",\"urls\":");
    list(&mut o, r.urls.iter().map(String::as_str));
    o.push_str(",\"host\":");
    match &r.host {
        Some(h) => esc(&mut o, h),
        None => o.push_str("null"),
    }
    o.push_str(",\"hidden\":");
    list(&mut o, r.hidden.iter().map(String::as_str));
    let _ = write!(
        o,
        ",\"padding\":{},\"truncated\":{},\"allowlisted\":{}}}",
        r.padding, r.truncated, r.allowlisted
    );
    o
}
