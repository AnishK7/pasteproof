//! Terminal output and the confirmation prompt.

use crate::msg;
use pasteproof_engine::{Report, Verdict};
use std::fs::OpenOptions;
use std::io::{IsTerminal, Read, Write};

struct Style {
    on: bool,
}

impl Style {
    fn detect(is_tty: bool) -> Self {
        let on = is_tty
            && std::env::var_os("NO_COLOR").is_none()
            && std::env::var("TERM").map_or(true, |t| t != "dumb");
        Style { on }
    }
    fn paint(&self, code: &str, s: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
}

fn render(r: &Report, st: &Style, verbose: bool) -> String {
    let mut o = String::new();
    match r.verdict {
        Verdict::Danger => o.push_str(&format!(
            "\n  {}\n\n",
            st.paint("1;97;41", &format!(" [!] {} ", msg::DANGER_TITLE))
        )),
        Verdict::Caution => o.push_str(&format!(
            "\n  {}\n\n",
            st.paint("1;30;43", &format!(" [?] {} ", msg::CAUTION_TITLE))
        )),
        Verdict::Allow => {
            o.push_str(&format!("  {} {}\n", st.paint("1;32", "allow"), msg::SAFE));
            return o;
        }
    }
    o.push_str(&format!("  {}\n", st.paint("1", msg::WHAT_IT_DOES)));
    for e in r.explanations() {
        o.push_str(&format!("    - {e}\n"));
    }
    if !r.hidden.is_empty() {
        o.push_str(&format!("\n  {}\n", st.paint("1", msg::HIDDEN)));
        for h in &r.hidden {
            o.push_str(&format!("    > {h}\n"));
        }
    }
    if verbose {
        o.push_str("\n  Rules:\n");
        for m in &r.matched {
            o.push_str(&format!(
                "    {} [{}] {}\n",
                m.id,
                m.severity.as_str(),
                m.title
            ));
        }
        o.push_str(&format!("  Signals: {}\n", r.signal_names().join(", ")));
        if !r.urls.is_empty() {
            o.push_str(&format!("  URLs: {}\n", r.urls.join(" ")));
        }
        o.push_str(&format!("  Score: {}/100\n", r.score));
    }
    if r.verdict == Verdict::Danger {
        o.push_str(&format!("\n  {}\n", st.paint("1", msg::NEVER)));
    } else {
        for a in r.advice().iter().take(1) {
            o.push_str(&format!("\n  {a}\n"));
        }
    }
    o
}

pub fn print_report(r: &Report, verbose: bool) {
    let st = Style::detect(std::io::stdout().is_terminal());
    print!("{}", render(r, &st, verbose));
}

/// Show the warning on the terminal and ask. Returns true to run.
pub fn confirm(r: &Report) -> bool {
    let Ok(tty) = OpenOptions::new().read(true).write(true).open("/dev/tty") else {
        eprintln!("{}", msg::NO_TTY);
        return true;
    };
    let mut out = match tty.try_clone() {
        Ok(t) => t,
        Err(_) => return true,
    };
    let st = Style::detect(true);
    let mut text = render(r, &st, false);
    if r.verdict == Verdict::Caution && r.matched.iter().any(|m| m.allowlistable) {
        if let Some(o) = r.urls.first().and_then(|u| origin(u)) {
            text.push_str(&format!("  {} pasteproof allow add {o}\n", msg::ALLOW_TIP));
        }
    }
    text.push('\n');
    text.push_str("  ");
    text.push_str(if r.verdict == Verdict::Danger {
        msg::DANGER_PROMPT
    } else {
        msg::CAUTION_PROMPT
    });
    if out
        .write_all(text.as_bytes())
        .and_then(|_| out.flush())
        .is_err()
    {
        return true;
    }
    let ans = read_answer(&tty, &mut out).trim().to_ascii_lowercase();
    let run = match r.verdict {
        Verdict::Danger => ans == "run",
        _ => ans == "y" || ans == "yes",
    };
    if !run {
        let _ = writeln!(out, "  {}\n", msg::CANCELLED);
    }
    run
}

fn origin(u: &str) -> Option<String> {
    let (scheme, rest) = u.split_once("://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    Some(format!("{scheme}://{host}").to_ascii_lowercase())
}

/// Read one short answer key by key. The shell's line editor leaves the
/// terminal in raw mode (no echo, Enter sends CR), so echo and handle
/// Backspace/Ctrl-C ourselves.
fn read_answer(tty: &std::fs::File, out: &mut std::fs::File) -> String {
    let mut ans = String::new();
    let mut byte = [0u8; 1];
    let mut input = tty;
    while let Ok(1) = input.read(&mut byte) {
        match byte[0] {
            b'\r' | b'\n' | 0x04 => break,
            0x03 | 0x1b => {
                ans.clear();
                break;
            }
            0x7f | 0x08 => {
                if ans.pop().is_some() {
                    let _ = out.write_all(b"\x08 \x08");
                }
            }
            b if (b.is_ascii_graphic() || b == b' ') && ans.len() < 32 => {
                ans.push(b as char);
                let _ = out.write_all(&[b]);
            }
            _ => {}
        }
        let _ = out.flush();
    }
    let _ = out.write_all(b"\r\n");
    ans
}
