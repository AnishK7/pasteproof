//! `pasteproof` - stops ClickFix-style "paste this command" attacks.
//!
//! Hand-written argument parsing and no dependencies besides the engine,
//! so the binary is small and starts in about a millisecond.

#![forbid(unsafe_code)]

mod allow;
mod msg;
mod ui;

use pasteproof_engine::{analyze, Dialect, Options, Report, Verdict};
use std::io::Read;
use std::process::ExitCode;

const EXIT_CANCEL: u8 = 10;
const EXIT_USAGE: u8 = 64;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        print!("{}", msg::HELP);
        return ExitCode::from(EXIT_USAGE);
    };
    let rest = &args[1..];
    match cmd.as_str() {
        "check" => check(rest, false),
        "why" => check(rest, true),
        "guard" => guard(rest),
        "init" => init(rest),
        "allow" => allow::command(rest),
        "rules" => rules(),
        "-V" | "--version" | "version" => {
            println!("pasteproof {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "-h" | "--help" | "help" => {
            print!("{}", msg::HELP);
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("pasteproof: unknown command '{other}'. Try `pasteproof --help`.");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

struct Parsed {
    json: bool,
    pasted: bool,
    dialect: Dialect,
    text: String,
}

fn parse_args(rest: &[String]) -> Result<Parsed, String> {
    let mut p = Parsed {
        json: false,
        pasted: false,
        dialect: Dialect::Auto,
        text: String::new(),
    };
    let mut stdin = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--json" => p.json = true,
            "--pasted" => p.pasted = true,
            "--stdin" | "-" => stdin = true,
            "--shell" => {
                i += 1;
                p.dialect = match rest.get(i).map(String::as_str) {
                    Some("pwsh" | "powershell") => Dialect::PowerShell,
                    Some("cmd") => Dialect::Cmd,
                    Some(_) => Dialect::Posix,
                    None => return Err("--shell needs a value".into()),
                };
            }
            "--" => {
                p.text = rest[i + 1..].join(" ");
                break;
            }
            s if s.starts_with("--") => return Err(format!("unknown option {s}")),
            _ => {
                p.text = rest[i..].join(" ");
                break;
            }
        }
        i += 1;
    }
    if stdin {
        let mut buf = String::new();
        std::io::stdin()
            .take(pasteproof_engine::MAX_INPUT as u64 + 1)
            .read_to_string(&mut buf)
            .map_err(|e| e.to_string())?;
        p.text = buf;
    }
    Ok(p)
}

/// Analyse; consult the allowlist file only if it could change the result,
/// so the common path does no disk I/O at all.
fn run(text: &str, pasted: bool, dialect: Dialect) -> Report {
    let opts = Options {
        pasted,
        dialect,
        allow_origins: &[],
    };
    let r = analyze(text, &opts);
    if r.verdict == Verdict::Allow
        || r.urls.is_empty()
        || !r.matched.iter().any(|m| m.allowlistable)
    {
        return r;
    }
    let list = allow::load();
    if list.is_empty() {
        return r;
    }
    let refs: Vec<&str> = list.iter().map(String::as_str).collect();
    analyze(
        text,
        &Options {
            pasted,
            dialect,
            allow_origins: &refs,
        },
    )
}

fn exit_for(v: Verdict) -> ExitCode {
    ExitCode::from(match v {
        Verdict::Allow => 0,
        Verdict::Caution => 1,
        Verdict::Danger => 2,
    })
}

fn check(rest: &[String], verbose: bool) -> ExitCode {
    let p = match parse_args(rest) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("pasteproof: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    if p.text.is_empty() {
        eprintln!(
            "pasteproof: nothing to check. Usage: pasteproof check -- '<command>'  (or --stdin)"
        );
        return ExitCode::from(EXIT_USAGE);
    }
    let r = run(&p.text, p.pasted, p.dialect);
    if p.json {
        println!("{}", r.to_json());
    } else {
        ui::print_report(&r, verbose);
    }
    exit_for(r.verdict)
}

/// Called by the shell integration before a line runs.
/// Exit 0 = run the line, 10 = the user cancelled. Anything else (crash,
/// missing binary) makes the shell run the line: fail open.
fn guard(rest: &[String]) -> ExitCode {
    let Ok(p) = parse_args(rest) else {
        return ExitCode::SUCCESS;
    };
    if p.text.trim().is_empty() {
        return ExitCode::SUCCESS;
    }
    let r = run(&p.text, p.pasted, p.dialect);
    let ask = match r.verdict {
        Verdict::Allow => false,
        Verdict::Danger => true,
        // Typed commands are the user's own; only question pasted ones
        // (unless the user opts into strict mode).
        Verdict::Caution => p.pasted || std::env::var_os("PASTEPROOF_STRICT").is_some(),
    };
    if !ask || ui::confirm(&r) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_CANCEL)
    }
}

fn init(rest: &[String]) -> ExitCode {
    // Bake in our own absolute path so the snippet needs no PATH lookup.
    let me = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(shell_quote))
        .unwrap_or_else(|| "pasteproof".into());
    match rest.first().map(String::as_str) {
        Some("bash") => print!(
            "{}",
            include_str!("../shell/pasteproof.bash").replace("@PASTEPROOF_SELF@", &me)
        ),
        Some("zsh") => print!(
            "{}",
            include_str!("../shell/pasteproof.zsh").replace("@PASTEPROOF_SELF@", &me)
        ),
        _ => {
            eprintln!(
                "Usage: pasteproof init bash|zsh\n\nAdd to ~/.bashrc:  eval \"$(pasteproof init bash)\"\nAdd to ~/.zshrc:   eval \"$(pasteproof init zsh)\""
            );
            return ExitCode::from(EXIT_USAGE);
        }
    }
    ExitCode::SUCCESS
}

/// Single-quote a path for safe use in shell code.
fn shell_quote(p: &str) -> String {
    format!("'{}'", p.replace('\'', "'\\''"))
}

fn rules() -> ExitCode {
    for r in pasteproof_engine::RULES {
        println!("{}  {:<7}  {}", r.id, r.severity.as_str(), r.title);
    }
    ExitCode::SUCCESS
}
