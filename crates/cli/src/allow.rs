//! Per-user allowlist of trusted installer origins.
//! Stored one entry per line in $XDG_CONFIG_HOME/pasteproof/allow.txt
//! (default ~/.config/pasteproof/allow.txt). Only read when needed.

use std::path::PathBuf;
use std::process::ExitCode;

fn path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("pasteproof").join("allow.txt"))
}

pub fn load() -> Vec<String> {
    let Some(p) = path() else { return Vec::new() };
    std::fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().trim_end_matches('/').to_ascii_lowercase())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

fn save(list: &[String]) -> std::io::Result<()> {
    let p = path().ok_or_else(|| std::io::Error::other("cannot find config directory"))?;
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut body = String::from(
        "# Trusted origins for pasteproof (one per line): https://host or bare host\n",
    );
    for e in list {
        body.push_str(e);
        body.push('\n');
    }
    std::fs::write(p, body)
}

fn valid(e: &str) -> bool {
    let host = e
        .strip_prefix("https://")
        .or_else(|| e.strip_prefix("http://"))
        .unwrap_or(e);
    !host.is_empty()
        && !host.contains('/')
        && !host.contains('*')
        && host.contains('.')
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':')
}

pub fn command(rest: &[String]) -> ExitCode {
    let mut list = load();
    match (rest.first().map(String::as_str), rest.get(1)) {
        (Some("list") | None, _) => {
            if list.is_empty() {
                println!(
                    "No trusted origins. Add one with: pasteproof allow add https://example.com"
                );
            }
            for e in &list {
                println!("{e}");
            }
        }
        (Some("add"), Some(e)) => {
            let e = e.trim().trim_end_matches('/').to_ascii_lowercase();
            if !valid(&e) {
                eprintln!("pasteproof: '{e}' isn't a plain origin. Use e.g. https://sh.rustup.rs (no paths or wildcards).");
                return ExitCode::from(64);
            }
            if e.starts_with("http://") {
                eprintln!("pasteproof: warning: trusting unencrypted http:// lets anyone on your network change what runs.");
            }
            if !list.contains(&e) {
                list.push(e.clone());
            }
            if let Err(err) = save(&list) {
                eprintln!("pasteproof: could not save allowlist: {err}");
                return ExitCode::from(74);
            }
            println!("Trusted {e}");
        }
        (Some("remove" | "rm"), Some(e)) => {
            let e = e.trim().trim_end_matches('/').to_ascii_lowercase();
            list.retain(|x| *x != e);
            if let Err(err) = save(&list) {
                eprintln!("pasteproof: could not save allowlist: {err}");
                return ExitCode::from(74);
            }
            println!("Removed {e}");
        }
        _ => {
            eprintln!("Usage: pasteproof allow [list | add <origin> | remove <origin>]");
            return ExitCode::from(64);
        }
    }
    ExitCode::SUCCESS
}
