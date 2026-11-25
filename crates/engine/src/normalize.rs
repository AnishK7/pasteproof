//! Unicode normalisation: removes invisible characters, maps lookalikes
//! and exotic spaces to ASCII, and remembers where lookalikes were so the
//! lexer can tell whether they appeared in code or inside quoted text.

pub struct Normalized {
    pub text: String,
    /// Invisible characters (zero-width, bidi overrides, ...) were removed.
    pub invisible: bool,
    /// Byte offsets (in `text`) of characters mapped from a lookalike.
    pub confusable_at: Vec<usize>,
}

pub fn normalize(s: &str) -> Normalized {
    // Fast path: plain ASCII without carriage returns needs no work.
    if s.is_ascii() && !s.contains('\r') {
        return Normalized {
            text: s.to_string(),
            invisible: false,
            confusable_at: Vec::new(),
        };
    }
    let mut text = String::with_capacity(s.len());
    let mut invisible = false;
    let mut confusable_at = Vec::new();
    for c in s.chars() {
        match c {
            '\r' => {}
            '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{00AD}'
            | '\u{180E}'
            | '\u{034F}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{3164}'
            | '\u{FFA0}' => invisible = true,
            // Exotic spaces become plain spaces (they are common in text
            // copied from web pages, so they are not suspicious by themselves).
            '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}' => text.push(' '),
            // Fullwidth ASCII forms (｜ ｃｕｒｌ ...).
            '\u{FF01}'..='\u{FF5E}' => {
                confusable_at.push(text.len());
                text.push(char::from_u32(c as u32 - 0xFEE0).unwrap_or(c));
            }
            '\u{2223}' | '\u{01C0}' | '\u{2502}' | '\u{23D0}' | '\u{FFE8}' => {
                confusable_at.push(text.len());
                text.push('|');
            }
            '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2014}' | '\u{2212}'
            | '\u{FE63}' => {
                confusable_at.push(text.len());
                text.push('-');
            }
            '\u{2044}' | '\u{2215}' | '\u{29F8}' => {
                confusable_at.push(text.len());
                text.push('/');
            }
            '\u{2024}' | '\u{FE52}' => {
                confusable_at.push(text.len());
                text.push('.');
            }
            '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}' | '\u{2032}' => {
                confusable_at.push(text.len());
                text.push('\'');
            }
            '\u{201C}' | '\u{201D}' | '\u{201E}' | '\u{2033}' => {
                confusable_at.push(text.len());
                text.push('"');
            }
            _ => text.push(c),
        }
    }
    Normalized {
        text,
        invisible,
        confusable_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_is_untouched() {
        let n = normalize("curl -fsSL https://x | sh");
        assert_eq!(n.text, "curl -fsSL https://x | sh");
        assert!(!n.invisible && n.confusable_at.is_empty());
    }

    #[test]
    fn maps_lookalikes_and_drops_invisibles() {
        let n = normalize("curl\u{200B} x \u{FF5C} sh");
        assert_eq!(n.text, "curl x | sh");
        assert!(n.invisible);
        assert_eq!(n.confusable_at.len(), 1);
    }
}
