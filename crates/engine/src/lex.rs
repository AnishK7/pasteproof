//! A small, forgiving shell lexer/parser.
//!
//! It never fails: malformed input (unterminated quotes, stray brackets) is
//! parsed on a best-effort basis. It understands just enough POSIX shell to
//! see pipelines, separators, redirections, quoting, comments and
//! substitutions. PowerShell and cmd.exe lines tokenise well enough for the
//! structural checks; their specifics are handled by `text.rs`.

/// Placeholder inserted into a word's text where a substitution was.
pub const SUBST_MARK: char = '\u{1}';

#[derive(Default, Debug)]
pub struct Word {
    /// Unquoted, unescaped value.
    pub text: String,
    /// Some part of the word was quoted.
    pub quoted: bool,
    /// A backslash escaped a letter or digit (`c\url`).
    pub escaped_letter: bool,
    /// Quotes split the word's letters (`c"ur"l`) - only meaningful for argv0.
    pub split_quotes: bool,
    /// Contains `$'...'` ANSI-C quoting.
    pub ansi_c: bool,
    /// Contains a variable expansion.
    pub has_var: bool,
    /// Command/process substitutions inside this word.
    pub substs: Vec<Subst>,
}

#[derive(Debug)]
pub struct Subst {
    pub kind: SubstKind,
    pub inner: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubstKind {
    /// `$(...)` or backticks.
    Command,
    /// `<(...)`.
    ProcIn,
    /// `>(...)`.
    ProcOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirKind {
    Out,
    Append,
    In,
    HereStr,
    HereDoc,
    Dup,
}

#[derive(Debug)]
pub struct Redir {
    pub kind: RedirKind,
    pub target: Word,
}

#[derive(Default, Debug)]
pub struct Command {
    pub words: Vec<Word>,
    pub redirs: Vec<Redir>,
}

#[derive(Default, Debug)]
pub struct Pipeline {
    pub cmds: Vec<Command>,
    pub background: bool,
    /// Pipelines `[start, end)` of a `( ... )` group whose output is piped
    /// into this pipeline, e.g. `(curl a || curl b) | sh`.
    pub group_input: Option<(usize, usize)>,
}

#[derive(Default, Debug)]
pub struct Parsed {
    pub pipelines: Vec<Pipeline>,
    pub comments: Vec<String>,
    /// Longest run of unquoted whitespace that is followed by more content.
    pub padding: usize,
    /// Text that followed the longest padding run (truncated).
    pub padded_tail: String,
    /// A lookalike character appeared outside quotes.
    pub confusable: bool,
}

struct Lexer<'a> {
    cs: Vec<(usize, char)>,
    src: &'a str,
    i: usize,
    p: Parsed,
    pipe: Pipeline,
    cmd: Command,
    word: Word,
    in_word: bool,
    word_has_unquoted: bool,
    pending: Option<RedirKind>,
    confusable_at: &'a [usize],
    groups: Vec<usize>,
    last_group: Option<(usize, usize)>,
}

pub fn parse(src: &str, confusable_at: &[usize]) -> Parsed {
    let mut lx = Lexer {
        cs: src.char_indices().collect(),
        src,
        i: 0,
        p: Parsed::default(),
        pipe: Pipeline::default(),
        cmd: Command::default(),
        word: Word::default(),
        in_word: false,
        word_has_unquoted: false,
        pending: None,
        confusable_at,
        groups: Vec::new(),
        last_group: None,
    };
    lx.run();
    lx.p
}

impl Lexer<'_> {
    #[inline]
    fn peek(&self, k: usize) -> Option<char> {
        self.cs.get(self.i + k).map(|&(_, c)| c)
    }

    fn finish_word(&mut self) {
        if !self.in_word {
            return;
        }
        let w = std::mem::take(&mut self.word);
        self.in_word = false;
        self.word_has_unquoted = false;
        match self.pending.take() {
            Some(kind) => self.cmd.redirs.push(Redir { kind, target: w }),
            None => self.cmd.words.push(w),
        }
    }

    fn finish_cmd(&mut self) {
        self.finish_word();
        self.pending = None;
        if !self.cmd.words.is_empty() || !self.cmd.redirs.is_empty() {
            let c = std::mem::take(&mut self.cmd);
            self.pipe.cmds.push(c);
        }
    }

    fn finish_pipe(&mut self, background: bool) {
        self.finish_cmd();
        if !self.pipe.cmds.is_empty() {
            let mut p = std::mem::take(&mut self.pipe);
            p.background = background;
            self.p.pipelines.push(p);
        }
    }

    fn start_word(&mut self) {
        self.in_word = true;
        self.last_group = None;
    }

    fn mark_quoted(&mut self) {
        if self.in_word && self.word_has_unquoted {
            self.word.split_quotes = true;
        }
        self.start_word();
        self.word.quoted = true;
    }

    fn push_unquoted(&mut self, c: char) {
        if self.word.quoted && self.in_word {
            self.word.split_quotes = true;
        }
        self.start_word();
        self.word_has_unquoted = true;
        self.word.text.push(c);
    }

    /// Collect text up to the matching `)` starting at `self.i` (just past
    /// the opening bracket). Respects quotes and nesting.
    fn balanced(&mut self) -> String {
        let start = self.cs.get(self.i).map_or(self.src.len(), |&(b, _)| b);
        let mut depth = 1usize;
        let mut q: Option<char> = None;
        while let Some(c) = self.peek(0) {
            match (q, c) {
                (Some(qc), _) if c == qc => q = None,
                (Some('"'), '\\') => self.i += 1,
                (Some(_), _) => {}
                (None, '\'' | '"' | '`') => q = Some(c),
                (None, '\\') => self.i += 1,
                (None, '(') => depth += 1,
                (None, ')') => {
                    depth -= 1;
                    if depth == 0 {
                        let end = self.cs[self.i].0;
                        self.i += 1;
                        return self.src[start..end].to_string();
                    }
                }
                _ => {}
            }
            self.i += 1;
        }
        self.src[start.min(self.src.len())..].to_string()
    }

    fn backtick(&mut self) -> String {
        let start = self.cs.get(self.i).map_or(self.src.len(), |&(b, _)| b);
        while let Some(c) = self.peek(0) {
            if c == '\\' {
                self.i += 2;
                continue;
            }
            if c == '`' {
                let end = self.cs[self.i].0;
                self.i += 1;
                return self.src[start..end].to_string();
            }
            self.i += 1;
        }
        self.src[start.min(self.src.len())..].to_string()
    }

    fn subst(&mut self, kind: SubstKind, inner: String) {
        self.start_word();
        self.word.substs.push(Subst { kind, inner });
        self.word.text.push(SUBST_MARK);
    }

    fn dollar(&mut self) {
        // self.i points at '$'
        match self.peek(1) {
            Some('(') if self.peek(2) == Some('(') => {
                self.i += 3;
                let inner = self.balanced();
                // consume the second closing paren of $(( ))
                if self.peek(0) == Some(')') {
                    self.i += 1;
                }
                self.start_word();
                self.word.text.push_str(&inner);
            }
            Some('(') => {
                self.i += 2;
                let inner = self.balanced();
                self.subst(SubstKind::Command, inner);
            }
            Some('\'') => {
                self.i += 2;
                self.start_word();
                self.word.quoted = true;
                self.word.ansi_c = true;
                self.ansi_c();
            }
            Some('{') => {
                self.start_word();
                self.word.has_var = true;
                while let Some(c) = self.peek(0) {
                    self.word.text.push(c);
                    self.i += 1;
                    if c == '}' {
                        break;
                    }
                }
            }
            _ => {
                self.start_word();
                self.word.has_var = true;
                self.word.text.push('$');
                self.i += 1;
            }
        }
    }

    fn ansi_c(&mut self) {
        while let Some(c) = self.peek(0) {
            self.i += 1;
            match c {
                '\'' => return,
                '\\' => {
                    let Some(e) = self.peek(0) else { return };
                    self.i += 1;
                    let ch = match e {
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        'a' | 'b' | 'e' | 'E' | 'f' | 'v' => ' ',
                        'x' => self.hex_digits(2).unwrap_or('x'),
                        'u' => self.hex_digits(4).unwrap_or('u'),
                        'U' => self.hex_digits(8).unwrap_or('U'),
                        '0'..='7' => {
                            let mut v = e.to_digit(8).unwrap_or(0);
                            for _ in 0..2 {
                                match self.peek(0).and_then(|d| d.to_digit(8)) {
                                    Some(d) => {
                                        v = v * 8 + d;
                                        self.i += 1;
                                    }
                                    None => break,
                                }
                            }
                            char::from_u32(v).unwrap_or(' ')
                        }
                        other => other,
                    };
                    self.word.text.push(ch);
                }
                _ => self.word.text.push(c),
            }
        }
    }

    fn hex_digits(&mut self, max: usize) -> Option<char> {
        let mut v = 0u32;
        let mut n = 0;
        while n < max {
            match self.peek(0).and_then(|d| d.to_digit(16)) {
                Some(d) => {
                    v = v * 16 + d;
                    self.i += 1;
                    n += 1;
                }
                None => break,
            }
        }
        if n == 0 {
            None
        } else {
            char::from_u32(v)
        }
    }

    fn run(&mut self) {
        let mut ws_run = 0usize;
        while self.i < self.cs.len() {
            let (pos, c) = self.cs[self.i];
            if c == ' ' || c == '\t' {
                ws_run += 1;
                self.finish_word();
                self.i += 1;
                continue;
            }
            if ws_run > 0 {
                if ws_run > self.p.padding && c != '\n' {
                    self.p.padding = ws_run;
                    let tail: String = self.src[pos..].chars().take(200).collect();
                    self.p.padded_tail = tail;
                }
                ws_run = 0;
            }
            if !self.confusable_at.is_empty() && self.confusable_at.binary_search(&pos).is_ok() {
                self.p.confusable = true;
            }
            match c {
                '\n' => {
                    self.finish_pipe(false);
                    self.i += 1;
                }
                '#' if !self.in_word => {
                    let start = pos + 1;
                    while let Some(ch) = self.peek(0) {
                        if ch == '\n' {
                            break;
                        }
                        self.i += 1;
                    }
                    let end = self.cs.get(self.i).map_or(self.src.len(), |&(b, _)| b);
                    self.p.comments.push(self.src[start..end].to_string());
                }
                '\\' => {
                    match self.peek(1) {
                        Some('\n') => {}
                        Some(nx) => {
                            if nx.is_ascii_alphanumeric() {
                                self.word.escaped_letter = true;
                            }
                            self.push_unquoted(nx);
                        }
                        None => {}
                    }
                    self.i += 2;
                }
                '\'' => {
                    self.mark_quoted();
                    self.i += 1;
                    while let Some(ch) = self.peek(0) {
                        self.i += 1;
                        if ch == '\'' {
                            break;
                        }
                        self.word.text.push(ch);
                    }
                }
                '"' => {
                    self.mark_quoted();
                    self.i += 1;
                    while let Some(ch) = self.peek(0) {
                        match ch {
                            '"' => {
                                self.i += 1;
                                break;
                            }
                            '\\' if matches!(self.peek(1), Some('"' | '\\' | '$' | '`' | '\n')) => {
                                if let Some(nx) = self.peek(1) {
                                    if nx != '\n' {
                                        self.word.text.push(nx);
                                    }
                                }
                                self.i += 2;
                            }
                            '$' if self.peek(1) == Some('(') && self.peek(2) != Some('(') => {
                                self.i += 2;
                                let inner = self.balanced();
                                self.subst(SubstKind::Command, inner);
                            }
                            '`' => {
                                self.i += 1;
                                let inner = self.backtick();
                                self.subst(SubstKind::Command, inner);
                            }
                            '$' => {
                                self.word.has_var = true;
                                self.word.text.push('$');
                                self.i += 1;
                            }
                            _ => {
                                self.word.text.push(ch);
                                self.i += 1;
                            }
                        }
                    }
                }
                '$' => {
                    self.word_has_unquoted = true;
                    self.dollar();
                }
                '`' => {
                    self.i += 1;
                    let inner = self.backtick();
                    self.subst(SubstKind::Command, inner);
                }
                '<' | '>' if !self.in_word && self.peek(1) == Some('(') => {
                    self.i += 2;
                    let inner = self.balanced();
                    let kind = if c == '<' {
                        SubstKind::ProcIn
                    } else {
                        SubstKind::ProcOut
                    };
                    self.subst(kind, inner);
                }
                '<' | '>' => {
                    let fd_word = self.in_word
                        && !self.word.quoted
                        && !self.word.text.is_empty()
                        && self.word.text.bytes().all(|b| b.is_ascii_digit());
                    if fd_word {
                        self.word = Word::default();
                        self.in_word = false;
                        self.word_has_unquoted = false;
                    } else {
                        self.finish_word();
                    }
                    let (kind, len) = match (c, self.peek(1), self.peek(2)) {
                        ('>', Some('>'), _) => (RedirKind::Append, 2),
                        ('>', Some('&'), _) => (RedirKind::Dup, 2),
                        ('>', Some('|'), _) => (RedirKind::Out, 2),
                        ('>', _, _) => (RedirKind::Out, 1),
                        ('<', Some('<'), Some('<')) => (RedirKind::HereStr, 3),
                        ('<', Some('<'), Some('-')) => (RedirKind::HereDoc, 3),
                        ('<', Some('<'), _) => (RedirKind::HereDoc, 2),
                        ('<', Some('&'), _) => (RedirKind::Dup, 2),
                        ('<', Some('>'), _) => (RedirKind::In, 2),
                        _ => (RedirKind::In, 1),
                    };
                    self.pending = Some(kind);
                    self.i += len;
                }
                '|' => {
                    if self.peek(1) == Some('|') {
                        self.finish_pipe(false);
                        self.i += 2;
                    } else {
                        let starts_pipe =
                            !self.in_word && self.cmd.words.is_empty() && self.pipe.cmds.is_empty();
                        if starts_pipe {
                            self.pipe.group_input = self.last_group.take();
                        }
                        self.finish_cmd();
                        self.i += if self.peek(1) == Some('&') { 2 } else { 1 };
                    }
                }
                '&' => match self.peek(1) {
                    Some('&') => {
                        self.finish_pipe(false);
                        self.i += 2;
                    }
                    Some('>') => {
                        self.finish_word();
                        let append = self.peek(2) == Some('>');
                        self.pending = Some(if append {
                            RedirKind::Append
                        } else {
                            RedirKind::Out
                        });
                        self.i += if append { 3 } else { 2 };
                    }
                    _ => {
                        self.finish_pipe(true);
                        self.i += 1;
                    }
                },
                ';' => {
                    self.finish_pipe(false);
                    self.i += if self.peek(1) == Some(';') { 2 } else { 1 };
                }
                '(' => {
                    self.finish_pipe(false);
                    self.groups.push(self.p.pipelines.len());
                    self.i += 1;
                }
                ')' => {
                    self.finish_pipe(false);
                    if let Some(start) = self.groups.pop() {
                        self.last_group = Some((start, self.p.pipelines.len()));
                    }
                    self.i += 1;
                }
                _ => {
                    self.push_unquoted(c);
                    self.i += 1;
                }
            }
        }
        self.finish_pipe(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(p: &Parsed) -> Vec<Vec<String>> {
        p.pipelines
            .iter()
            .flat_map(|pl| pl.cmds.iter())
            .map(|c| c.words.iter().map(|w| w.text.clone()).collect())
            .collect()
    }

    #[test]
    fn pipes_and_quotes() {
        let p = parse("curl -fsSL 'https://a.example/x y' | sh -s -- --flag", &[]);
        assert_eq!(p.pipelines.len(), 1);
        assert_eq!(p.pipelines[0].cmds.len(), 2);
        assert_eq!(words(&p)[0], ["curl", "-fsSL", "https://a.example/x y"]);
        assert_eq!(words(&p)[1], ["sh", "-s", "--", "--flag"]);
    }

    #[test]
    fn substitutions() {
        let p = parse(r#"bash -c "$(curl -fsSL https://a.example/i.sh)""#, &[]);
        let w = &p.pipelines[0].cmds[0].words[2];
        assert_eq!(w.substs.len(), 1);
        assert_eq!(w.substs[0].inner, "curl -fsSL https://a.example/i.sh");
        let p = parse("bash <(curl -s https://a.example)", &[]);
        assert_eq!(
            p.pipelines[0].cmds[0].words[1].substs[0].kind,
            SubstKind::ProcIn
        );
    }

    #[test]
    fn comments_padding_and_redirects() {
        let p = parse(
            "echo hi > /tmp/x 2>&1                                   # I am not a robot",
            &[],
        );
        assert_eq!(p.comments, [" I am not a robot"]);
        assert!(p.padding >= 30);
        assert_eq!(p.pipelines[0].cmds[0].redirs[0].kind, RedirKind::Out);
        assert_eq!(p.pipelines[0].cmds[0].redirs[0].target.text, "/tmp/x");
    }

    #[test]
    fn obfuscated_names() {
        let p = parse(r#"c\url x; c"ur"l y; $'\x63url' z"#, &[]);
        let c = &p.pipelines;
        assert!(c[0].cmds[0].words[0].escaped_letter);
        assert_eq!(c[0].cmds[0].words[0].text, "curl");
        assert!(c[1].cmds[0].words[0].split_quotes);
        assert_eq!(c[2].cmds[0].words[0].text, "curl");
        assert!(c[2].cmds[0].words[0].ansi_c);
    }

    #[test]
    fn never_panics_on_garbage() {
        for s in [
            "'", "\"", "$(", "`", "<(", "\\", "$'\\x", "((((", "))))", "a\\", "$((", "${", "<<<",
            "&>",
        ] {
            let _ = parse(s, &[]);
        }
    }
}
