const WORD_BYTES: usize = 11;
pub const MAX_TAG_BYTES: usize = 4096;
const TRIGGER_WORDS: [&[u8]; 5] = [
    b"password",
    b"sslpassword",
    b"pgpassword",
    b"passwd",
    b"uescape",
];
const NON_ASCII: u8 = 0x80;

fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn is_newline(byte: u8) -> bool {
    byte == b'\n' || byte == b'\r'
}

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80
}

fn is_tag_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte >= 0x80
}

fn is_tag(byte: u8) -> bool {
    is_tag_start(byte) || byte.is_ascii_digit()
}

fn is_lead_byte(byte: u8) -> bool {
    (0x81..=0xfe).contains(&byte)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    pub backslash_escapes: bool,
    pub multibyte_trail: bool,
}

#[derive(Default)]
struct WordBuffer {
    word: [u8; WORD_BYTES],
    length: usize,
    long: bool,
}

impl WordBuffer {
    fn push(&mut self, byte: u8) {
        if self.length < WORD_BYTES {
            self.word[self.length] = byte.to_ascii_lowercase();
            self.length += 1;
        } else {
            self.long = true;
        }
    }

    fn take(&mut self) -> Option<bool> {
        let ended = (self.length > 0 || self.long)
            .then(|| !self.long && TRIGGER_WORDS.contains(&&self.word[..self.length]));
        self.length = 0;
        self.long = false;
        ended
    }
}

#[derive(Default)]
struct Authority {
    active: bool,
    colon: bool,
}

#[derive(Default)]
struct Trigger {
    word: WordBuffer,
    last_matched: bool,
    window: [u8; 3],
    authority: Authority,
    found: bool,
}

impl Trigger {
    fn char(&mut self, byte: u8) {
        if is_word(byte) {
            self.word.push(byte);
        } else {
            self.end_word();
        }
        self.uri(byte);
    }

    fn decoded(&mut self, code_point: u32) {
        match u8::try_from(code_point) {
            Ok(byte) if byte < NON_ASCII => self.char(byte),
            _ => self.char(NON_ASCII),
        }
    }

    fn end_word(&mut self) {
        if let Some(matched) = self.word.take() {
            self.last_matched = matched;
            self.found |= matched;
        }
    }

    fn uri(&mut self, byte: u8) {
        let authority = &mut self.authority;
        if authority.active {
            if byte == b'@' {
                self.found |= authority.colon;
                authority.active = false;
            } else if byte == b'/' || is_space(byte) {
                authority.active = false;
            } else if byte == b':' {
                authority.colon = true;
            }
        }
        self.window = [self.window[1], self.window[2], byte];
        if &self.window == b"://" {
            self.authority = Authority {
                active: true,
                colon: false,
            };
        }
    }

    fn finish(&mut self) -> bool {
        self.end_word();
        self.found
    }
}

pub struct Masked {
    pub bytes: Vec<u8>,
    pub total: usize,
    capacity: usize,
    space: bool,
    last: u8,
}

impl Masked {
    fn put(&mut self, byte: u8) {
        self.last = byte;
        self.total = self.total.saturating_add(1);
        if self.bytes.len() < self.capacity {
            self.bytes.push(byte);
        }
    }

    fn flush_space(&mut self) {
        if self.space {
            self.space = false;
            self.put(b' ');
        }
    }

    fn gap(&mut self) {
        if self.total > 0 {
            self.space = true;
        }
    }

    fn code(&mut self, byte: u8) {
        if is_space(byte) {
            self.gap();
        } else {
            self.flush_space();
            self.put(byte);
        }
    }

    fn literal(&mut self) {
        self.flush_space();
        if self.last == b'\'' {
            self.put(b' ');
        }
        for byte in *b"'?'" {
            self.put(byte);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Standard,
    Escape,
    Unicode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Escape {
    None,
    Backslash,
    Trail,
    Digits {
        radix: u32,
        value: u32,
        got: u32,
        max: u32,
        letter: u8,
    },
}

#[derive(Default)]
struct Lookahead {
    newline: bool,
    dash: bool,
    comment: bool,
    spaced: bool,
    side: Trigger,
}

enum State {
    Code,
    Dash,
    Slash,
    LineComment,
    Block {
        depth: usize,
        last: u8,
    },
    Literal {
        kind: Kind,
        quote: bool,
        escape: Escape,
    },
    AfterQuote {
        kind: Kind,
        ahead: Box<Lookahead>,
    },
    Ident {
        unicode: bool,
        quote: bool,
        escape: Escape,
        hidden: bool,
    },
    DollarOpen {
        tag: Vec<u8>,
    },
    Dollar {
        pattern: Vec<u8>,
        matched: usize,
    },
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Next {
    Shown,
    Armed,
    Word,
    UnicodePrefix,
}

pub struct Lexer {
    state: State,
    reading: Reading,
    word_length: usize,
    word_first: u8,
    word_number: bool,
    code_word: WordBuffer,
    next: Next,
    after_unicode_prefix: bool,
    trigger: Trigger,
    masked: Masked,
}

pub struct Scanned {
    pub masked: Masked,
    pub sensitive: bool,
    pub malformed: bool,
}

enum Step {
    Done,
    Again,
}

impl Lexer {
    pub fn new(capacity: usize, reading: Reading) -> Self {
        Self {
            state: State::Code,
            reading,
            word_length: 0,
            word_first: 0,
            word_number: false,
            code_word: WordBuffer::default(),
            next: Next::Shown,
            after_unicode_prefix: false,
            trigger: Trigger::default(),
            masked: Masked {
                bytes: Vec::new(),
                total: 0,
                capacity,
                space: false,
                last: 0,
            },
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        for byte in bytes {
            while let Step::Again = self.step(*byte) {}
        }
    }

    pub fn is_malformed(&self) -> bool {
        matches!(self.state, State::Malformed)
    }

    pub fn finish(mut self) -> Scanned {
        let malformed = self.is_malformed();
        match std::mem::replace(&mut self.state, State::Code) {
            State::Code => self.end_code_word(),
            State::Dash => self.masked.code(b'-'),
            State::Slash => self.masked.code(b'/'),
            State::DollarOpen { tag } => {
                self.masked.code(b'$');
                for byte in tag {
                    self.masked.code(byte);
                }
            }
            State::Literal { escape, .. } | State::Ident { escape, .. } => {
                self.flush_escape(escape);
            }
            State::AfterQuote { mut ahead, .. } => {
                self.trigger.char(b'\'');
                self.trigger.found |= ahead.side.finish();
                if ahead.dash {
                    if ahead.spaced {
                        self.masked.gap();
                    }
                    self.masked.code(b'-');
                }
            }
            State::LineComment | State::Block { .. } | State::Dollar { .. } | State::Malformed => {}
        }
        Scanned {
            sensitive: self.trigger.finish(),
            masked: self.masked,
            malformed,
        }
    }

    fn word_is(&self, letter: u8) -> bool {
        self.word_length == 1 && self.word_first == letter
    }

    fn end_code_word(&mut self) {
        if self.code_word.take() == Some(true) {
            self.next = Next::Armed;
        }
    }

    fn step(&mut self, byte: u8) -> Step {
        match &mut self.state {
            State::Code => {
                self.code(byte);
                Step::Done
            }
            State::Dash => {
                if byte == b'-' {
                    self.trigger.char(byte);
                    self.state = State::LineComment;
                    self.end_masked_word();
                    self.masked.gap();
                } else {
                    self.state = State::Code;
                    self.word_length = 0;
                    self.punctuation(b'-');
                    self.code(byte);
                }
                Step::Done
            }
            State::Slash => {
                if byte == b'*' {
                    self.trigger.char(byte);
                    self.state = State::Block { depth: 1, last: 0 };
                    self.end_masked_word();
                    self.masked.gap();
                } else {
                    self.state = State::Code;
                    self.word_length = 0;
                    self.punctuation(b'/');
                    self.code(byte);
                }
                Step::Done
            }
            State::LineComment => {
                self.trigger.char(byte);
                if is_newline(byte) {
                    self.state = State::Code;
                    self.word_length = 0;
                }
                Step::Done
            }
            State::Block { depth, last } => {
                self.trigger.char(byte);
                if *last == b'*' && byte == b'/' {
                    *depth -= 1;
                    *last = 0;
                    if *depth == 0 {
                        self.state = State::Code;
                        self.word_length = 0;
                        self.masked.gap();
                    }
                } else if *last == b'/' && byte == b'*' {
                    *depth += 1;
                    *last = 0;
                } else {
                    *last = byte;
                }
                Step::Done
            }
            State::Literal {
                kind,
                quote,
                escape,
            } => {
                let (kind, quoted, current) = (*kind, *quote, *escape);
                if !quoted {
                    return self.literal_byte(kind, current, byte);
                }
                if byte == b'\'' {
                    self.trigger.char(byte);
                    if let State::Literal { quote, .. } = &mut self.state {
                        *quote = false;
                    }
                    return Step::Done;
                }
                if is_space(byte) || byte == b'-' {
                    let mut ahead = Box::new(Lookahead {
                        newline: is_newline(byte),
                        dash: byte == b'-',
                        spaced: is_space(byte),
                        ..Lookahead::default()
                    });
                    if is_space(byte) {
                        ahead.side.char(byte);
                    }
                    self.state = State::AfterQuote { kind, ahead };
                    return Step::Done;
                }
                self.trigger.char(b'\'');
                self.state = State::Code;
                self.word_length = 0;
                Step::Again
            }
            State::AfterQuote { kind, ahead } => {
                let kind = *kind;
                if ahead.comment {
                    ahead.side.char(byte);
                    if is_newline(byte) {
                        ahead.comment = false;
                        ahead.newline = true;
                    }
                    return Step::Done;
                }
                if ahead.dash {
                    if byte == b'-' {
                        ahead.dash = false;
                        ahead.comment = true;
                        ahead.side.char(byte);
                        return Step::Done;
                    }
                    return self.end_lookahead();
                }
                if is_space(byte) {
                    ahead.spaced = true;
                    ahead.newline |= is_newline(byte);
                    ahead.side.char(byte);
                    return Step::Done;
                }
                if byte == b'-' {
                    ahead.dash = true;
                    return Step::Done;
                }
                if byte == b'\'' && ahead.newline {
                    let found = ahead.side.finish();
                    self.trigger.found |= found;
                    self.state = State::Literal {
                        kind,
                        quote: false,
                        escape: Escape::None,
                    };
                    return Step::Done;
                }
                self.end_lookahead()
            }
            State::Ident {
                unicode,
                quote,
                escape,
                hidden,
            } => {
                let (unicode, quoted, current, hidden) = (*unicode, *quote, *escape, *hidden);
                if quoted {
                    if byte == b'"' {
                        if !hidden {
                            self.masked.put(byte);
                        }
                        if let State::Ident { quote, .. } = &mut self.state {
                            *quote = false;
                        }
                        return Step::Done;
                    }
                    if self.trigger.last_matched && !hidden {
                        self.next = Next::Armed;
                    }
                    self.state = State::Code;
                    self.word_length = 0;
                    return Step::Again;
                }
                self.ident_byte(unicode, current, hidden, byte)
            }
            State::DollarOpen { tag } => {
                if byte == b'$' {
                    let mut pattern = Vec::with_capacity(tag.len() + 2);
                    pattern.push(b'$');
                    pattern.extend_from_slice(tag);
                    pattern.push(b'$');
                    self.trigger.char(byte);
                    self.state = State::Dollar {
                        pattern,
                        matched: 0,
                    };
                    self.begin_literal();
                    return Step::Done;
                }
                let continues = if tag.is_empty() {
                    is_tag_start(byte)
                } else {
                    is_tag(byte)
                };
                if continues {
                    if tag.len() >= MAX_TAG_BYTES {
                        self.state = State::Malformed;
                    } else {
                        tag.push(byte);
                        self.trigger.char(byte);
                    }
                    return Step::Done;
                }
                let tag = std::mem::take(tag);
                self.state = State::Code;
                self.punctuation(b'$');
                for part in &tag {
                    self.masked.code(*part);
                    self.code_word.push(*part);
                }
                self.word_length = tag.len();
                self.word_first = tag.first().map_or(0, u8::to_ascii_lowercase);
                self.word_number = false;
                self.code(byte);
                Step::Done
            }
            State::Dollar { pattern, matched } => {
                self.trigger.char(byte);
                if pattern.get(*matched) == Some(&byte) {
                    *matched += 1;
                    if *matched == pattern.len() {
                        self.state = State::Code;
                        self.word_length = 0;
                    }
                } else if byte == b'$' {
                    *matched = 1;
                } else {
                    *matched = 0;
                }
                Step::Done
            }
            State::Malformed => Step::Done,
        }
    }

    fn end_lookahead(&mut self) -> Step {
        let State::AfterQuote { mut ahead, .. } = std::mem::replace(&mut self.state, State::Code)
        else {
            return Step::Again;
        };
        self.trigger.char(b'\'');
        self.trigger.char(b' ');
        self.trigger.found |= ahead.side.finish();
        if ahead.spaced || ahead.comment {
            self.masked.gap();
        }
        self.word_length = 0;
        if ahead.dash {
            self.code(b'-');
        }
        Step::Again
    }

    fn begin_literal(&mut self) {
        if !self.in_masked_word() {
            self.masked.literal();
        }
        self.next = Next::Shown;
    }

    fn in_masked_word(&self) -> bool {
        matches!(self.next, Next::Word | Next::UnicodePrefix)
    }

    fn end_masked_word(&mut self) {
        if self.in_masked_word() {
            self.next = Next::Shown;
        }
    }

    fn punctuation(&mut self, byte: u8) {
        match self.next {
            Next::Word | Next::UnicodePrefix => self.next = Next::Shown,
            Next::Armed if byte != b'=' => self.next = Next::Shown,
            Next::Armed | Next::Shown => {}
        }
        self.masked.code(byte);
    }

    fn code(&mut self, byte: u8) {
        self.trigger.char(byte);
        let continues_word = is_word(byte) || byte == b'$';
        if !continues_word {
            self.end_code_word();
        }
        if self.after_unicode_prefix {
            self.after_unicode_prefix = false;
            if byte == b'\'' {
                self.word_length = 0;
                self.state = State::Literal {
                    kind: Kind::Unicode,
                    quote: false,
                    escape: Escape::None,
                };
                self.begin_literal();
                return;
            }
            if byte == b'"' {
                self.open_ident(true);
                return;
            }
        }
        match byte {
            b'-' => self.state = State::Dash,
            b'/' => self.state = State::Slash,
            b'\'' => {
                let kind = if self.word_is(b'e') || self.reading.backslash_escapes {
                    Kind::Escape
                } else {
                    Kind::Standard
                };
                self.word_length = 0;
                self.state = State::Literal {
                    kind,
                    quote: false,
                    escape: Escape::None,
                };
                self.begin_literal();
            }
            b'"' => self.open_ident(false),
            b'$' if self.word_length == 0 || self.word_number => {
                self.state = State::DollarOpen { tag: Vec::new() };
            }
            b'&' if self.word_is(b'u') => {
                if self.next == Next::Word {
                    self.next = Next::UnicodePrefix;
                } else {
                    self.masked.code(byte);
                }
                self.word_length = 0;
                self.after_unicode_prefix = true;
            }
            _ if is_space(byte) => {
                self.word_length = 0;
                self.end_masked_word();
                self.masked.code(byte);
            }
            _ if continues_word => {
                let digit = byte.is_ascii_digit();
                if self.word_length == 0 || (self.word_number && !digit) {
                    let fresh = self.word_length == 0;
                    self.word_length = 0;
                    self.word_first = byte.to_ascii_lowercase();
                    self.word_number = digit;
                    match self.next {
                        Next::Armed => {
                            self.masked.literal();
                            self.next = Next::Word;
                        }
                        Next::UnicodePrefix if fresh => self.next = Next::Shown,
                        Next::Word | Next::UnicodePrefix | Next::Shown => {}
                    }
                }
                self.word_length += 1;
                self.code_word.push(byte);
                if self.next != Next::Word {
                    self.masked.code(byte);
                }
            }
            _ => {
                self.word_length = 0;
                self.punctuation(byte);
            }
        }
    }

    fn open_ident(&mut self, unicode: bool) {
        let hidden = matches!(self.next, Next::Armed | Next::Word | Next::UnicodePrefix);
        match self.next {
            Next::Armed => self.masked.literal(),
            Next::Shown => self.masked.code(b'"'),
            Next::Word | Next::UnicodePrefix => {}
        }
        self.next = Next::Shown;
        self.word_length = 0;
        self.state = State::Ident {
            unicode,
            quote: false,
            escape: Escape::None,
            hidden,
        };
    }

    fn set_escape(&mut self, next: Escape) {
        match &mut self.state {
            State::Literal { escape, .. } | State::Ident { escape, .. } => *escape = next,
            _ => {}
        }
    }

    fn flush_escape(&mut self, escape: Escape) {
        match escape {
            Escape::Digits {
                got: 0, letter: 0, ..
            }
            | Escape::None
            | Escape::Trail => {}
            Escape::Backslash => self.trigger.char(b'\\'),
            Escape::Digits { got: 0, letter, .. } => self.trigger.char(letter),
            Escape::Digits { value, .. } => self.trigger.decoded(value),
        }
    }

    fn escape_byte(&mut self, kind: Kind, escape: Escape, byte: u8) -> Step {
        match escape {
            Escape::None => Step::Done,
            Escape::Trail => {
                self.set_escape(Escape::None);
                if byte >= 0x40 {
                    Step::Done
                } else {
                    Step::Again
                }
            }
            Escape::Backslash => {
                let next = match (kind, byte) {
                    (Kind::Escape, b'x') => Some((16, 0, 0, 2, b'x')),
                    (Kind::Escape, b'u') => Some((16, 0, 0, 4, b'u')),
                    (Kind::Escape, b'U') => Some((16, 0, 0, 8, b'U')),
                    (Kind::Escape, b'0'..=b'7') => Some((8, u32::from(byte - b'0'), 1, 3, 0)),
                    (Kind::Unicode, b'+') => Some((16, 0, 0, 6, b'+')),
                    (Kind::Unicode, _) if byte.is_ascii_hexdigit() => {
                        Some((16, hex(byte), 1, 4, 0))
                    }
                    _ => None,
                };
                if let Some((radix, value, got, max, letter)) = next {
                    self.set_escape(Escape::Digits {
                        radix,
                        value,
                        got,
                        max,
                        letter,
                    });
                    return Step::Done;
                }
                self.set_escape(Escape::None);
                match (kind, byte) {
                    (Kind::Escape, b'b') => self.trigger.char(0x08),
                    (Kind::Escape, b'f') => self.trigger.char(0x0c),
                    (Kind::Escape, b'n') => self.trigger.char(b'\n'),
                    (Kind::Escape, b'r') => self.trigger.char(b'\r'),
                    (Kind::Escape, b't') => self.trigger.char(b'\t'),
                    (Kind::Escape, _) => self.trigger.char(byte),
                    (_, b'\\') => self.trigger.char(b'\\'),
                    _ => {
                        self.trigger.char(b'\\');
                        return Step::Again;
                    }
                }
                Step::Done
            }
            Escape::Digits {
                radix,
                value,
                got,
                max,
                letter,
            } => match char::from(byte).to_digit(radix) {
                Some(digit) => {
                    let value = value.saturating_mul(radix).saturating_add(digit);
                    if got + 1 == max {
                        self.set_escape(Escape::None);
                        self.trigger.decoded(value);
                    } else {
                        self.set_escape(Escape::Digits {
                            radix,
                            value,
                            got: got + 1,
                            max,
                            letter,
                        });
                    }
                    Step::Done
                }
                None => {
                    self.set_escape(Escape::None);
                    self.flush_escape(escape);
                    Step::Again
                }
            },
        }
    }

    fn literal_byte(&mut self, kind: Kind, escape: Escape, byte: u8) -> Step {
        if escape != Escape::None {
            return self.escape_byte(kind, escape, byte);
        }
        match byte {
            b'\'' => {
                if let State::Literal { quote, .. } = &mut self.state {
                    *quote = true;
                }
            }
            b'\\' if kind != Kind::Standard => self.set_escape(Escape::Backslash),
            _ if kind == Kind::Escape && self.reading.multibyte_trail && is_lead_byte(byte) => {
                self.trigger.char(NON_ASCII);
                self.set_escape(Escape::Trail);
            }
            _ => self.trigger.char(byte),
        }
        Step::Done
    }

    fn ident_byte(&mut self, unicode: bool, escape: Escape, hidden: bool, byte: u8) -> Step {
        if escape != Escape::None {
            let step = self.escape_byte(Kind::Unicode, escape, byte);
            if let Step::Done = step
                && !hidden
            {
                self.masked.put(byte);
            }
            return step;
        }
        if !hidden {
            self.masked.put(byte);
        }
        match byte {
            b'"' => {
                self.trigger.char(byte);
                if let State::Ident { quote, .. } = &mut self.state {
                    *quote = true;
                }
            }
            b'\\' if unicode => self.set_escape(Escape::Backslash),
            _ => self.trigger.char(byte),
        }
        Step::Done
    }
}

fn hex(byte: u8) -> u32 {
    char::from(byte).to_digit(16).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{Lexer, MAX_TAG_BYTES, Reading, Scanned};

    const CAPACITY: usize = 1 << 20;
    const SECRET: &[u8] = b"qz#~^%";
    const DEFAULT: Reading = Reading {
        backslash_escapes: false,
        multibyte_trail: false,
    };
    const READINGS: [Reading; 4] = [
        DEFAULT,
        Reading {
            backslash_escapes: true,
            multibyte_trail: false,
        },
        Reading {
            backslash_escapes: false,
            multibyte_trail: true,
        },
        Reading {
            backslash_escapes: true,
            multibyte_trail: true,
        },
    ];

    fn scan_with(reading: Reading, pieces: &[&[u8]]) -> Scanned {
        let mut lexer = Lexer::new(CAPACITY, reading);
        for piece in pieces {
            lexer.feed(piece);
        }
        lexer.finish()
    }

    fn scan(text: &str) -> Scanned {
        scan_with(DEFAULT, &[text.as_bytes()])
    }

    fn masked(text: &str) -> String {
        String::from_utf8(scan(text).masked.bytes).unwrap()
    }

    #[test]
    fn every_way_of_writing_a_password_or_a_credential_is_found() {
        for statement in [
            "ALTER ROLE app PASSWORD 'secret'",
            "create user app with encrypted password 'secret'",
            "AlTeR/**/RoLe app\n\tPaSsWoRd 'secret'",
            "WITH x AS (SELECT 1) ALTER ROLE app PASSWORD 'secret'",
            "DO $$BEGIN EXECUTE 'ALTER ROLE app PASSWORD ''secret'''; END$$",
            "ALTER SYSTEM SET primary_conninfo = 'host=h user=r password=secret'",
            "CREATE SUBSCRIPTION s CONNECTION 'host=h password=secret' PUBLICATION p",
            "SELECT dblink_connect('host=h password=secret')",
            "SELECT dblink_connect('host=h sslpassword=secret')",
            "CREATE SERVER s FOREIGN DATA WRAPPER postgres_fdw OPTIONS (password 'secret')",
            "CREATE USER MAPPING FOR app SERVER s OPTIONS (\"user\" 'r', password 'secret')",
            "CREATE USER MAPPING FOR app SERVER s OPTIONS (U&\"\\0070assword\" 'secret')",
            "SELECT dblink_connect(U&'host=h \\0070assword=secret')",
            "SELECT dblink_connect(U&'host=h \\+000070assword=secret')",
            "SELECT dblink_connect(U&'host=h !0070assword=secret' UESCAPE '!')",
            "SELECT dblink_connect(E'host=h \\x70assword=secret')",
            "SELECT dblink_connect(E'host=h \\160assword=secret')",
            "SELECT dblink_connect(E'host=h \\u0070assword=secret')",
            "SELECT dblink_connect(E'host=h \\U00000070assword=secret')",
            "SELECT dblink_connect(E'host=h password=secret')",
            "SELECT dblink_connect('host=h pass'\n'word=secret')",
            "SELECT dblink_connect('host=h pass' -- c\n'word=secret')",
            "SELECT dblink_connect(E'host=h pass'\n'\\x77ord=secret')",
            "COPY t TO PROGRAM 'PGPASSWORD=hunter2 pg_dump'",
            "SELECT dblink_connect('postgresql://u:hunter2@h/db')",
            "SELECT dblink_connect('postgresql://u:@h/db')",
            "SELECT dblink_connect('postgresql://:hunter2@h/db')",
            "SELECT $tag$passwd=secret$tag$",
            "UPDATE accounts SET password = 'x'",
            "SELECT 1 -- password",
            "ALTER ROLE app PASSWORD",
        ] {
            assert!(scan(statement).sensitive, "{statement}");
        }
        for statement in [
            "SELECT 1",
            "SELECT password_hash FROM users",
            "SELECT passwords FROM t",
            "SELECT passwordé FROM t",
            "ALTER ROLE x PASSWORDé 'y'",
            "SELECT 'pass word', E'\\x70ass word'",
            "SELECT 'pass' 'word'",
            "SELECT 'http://example.com/a:b@c'",
            "SELECT 'mailto:user@host'",
            "SELECT 'http://host:5432/db'",
        ] {
            assert!(!scan(statement).sensitive, "{statement}");
        }
    }

    #[test]
    fn literals_and_comments_are_masked_and_the_shape_is_kept() {
        let tag = "t".repeat(100);
        let long_tag = format!("SELECT ${tag}$secret${tag}$ FROM payments");
        for (statement, expected) in [
            (
                "ALTER ROLE app PASSWORD 'hunter2'",
                "ALTER ROLE app PASSWORD '?'",
            ),
            ("DROP TABLE payments -- password", "DROP TABLE payments"),
            (
                "SELECT  E'a\\'b' ,\t$q$x$q$ /* c /* d */ e */ FROM \"t  x\" -- z\n WHERE U&'\\0061' = N'n' AND b = $1",
                "SELECT E'?' , '?' FROM \"t  x\" WHERE U&'?' = N'?' AND b = $1",
            ),
            (
                "SELECT 'it''s' || x'1f' || B'01'",
                "SELECT '?' || x'?' || B'?'",
            ),
            ("SELECT a-b, c/d, e - -f", "SELECT a-b, c/d, e - -f"),
            ("SELECT a$b$ FROM t", "SELECT a$b$ FROM t"),
            ("SELECT \"a\"\"b\" FROM t", "SELECT \"a\"\"b\" FROM t"),
            ("/* c */ SELECT 1", "SELECT 1"),
            ("SELECT $aa$$a$aa$ FROM t", "SELECT '?' FROM t"),
            (long_tag.as_str(), "SELECT '?' FROM payments"),
            ("SELECT 'abc", "SELECT '?'"),
            ("SELECT E'ab\\", "SELECT E'?'"),
            ("SELECT $q$abc", "SELECT '?'"),
            ("SELECT 1 /* abc", "SELECT 1"),
            ("SELECT \"abc", "SELECT \"abc"),
            ("SELECT 'a'$$b$$, $$$$$$c$$", "SELECT '?' '?', '?' '?'"),
            ("SELECT 1E'a\\'b' , 2", "SELECT 1E'?' , 2"),
            ("SELECT 1$q$a$q$", "SELECT 1'?'"),
            ("SELECT 1.5E'a\\'b'", "SELECT 1.5E'?'"),
        ] {
            assert_eq!(masked(statement), expected, "{statement}");
        }
    }

    #[test]
    fn continued_strings_are_one_literal_of_the_first_kind() {
        for (statement, expected) in [
            (
                "CREATE ROLE x PASSWORD E'a'\n'b\\' hunter2'",
                "CREATE ROLE x PASSWORD '?'",
            ),
            (
                "SELECT E'a'\n'\\'';SELECT 1/0 AS zqx9; -- password",
                "SELECT E'?';SELECT 1/0 AS zqx9;",
            ),
            ("SELECT E'x'\n'\\' ; DROP TABLE users; --'", "SELECT E'?'"),
            ("SELECT 'a'\n'b' FROM t", "SELECT '?' FROM t"),
            ("SELECT 'a'\r\n'b' FROM t", "SELECT '?' FROM t"),
            ("SELECT 'a' -- c\n'b' FROM t", "SELECT '?' FROM t"),
            ("SELECT 'a'\n  -- c\n\t'b' FROM t", "SELECT '?' FROM t"),
            ("SELECT U&'a'\n'\\0062' FROM t", "SELECT U&'?' FROM t"),
            ("SELECT 'a'\n'b\\' FROM t", "SELECT '?' FROM t"),
            ("SELECT 'a' 'b' FROM t", "SELECT '?' '?' FROM t"),
            ("SELECT 'a'/* c */\n'b' FROM t", "SELECT '?' '?' FROM t"),
            ("SELECT 'a' -1", "SELECT '?' -1"),
            ("SELECT 'a'\n-1", "SELECT '?' -1"),
            ("SELECT 'a'\n", "SELECT '?'"),
            ("SELECT 'a' -", "SELECT '?' -"),
        ] {
            assert_eq!(masked(statement), expected, "{statement:?}");
        }
        let leak = scan("CREATE ROLE x PASSWORD E'a'\n'b\\' hunter2'");
        assert!(!String::from_utf8_lossy(&leak.masked.bytes).contains("hunter2"));
    }

    #[test]
    fn the_token_after_a_password_word_is_masked_whatever_it_is() {
        for (statement, expected) in [
            (
                "ALTER ROLE app PASSWORD hunter2",
                "ALTER ROLE app PASSWORD '?'",
            ),
            (
                "ALTER ROLE app PASSWORD \"hunter2\" VALID UNTIL 'x'",
                "ALTER ROLE app PASSWORD '?' VALID UNTIL '?'",
            ),
            (
                "ALTER ROLE app PASSWORD \"hunter2",
                "ALTER ROLE app PASSWORD '?'",
            ),
            (
                "ALTER ROLE app PASSWORD 12345678",
                "ALTER ROLE app PASSWORD '?'",
            ),
            (
                "ALTER ROLE app PASSWORD = hunter2",
                "ALTER ROLE app PASSWORD = '?'",
            ),
            (
                "ALTER ROLE app WITH PASSWORD E'x' LOGIN",
                "ALTER ROLE app WITH PASSWORD '?' LOGIN",
            ),
            (
                "ALTER ROLE app PASSWORD U&\"\\0068unter2\"",
                "ALTER ROLE app PASSWORD '?'",
            ),
            (
                "ALTER ROLE app PASSWORD -- c\n hunter2",
                "ALTER ROLE app PASSWORD '?'",
            ),
            (
                "ALTER ROLE app PASSWORD/* c */hunter2;",
                "ALTER ROLE app PASSWORD '?';",
            ),
            (
                "ALTER ROLE app PASSWORD; SELECT 1",
                "ALTER ROLE app PASSWORD; SELECT 1",
            ),
            (
                "SELECT U&'x!0061' UESCAPE '!' FROM t",
                "SELECT U&'?' UESCAPE '?' FROM t",
            ),
            (
                "OPTIONS (sslpassword hunter2, passwd hunter3)",
                "OPTIONS (sslpassword '?', passwd '?')",
            ),
            ("SELECT \"x\" FROM t", "SELECT \"x\" FROM t"),
        ] {
            assert_eq!(masked(statement), expected, "{statement:?}");
        }
    }

    #[test]
    fn a_dollar_tag_longer_than_four_kib_is_malformed_and_kept_small() {
        let mut lexer = Lexer::new(CAPACITY, DEFAULT);
        lexer.feed(b"SELECT $");
        lexer.feed(&vec![b't'; MAX_TAG_BYTES]);
        assert!(!lexer.is_malformed());
        lexer.feed(b"t");
        assert!(lexer.is_malformed());
        for _ in 0..80 {
            lexer.feed(&[b't'; 64 * 1024]);
        }
        lexer.feed(b"$secret$");
        let scanned = lexer.finish();
        assert!(scanned.malformed);
        assert_eq!(scanned.masked.bytes, b"SELECT");
    }

    #[test]
    fn the_masked_length_counts_past_the_kept_bytes() {
        let mut lexer = Lexer::new(10, DEFAULT);
        lexer.feed(b"SELECT 'x' FROM payments");
        let scanned = lexer.finish();
        assert_eq!(scanned.masked.bytes, b"SELECT '?'");
        assert_eq!(scanned.masked.total, "SELECT '?' FROM payments".len());
    }

    #[test]
    fn the_readings_disagree_exactly_on_the_hostile_forms() {
        let shown = |reading: Reading, text: &[u8]| scan_with(reading, &[text]).masked.bytes;
        let backslash = b"SELECT '\\' ;DROP TABLE users; --' /* password */";
        assert_ne!(shown(READINGS[0], backslash), shown(READINGS[1], backslash));
        let mut trail = b"SELECT E'".to_vec();
        trail.extend_from_slice(&[0x83, 0x5c]);
        trail.extend_from_slice(b"';DROP TABLE users; -- password '");
        assert_ne!(shown(READINGS[0], &trail), shown(READINGS[2], &trail));
        for plain in [
            "SELECT 'C:\\path' FROM t".as_bytes(),
            "SELECT E'\u{e9}' FROM t".as_bytes(),
            "SELECT E'\u{20ac}' FROM t".as_bytes(),
        ] {
            let first = shown(READINGS[0], plain);
            for reading in &READINGS[1..] {
                assert_eq!(shown(*reading, plain), first, "{plain:?}");
            }
        }
    }

    struct Random(u64);

    impl Random {
        fn next(&mut self, below: usize) -> usize {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            usize::try_from(self.0 >> 33).unwrap() % below
        }

        fn secret(&mut self) -> String {
            (0..self.next(6))
                .map(|_| char::from(SECRET[self.next(SECRET.len())]))
                .collect()
        }
    }

    fn push(text: &mut String, piece: &str) {
        let first = piece.bytes().next();
        let glued = text.bytes().last().is_some_and(|byte| {
            super::is_word(byte)
                || byte == b'$'
                || (byte == b'-' && first == Some(b'-'))
                || (byte == b'/' && first == Some(b'*'))
        });
        if glued {
            text.push(' ');
        }
        text.push_str(piece);
    }

    fn statement(random: &mut Random) -> String {
        let words = [
            "SELECT", "a", "1", "(", ")", ",", "=", "/", "password", "$1", "b$",
        ];
        let gaps = ["\n", " -- c\n", "\n -- d\n ", "\r\n", " ", "/**/\n"];
        let continuations = ["\n", " -- c\n", "\n -- d\n ", "\r\n"];
        let mut text = String::new();
        for _ in 0..random.next(12) + 1 {
            let piece = match random.next(15) {
                0 => format!("'{}'", random.secret()),
                1 => format!("E'{}\\'{}'", random.secret(), random.secret()),
                2 => format!("U&'{}\\0071'", random.secret()),
                3 => format!("$qz${}$qz$", random.secret()),
                4 => format!("$${}$$", random.secret()),
                5 => format!("-- {}\n", random.secret()),
                6 => format!("/* {} /* {} */ */", random.secret(), random.secret()),
                7 => "\"Col  1\"".to_owned(),
                8 => " \t\n ".to_owned(),
                9 => "-".to_owned(),
                10 => format!("'{}''{}'", random.secret(), random.secret()),
                11 => format!(
                    "'{}'{}'{}'",
                    random.secret(),
                    gaps[random.next(gaps.len())],
                    random.secret()
                ),
                12 => format!(
                    "E'{}'{}'{}\\'{}'",
                    random.secret(),
                    continuations[random.next(continuations.len())],
                    random.secret(),
                    random.secret()
                ),
                _ => words[random.next(words.len())].to_owned(),
            };
            push(&mut text, &piece);
            text.push_str([" ", "", "\n"][random.next(3)]);
        }
        match random.next(4) {
            0 => push(&mut text, &format!("'{}", random.secret())),
            1 => push(&mut text, &format!("/* {}", random.secret())),
            2 => push(&mut text, &format!("$qz${}", random.secret())),
            _ => {}
        }
        text
    }

    #[test]
    fn masking_hides_every_literal_and_comment_is_idempotent_and_ignores_chunking() {
        let mut random = Random(7);
        for _ in 0..6000 {
            let text = statement(&mut random);
            let bytes = text.as_bytes();
            for reading in READINGS {
                let whole = scan_with(reading, &[bytes]);
                let output = whole.masked.bytes.clone();
                assert!(
                    !output.iter().any(|byte| SECRET.contains(byte)),
                    "{reading:?} {text:?} -> {:?}",
                    String::from_utf8_lossy(&output)
                );
                let again = scan_with(reading, &[&output]);
                assert_eq!(again.masked.bytes, output, "{reading:?} {text:?}");
                let bytewise_pieces: Vec<&[u8]> = bytes.chunks(1).collect();
                let bytewise = scan_with(reading, &bytewise_pieces);
                assert_eq!(bytewise.masked.bytes, output, "{reading:?} {text:?}");
                assert_eq!(bytewise.masked.total, whole.masked.total);
                assert_eq!(bytewise.sensitive, whole.sensitive);
                if reading != DEFAULT {
                    continue;
                }
                for split in 0..=bytes.len() {
                    let chunked = scan_with(reading, &[&bytes[..split], &bytes[split..]]);
                    assert_eq!(chunked.masked.bytes, output, "{split} {text:?}");
                    assert_eq!(chunked.masked.total, whole.masked.total, "{split} {text:?}");
                    assert_eq!(chunked.sensitive, whole.sensitive, "{split} {text:?}");
                }
            }
        }
    }
}
