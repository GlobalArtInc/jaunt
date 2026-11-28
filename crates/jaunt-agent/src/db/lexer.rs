const WORD_BYTES: usize = 11;
const MAX_TAG_BYTES: usize = 4096;
const TRIGGER_WORDS: [&[u8]; 4] = [b"password", b"sslpassword", b"pgpassword", b"passwd"];
const NON_ASCII: u8 = 0x80;

fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
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

#[derive(Default)]
struct Authority {
    active: bool,
    length: usize,
    colon: bool,
}

#[derive(Default)]
struct Trigger {
    word: [u8; WORD_BYTES],
    length: usize,
    long: bool,
    window: [u8; 3],
    authority: Authority,
    found: bool,
}

impl Trigger {
    fn char(&mut self, byte: u8) {
        if is_word(byte) {
            if self.length < WORD_BYTES {
                self.word[self.length] = byte.to_ascii_lowercase();
                self.length += 1;
            } else {
                self.long = true;
            }
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
        let word = &self.word[..self.length];
        if !self.long && TRIGGER_WORDS.contains(&word) {
            self.found = true;
        }
        self.length = 0;
        self.long = false;
    }

    fn uri(&mut self, byte: u8) {
        let authority = &mut self.authority;
        if authority.active {
            if byte == b'@' {
                self.found |= authority.colon;
                authority.active = false;
            } else if byte == b'/' || is_space(byte) {
                authority.active = false;
            } else {
                if byte == b':' && authority.length >= 1 {
                    authority.colon = true;
                }
                authority.length += 1;
            }
        }
        self.window = [self.window[1], self.window[2], byte];
        if &self.window == b"://" {
            self.authority = Authority {
                active: true,
                length: 0,
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
    Digits {
        radix: u32,
        value: u32,
        got: u32,
        max: u32,
        letter: u8,
    },
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
    Ident {
        unicode: bool,
        quote: bool,
        escape: Escape,
    },
    DollarOpen {
        tag: Vec<u8>,
    },
    Dollar {
        pattern: Vec<u8>,
        matched: usize,
    },
    Overflow,
}

pub struct Lexer {
    state: State,
    backslash_escapes: bool,
    word_length: usize,
    word_first: u8,
    word_number: bool,
    after_unicode_prefix: bool,
    trigger: Trigger,
    masked: Masked,
}

pub struct Scanned {
    pub masked: Masked,
    pub sensitive: bool,
}

enum Step {
    Done,
    Again,
}

impl Lexer {
    pub fn new(capacity: usize, backslash_escapes: bool) -> Self {
        Self {
            state: State::Code,
            backslash_escapes,
            word_length: 0,
            word_first: 0,
            word_number: false,
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

    pub fn finish(mut self) -> Scanned {
        match std::mem::replace(&mut self.state, State::Code) {
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
            _ => {}
        }
        Scanned {
            sensitive: self.trigger.finish(),
            masked: self.masked,
        }
    }

    fn word_is(&self, letter: u8) -> bool {
        self.word_length == 1 && self.word_first == letter
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
                    self.masked.gap();
                    Step::Done
                } else {
                    self.masked.code(b'-');
                    self.state = State::Code;
                    self.word_length = 0;
                    self.code(byte);
                    Step::Done
                }
            }
            State::Slash => {
                if byte == b'*' {
                    self.trigger.char(byte);
                    self.state = State::Block { depth: 1, last: 0 };
                    self.masked.gap();
                    Step::Done
                } else {
                    self.masked.code(b'/');
                    self.state = State::Code;
                    self.word_length = 0;
                    self.code(byte);
                    Step::Done
                }
            }
            State::LineComment => {
                self.trigger.char(byte);
                if byte == b'\n' || byte == b'\r' {
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
                if quoted {
                    if byte == b'\'' {
                        if let State::Literal { quote, .. } = &mut self.state {
                            *quote = false;
                        }
                        return Step::Done;
                    }
                    self.state = State::Code;
                    self.word_length = 0;
                    return Step::Again;
                }
                self.literal_byte(kind, current, byte)
            }
            State::Ident {
                unicode,
                quote,
                escape,
            } => {
                let (unicode, quoted, current) = (*unicode, *quote, *escape);
                if quoted {
                    if byte == b'"' {
                        self.masked.put(byte);
                        if let State::Ident { quote, .. } = &mut self.state {
                            *quote = false;
                        }
                        return Step::Done;
                    }
                    self.state = State::Code;
                    self.word_length = 0;
                    return Step::Again;
                }
                self.ident_byte(unicode, current, byte)
            }
            State::DollarOpen { tag } => {
                if byte == b'$' {
                    let mut pattern = Vec::with_capacity(tag.len() + 2);
                    pattern.push(b'$');
                    pattern.extend_from_slice(tag);
                    pattern.push(b'$');
                    self.trigger.char(byte);
                    self.masked.literal();
                    self.state = State::Dollar {
                        pattern,
                        matched: 0,
                    };
                    return Step::Done;
                }
                let continues = if tag.is_empty() {
                    is_tag_start(byte)
                } else {
                    is_tag(byte)
                };
                if continues {
                    if tag.len() >= MAX_TAG_BYTES {
                        self.trigger.char(byte);
                        self.masked.literal();
                        self.state = State::Overflow;
                    } else {
                        tag.push(byte);
                        self.trigger.char(byte);
                    }
                    return Step::Done;
                }
                let tag = std::mem::take(tag);
                self.masked.code(b'$');
                for part in &tag {
                    self.masked.code(*part);
                }
                self.word_length = tag.len();
                self.word_first = tag.first().map_or(0, u8::to_ascii_lowercase);
                self.word_number = false;
                self.state = State::Code;
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
            State::Overflow => {
                self.trigger.char(byte);
                Step::Done
            }
        }
    }

    fn code(&mut self, byte: u8) {
        self.trigger.char(byte);
        if self.after_unicode_prefix {
            self.after_unicode_prefix = false;
            if byte == b'\'' {
                self.masked.literal();
                self.word_length = 0;
                self.state = State::Literal {
                    kind: Kind::Unicode,
                    quote: false,
                    escape: Escape::None,
                };
                return;
            }
            if byte == b'"' {
                self.masked.code(byte);
                self.word_length = 0;
                self.state = State::Ident {
                    unicode: true,
                    quote: false,
                    escape: Escape::None,
                };
                return;
            }
        }
        match byte {
            b'-' => self.state = State::Dash,
            b'/' => self.state = State::Slash,
            b'\'' => {
                let kind = if self.word_is(b'e') || self.backslash_escapes {
                    Kind::Escape
                } else {
                    Kind::Standard
                };
                self.masked.literal();
                self.word_length = 0;
                self.state = State::Literal {
                    kind,
                    quote: false,
                    escape: Escape::None,
                };
            }
            b'"' => {
                self.masked.code(byte);
                self.word_length = 0;
                self.state = State::Ident {
                    unicode: false,
                    quote: false,
                    escape: Escape::None,
                };
            }
            b'$' if self.word_length == 0 || self.word_number => {
                self.state = State::DollarOpen { tag: Vec::new() };
            }
            b'&' if self.word_is(b'u') => {
                self.masked.code(byte);
                self.word_length = 0;
                self.after_unicode_prefix = true;
            }
            _ => {
                self.masked.code(byte);
                if is_word(byte) || byte == b'$' {
                    let digit = byte.is_ascii_digit();
                    if self.word_length == 0 || (self.word_number && !digit) {
                        self.word_length = 0;
                        self.word_first = byte.to_ascii_lowercase();
                        self.word_number = digit;
                    }
                    self.word_length += 1;
                } else {
                    self.word_length = 0;
                }
            }
        }
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
            | Escape::None => {}
            Escape::Backslash => self.trigger.char(b'\\'),
            Escape::Digits { got: 0, letter, .. } => self.trigger.char(letter),
            Escape::Digits { value, .. } => self.trigger.decoded(value),
        }
    }

    fn escape_byte(&mut self, kind: Kind, escape: Escape, byte: u8) -> Step {
        match escape {
            Escape::None => Step::Done,
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
                self.trigger.char(byte);
                if let State::Literal { quote, .. } = &mut self.state {
                    *quote = true;
                }
            }
            b'\\' if kind != Kind::Standard => self.set_escape(Escape::Backslash),
            _ => self.trigger.char(byte),
        }
        Step::Done
    }

    fn ident_byte(&mut self, unicode: bool, escape: Escape, byte: u8) -> Step {
        if escape != Escape::None {
            let step = self.escape_byte(Kind::Unicode, escape, byte);
            if let Step::Done = step {
                self.masked.put(byte);
            }
            return step;
        }
        self.masked.put(byte);
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
    use super::{Lexer, Scanned};

    const CAPACITY: usize = 1 << 20;
    const SECRET: &[u8] = b"qz#~^%";

    fn scan_in(pieces: &[&[u8]]) -> Scanned {
        let mut lexer = Lexer::new(CAPACITY, false);
        for piece in pieces {
            lexer.feed(piece);
        }
        lexer.finish()
    }

    fn scan(text: &str) -> Scanned {
        scan_in(&[text.as_bytes()])
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
            "SELECT dblink_connect(E'host=h \\x70assword=secret')",
            "SELECT dblink_connect(E'host=h \\160assword=secret')",
            "SELECT dblink_connect(E'host=h \\u0070assword=secret')",
            "SELECT dblink_connect(E'host=h \\U00000070assword=secret')",
            "SELECT dblink_connect(E'host=h password=secret')",
            "COPY t TO PROGRAM 'PGPASSWORD=hunter2 pg_dump'",
            "SELECT dblink_connect('postgresql://u:hunter2@h/db')",
            "SELECT dblink_connect('postgresql://u:@h/db')",
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
            "SELECT 'http://example.com/a:b@c'",
            "SELECT 'mailto:user@host'",
            "SELECT 'http://host:5432/db'",
        ] {
            assert!(!scan(statement).sensitive, "{statement}");
        }
    }

    #[test]
    fn literals_and_comments_are_masked_and_the_shape_is_kept() {
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
            ("SELECT 'abc", "SELECT '?'"),
            ("SELECT E'ab\\", "SELECT E'?'"),
            ("SELECT $q$abc", "SELECT '?'"),
            ("SELECT 1 /* abc", "SELECT 1"),
            ("SELECT 1E'a\\'b' , 2", "SELECT 1E'?' , 2"),
            ("SELECT 1$q$a$q$", "SELECT 1'?'"),
            ("SELECT 1.5E'a\\'b'", "SELECT 1.5E'?'"),
            ("SELECT \"abc", "SELECT \"abc"),
            ("SELECT 'a'$$b$$, $$$$$$c$$", "SELECT '?' '?', '?' '?'"),
        ] {
            assert_eq!(masked(statement), expected, "{statement}");
        }
        let long_tag = format!("SELECT ${tag}$secret${tag}$", tag = "t".repeat(5000));
        assert_eq!(masked(&long_tag), "SELECT '?'");
    }

    #[test]
    fn plain_strings_follow_backslash_escapes_when_the_session_turned_them_on() {
        let text = b"SELECT 'a\\' qz', '\\x70assword=x'";
        let mut lexer = Lexer::new(CAPACITY, true);
        lexer.feed(text);
        let scanned = lexer.finish();
        assert_eq!(scanned.masked.bytes, b"SELECT '?', '?'");
        assert!(scanned.sensitive);
        assert!(!scan_in(&[text]).sensitive);
    }

    #[test]
    fn the_masked_length_counts_past_the_kept_bytes() {
        let mut lexer = Lexer::new(10, false);
        lexer.feed(b"SELECT 'x' FROM payments");
        let scanned = lexer.finish();
        assert_eq!(scanned.masked.bytes, b"SELECT '?'");
        assert_eq!(scanned.masked.total, "SELECT '?' FROM payments".len());
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

    fn statement(random: &mut Random) -> String {
        let words = [
            "SELECT", "a", "1", "(", ")", ",", "=", "/", "password", "$1", "b$",
        ];
        let mut text = String::new();
        for _ in 0..random.next(12) + 1 {
            let piece = match random.next(12) {
                0 => format!("'{}'", random.secret()),
                10 => format!("'{}''{}'", random.secret(), random.secret()),
                1 => format!("E'{}\\'{}'", random.secret(), random.secret()),
                2 => format!("U&'{}\\0071'", random.secret()),
                3 => format!("$qz${}$qz$", random.secret()),
                4 => format!("$${}$$", random.secret()),
                5 => format!("-- {}\n", random.secret()),
                6 => format!("/* {} /* {} */ */", random.secret(), random.secret()),
                7 => "\"Col  1\"".to_owned(),
                8 => " \t\n ".to_owned(),
                9 => "-".to_owned(),
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

    fn push(text: &mut String, piece: &str) {
        let glued = text
            .bytes()
            .last()
            .is_some_and(|byte| super::is_word(byte) || byte == b'$');
        if glued {
            text.push(' ');
        }
        text.push_str(piece);
    }

    #[test]
    fn masking_hides_every_literal_and_comment_is_idempotent_and_ignores_chunking() {
        let mut random = Random(7);
        for _ in 0..6000 {
            let text = statement(&mut random);
            let whole = scan(&text);
            let output = whole.masked.bytes.clone();
            assert!(
                !output.iter().any(|byte| SECRET.contains(byte)),
                "{text:?} -> {:?}",
                String::from_utf8_lossy(&output)
            );
            let again = scan_in(&[&output]);
            assert_eq!(again.masked.bytes, output, "{text:?}");
            let bytes = text.as_bytes();
            let split = random.next(bytes.len() + 1);
            let chunked = scan_in(&[&bytes[..split], &bytes[split..]]);
            let bytewise_pieces: Vec<&[u8]> = bytes.chunks(1).collect();
            let bytewise = scan_in(&bytewise_pieces);
            for other in [chunked, bytewise] {
                assert_eq!(other.masked.bytes, output, "{text:?}");
                assert_eq!(other.masked.total, whole.masked.total, "{text:?}");
                assert_eq!(other.sensitive, whole.sensitive, "{text:?}");
            }
        }
    }
}
