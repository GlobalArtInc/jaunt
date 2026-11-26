use std::fmt;

use bytes::Bytes;

#[derive(Clone, PartialEq, Eq)]
pub struct Statement {
    text: Bytes,
}

impl Statement {
    pub(crate) fn new(text: &[u8]) -> Self {
        Self {
            text: Bytes::copy_from_slice(text),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.text
    }

    pub fn length(&self) -> usize {
        self.text.len()
    }

    pub fn excerpt(&self, limit: usize) -> Excerpt {
        Excerpt::of(&self.text, limit)
    }

    pub fn kind(&self) -> StatementKind {
        StatementKind::of(&self.text)
    }

    pub fn is_compound(&self) -> bool {
        is_compound(&self.text)
    }
}

impl fmt::Debug for Statement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Statement")
            .field("length", &self.text.len())
            .field("kind", &self.kind())
            .field("compound", &self.is_compound())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Excerpt {
    pub text: String,
    pub truncated: bool,
    pub dropped_bytes: usize,
}

impl Excerpt {
    pub fn of(bytes: &[u8], limit: usize) -> Self {
        let mut text = String::new();
        let mut consumed = 0;
        'chunks: for chunk in bytes.utf8_chunks() {
            for character in chunk.valid().chars() {
                if text.len() + character.len_utf8() > limit {
                    break 'chunks;
                }
                text.push(character);
                consumed += character.len_utf8();
            }
            let invalid = chunk.invalid();
            if !invalid.is_empty() {
                if text.len() + char::REPLACEMENT_CHARACTER.len_utf8() > limit {
                    break;
                }
                text.push(char::REPLACEMENT_CHARACTER);
                consumed += invalid.len();
            }
        }
        let dropped_bytes = bytes.len() - consumed;
        Self {
            text,
            truncated: dropped_bytes > 0,
            dropped_bytes,
        }
    }
}

impl fmt::Debug for Excerpt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Excerpt")
            .field("length", &self.text.len())
            .field("truncated", &self.truncated)
            .field("dropped_bytes", &self.dropped_bytes)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatementKind {
    Select,
    Insert,
    Update,
    Delete,
    Ddl,
    Copy,
    Set,
    Other,
}

impl StatementKind {
    pub fn of(text: &[u8]) -> Self {
        let Some(start) = first_token(text) else {
            return Self::Other;
        };
        if is_compound(text) {
            return Self::Other;
        }
        let word_end = text[start..]
            .iter()
            .position(|byte| !is_identifier(*byte))
            .map_or(text.len(), |offset| start + offset);
        let word = &text[start..word_end];
        let matches = |keyword: &str| word.eq_ignore_ascii_case(keyword.as_bytes());
        if matches("select") {
            Self::Select
        } else if matches("insert") {
            Self::Insert
        } else if matches("update") {
            Self::Update
        } else if matches("delete") {
            Self::Delete
        } else if matches("copy") {
            Self::Copy
        } else if matches("set") || matches("reset") {
            Self::Set
        } else if [
            "create", "alter", "drop", "truncate", "comment", "grant", "revoke",
        ]
        .into_iter()
        .any(matches)
        {
            Self::Ddl
        } else {
            Self::Other
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Ddl => "ddl",
            Self::Copy => "copy",
            Self::Set => "set",
            Self::Other => "other",
        }
    }
}

fn is_identifier(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$' || byte >= 0x80
}

fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn is_compound(text: &[u8]) -> bool {
    let Some(start) = first_token(text) else {
        return false;
    };
    let Some(semicolon) = text[start..].iter().position(|byte| *byte == b';') else {
        return false;
    };
    let mut position = start + semicolon + 1;
    while position < text.len() {
        let byte = text[position];
        if is_space(byte) || byte == b';' {
            position += 1;
        } else if text[position..].starts_with(b"--") {
            match text[position..].iter().position(|byte| *byte == b'\n') {
                Some(line_end) => position += line_end + 1,
                None => return false,
            }
        } else if text[position..].starts_with(b"/*") {
            match block_comment_end(text, position) {
                Some(end) => position = end,
                None => return true,
            }
        } else {
            return true;
        }
    }
    false
}

fn first_token(text: &[u8]) -> Option<usize> {
    let mut position = 0;
    while position < text.len() {
        let byte = text[position];
        if is_space(byte) || byte == b'(' || byte == b';' {
            position += 1;
        } else if text[position..].starts_with(b"--") {
            let line_end = text[position..].iter().position(|byte| *byte == b'\n')?;
            position += line_end + 1;
        } else if text[position..].starts_with(b"/*") {
            position = block_comment_end(text, position)?;
        } else {
            return Some(position);
        }
    }
    None
}

fn block_comment_end(text: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut position = start;
    while position + 1 < text.len() {
        match (text[position], text[position + 1]) {
            (b'/', b'*') => {
                depth += 1;
                position += 2;
            }
            (b'*', b'/') => {
                depth -= 1;
                position += 2;
                if depth == 0 {
                    return Some(position);
                }
            }
            _ => position += 1,
        }
    }
    None
}
