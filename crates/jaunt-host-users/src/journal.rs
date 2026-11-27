use std::fmt;

pub(crate) const MAX_LOGGED_TEXT_BYTES: usize = 256;

const MAX_LOGGED_LOGIN_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Severity {
    #[default]
    Info,
    Warning,
    Error,
}

impl Severity {
    fn prefix(self) -> &'static str {
        match self {
            Self::Info => "<6>INFO",
            Self::Warning => "<4>WARN",
            Self::Error => "<3>ERROR",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Entry {
    severity: Severity,
    fields: Vec<(&'static str, String)>,
}

impl Entry {
    pub(crate) fn new(severity: Severity) -> Self {
        Self {
            severity,
            fields: Vec::new(),
        }
    }

    pub(crate) fn raise(&mut self, severity: Severity) {
        self.severity = self.severity.max(severity);
    }

    pub(crate) fn field(&mut self, key: &'static str, value: impl fmt::Display) {
        self.fields.push((key, value.to_string()));
    }

    pub(crate) fn text(&mut self, key: &'static str, bytes: &[u8]) {
        self.fields.push((
            key,
            format!("\"{}\"", printable(bytes, MAX_LOGGED_TEXT_BYTES)),
        ));
    }

    pub(crate) fn login(&mut self, raw: &str) {
        self.fields.push(("login", escape_login(raw)));
    }
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.severity.prefix())?;
        for (key, value) in &self.fields {
            write!(f, " {key}={value}")?;
        }
        Ok(())
    }
}

pub(crate) fn escape_login(raw: &str) -> String {
    let mut escaped = String::with_capacity(raw.len().min(MAX_LOGGED_LOGIN_BYTES));
    for byte in raw.bytes().take(MAX_LOGGED_LOGIN_BYTES) {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
            escaped.push(char::from(byte));
        } else {
            escaped.push_str(&format!("\\x{byte:02x}"));
        }
    }
    if raw.len() > MAX_LOGGED_LOGIN_BYTES {
        escaped.push_str("...");
    }
    if escaped.is_empty() {
        escaped.push_str("\"\"");
    }
    escaped
}

pub(crate) fn printable(bytes: &[u8], limit: usize) -> String {
    let text: String = bytes
        .iter()
        .take(limit)
        .map(|byte| match byte {
            b'"' => '\'',
            b'\\' => '/',
            b' '..=b'~' => char::from(*byte),
            0x80..=0xff => '?',
            _ => ' ',
        })
        .collect();
    text.trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use super::{Entry, MAX_LOGGED_TEXT_BYTES, Severity, escape_login, printable};

    #[test]
    fn a_login_is_logged_escaped_and_bounded() {
        for (raw, logged) in [
            ("alice", "alice"),
            ("a.b_c-9", "a.b_c-9"),
            ("Rozmarin", "Rozmarin"),
            ("al ice", "al\\x20ice"),
            ("a\nb=c\"", "a\\x0ab\\x3dc\\x22"),
            ("\u{1b}[31m", "\\x1b\\x5b31m"),
            ("\u{e9}", "\\xc3\\xa9"),
            ("", "\"\""),
        ] {
            assert_eq!(escape_login(raw), logged, "{raw:?}");
        }
        let long = "a".repeat(100);
        assert_eq!(escape_login(&long), format!("{}...", "a".repeat(64)));
    }

    #[test]
    fn tool_output_keeps_at_most_the_limit_without_control_characters() {
        assert_eq!(
            printable(
                b"useradd: user 'x' exists\n\tagain\x1b[0m \"q\" \\ \xff\n",
                256
            ),
            "useradd: user 'x' exists  again [0m 'q' / ?"
        );
        let long = vec![b'x'; 1000];
        assert_eq!(printable(&long, MAX_LOGGED_TEXT_BYTES).len(), 256);
    }

    #[test]
    fn an_entry_renders_one_line_with_the_highest_severity_seen() {
        let mut entry = Entry::new(Severity::Info);
        entry.field("ref", "H-0000000A");
        entry.login("bad name");
        entry.raise(Severity::Error);
        entry.raise(Severity::Warning);
        entry.text("stderr", b"line one\nline two\n");
        assert_eq!(
            entry.to_string(),
            "<3>ERROR ref=H-0000000A login=bad\\x20name stderr=\"line one line two\""
        );
    }
}
