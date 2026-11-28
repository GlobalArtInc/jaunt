use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use jaunt_pgwire::{Excerpt, Notice, StatementKind};
use jaunt_proto::{AgentEventValue, MAX_QUERY_BYTES, QueryAudit};
use sha2::{Digest, Sha256};

use super::lexer::{Lexer, Reading, Scanned};
use crate::clock::Clock;
use crate::runtime::events::{SessionEvent, SessionEvents};

pub const QUERY_LIMIT: usize = MAX_QUERY_BYTES as usize;
const NAME_LIMIT: usize = 128;
const HOST_LIMIT: usize = 255;
const SHORT_LIMIT: usize = 32;
const DB_MESSAGE_LIMIT: usize = 512;
const CAPTURE_BYTES: usize = QUERY_LIMIT + 3;

const SESSION_START: &str = "db.session.start";
const SESSION_END: &str = "db.session.end";
const QUERY: &str = "db.query";
const ERROR: &str = "db.error";
const PROTOCOL_ERROR: &str = "db.protocol_error";

pub fn cut(text: &str, max: usize) -> &str {
    let mut end = max.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn text(value: &str, max: usize) -> AgentEventValue {
    AgentEventValue::Text(cut(value, max).to_owned())
}

fn int(value: u64) -> AgentEventValue {
    AgentEventValue::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Simple,
    Extended,
}

impl Protocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::Simple => "simple",
            Self::Extended => "extended",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolProblem {
    PasswordRequested,
    ClientMalformed,
    ClientTooLarge,
    ClientFunctionCall,
    ClientUnexpected,
    ClientEncoding,
    ServerMalformed,
    ServerTooLarge,
    ServerUnexpected,
}

impl ProtocolProblem {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PasswordRequested => "password_requested",
            Self::ClientMalformed => "client_malformed",
            Self::ClientTooLarge => "client_too_large",
            Self::ClientFunctionCall => "client_function_call",
            Self::ClientUnexpected => "client_unexpected_message",
            Self::ClientEncoding => "client_encoding",
            Self::ServerMalformed => "server_malformed",
            Self::ServerTooLarge => "server_too_large",
            Self::ServerUnexpected => "server_unexpected_message",
        }
    }
}

const READINGS: [Reading; 2] = [
    Reading {
        backslash_escapes: false,
    },
    Reading {
        backslash_escapes: true,
    },
];

pub struct QueryCapture {
    prefix: Vec<u8>,
    hasher: Sha256,
    length: usize,
    lexers: Vec<Lexer>,
    pipelined: bool,
    high: bool,
}

impl Default for QueryCapture {
    fn default() -> Self {
        Self::new(false)
    }
}

impl QueryCapture {
    pub fn new(pipelined: bool) -> Self {
        Self {
            prefix: Vec::new(),
            hasher: Sha256::new(),
            length: 0,
            lexers: READINGS
                .iter()
                .map(|reading| Lexer::new(CAPTURE_BYTES, *reading))
                .collect(),
            pipelined,
            high: false,
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        let room = CAPTURE_BYTES.saturating_sub(self.prefix.len());
        self.prefix
            .extend_from_slice(&bytes[..room.min(bytes.len())]);
        self.hasher.update(bytes);
        self.length = self.length.saturating_add(bytes.len());
        self.high |= bytes.iter().any(|byte| *byte >= 0x80);
        for lexer in &mut self.lexers {
            lexer.feed(bytes);
        }
    }

    pub fn is_malformed(&self) -> bool {
        self.lexers.iter().any(Lexer::is_malformed)
    }

    pub fn of(bytes: &[u8], pipelined: bool) -> Self {
        let mut capture = Self::new(pipelined);
        capture.feed(bytes);
        capture
    }

    pub fn finish(self) -> CapturedQuery {
        let mut scans: Vec<Scanned> = self.lexers.into_iter().map(Lexer::finish).collect();
        let sensitive = scans.iter().any(|scan| scan.sensitive);
        let malformed = scans.iter().any(|scan| scan.malformed);
        let ambiguous = scans.windows(2).any(|pair| {
            pair[0].masked.bytes != pair[1].masked.bytes
                || pair[0].masked.total != pair[1].masked.total
        });
        let primary = scans.swap_remove(0);
        let digest = self.hasher.finalize();
        let mut sha256 = String::with_capacity(64);
        for byte in digest.as_slice() {
            sha256.push_str(&format!("{byte:02x}"));
        }
        let shown = if (self.pipelined && self.high) || (sensitive && ambiguous) {
            Shown::Command
        } else if sensitive {
            Shown::Masked(primary.masked.bytes, primary.masked.total)
        } else {
            Shown::Plain
        };
        CapturedQuery {
            command: StatementKind::of(&self.prefix),
            shown,
            malformed,
            prefix: self.prefix,
            sha256,
            length: self.length,
        }
    }
}

enum Shown {
    Plain,
    Masked(Vec<u8>, usize),
    Command,
}

pub struct CapturedQuery {
    prefix: Vec<u8>,
    sha256: String,
    length: usize,
    command: StatementKind,
    shown: Shown,
    malformed: bool,
}

impl CapturedQuery {
    pub fn is_sensitive(&self) -> bool {
        !matches!(self.shown, Shown::Plain)
    }

    pub fn is_malformed(&self) -> bool {
        self.malformed
    }

    fn fields(
        &self,
        mode: QueryAudit,
        limit: usize,
        protocol: Protocol,
    ) -> BTreeMap<String, AgentEventValue> {
        let mut fields = BTreeMap::new();
        fields.insert("protocol".to_owned(), text(protocol.as_str(), SHORT_LIMIT));
        fields.insert(
            "command".to_owned(),
            text(self.command.as_str(), SHORT_LIMIT),
        );
        let (kept, total) = match &self.shown {
            Shown::Command => return fields,
            Shown::Masked(masked, total) => (masked, *total),
            Shown::Plain => {
                fields.insert(
                    "length".to_owned(),
                    AgentEventValue::Int(i64::try_from(self.length).unwrap_or(i64::MAX)),
                );
                fields.insert(
                    "sha256".to_owned(),
                    AgentEventValue::Text(self.sha256.clone()),
                );
                (&self.prefix, self.length)
            }
        };
        if mode == QueryAudit::Text {
            let excerpt = Excerpt::of(kept, limit.min(QUERY_LIMIT));
            let truncated = excerpt.truncated || total > kept.len();
            fields.insert("text".to_owned(), AgentEventValue::Text(excerpt.text));
            fields.insert("truncated".to_owned(), AgentEventValue::Bool(truncated));
        }
        fields
    }
}

#[derive(Debug, Clone, Copy)]
pub struct QuerySettings {
    pub mode: QueryAudit,
    pub limit: usize,
}

pub struct SessionStart<'a> {
    pub db_user: &'a str,
    pub db_name: &'a str,
    pub application_name: Option<&'a str>,
    pub server: &'a str,
}

#[derive(Default)]
struct Counts {
    queries: AtomicU64,
    errors: AtomicU64,
    bytes: AtomicU64,
    cycles_sent: AtomicU64,
    sensitive_through: AtomicU64,
    ready_seen: AtomicU64,
}

pub struct SessionAudit {
    events: SessionEvents,
    clock: Arc<dyn Clock>,
    started: SystemTime,
    settings: QuerySettings,
    counts: Counts,
}

impl SessionAudit {
    pub fn start(
        events: SessionEvents,
        clock: Arc<dyn Clock>,
        settings: QuerySettings,
        start: &SessionStart<'_>,
    ) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert("db_user".to_owned(), text(start.db_user, NAME_LIMIT));
        fields.insert("db_name".to_owned(), text(start.db_name, NAME_LIMIT));
        fields.insert("server".to_owned(), text(start.server, HOST_LIMIT));
        if let Some(name) = start.application_name {
            fields.insert("application_name".to_owned(), text(name, NAME_LIMIT));
        }
        events.emit(SessionEvent {
            name: SESSION_START,
            fields,
        });
        let started = clock.now();
        Self {
            events,
            clock,
            started,
            settings,
            counts: Counts::default(),
        }
    }

    pub fn query(&self, query: &CapturedQuery, protocol: Protocol) {
        self.counts.queries.fetch_add(1, Ordering::AcqRel);
        self.events.emit(SessionEvent {
            name: QUERY,
            fields: query.fields(self.settings.mode, self.settings.limit, protocol),
        });
    }

    pub fn simple_query(&self, query: &CapturedQuery) {
        let cycle = self.counts.cycles_sent.fetch_add(1, Ordering::SeqCst) + 1;
        if query.is_sensitive() {
            self.counts
                .sensitive_through
                .fetch_max(cycle, Ordering::SeqCst);
        }
        self.query(query, Protocol::Simple);
    }

    pub fn extended_query(&self, query: &CapturedQuery) {
        if query.is_sensitive() {
            self.sensitive_cycle();
        }
        self.query(query, Protocol::Extended);
    }

    pub fn unconfirmed(&self) -> bool {
        self.counts.cycles_sent.load(Ordering::SeqCst)
            > self.counts.ready_seen.load(Ordering::SeqCst)
    }

    pub fn sensitive_cycle(&self) {
        let cycle = self.counts.cycles_sent.load(Ordering::SeqCst) + 1;
        self.counts
            .sensitive_through
            .fetch_max(cycle, Ordering::SeqCst);
    }

    pub fn sync_sent(&self) {
        self.counts.cycles_sent.fetch_add(1, Ordering::SeqCst);
    }

    pub fn ready(&self) {
        self.counts.ready_seen.fetch_add(1, Ordering::SeqCst);
    }

    pub fn error(&self, notice: &Notice) {
        self.counts.errors.fetch_add(1, Ordering::AcqRel);
        let withheld = self.counts.ready_seen.load(Ordering::SeqCst)
            < self.counts.sensitive_through.load(Ordering::SeqCst);
        let mut fields = BTreeMap::new();
        fields.insert("sqlstate".to_owned(), text(&notice.code, SHORT_LIMIT));
        if !withheld {
            fields.insert(
                "error_message".to_owned(),
                text(&notice.message, DB_MESSAGE_LIMIT),
            );
        }
        self.events.emit(SessionEvent {
            name: ERROR,
            fields,
        });
    }

    pub fn protocol_error(&self, problem: ProtocolProblem) {
        let mut fields = BTreeMap::new();
        fields.insert("reason".to_owned(), text(problem.as_str(), NAME_LIMIT));
        self.events.emit(SessionEvent {
            name: PROTOCOL_ERROR,
            fields,
        });
    }

    pub fn add_bytes(&self, count: usize) {
        self.counts
            .bytes
            .fetch_add(u64::try_from(count).unwrap_or(u64::MAX), Ordering::AcqRel);
    }
}

impl Drop for SessionAudit {
    fn drop(&mut self) {
        let elapsed = self
            .clock
            .now()
            .duration_since(self.started)
            .unwrap_or_default();
        let mut fields = BTreeMap::new();
        fields.insert(
            "queries".to_owned(),
            int(self.counts.queries.load(Ordering::Acquire)),
        );
        fields.insert(
            "errors".to_owned(),
            int(self.counts.errors.load(Ordering::Acquire)),
        );
        fields.insert(
            "bytes".to_owned(),
            int(self.counts.bytes.load(Ordering::Acquire)),
        );
        fields.insert(
            "duration_ms".to_owned(),
            int(u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)),
        );
        self.events.emit(SessionEvent {
            name: SESSION_END,
            fields,
        });
    }
}

#[cfg(test)]
mod tests {
    use jaunt_proto::{AgentEventValue, QueryAudit};

    use super::{Protocol, QueryCapture, cut};

    fn keys(fields: &std::collections::BTreeMap<String, AgentEventValue>) -> Vec<&str> {
        let mut keys: Vec<&str> = fields.keys().map(String::as_str).collect();
        keys.sort_unstable();
        keys
    }

    #[test]
    fn a_sensitive_statement_is_written_masked_without_digest_or_length() {
        let mut capture = QueryCapture::default();
        for piece in [
            "SELECT /*".to_owned(),
            "x".repeat(9000),
            "*/ dblink_connect('host=h pass".to_owned(),
            "WORD=secret')".to_owned(),
        ] {
            capture.feed(piece.as_bytes());
        }
        let captured = capture.finish();
        assert!(captured.is_sensitive());
        let fields = captured.fields(QueryAudit::Text, 4096, Protocol::Simple);
        assert_eq!(keys(&fields), ["command", "protocol", "text", "truncated"]);
        assert_eq!(
            fields["text"],
            AgentEventValue::Text("SELECT dblink_connect('?')".to_owned())
        );
        assert_eq!(fields["truncated"], AgentEventValue::Bool(false));
        let cut_short = captured.fields(QueryAudit::Text, 10, Protocol::Simple);
        assert_eq!(
            cut_short["text"],
            AgentEventValue::Text("SELECT dbl".to_owned())
        );
        assert_eq!(cut_short["truncated"], AgentEventValue::Bool(true));
        let digest = captured.fields(QueryAudit::Digest, 4096, Protocol::Extended);
        assert_eq!(keys(&digest), ["command", "protocol"]);
    }

    #[test]
    fn a_plain_statement_keeps_the_digest_and_the_length_of_the_whole_text() {
        let text = format!("SELECT '{}'", "a".repeat(20_000));
        let captured = QueryCapture::of(text.as_bytes(), false).finish();
        assert!(!captured.is_sensitive());
        let fields = captured.fields(QueryAudit::Text, 4096, Protocol::Simple);
        assert_eq!(
            keys(&fields),
            [
                "command",
                "length",
                "protocol",
                "sha256",
                "text",
                "truncated"
            ]
        );
        assert_eq!(text.len(), 20_009);
        assert_eq!(
            fields["length"],
            AgentEventValue::Int(i64::try_from(text.len()).unwrap())
        );
        assert_eq!(
            fields["sha256"],
            AgentEventValue::Text(crate::keys::sha256_hex(text.as_bytes()))
        );
        let one = QueryCapture::of(b"SELECT 1", false).finish();
        let fields = one.fields(QueryAudit::Digest, 4096, Protocol::Simple);
        assert_eq!(keys(&fields), ["command", "length", "protocol", "sha256"]);
        assert_eq!(fields["length"], AgentEventValue::Int(8));
    }

    #[test]
    fn a_statement_the_readings_disagree_on_loses_its_text_only_when_it_names_a_password() {
        for text in [
            b"SELECT 'a\\' x' FROM t -- password".to_vec(),
            b"SELECT '\\' ;DROP TABLE users; --' /* password */".to_vec(),
        ] {
            let captured = QueryCapture::of(&text, false).finish();
            assert!(captured.is_sensitive(), "{text:?}");
            let fields = captured.fields(QueryAudit::Text, 4096, Protocol::Simple);
            assert_eq!(keys(&fields), ["command", "protocol"], "{text:?}");
        }
        let doubtful = b"SELECT replace(p, '\\', '/') FROM t";
        let captured = QueryCapture::of(doubtful, false).finish();
        assert!(!captured.is_sensitive());
        let fields = captured.fields(QueryAudit::Text, 4096, Protocol::Simple);
        assert_eq!(
            keys(&fields),
            [
                "command",
                "length",
                "protocol",
                "sha256",
                "text",
                "truncated"
            ]
        );
        assert_eq!(
            fields["text"],
            AgentEventValue::Text("SELECT replace(p, '\\', '/') FROM t".to_owned())
        );
        let escaped =
            QueryCapture::of(b"SELECT dblink_connect('host=h \\x70assword=x')", false).finish();
        assert!(escaped.is_sensitive());
        let fields = escaped.fields(QueryAudit::Text, 4096, Protocol::Simple);
        assert_eq!(
            fields["text"],
            AgentEventValue::Text("SELECT dblink_connect('?')".to_owned())
        );
    }

    #[test]
    fn a_statement_with_high_bytes_sent_behind_unconfirmed_ones_keeps_only_its_command() {
        let mut big5 = b"SELECT '$a$".to_vec();
        big5.extend_from_slice(&[0xa4, 0xee, 0xa7, 0xc0]);
        big5.extend_from_slice(b";SELECT 1/0 AS zqx9;");
        big5.push(0xea);
        big5.extend_from_slice(b"\\''/*");
        big5.extend_from_slice(&[0xc5, 0xa3]);
        big5.push(b'\'');
        let pipelined = QueryCapture::of(&big5, true).finish();
        assert!(pipelined.is_sensitive());
        let fields = pipelined.fields(QueryAudit::Text, 4096, Protocol::Simple);
        assert_eq!(keys(&fields), ["command", "protocol"]);
        let alone = QueryCapture::of(&big5, false).finish();
        assert!(!alone.is_sensitive());
        assert!(
            alone
                .fields(QueryAudit::Text, 4096, Protocol::Simple)
                .contains_key("text")
        );
        let ascii = QueryCapture::of(b"SELECT 'a\\' FROM t", true).finish();
        assert!(!ascii.is_sensitive());
        assert!(
            ascii
                .fields(QueryAudit::Text, 4096, Protocol::Simple)
                .contains_key("text")
        );
    }

    #[test]
    fn a_dollar_tag_over_the_limit_makes_the_statement_malformed() {
        let mut capture = QueryCapture::default();
        capture.feed(b"SELECT $");
        capture.feed(&vec![b't'; super::super::lexer::MAX_TAG_BYTES]);
        assert!(!capture.is_malformed());
        capture.feed(b"t$x$");
        assert!(capture.is_malformed());
        assert!(capture.finish().is_malformed());
    }

    #[test]
    fn cuts_never_split_a_character() {
        assert_eq!(cut("añb", 2), "a");
        assert_eq!(cut("añb", 3), "añ");
        assert_eq!(cut("abc", 10), "abc");
        assert_eq!(cut("€", 2), "");
    }

    #[test]
    fn the_text_is_cut_on_a_character_boundary_and_the_digest_covers_everything() {
        let text = format!("SELECT '{}'", "é".repeat(5000));
        let captured = QueryCapture::of(text.as_bytes(), false).finish();
        let fields = captured.fields(QueryAudit::Text, 11, Protocol::Simple);
        assert_eq!(
            fields["text"],
            AgentEventValue::Text("SELECT 'é".to_owned())
        );
        assert_eq!(fields["truncated"], AgentEventValue::Bool(true));
        assert_eq!(
            fields["sha256"],
            AgentEventValue::Text(crate::keys::sha256_hex(text.as_bytes()))
        );
        let wide = captured.fields(QueryAudit::Text, 100_000, Protocol::Simple);
        let AgentEventValue::Text(kept) = &wide["text"] else {
            panic!("expected a text");
        };
        assert!(kept.len() <= super::QUERY_LIMIT && kept.len() > super::QUERY_LIMIT - 2);
        assert!(text.starts_with(kept.as_str()));
        let digest = captured.fields(QueryAudit::Digest, 100, Protocol::Extended);
        assert!(!digest.contains_key("text") && !digest.contains_key("truncated"));
        assert_eq!(
            digest["command"],
            AgentEventValue::Text("select".to_owned())
        );
        assert_eq!(
            digest["protocol"],
            AgentEventValue::Text("extended".to_owned())
        );
    }
}
