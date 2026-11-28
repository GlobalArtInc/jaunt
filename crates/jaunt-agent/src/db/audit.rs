use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use jaunt_pgwire::{Excerpt, Notice, StatementKind};
use jaunt_proto::{AgentEventValue, MAX_QUERY_BYTES, QueryAudit};
use sha2::{Digest, Sha256};

use crate::clock::Clock;
use crate::runtime::events::{SessionEvent, SessionEvents};

pub const QUERY_LIMIT: usize = MAX_QUERY_BYTES as usize;
const NAME_LIMIT: usize = 128;
const HOST_LIMIT: usize = 255;
const SHORT_LIMIT: usize = 32;
const DB_MESSAGE_LIMIT: usize = 512;
const CAPTURE_BYTES: usize = QUERY_LIMIT + 3;
const WORD_BYTES: usize = 8;

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
            Self::ServerMalformed => "server_malformed",
            Self::ServerTooLarge => "server_too_large",
            Self::ServerUnexpected => "server_unexpected_message",
        }
    }
}

#[derive(Default)]
struct WordScan {
    word: [u8; WORD_BYTES],
    length: usize,
    long: bool,
    password: bool,
}

impl WordScan {
    fn feed(&mut self, bytes: &[u8]) {
        for byte in bytes {
            if byte.is_ascii_alphanumeric() || *byte == b'_' || *byte >= 0x80 {
                if self.length < WORD_BYTES {
                    self.word[self.length] = byte.to_ascii_lowercase();
                    self.length += 1;
                } else {
                    self.long = true;
                }
            } else {
                self.end_word();
            }
        }
    }

    fn end_word(&mut self) {
        if !self.long && &self.word[..self.length] == b"password" {
            self.password = true;
        }
        self.length = 0;
        self.long = false;
    }

    fn names_a_password(mut self) -> bool {
        self.end_word();
        self.password
    }
}

pub struct QueryCapture {
    prefix: Vec<u8>,
    hasher: Sha256,
    length: usize,
    words: WordScan,
}

impl Default for QueryCapture {
    fn default() -> Self {
        Self {
            prefix: Vec::new(),
            hasher: Sha256::new(),
            length: 0,
            words: WordScan::default(),
        }
    }
}

impl QueryCapture {
    pub fn feed(&mut self, bytes: &[u8]) {
        let room = CAPTURE_BYTES.saturating_sub(self.prefix.len());
        self.prefix
            .extend_from_slice(&bytes[..room.min(bytes.len())]);
        self.hasher.update(bytes);
        self.length = self.length.saturating_add(bytes.len());
        self.words.feed(bytes);
    }

    pub fn of(bytes: &[u8]) -> Self {
        let mut capture = Self::default();
        capture.feed(bytes);
        capture
    }

    pub fn finish(self) -> CapturedQuery {
        let digest = self.hasher.finalize();
        let mut sha256 = String::with_capacity(64);
        for byte in digest.as_slice() {
            sha256.push_str(&format!("{byte:02x}"));
        }
        CapturedQuery {
            command: StatementKind::of(&self.prefix),
            sensitive: self.words.names_a_password(),
            prefix: self.prefix,
            sha256,
            length: self.length,
        }
    }
}

pub struct CapturedQuery {
    prefix: Vec<u8>,
    sha256: String,
    length: usize,
    command: StatementKind,
    sensitive: bool,
}

impl CapturedQuery {
    pub fn is_sensitive(&self) -> bool {
        self.sensitive
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
        if self.sensitive {
            return fields;
        }
        fields.insert(
            "sha256".to_owned(),
            AgentEventValue::Text(self.sha256.clone()),
        );
        if mode == QueryAudit::Text {
            let excerpt = Excerpt::of(&self.prefix, limit.min(QUERY_LIMIT));
            let truncated = excerpt.truncated || self.length > self.prefix.len();
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
            let cycle = self.counts.cycles_sent.load(Ordering::SeqCst) + 1;
            self.counts
                .sensitive_through
                .fetch_max(cycle, Ordering::SeqCst);
        }
        self.query(query, Protocol::Extended);
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

    fn sensitive(text: &str) -> bool {
        QueryCapture::of(text.as_bytes()).finish().is_sensitive()
    }

    #[test]
    fn every_statement_that_names_a_password_is_found_however_it_is_written() {
        for statement in [
            "ALTER ROLE app PASSWORD 'secret'",
            "create user app with encrypted password 'secret'",
            "AlTeR/**/RoLe app\n\tPaSsWoRd 'secret'",
            "-- comment\nALTER USER app ENCRYPTED PASSWORD 'secret'",
            "WITH x AS (SELECT 1) ALTER ROLE app PASSWORD 'secret'",
            "SELECT 1; ALTER ROLE app PASSWORD 'secret'",
            "CREATE GROUP admins PASSWORD 'secret'",
            "ALTER ROLE \"app\" PASSWORD$q$secret$q$",
            "DO $$BEGIN EXECUTE 'ALTER ROLE app PASSWORD ''secret'''; END$$",
            "ALTER SYSTEM SET primary_conninfo = 'host=h user=r password=secret'",
            "CREATE SUBSCRIPTION s CONNECTION 'host=h dbname=d password=secret' PUBLICATION p",
            "SELECT dblink_connect('host=h password=secret')",
            "CREATE SERVER s FOREIGN DATA WRAPPER postgres_fdw OPTIONS (password 'secret')",
            "CREATE USER MAPPING FOR app SERVER s OPTIONS (user 'r', password 'secret')",
            "COPY t TO PROGRAM 'psql \"host=h password=secret\"'",
            "SELECT $tag$PASSWORD=secret$tag$",
            "UPDATE accounts SET password = 'x'",
            "SELECT password FROM t",
        ] {
            assert!(sensitive(statement), "{statement}");
        }
        for statement in [
            "SELECT 1",
            "SELECT password_hash FROM users",
            "SELECT passwords FROM t",
            "ALTER ROLE app SET search_path = public",
            "SELECT 'pass word'",
        ] {
            assert!(!sensitive(statement), "{statement}");
        }
    }

    #[test]
    fn a_password_beyond_the_captured_prefix_or_split_across_pieces_is_found() {
        let mut capture = QueryCapture::default();
        for piece in [
            "SELECT /*".to_owned(),
            "x".repeat(9000),
            "*/ 'host=h pass".to_owned(),
            "WORD=secret'".to_owned(),
        ] {
            capture.feed(piece.as_bytes());
        }
        let captured = capture.finish();
        assert!(captured.is_sensitive());
        let fields = captured.fields(QueryAudit::Text, 4096, Protocol::Simple);
        let mut keys: Vec<&str> = fields.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["command", "protocol"]);
        let plain = QueryCapture::of(b"SELECT 1").finish();
        assert!(!plain.is_sensitive());
        let fields = plain.fields(QueryAudit::Text, 4096, Protocol::Simple);
        assert_eq!(
            fields["sha256"],
            AgentEventValue::Text(crate::keys::sha256_hex(b"SELECT 1"))
        );
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
        let captured = QueryCapture::of(text.as_bytes()).finish();
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
