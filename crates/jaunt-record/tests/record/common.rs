use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use jaunt_record::{
    Accepted, Assembler, Chunk, Clock, Limits, Recorder, RecorderConfig, SessionKind,
    SessionManifest, Sink, SinkError,
};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const SESSION: &str = "sess-1";

pub fn assembler(limits: Limits) -> Assembler {
    Assembler::new(SESSION, limits)
}

pub fn three_chunk_session() -> (Vec<Chunk>, SessionManifest) {
    let (mut recorder, _clock) = recorder(false);
    recorder.push_output(b"one").unwrap();
    recorder.flush().unwrap();
    recorder.push_output(b"two").unwrap();
    recorder.flush().unwrap();
    recorder.push_output(b"three").unwrap();
    let manifest = recorder.finish(Some(0), 9).unwrap();
    (recorder.take_chunks(), manifest)
}

pub fn forged_from_compressed(seq: u64, raw_len: u64, compressed: Vec<u8>, is_last: bool) -> Chunk {
    let sha256 = Sha256::digest(&compressed)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Chunk {
        session_id: SESSION.to_owned(),
        seq,
        raw_len,
        compressed,
        sha256,
        is_last,
    }
}

pub fn forged(seq: u64, raw: &[u8], is_last: bool) -> Chunk {
    let compressed = zstd::bulk::compress(raw, 3).unwrap();
    forged_from_compressed(seq, raw.len() as u64, compressed, is_last)
}

pub fn accept_all(assembler: &mut Assembler, chunks: &[Chunk], sink: &mut VecSink) {
    for chunk in chunks {
        assert_eq!(assembler.accept(chunk, sink), Ok(Accepted::New));
    }
}

#[derive(Clone)]
pub struct TestClock(Arc<AtomicU64>);

impl TestClock {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU64::new(0)))
    }

    pub fn set_micros(&self, micros: u64) {
        self.0.store(micros, Ordering::SeqCst);
    }

    pub fn advance_micros(&self, micros: u64) {
        self.0.fetch_add(micros, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn elapsed(&self) -> Duration {
        Duration::from_micros(self.0.load(Ordering::SeqCst))
    }
}

pub fn config(record_input: bool) -> RecorderConfig {
    RecorderConfig {
        session_id: "sess-1".to_owned(),
        kind: SessionKind::Shell,
        node: "node-a".to_owned(),
        user: "alice".to_owned(),
        login: "root".to_owned(),
        command: None,
        started_at: 1_700_000_000,
        width: 80,
        height: 24,
        shell: "/bin/bash".to_owned(),
        term: "xterm-256color".to_owned(),
        record_input,
    }
}

pub fn recorder(record_input: bool) -> (Recorder, TestClock) {
    let clock = TestClock::new();
    let recorder = Recorder::new(config(record_input), Box::new(clock.clone())).unwrap();
    (recorder, clock)
}

pub fn inflate(chunk: &Chunk) -> Vec<u8> {
    zstd::stream::decode_all(&chunk.compressed[..]).unwrap()
}

pub fn cast_of(chunks: &[Chunk]) -> Vec<u8> {
    chunks.iter().flat_map(inflate).collect()
}

pub fn finish_cast(mut recorder: Recorder) -> (Vec<u8>, SessionManifest, Vec<Chunk>) {
    let manifest = recorder.finish(Some(0), 1_700_000_100).unwrap();
    let chunks = recorder.take_chunks();
    (cast_of(&chunks), manifest, chunks)
}

pub fn event_lines(cast: &[u8]) -> Vec<String> {
    String::from_utf8(cast.to_vec())
        .unwrap()
        .lines()
        .skip(1)
        .map(str::to_owned)
        .collect()
}

#[derive(Default)]
pub struct VecSink {
    pub written: Vec<(u64, Vec<u8>)>,
}

impl Sink for VecSink {
    fn write(&mut self, seq: u64, raw: &[u8]) -> Result<(), SinkError> {
        self.written.push((seq, raw.to_vec()));
        Ok(())
    }
}

pub struct FlakySink {
    pub inner: VecSink,
    pub failing_seq: Option<u64>,
}

impl FlakySink {
    pub fn failing_at(seq: u64) -> Self {
        Self {
            inner: VecSink::default(),
            failing_seq: Some(seq),
        }
    }

    pub fn recover(&mut self) {
        self.failing_seq = None;
    }
}

impl Sink for FlakySink {
    fn write(&mut self, seq: u64, raw: &[u8]) -> Result<(), SinkError> {
        if self.failing_seq == Some(seq) {
            return Err(SinkError::new("PAYLOADSECRET disk is full"));
        }
        self.inner.write(seq, raw)
    }
}

impl VecSink {
    pub fn seqs(&self) -> Vec<u64> {
        self.written.iter().map(|(seq, _)| *seq).collect()
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.written
            .iter()
            .flat_map(|(_, raw)| raw.clone())
            .collect()
    }
}

pub struct Event {
    pub kind: String,
    pub data: String,
}

pub struct Cast {
    pub events: Vec<Event>,
}

pub fn parse_cast(bytes: &[u8]) -> Result<Cast, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "not utf-8".to_owned())?;
    if !text.ends_with('\n') {
        return Err("missing trailing newline".to_owned());
    }
    let mut lines = text.split_terminator('\n');
    let header: Value = serde_json::from_str(lines.next().ok_or("empty cast")?)
        .map_err(|_| "header is not json".to_owned())?;
    let header = header.as_object().ok_or("header is not an object")?;
    let mut keys: Vec<&str> = header.keys().map(String::as_str).collect();
    keys.sort_unstable();
    if keys != ["env", "height", "timestamp", "version", "width"] {
        return Err("unexpected header keys".to_owned());
    }
    if header["version"] != 2 {
        return Err("version is not 2".to_owned());
    }
    for key in ["width", "height", "timestamp"] {
        header[key].as_u64().ok_or("header number expected")?;
    }
    let env = header["env"].as_object().ok_or("env is not an object")?;
    if env.len() != 2 || !env["SHELL"].is_string() || !env["TERM"].is_string() {
        return Err("bad env".to_owned());
    }
    let mut events = Vec::new();
    let mut previous = 0.0;
    for line in lines {
        let value: Value =
            serde_json::from_str(line).map_err(|_| "event is not json".to_owned())?;
        let items = value.as_array().ok_or("event is not an array")?;
        if items.len() != 3 {
            return Err("event arity".to_owned());
        }
        let time = items[0].as_f64().ok_or("time is not a number")?;
        if time < previous {
            return Err("time decreased".to_owned());
        }
        previous = time;
        let literal = line[1..].split(',').next().ok_or("no time literal")?;
        let decimals = literal.split('.').nth(1).map_or(0, str::len);
        if decimals > 6 {
            return Err("too many decimals".to_owned());
        }
        let kind = items[1].as_str().ok_or("kind is not a string")?;
        let data = items[2].as_str().ok_or("data is not a string")?;
        match kind {
            "o" | "i" | "m" => {}
            "r" => {
                let (cols, rows) = data.split_once('x').ok_or("bad resize")?;
                cols.parse::<u16>().map_err(|_| "bad cols".to_owned())?;
                rows.parse::<u16>().map_err(|_| "bad rows".to_owned())?;
            }
            _ => return Err("unknown kind".to_owned()),
        }
        events.push(Event {
            kind: kind.to_owned(),
            data: data.to_owned(),
        });
    }
    Ok(Cast { events })
}

pub fn joined_data(cast: &Cast, kind: &str) -> String {
    cast.events
        .iter()
        .filter(|event| event.kind == kind)
        .map(|event| event.data.as_str())
        .collect()
}

const WORDS: [&str; 8] = [
    "ls",
    "-la",
    "total",
    "drwxr-xr-x",
    "\"quoted\"",
    "back\\slash",
    "tab\there",
    "ok",
];
const WIDE: [&str; 5] = [
    "\u{e9}",
    "\u{65e5}\u{672c}",
    "\u{1f600}",
    "\u{20ac}",
    "\u{ffff}",
];

pub fn random_bytes(rng: &mut StdRng, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 16);
    while out.len() < len {
        match rng.random_range(0..10) {
            0..=4 => {
                out.extend_from_slice(WORDS[rng.random_range(0..WORDS.len())].as_bytes());
                out.push(b' ');
            }
            5 => out.extend_from_slice(if rng.random_bool(0.5) { b"\r\n" } else { b"\n" }),
            6 | 7 => out.extend_from_slice(WIDE[rng.random_range(0..WIDE.len())].as_bytes()),
            8 => out.extend_from_slice(b"\x1b[31m\x00\x07\x7f"),
            _ => {
                for _ in 0..rng.random_range(1..4) {
                    out.push(rng.random());
                }
            }
        }
    }
    out.truncate(len);
    out
}

pub struct Driven {
    pub output: Vec<u8>,
}

pub fn drive(recorder: &mut Recorder, clock: &TestClock, rng: &mut StdRng, total: usize) -> Driven {
    let mut driven = Driven {
        output: Vec::with_capacity(total),
    };
    while driven.output.len() < total {
        clock.advance_micros(rng.random_range(0..2_000));
        let size = if rng.random_range(0..500) == 0 {
            rng.random_range(50_000..200_000)
        } else {
            rng.random_range(1..4_096)
        };
        let bytes = random_bytes(rng, size);
        recorder.push_output(&bytes).unwrap();
        driven.output.extend_from_slice(&bytes);
        match rng.random_range(0..40) {
            0 => recorder
                .resize(rng.random_range(1..300), rng.random_range(1..100))
                .unwrap(),
            1 => recorder.marker("mark \"x\"").unwrap(),
            2 => recorder.flush().unwrap(),
            3 => {
                let bytes = random_bytes(rng, 16);
                recorder.push_input(&bytes).unwrap();
            }
            _ => {}
        }
    }
    driven
}

pub fn seeded(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}
