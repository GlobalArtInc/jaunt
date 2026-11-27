use std::collections::HashMap;
use std::future::Future;
use std::io::{self, Read};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::task::{Context, Poll};

use axum::body::{Body, Bytes, HttpBody};
use axum::extract::{Path, State};
use axum::http::{HeaderValue, Method, StatusCode, Uri, header};
use axum::response::Response;
use hyper::body::Frame;
use jaunt_audit::{RecordingKey, RecordingStoreError, StoredRecording};
use jaunt_record::SessionKind;
use jaunt_store::{Recording, RecordingState, is_session_id};
use serde::Serialize;
use tokio::task::JoinHandle;

use crate::control::Control;
use crate::http::{empty_response, error_response, json_response, server_error};

use super::admin_common::{Refusal, conflict, invalid_request, not_found, once};
use super::admin_principal::AdminPrincipal;
use super::session::{RecordingsRead, RequireAdmin};

pub const DEFAULT_PLAYBACK_LIMIT_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const STREAM_CHUNK_BYTES: usize = 64 * 1024;
const VIEW_WINDOW_SECS: i64 = 60;
const MAX_TRACKED_VIEWS: usize = 4096;
const MAX_COMMAND_CHARS: usize = 1024;
const CAST_CONTENT_TYPE: &str = "application/x-asciicast; charset=utf-8";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ViewKind {
    Stream,
    Download,
    Manifest,
}

impl ViewKind {
    const fn as_str(self) -> &'static str {
        match self {
            ViewKind::Stream => "stream",
            ViewKind::Download => "download",
            ViewKind::Manifest => "manifest",
        }
    }
}

type ViewKey = (String, String, ViewKind);

pub(crate) struct ViewLog {
    windows: Mutex<HashMap<ViewKey, i64>>,
}

impl Default for ViewLog {
    fn default() -> ViewLog {
        ViewLog {
            windows: Mutex::new(HashMap::new()),
        }
    }
}

impl ViewLog {
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.windows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    pub(crate) fn admit(&self, actor: &str, session_id: &str, kind: ViewKind, now: i64) -> bool {
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (actor.to_owned(), session_id.to_owned(), kind);
        if let Some(last) = windows.get(&key)
            && now.saturating_sub(*last) < VIEW_WINDOW_SECS
        {
            return false;
        }
        if !windows.contains_key(&key) && windows.len() >= MAX_TRACKED_VIEWS {
            windows.retain(|_, last| now.saturating_sub(*last) < VIEW_WINDOW_SECS);
            if windows.len() >= MAX_TRACKED_VIEWS {
                return true;
            }
        }
        windows.insert(key, now);
        true
    }
}

pub(crate) struct PlaybackLimit(AtomicU64);

impl Default for PlaybackLimit {
    fn default() -> PlaybackLimit {
        PlaybackLimit(AtomicU64::new(DEFAULT_PLAYBACK_LIMIT_BYTES))
    }
}

impl PlaybackLimit {
    pub(crate) fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    pub(crate) fn set(&self, bytes: u64) {
        self.0.store(bytes, Ordering::Relaxed);
    }
}

type Reader = Box<dyn Read + Send>;

enum Cursor {
    Idle(Reader),
    Reading(JoinHandle<(Reader, io::Result<Vec<u8>>)>),
    Finished,
}

pub(crate) struct CastBody {
    cursor: Cursor,
    budget: Option<u64>,
    chunk: usize,
}

impl CastBody {
    pub(crate) fn new(reader: Reader, budget: Option<u64>, chunk: usize) -> CastBody {
        CastBody {
            cursor: Cursor::Idle(reader),
            budget,
            chunk: chunk.max(1),
        }
    }

    fn want(&self) -> usize {
        match self.budget {
            Some(left) => usize::try_from(left.saturating_add(1))
                .map_or(self.chunk, |left| left.min(self.chunk)),
            None => self.chunk,
        }
    }
}

fn read_chunk(reader: &mut Reader, want: usize) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0_u8; want];
    let mut filled = 0;
    while filled < want {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    buffer.truncate(filled);
    Ok(buffer)
}

impl HttpBody for CastBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        loop {
            match std::mem::replace(&mut self.cursor, Cursor::Finished) {
                Cursor::Finished => return Poll::Ready(None),
                Cursor::Idle(mut reader) => {
                    let want = self.want();
                    self.cursor = Cursor::Reading(tokio::task::spawn_blocking(move || {
                        let read = read_chunk(&mut reader, want);
                        (reader, read)
                    }));
                }
                Cursor::Reading(mut handle) => match Pin::new(&mut handle).poll(cx) {
                    Poll::Pending => {
                        self.cursor = Cursor::Reading(handle);
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(_)) => {
                        return Poll::Ready(Some(Err(io::Error::other(
                            "the recording read was interrupted",
                        ))));
                    }
                    Poll::Ready(Ok((_, Err(err)))) => return Poll::Ready(Some(Err(err))),
                    Poll::Ready(Ok((reader, Ok(data)))) => {
                        if data.is_empty() {
                            return Poll::Ready(None);
                        }
                        if let Some(left) = self.budget {
                            let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
                            if len > left {
                                return Poll::Ready(Some(Err(io::Error::other(
                                    "the recording is larger than the playback limit",
                                ))));
                            }
                            self.budget = Some(left - len);
                        }
                        self.cursor = Cursor::Idle(reader);
                        return Poll::Ready(Some(Ok(Frame::data(Bytes::from(data)))));
                    }
                },
            }
        }
    }
}

#[derive(Serialize)]
struct ManifestBody {
    state: &'static str,
    kind: SessionKind,
    chunks: u64,
    raw_bytes: u64,
    incomplete: bool,
    salvaged: bool,
    input_recorded: bool,
    dropped_chunks: u64,
    has_cast: bool,
    started_at: u64,
    ended_at: Option<u64>,
    command: Option<String>,
    playback_limit_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unavailable {
    Missing,
    NotReady,
    Store,
    Server,
}

impl Unavailable {
    fn into_response(self) -> Response {
        match self {
            Unavailable::Missing => not_found(),
            Unavailable::NotReady => conflict("recording_not_ready"),
            Unavailable::Store => {
                error_response(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable")
            }
            Unavailable::Server => server_error(),
        }
    }
}

struct Located {
    row: Recording,
    stored: StoredRecording,
}

async fn locate(control: &Control, id: &str) -> Result<Located, Unavailable> {
    if !is_session_id(id) {
        return Err(Unavailable::Missing);
    }
    let Some(uploads) = control.recordings.as_ref() else {
        return Err(Unavailable::Missing);
    };
    let target = match control.store.recordings().upload_target(id).await {
        Ok(Some(target)) => target,
        Ok(None) => return Err(Unavailable::Missing),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "reading a session for playback failed");
            return Err(Unavailable::Server);
        }
    };
    let (Some(row), Some(authorized_at)) = (target.recording, target.authorized_at) else {
        return Err(Unavailable::Missing);
    };
    match row.state {
        RecordingState::Failed => return Err(Unavailable::Missing),
        RecordingState::Receiving => return Err(Unavailable::NotReady),
        RecordingState::Complete | RecordingState::Incomplete => {}
    }
    let key = RecordingKey::new(id, authorized_at).map_err(|err| {
        tracing::error!(target: "jaunt::control", error = %err, "a session cannot name a recording");
        Unavailable::Server
    })?;
    let sink = uploads.sink();
    let opened = tokio::task::spawn_blocking(move || sink.open(&key)).await;
    match opened {
        Ok(Ok(Some(stored))) => Ok(Located { row, stored }),
        Ok(Ok(None)) => {
            tracing::error!(target: "jaunt::control", "a stored recording is missing from the recording storage");
            Err(Unavailable::Missing)
        }
        Ok(Err(RecordingStoreError::Unavailable)) => {
            tracing::warn!(target: "jaunt::control", "the recording storage is unavailable for playback");
            Err(Unavailable::Store)
        }
        Ok(Err(err)) => {
            tracing::error!(target: "jaunt::control", error = %err, "opening a stored recording failed");
            Err(Unavailable::Server)
        }
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "opening a stored recording was interrupted");
            Err(Unavailable::Server)
        }
    }
}

fn record_view(control: &Control, principal: &AdminPrincipal, session_id: &str, kind: ViewKind) {
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return;
    };
    let actor = principal.user().id.as_str();
    if !control.web.views.admit(actor, session_id, kind, now.secs) {
        return;
    }
    tracing::info!(
        target: "jaunt::audit",
        event = "recording.viewed",
        user_id = actor,
        session_id,
        kind = kind.as_str()
    );
}

fn download_requested(query: Option<&str>) -> Result<bool, Refusal> {
    let mut download = None;
    for (key, value) in form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match key.as_ref() {
            "download" if value == "1" => once(&mut download, true)?,
            _ => return Err(Refusal::Malformed),
        }
    }
    Ok(download.unwrap_or(false))
}

fn get_only() -> Response {
    let mut response = empty_response(StatusCode::METHOD_NOT_ALLOWED);
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static("GET"));
    response
}

pub(crate) async fn stream(
    State(control): State<Control>,
    admin: RequireAdmin<RecordingsRead>,
    Path(id): Path<String>,
    method: Method,
    uri: Uri,
) -> Response {
    if method != Method::GET {
        return get_only();
    }
    let download = match download_requested(uri.query()) {
        Ok(download) => download,
        Err(_) => return invalid_request(),
    };
    let located = match locate(&control, &id).await {
        Ok(located) => located,
        Err(unavailable) => return unavailable.into_response(),
    };
    let limit = control.web.playback.get();
    if !download && located.row.raw_bytes > limit {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "recording_too_large");
    }
    let Some(cast) = located.stored.cast else {
        return not_found();
    };
    let kind = if download {
        ViewKind::Download
    } else {
        ViewKind::Stream
    };
    record_view(&control, &admin.principal, &id, kind);
    let reader: Reader = Box::new(cast);
    let budget = (!download).then_some(limit);
    let mut response = Response::new(Body::new(CastBody::new(reader, budget, STREAM_CHUNK_BYTES)));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CAST_CONTENT_TYPE),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(disposition) = HeaderValue::try_from(format!("attachment; filename=\"{id}.cast\"")) {
        headers.insert(header::CONTENT_DISPOSITION, disposition);
    }
    response
}

pub(crate) async fn manifest(
    State(control): State<Control>,
    admin: RequireAdmin<RecordingsRead>,
    Path(id): Path<String>,
    method: Method,
) -> Response {
    if method != Method::GET {
        return get_only();
    }
    let located = match locate(&control, &id).await {
        Ok(located) => located,
        Err(unavailable) => return unavailable.into_response(),
    };
    record_view(&control, &admin.principal, &id, ViewKind::Manifest);
    let Located { row, stored } = located;
    let manifest = stored.manifest;
    json_response(
        StatusCode::OK,
        &ManifestBody {
            state: row.state.as_str(),
            kind: manifest.kind,
            chunks: row.chunks,
            raw_bytes: row.raw_bytes,
            incomplete: row.state == RecordingState::Incomplete,
            salvaged: row.salvaged,
            input_recorded: row.input_recorded,
            dropped_chunks: row.dropped_chunks,
            has_cast: stored.cast.is_some(),
            started_at: manifest.started_at,
            ended_at: manifest.ended_at,
            command: manifest
                .command
                .map(|command| command.chars().take(MAX_COMMAND_CHARS).collect()),
            playback_limit_bytes: control.web.playback.get(),
        },
    )
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use http_body_util::BodyExt;

    use super::{CastBody, Reader, ViewKind, ViewLog, download_requested};

    struct Counting {
        produced: Arc<AtomicU64>,
        total: u64,
    }

    impl Read for Counting {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let done = self.produced.load(Ordering::SeqCst);
            let count = usize::try_from((self.total - done).min(buffer.len() as u64)).unwrap();
            buffer[..count].fill(b'x');
            self.produced.fetch_add(count as u64, Ordering::SeqCst);
            Ok(count)
        }
    }

    fn counting(total: u64) -> (Reader, Arc<AtomicU64>) {
        let produced = Arc::new(AtomicU64::new(0));
        (
            Box::new(Counting {
                produced: produced.clone(),
                total,
            }),
            produced,
        )
    }

    #[tokio::test]
    async fn a_fifty_mebibyte_cast_is_read_only_as_fast_as_the_client_takes_it() {
        const CHUNK: usize = 64 * 1024;
        let total = 50 * 1024 * 1024;
        let (reader, produced) = counting(total);
        let mut body = CastBody::new(reader, None, CHUNK);

        let mut taken = 0_u64;
        while let Some(frame) = body.frame().await {
            taken += frame.unwrap().into_data().unwrap().len() as u64;
            let read_ahead = produced.load(Ordering::SeqCst) - taken;
            assert!(read_ahead <= 2 * CHUNK as u64, "{read_ahead}");
        }

        assert_eq!(taken, total);
        assert_eq!(produced.load(Ordering::SeqCst), total);
    }

    #[tokio::test]
    async fn an_unread_body_reads_nothing_and_a_stalled_client_holds_back_the_reader() {
        let (reader, produced) = counting(10 * 1024 * 1024);
        let mut body = CastBody::new(reader, None, 4096);
        assert_eq!(produced.load(Ordering::SeqCst), 0);
        let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(first.len(), 4096);
        tokio::task::yield_now().await;
        assert!(produced.load(Ordering::SeqCst) <= 2 * 4096);
    }

    #[tokio::test]
    async fn an_inline_body_fails_when_the_stored_file_outgrows_the_limit() {
        let (reader, _) = counting(1000);
        let mut at_limit = CastBody::new(reader, Some(1000), 300);
        let mut got = 0;
        while let Some(frame) = at_limit.frame().await {
            got += frame.unwrap().into_data().unwrap().len();
        }
        assert_eq!(got, 1000);

        let (reader, _) = counting(1001);
        let mut over = CastBody::new(reader, Some(1000), 300);
        let mut failed = false;
        while let Some(frame) = over.frame().await {
            if frame.is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed);
    }

    #[tokio::test]
    async fn a_read_error_ends_the_body_with_an_error() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("disk"))
            }
        }
        let mut body = CastBody::new(Box::new(Broken), None, 4096);
        assert!(body.frame().await.unwrap().is_err());
    }

    #[test]
    fn views_are_admitted_once_a_minute_per_actor_session_and_kind() {
        let log = ViewLog::default();
        assert!(log.admit("u1", "s1", ViewKind::Stream, 100));
        assert!(!log.admit("u1", "s1", ViewKind::Stream, 159));
        assert!(log.admit("u1", "s1", ViewKind::Stream, 160));
        assert!(log.admit("u1", "s1", ViewKind::Manifest, 100));
        assert!(log.admit("u1", "s1", ViewKind::Download, 100));
        assert!(log.admit("u2", "s1", ViewKind::Stream, 100));
        assert!(log.admit("u1", "s2", ViewKind::Stream, 100));
    }

    #[test]
    fn a_full_view_table_still_admits_new_views_without_growing() {
        let log = ViewLog::default();
        for index in 0..super::MAX_TRACKED_VIEWS {
            assert!(log.admit(&format!("u{index}"), "s", ViewKind::Stream, 100));
        }
        assert_eq!(log.tracked(), super::MAX_TRACKED_VIEWS);
        assert!(log.admit("late", "s", ViewKind::Stream, 100));
        assert!(log.admit("late", "s", ViewKind::Stream, 100));
        assert_eq!(log.tracked(), super::MAX_TRACKED_VIEWS);
        assert!(log.admit("late", "s", ViewKind::Stream, 1000));
        assert_eq!(log.tracked(), 1);
    }

    #[test]
    fn only_a_single_download_flag_set_to_one_is_accepted() {
        assert_eq!(download_requested(None), Ok(false));
        assert_eq!(download_requested(Some("download=1")), Ok(true));
        for bad in [
            "download=0",
            "download=",
            "download=1&download=1",
            "x=1",
            "download=true",
        ] {
            assert!(download_requested(Some(bad)).is_err(), "{bad}");
        }
    }
}
