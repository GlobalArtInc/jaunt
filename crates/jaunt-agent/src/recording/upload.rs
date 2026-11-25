use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_proto::{
    RecordingChunk, RecordingComplete, RecordingKind, RecordingManifest, RecordingRefusal,
};
use jaunt_record::{Chunk, SessionKind, SessionManifest};
use tokio::sync::OwnedSemaphorePermit;

use super::session::{End, Shared, Work, dropped};
use super::{SHUTDOWN_GRACE, Service};
use crate::run::api::ApiError;

pub const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
pub const RETRY_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
pub const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);
pub const RETRY_AFTER_MIN: Duration = Duration::from_secs(1);
pub const RETRY_AFTER_MAX: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Next {
    Retry(Option<Duration>),
    Final(&'static str),
    Disabled,
    Stop,
}

pub(crate) fn classify(error: &ApiError) -> Next {
    match error {
        ApiError::Shutdown => Next::Stop,
        ApiError::NodeRemoved => Next::Final("node_removed"),
        ApiError::Request | ApiError::ServerName => Next::Final("request_not_built"),
        ApiError::Status {
            status,
            code,
            retry_after,
        } => classify_status(*status, code, *retry_after),
        ApiError::Unauthorized
        | ApiError::ConnectTimeout
        | ApiError::Tcp(_)
        | ApiError::Tls(_)
        | ApiError::UnexpectedProtocol
        | ApiError::Http2(_)
        | ApiError::CallTimeout
        | ApiError::BodyTooLarge
        | ApiError::BadResponse => Next::Retry(None),
    }
}

fn classify_status(status: u16, code: &str, retry_after: Option<Duration>) -> Next {
    let refusal = RecordingRefusal::from_code(code);
    match status {
        404 if refusal == Some(RecordingRefusal::SessionUnknown) => {
            Next::Final(RecordingRefusal::SessionUnknown.code())
        }
        404 => Next::Disabled,
        409 => Next::Final(
            refusal
                .filter(|refusal| refusal.status() == 409)
                .map_or("conflict", RecordingRefusal::code),
        ),
        413 => Next::Final(RecordingRefusal::TooLarge.code()),
        422 => Next::Final(RecordingRefusal::BadChunk.code()),
        429 | 507 => Next::Retry(retry_after),
        401 | 403 | 408 | 500..=599 => Next::Retry(None),
        _ => Next::Final("refused"),
    }
}

pub(crate) fn backoff(attempt: u32, sample: f64) -> Duration {
    let factor = 1_u32.checked_shl(attempt).unwrap_or(u32::MAX);
    let cap = BACKOFF_INITIAL
        .checked_mul(factor)
        .map_or(BACKOFF_MAX, |delay| delay.min(BACKOFF_MAX));
    let fraction = if sample.is_finite() {
        sample.clamp(0.0, 1.0)
    } else {
        1.0
    };
    cap.mul_f64(0.5 + fraction / 2.0)
}

pub(crate) fn honored(retry_after: Duration) -> Duration {
    retry_after.clamp(RETRY_AFTER_MIN, RETRY_AFTER_MAX)
}

pub(crate) fn wire_chunk(chunk: &Chunk) -> RecordingChunk {
    RecordingChunk {
        seq: chunk.seq,
        raw_len: chunk.raw_len,
        sha256: chunk.sha256.clone(),
        is_last: chunk.is_last,
        data: STANDARD.encode(&chunk.compressed),
    }
}

pub(crate) fn wire_manifest(manifest: SessionManifest) -> RecordingManifest {
    RecordingManifest {
        version: manifest.version,
        session_id: manifest.session_id,
        kind: match manifest.kind {
            SessionKind::Shell => RecordingKind::Shell,
            SessionKind::Exec => RecordingKind::Exec,
            SessionKind::Sftp => RecordingKind::Sftp,
        },
        node: manifest.node,
        user: manifest.user,
        login: manifest.login,
        started_at: manifest.started_at,
        ended_at: manifest.ended_at,
        exit_status: manifest.exit_status,
        command: manifest.command,
        bytes_out: manifest.bytes_out,
        bytes_in: manifest.bytes_in,
        input_recorded: manifest.input_recorded,
        chunks: manifest.chunks,
        raw_bytes: manifest.raw_bytes,
        incomplete: manifest.incomplete,
        dropped_chunks: manifest.dropped_chunks,
        digest: manifest.digest,
    }
}

pub(crate) struct Uploader {
    pub(crate) service: Arc<Service>,
    pub(crate) shared: Arc<Shared>,
    pub(crate) session_id: String,
    pub(crate) id: u64,
    pub(crate) _permit: OwnedSemaphorePermit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Continue,
    Stop,
}

struct Progress {
    attempt: u32,
    failing_since: Option<SystemTime>,
    retry_at: Option<SystemTime>,
    next_flush: SystemTime,
    draining: bool,
}

impl Progress {
    fn give_up_at(&self) -> Option<SystemTime> {
        self.failing_since.map(|since| since + RETRY_WINDOW)
    }
}

impl Drop for Uploader {
    fn drop(&mut self) {
        if self.shared.end(End::Failed) {
            dropped(&self.session_id, End::Failed);
        }
        self.service.unregister(self.id);
    }
}

impl Uploader {
    pub(crate) async fn run(self) {
        let now = self.service.clock.now();
        let mut progress = Progress {
            attempt: 0,
            failing_since: None,
            retry_at: None,
            next_flush: now + FLUSH_INTERVAL,
            draining: false,
        };
        self.drive(&mut progress).await;
    }

    fn deadline(&self) -> Option<SystemTime> {
        let drain = self.service.drain_started()?;
        let from = match self.shared.finished_at() {
            Some(finished) => finished.max(drain),
            None => drain,
        };
        Some(from + SHUTDOWN_GRACE)
    }

    async fn drive(&self, progress: &mut Progress) {
        loop {
            if self.step(progress).await == Flow::Stop {
                return;
            }
        }
    }

    async fn step(&self, progress: &mut Progress) -> Flow {
        let now = self.service.clock.now();
        if self.shared.ended() {
            return Flow::Stop;
        }
        if !progress.draining && self.service.shutting_down() {
            progress.draining = true;
            progress.retry_at = None;
        }
        if self.deadline().is_some_and(|deadline| now >= deadline) {
            return self.end(End::Shutdown);
        }
        if progress.give_up_at().is_some_and(|at| now >= at) {
            return self.end(End::GaveUp);
        }
        if self.service.disabled(now) {
            return self.end(End::Disabled);
        }
        if now >= progress.next_flush {
            if self.shared.flush().is_err() {
                return self.end(End::Failed);
            }
            progress.next_flush = now + FLUSH_INTERVAL;
        }
        if progress.retry_at.is_none_or(|at| now >= at) {
            progress.retry_at = None;
            match self.shared.next_work() {
                Work::Done => return Flow::Stop,
                Work::Chunk(chunk) => return self.send_chunk(&chunk, progress).await,
                Work::Complete(manifest) => return self.send_complete(manifest, progress).await,
                Work::Idle => {}
            }
        }
        self.wait(progress).await;
        Flow::Continue
    }

    async fn wait(&self, progress: &Progress) {
        let deadline = self.deadline();
        let until = [
            Some(progress.next_flush),
            progress.retry_at,
            progress.give_up_at(),
            deadline,
        ]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(progress.next_flush);
        tokio::select! {
            () = self.shared.woken() => {}
            () = self.service.clock.sleep_until(until) => {}
            () = self.service.shutdown.cancelled(), if !progress.draining => {}
            () = self.service.draining(), if deadline.is_none() => {}
        }
    }

    async fn bounded<T>(
        &self,
        call: impl Future<Output = Result<T, ApiError>>,
    ) -> Option<Result<T, ApiError>> {
        tokio::pin!(call);
        loop {
            let Some(deadline) = self.deadline() else {
                tokio::select! {
                    result = &mut call => return Some(result),
                    () = self.service.draining() => continue,
                }
            };
            tokio::select! {
                result = &mut call => return Some(result),
                () = self.service.clock.sleep_until(deadline) => {
                    if self.deadline().is_some_and(|now_due| now_due <= deadline) {
                        return None;
                    }
                }
                () = self.shared.woken() => {}
            }
        }
    }

    async fn send_chunk(&self, chunk: &Chunk, progress: &mut Progress) -> Flow {
        let body = wire_chunk(chunk);
        let sent = self
            .bounded(self.service.transport.chunk(&self.session_id, &body))
            .await;
        match sent {
            None => self.end(End::Shutdown),
            Some(Ok(_)) => match self.shared.acked(chunk.seq) {
                Ok(()) => succeeded(progress),
                Err(error) => {
                    tracing::error!(
                        target: "jaunt::agent",
                        session_id = self.session_id.as_str(),
                        error = %error,
                        "a recording chunk could not be released after the server acknowledged it"
                    );
                    self.end(End::Failed)
                }
            },
            Some(Err(error)) => self.failed(&error, progress),
        }
    }

    async fn send_complete(&self, manifest: SessionManifest, progress: &mut Progress) -> Flow {
        let body = RecordingComplete {
            manifest: wire_manifest(manifest),
        };
        let sent = self
            .bounded(self.service.transport.complete(&self.session_id, &body))
            .await;
        match sent {
            None => self.end(End::Shutdown),
            Some(Ok(receipt)) => {
                if self.shared.end(End::Stored) {
                    tracing::info!(
                        target: "jaunt::agent",
                        event = "agent.ssh.recording_stored",
                        session_id = self.session_id.as_str(),
                        chunks = receipt.chunks,
                        state = ?receipt.state,
                        "the server stored the recording of this session"
                    );
                }
                Flow::Stop
            }
            Some(Err(error)) => self.failed(&error, progress),
        }
    }

    fn failed(&self, error: &ApiError, progress: &mut Progress) -> Flow {
        let now = self.service.clock.now();
        match classify(error) {
            Next::Retry(retry_after) => {
                progress.failing_since.get_or_insert(now);
                if progress.give_up_at().is_some_and(|at| now >= at) {
                    return self.end(End::GaveUp);
                }
                let delay = match retry_after {
                    Some(after) => honored(after),
                    None => backoff(progress.attempt, (self.service.jitter)()),
                };
                progress.attempt = progress.attempt.saturating_add(1);
                progress.retry_at = Some(now + delay);
                tracing::debug!(
                    target: "jaunt::agent",
                    session_id = self.session_id.as_str(),
                    error = %error,
                    retry_in_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                    "a recording upload failed; retrying"
                );
                Flow::Continue
            }
            Next::Final(reason) => self.end(End::Refused(reason)),
            Next::Disabled => {
                self.service.disable(now);
                self.end(End::Disabled)
            }
            Next::Stop => self.end(End::Shutdown),
        }
    }

    fn end(&self, end: End) -> Flow {
        if self.shared.end(end) && end != End::Disabled {
            dropped(&self.session_id, end);
        }
        Flow::Stop
    }
}

fn succeeded(progress: &mut Progress) -> Flow {
    progress.attempt = 0;
    progress.failing_since = None;
    progress.retry_at = None;
    Flow::Continue
}
