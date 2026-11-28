use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::HeaderValue;
use jaunt_limits::LogThrottle;
use zeroize::Zeroizing;

use super::KubeLimits;
use crate::clock::Clock;

const MAX_TOKEN_BYTES: u64 = 64 * 1024;
const BEARER: &[u8] = b"Bearer ";
const FAILURE_LOG_EVERY: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
enum TokenError {
    #[error("cannot read the service account token file: {0}")]
    Read(io::ErrorKind),
    #[error("the service account token file is empty")]
    Empty,
    #[error("the service account token file is larger than {MAX_TOKEN_BYTES} bytes")]
    TooLarge,
    #[error("the service account token holds bytes that cannot be sent in a header")]
    Characters,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileStamp {
    modified: Option<SystemTime>,
    len: u64,
}

pub(crate) fn file_stamp(path: &Path) -> Option<FileStamp> {
    fs::metadata(path).ok().map(|meta| FileStamp {
        modified: meta.modified().ok(),
        len: meta.len(),
    })
}

#[derive(Default)]
struct TokenState {
    bearer: Option<HeaderValue>,
    stamp: Option<FileStamp>,
    read_at: Option<SystemTime>,
    checked_at: Option<SystemTime>,
}

pub(crate) struct TokenSource {
    path: PathBuf,
    clock: Arc<dyn Clock>,
    reread: Duration,
    check_every: Duration,
    state: Mutex<TokenState>,
    failures: LogThrottle,
}

impl fmt::Debug for TokenSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenSource")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl TokenSource {
    pub(crate) fn new(path: PathBuf, clock: Arc<dyn Clock>, limits: KubeLimits) -> Self {
        Self {
            path,
            clock,
            reread: limits.token_reread,
            check_every: limits.token_check_every,
            state: Mutex::new(TokenState::default()),
            failures: LogThrottle::new(FAILURE_LOG_EVERY),
        }
    }

    pub(crate) fn bearer(&self) -> Option<HeaderValue> {
        let now = self.clock.now();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let checked_recently = state
            .checked_at
            .is_some_and(|at| now < at.checked_add(self.check_every).unwrap_or(at));
        if checked_recently {
            return state.bearer.clone();
        }
        state.checked_at = Some(now);
        let stamp = file_stamp(&self.path);
        let stale = state.bearer.is_none()
            || stamp.is_none()
            || stamp != state.stamp
            || state
                .read_at
                .is_none_or(|at| now >= at.checked_add(self.reread).unwrap_or(at));
        if stale {
            match read_bearer(&self.path) {
                Ok(bearer) => {
                    state.bearer = Some(bearer);
                    state.stamp = stamp;
                    state.read_at = Some(now);
                }
                Err(error) => self.failed(&error, state.bearer.is_some(), now),
            }
        }
        state.bearer.clone()
    }

    fn failed(&self, error: &TokenError, kept: bool, now: SystemTime) {
        let tick = now.duration_since(UNIX_EPOCH).unwrap_or_default();
        if let Some(suppressed) = self.failures.admit(tick) {
            tracing::warn!(
                target: "jaunt::agent",
                error = %error,
                kept_previous = kept,
                suppressed,
                "reading the service account token for the Kubernetes API server failed"
            );
        }
    }
}

fn read_bearer(path: &Path) -> Result<HeaderValue, TokenError> {
    let file = File::open(path).map_err(|error| TokenError::Read(error.kind()))?;
    let mut raw = Zeroizing::new(Vec::new());
    file.take(MAX_TOKEN_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|error| TokenError::Read(error.kind()))?;
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > MAX_TOKEN_BYTES {
        return Err(TokenError::TooLarge);
    }
    let token = raw.trim_ascii();
    if token.is_empty() {
        return Err(TokenError::Empty);
    }
    if !token.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
        return Err(TokenError::Characters);
    }
    let mut line = Zeroizing::new(Vec::with_capacity(BEARER.len() + token.len()));
    line.extend_from_slice(BEARER);
    line.extend_from_slice(token);
    let mut bearer = HeaderValue::from_bytes(&line).map_err(|_| TokenError::Characters)?;
    bearer.set_sensitive(true);
    Ok(bearer)
}
