use std::error::Error as _;
use std::time::Duration;

use jaunt_proto::{EnrollRequest, EnrollResponse, ErrorBody, PollRequest, PollResponse};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::redirect::Policy;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::args::ServerUrl;

const ENROLL_PATH: &str = "/v1/agent/enroll";
const POLL_PATH: &str = "/v1/agent/enroll/poll";
const JSON: &str = "application/json";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_ERROR_CODE_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CallError {
    #[error("cannot set up the HTTP client")]
    Setup,
    #[error("cannot encode the request")]
    Encode,
    #[error("the request timed out")]
    TimedOut,
    #[error("cannot connect to the server ({detail})")]
    Connect { detail: String },
    #[error("the request failed ({detail})")]
    Transport { detail: String },
    #[error("the server asked to slow down (HTTP 429)")]
    TooManyRequests,
    #[error("the server does not know this enrollment")]
    NotFound,
    #[error("the server answered HTTP {status} ({code})")]
    Status { status: u16, code: String },
    #[error("the server's response is too large")]
    BodyTooLarge,
    #[error("the server sent a response that cannot be understood")]
    BadResponse,
}

impl CallError {
    pub fn is_transient(&self) -> bool {
        match self {
            CallError::TimedOut | CallError::Connect { .. } | CallError::Transport { .. } => true,
            CallError::Status { status, .. } => *status >= 500,
            _ => false,
        }
    }
}

pub struct EnrollClient {
    http: reqwest::Client,
    server: ServerUrl,
}

impl EnrollClient {
    pub fn new(server: &ServerUrl) -> Result<Self, CallError> {
        let mut builder = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(Policy::none())
            .use_rustls_tls();
        if server.is_plain_http() {
            builder = builder.no_proxy();
        } else {
            builder = builder.https_only(true);
        }
        let http = builder.build().map_err(|_| CallError::Setup)?;
        Ok(Self {
            http,
            server: server.clone(),
        })
    }

    pub async fn enroll(&self, request: &EnrollRequest) -> Result<EnrollResponse, CallError> {
        self.post(ENROLL_PATH, request).await
    }

    pub async fn poll(&self, request: &PollRequest) -> Result<PollResponse, CallError> {
        self.post(POLL_PATH, request).await
    }

    async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CallError> {
        let bytes = serde_json::to_vec(body).map_err(|_| CallError::Encode)?;
        let mut response = self
            .http
            .post(self.server.endpoint(path))
            .header(ACCEPT, JSON)
            .header(CONTENT_TYPE, JSON)
            .body(bytes)
            .send()
            .await
            .map_err(classify)?;
        let status = response.status().as_u16();
        if response
            .content_length()
            .is_some_and(|length| usize::try_from(length).map_or(true, |n| n > MAX_BODY_BYTES))
        {
            return Err(CallError::BodyTooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(classify)? {
            if body.len() + chunk.len() > MAX_BODY_BYTES {
                return Err(CallError::BodyTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        if (200..300).contains(&status) {
            return serde_json::from_slice(&body).map_err(|_| CallError::BadResponse);
        }
        let code = serde_json::from_slice::<ErrorBody>(&body)
            .map(|error| printable_code(&error.error))
            .unwrap_or_default();
        Err(match (status, code.as_str()) {
            (429, _) => CallError::TooManyRequests,
            (404, "not_found") => CallError::NotFound,
            _ => CallError::Status { status, code },
        })
    }
}

fn printable_code(code: &str) -> String {
    code.chars()
        .take(MAX_ERROR_CODE_LEN)
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

fn classify(error: reqwest::Error) -> CallError {
    if error.is_timeout() {
        return CallError::TimedOut;
    }
    let connect = error.is_connect();
    let error = error.without_url();
    let mut detail = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        detail.push_str(": ");
        detail.push_str(&cause.to_string());
        source = cause.source();
    }
    if connect {
        CallError::Connect { detail }
    } else {
        CallError::Transport { detail }
    }
}
