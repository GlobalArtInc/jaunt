use std::io::{self, Read};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use jaunt_proto::{
    ADMIN_CERTIFICATE_HEADER, CONTENT_DIGEST_HEADER, ClientConfig, ErrorBody, FinishRequest,
    FinishResponse, NodeList, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER, StartRequest,
    StartResponse, WhoamiResponse,
};
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use reqwest::redirect::Policy;
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Url;

use crate::admin_signature::SignedHeaders;
use crate::secret::Secret;
use crate::server_url::ServerUrl;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_BODY_BYTES: u64 = 1024 * 1024;

const JSON: &str = "application/json";
const START_PATH: &str = "/v1/login/start";
const FINISH_PATH: &str = "/v1/login/finish";
const WHOAMI_PATH: &str = "/v1/whoami";
const CLIENT_CONFIG_PATH: &str = "/v1/client-config";
const NODES_PATH: &str = "/v1/nodes";
const READ_CHUNK_BYTES: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerCode {
    InvalidGrant,
    Busy,
    NotConfigured,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApiError {
    #[error("cannot set up the HTTP client")]
    ClientSetup,
    #[error("the request to the server timed out")]
    TimedOut,
    #[error("cannot connect to the server (check the address and its TLS certificate)")]
    Connect,
    #[error("the request to the server failed")]
    Transport,
    #[error("the sign-in request is no longer valid, run `jaunt login` again")]
    InvalidGrant,
    #[error("the server is busy, try again")]
    Busy,
    #[error("the server has no SSH gateway configured")]
    NotConfigured,
    #[error(
        "the server does not accept this sign-in (expired or revoked), run `jaunt login` again"
    )]
    Unauthorized,
    #[error("the server rejected the request (HTTP {status})")]
    Rejected { status: u16 },
    #[error("the server's response is too large")]
    BodyTooLarge,
    #[error("the server sent a response that cannot be understood")]
    BadResponse,
}

pub struct ApiClient {
    http: Client,
    server: ServerUrl,
    deadline: Duration,
}

impl ApiClient {
    pub fn new(server: &ServerUrl) -> Result<ApiClient, ApiError> {
        let mut builder = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .redirect(Policy::none())
            .use_rustls_tls();
        if server.is_plain_http() {
            builder = builder.no_proxy();
        }
        let http = builder.build().map_err(|_| ApiError::ClientSetup)?;
        Ok(ApiClient {
            http,
            server: server.clone(),
            deadline: TOTAL_TIMEOUT,
        })
    }

    pub fn with_deadline(mut self, deadline: Duration) -> ApiClient {
        self.deadline = deadline;
        self
    }

    pub fn start(&self, request: &StartRequest) -> Result<StartResponse, ApiError> {
        self.post(START_PATH, request)
    }

    pub fn finish(&self, request: &FinishRequest) -> Result<FinishResponse, ApiError> {
        self.post(FINISH_PATH, request)
    }

    pub fn whoami(&self, token: &Secret) -> Result<WhoamiResponse, ApiError> {
        self.get_with_token(WHOAMI_PATH, token)
    }

    pub fn nodes(&self, token: &Secret) -> Result<NodeList, ApiError> {
        self.get_with_token(NODES_PATH, token)
    }

    pub fn endpoint_url(&self, path: &str) -> Result<Url, ApiError> {
        Url::parse(&self.server.endpoint(path)).map_err(|_| ApiError::Transport)
    }

    pub fn get_signed<T: DeserializeOwned>(
        &self,
        url: Url,
        signed: &SignedHeaders,
    ) -> Result<T, ApiError> {
        let header = |value: &str| HeaderValue::from_str(value).map_err(|_| ApiError::Transport);
        let request = self
            .http
            .get(url)
            .header(ACCEPT, JSON)
            .header(ADMIN_CERTIFICATE_HEADER, header(&signed.certificate)?)
            .header(CONTENT_DIGEST_HEADER, header(&signed.content_digest)?)
            .header(SIGNATURE_INPUT_HEADER, header(&signed.signature_input)?)
            .header(SIGNATURE_HEADER, header(&signed.signature)?);
        self.call(request)
    }

    pub fn client_config(&self) -> Result<ClientConfig, ApiError> {
        let request = self
            .http
            .get(self.server.endpoint(CLIENT_CONFIG_PATH))
            .header(ACCEPT, JSON);
        self.call(request)
    }

    fn get_with_token<T: DeserializeOwned>(
        &self,
        path: &str,
        token: &Secret,
    ) -> Result<T, ApiError> {
        let mut bearer = HeaderValue::from_str(&format!("Bearer {}", token.expose()))
            .map_err(|_| ApiError::Unauthorized)?;
        bearer.set_sensitive(true);
        let request = self
            .http
            .get(self.server.endpoint(path))
            .header(ACCEPT, JSON)
            .header(AUTHORIZATION, bearer);
        self.call(request)
    }

    fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T, ApiError> {
        let bytes = serde_json::to_vec(body).map_err(|_| ApiError::Transport)?;
        let request = self
            .http
            .post(self.server.endpoint(path))
            .header(ACCEPT, JSON)
            .header(CONTENT_TYPE, JSON)
            .body(bytes);
        self.call(request)
    }

    fn call<T: DeserializeOwned>(&self, request: RequestBuilder) -> Result<T, ApiError> {
        let deadline = Instant::now()
            .checked_add(self.deadline)
            .ok_or(ApiError::TimedOut)?;
        let request = request.timeout(self.deadline);
        let (results, inbox) = mpsc::channel();
        thread::Builder::new()
            .name("jaunt-http".to_owned())
            .spawn(move || drop(results.send(fetch(request, deadline))))
            .map_err(|_| ApiError::Transport)?;
        let (status, body) = match inbox.recv_timeout(self.deadline) {
            Ok(outcome) => outcome?,
            Err(RecvTimeoutError::Timeout) => return Err(ApiError::TimedOut),
            Err(RecvTimeoutError::Disconnected) => return Err(ApiError::Transport),
        };
        if (200..300).contains(&status) {
            serde_json::from_slice(&body).map_err(|_| ApiError::BadResponse)
        } else {
            Err(error_for(status, &body))
        }
    }
}

fn fetch(request: RequestBuilder, deadline: Instant) -> Result<(u16, Vec<u8>), ApiError> {
    let mut response = request.send().map_err(|err| {
        if err.is_timeout() {
            ApiError::TimedOut
        } else if err.is_connect() {
            ApiError::Connect
        } else {
            ApiError::Transport
        }
    })?;
    let status = response.status().as_u16();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BODY_BYTES)
    {
        return Err(ApiError::BodyTooLarge);
    }
    let mut body = Vec::new();
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    loop {
        if Instant::now() >= deadline {
            return Err(ApiError::TimedOut);
        }
        match response.read(&mut chunk) {
            Ok(0) => return Ok((status, body)),
            Ok(count) => {
                body.extend_from_slice(&chunk[..count]);
                if u64::try_from(body.len()).is_ok_and(|length| length > MAX_BODY_BYTES) {
                    return Err(ApiError::BodyTooLarge);
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) if err.kind() == io::ErrorKind::TimedOut => return Err(ApiError::TimedOut),
            Err(_) if Instant::now() >= deadline => return Err(ApiError::TimedOut),
            Err(_) => return Err(ApiError::Transport),
        }
    }
}

fn error_for(status: u16, body: &[u8]) -> ApiError {
    let code = match serde_json::from_slice::<ErrorBody>(body) {
        Ok(parsed) => match parsed.error.as_str() {
            "invalid_grant" => ServerCode::InvalidGrant,
            "busy" => ServerCode::Busy,
            "not_configured" => ServerCode::NotConfigured,
            _ => ServerCode::Other,
        },
        Err(_) => ServerCode::Other,
    };
    match (code, status) {
        (ServerCode::InvalidGrant, _) => ApiError::InvalidGrant,
        (ServerCode::Busy, _) => ApiError::Busy,
        (ServerCode::NotConfigured, 404) => ApiError::NotConfigured,
        (ServerCode::NotConfigured, _) => ApiError::Rejected { status },
        (ServerCode::Other, 401) => ApiError::Unauthorized,
        (ServerCode::Other, _) => ApiError::Rejected { status },
    }
}

#[cfg(test)]
mod tests {
    use super::{ApiError, error_for};

    #[test]
    fn server_error_codes_map_to_fixed_messages_and_unknown_text_is_never_echoed() {
        assert_eq!(
            error_for(400, br#"{"error":"invalid_grant"}"#),
            ApiError::InvalidGrant
        );
        assert_eq!(error_for(503, br#"{"error":"busy"}"#), ApiError::Busy);
        assert_eq!(error_for(401, b""), ApiError::Unauthorized);
        assert_eq!(
            error_for(500, br#"{"error":"server_error"}"#),
            ApiError::Rejected { status: 500 }
        );
        assert_eq!(
            error_for(400, br#"{"error":"<script>alert(1)</script>"}"#),
            ApiError::Rejected { status: 400 }
        );
        assert_eq!(
            error_for(502, b"<html>gateway</html>"),
            ApiError::Rejected { status: 502 }
        );
        assert!(
            ApiError::InvalidGrant
                .to_string()
                .contains("run `jaunt login` again")
        );
        assert_eq!(ApiError::Busy.to_string(), "the server is busy, try again");
        assert_eq!(
            error_for(404, br#"{"error":"not_configured"}"#),
            ApiError::NotConfigured
        );
        assert_eq!(
            error_for(500, br#"{"error":"not_configured"}"#),
            ApiError::Rejected { status: 500 }
        );
        assert_eq!(error_for(404, b""), ApiError::Rejected { status: 404 });
    }
}
