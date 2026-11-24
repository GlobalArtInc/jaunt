use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use subtle::ConstantTimeEq;
use url::form_urlencoded;
use zeroize::Zeroizing;

use crate::secret::Secret;

pub const MAX_REQUEST_BYTES: usize = 8 * 1024;
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_CONNECTIONS: usize = 16;

const MIN_PORT: u16 = 1024;
const BIND_ATTEMPTS: usize = 16;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const DRAIN_TIMEOUT: Duration = Duration::from_millis(200);
const DRAIN_LIMIT_BYTES: usize = 64 * 1024;
const READ_CHUNK_BYTES: usize = 1024;
const MAX_CODE_LEN: usize = 256;
const CALLBACK_PATH: &str = "/callback";
const HEAD_END: &[u8] = b"\r\n\r\n";

const SIGNED_IN_TEXT: &str = "Signed in. You can close this tab.";
const FAILED_TEXT: &str = "Sign-in failed. You can close this tab and try again from the terminal.";

#[derive(Debug, thiserror::Error)]
pub enum LoopbackError {
    #[error("cannot open the loopback listener: {0}")]
    Bind(io::Error),
    #[error("the operating system gave no usable loopback port")]
    NoUsablePort,
    #[error("the loopback listener failed: {0}")]
    Accept(io::Error),
    #[error("the sign-in timeout is out of range")]
    InvalidTimeout,
    #[error("timed out waiting for the browser sign-in")]
    TimedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureCode {
    AccessDenied,
    Other,
}

#[derive(Debug)]
pub enum Callback {
    Approved(Secret),
    Failed(FailureCode),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rejection {
    BadRequest,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    RequestTimeout,
    HeadersTooLarge,
}

impl Rejection {
    fn status(self) -> &'static str {
        match self {
            Rejection::BadRequest => "400 Bad Request",
            Rejection::Forbidden => "403 Forbidden",
            Rejection::NotFound => "404 Not Found",
            Rejection::MethodNotAllowed => "405 Method Not Allowed",
            Rejection::RequestTimeout => "408 Request Timeout",
            Rejection::HeadersTooLarge => "431 Request Header Fields Too Large",
        }
    }

    fn text(self) -> &'static str {
        match self {
            Rejection::BadRequest => "Bad request.",
            Rejection::Forbidden => "Forbidden.",
            Rejection::NotFound => "Not found.",
            Rejection::MethodNotAllowed => "Method not allowed.",
            Rejection::RequestTimeout => "Request timed out.",
            Rejection::HeadersTooLarge => "Request too large.",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LoopbackLimits {
    pub max_request_bytes: usize,
    pub read_timeout: Duration,
    pub max_connections: usize,
}

impl Default for LoopbackLimits {
    fn default() -> LoopbackLimits {
        LoopbackLimits {
            max_request_bytes: MAX_REQUEST_BYTES,
            read_timeout: READ_TIMEOUT,
            max_connections: MAX_CONNECTIONS,
        }
    }
}

#[derive(Debug)]
pub struct LoopbackListener {
    listener: TcpListener,
    port: u16,
    limits: LoopbackLimits,
}

impl LoopbackListener {
    pub fn bind() -> Result<LoopbackListener, LoopbackError> {
        LoopbackListener::bind_with(LoopbackLimits::default())
    }

    pub fn bind_with(limits: LoopbackLimits) -> Result<LoopbackListener, LoopbackError> {
        let mut unusable = Vec::new();
        for _ in 0..BIND_ATTEMPTS {
            let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
            let listener = TcpListener::bind(address).map_err(LoopbackError::Bind)?;
            let port = listener.local_addr().map_err(LoopbackError::Bind)?.port();
            if port >= MIN_PORT {
                return Ok(LoopbackListener {
                    listener,
                    port,
                    limits,
                });
            }
            unusable.push(listener);
        }
        Err(LoopbackError::NoUsablePort)
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn wait_for_callback(
        self,
        login_id: &str,
        timeout: Duration,
    ) -> Result<Callback, LoopbackError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(LoopbackError::InvalidTimeout)?;
        self.listener
            .set_nonblocking(true)
            .map_err(LoopbackError::Accept)?;
        let (results, inbox) = mpsc::channel::<Callback>();
        let (finished_tx, finished_rx) = mpsc::channel::<()>();
        let mut active = 0_usize;

        loop {
            while finished_rx.try_recv().is_ok() {
                active = active.saturating_sub(1);
            }
            if let Ok(callback) = inbox.try_recv() {
                return Ok(callback);
            }
            if Instant::now() >= deadline {
                return Err(LoopbackError::TimedOut);
            }
            if active < self.limits.max_connections {
                match self.listener.accept() {
                    Ok((stream, _)) => {
                        active += 1;
                        let worker = Worker {
                            port: self.port,
                            login_id: login_id.to_owned(),
                            limits: self.limits,
                            results: results.clone(),
                            finished: finished_tx.clone(),
                        };
                        let spawned = thread::Builder::new()
                            .name("jaunt-loopback".to_owned())
                            .spawn(move || worker.run(stream));
                        if spawned.is_err() {
                            active = active.saturating_sub(1);
                        }
                        continue;
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err) => return Err(LoopbackError::Accept(err)),
                }
            }
            if let Ok(callback) = inbox.recv_timeout(POLL_INTERVAL) {
                return Ok(callback);
            }
        }
    }
}

struct Worker {
    port: u16,
    login_id: String,
    limits: LoopbackLimits,
    results: mpsc::Sender<Callback>,
    finished: mpsc::Sender<()>,
}

impl Worker {
    fn run(self, mut stream: TcpStream) {
        self.serve(&mut stream);
        let _ = self.finished.send(());
    }

    fn serve(&self, stream: &mut TcpStream) {
        if stream.set_nonblocking(false).is_err() {
            return;
        }
        let verdict = read_head(stream, &self.limits)
            .and_then(|head| parse_head(&head, self.port, &self.login_id));
        let (status, text) = match &verdict {
            Ok(Callback::Approved(_)) => ("200 OK", SIGNED_IN_TEXT),
            Ok(Callback::Failed(_)) => ("200 OK", FAILED_TEXT),
            Err(rejection) => (rejection.status(), rejection.text()),
        };
        respond_best_effort(stream, status, text);
        if let Ok(callback) = verdict
            && self.results.send(callback).is_err()
        {
            return;
        }
        drain(stream);
    }
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(HEAD_END.len())
        .position(|window| window == HEAD_END)
}

fn read_head(
    stream: &mut TcpStream,
    limits: &LoopbackLimits,
) -> Result<Zeroizing<Vec<u8>>, Rejection> {
    let deadline = Instant::now()
        .checked_add(limits.read_timeout)
        .ok_or(Rejection::RequestTimeout)?;
    let mut buffer = Zeroizing::new(Vec::with_capacity(READ_CHUNK_BYTES));
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    loop {
        if let Some(end) = find_head_end(&buffer) {
            buffer.truncate(end);
            return Ok(buffer);
        }
        let room = limits.max_request_bytes.saturating_sub(buffer.len());
        if room == 0 {
            return Err(Rejection::HeadersTooLarge);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(Rejection::RequestTimeout)?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| Rejection::BadRequest)?;
        let take = room.min(chunk.len());
        match stream.read(&mut chunk[..take]) {
            Ok(0) => return Err(Rejection::BadRequest),
            Ok(count) => buffer.extend_from_slice(&chunk[..count]),
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(Rejection::RequestTimeout);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Rejection::BadRequest),
        }
    }
}

fn parse_head(head: &[u8], port: u16, login_id: &str) -> Result<Callback, Rejection> {
    let head = std::str::from_utf8(head).map_err(|_| Rejection::BadRequest)?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(Rejection::BadRequest)?;
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Rejection::BadRequest);
    };
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(Rejection::BadRequest);
    }
    if method != "GET" {
        return Err(Rejection::MethodNotAllowed);
    }
    check_headers(lines, port)?;
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != CALLBACK_PATH {
        return Err(Rejection::NotFound);
    }
    parse_query(query, login_id)
}

fn check_headers<'a>(lines: impl Iterator<Item = &'a str>, port: u16) -> Result<(), Rejection> {
    let mut host = None;
    let mut fetch_modes = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(Rejection::BadRequest)?;
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return Err(Rejection::BadRequest);
            }
            host = Some(value);
        } else if name.eq_ignore_ascii_case("sec-fetch-mode") {
            fetch_modes.push(value);
        }
    }
    if host != Some(format!("127.0.0.1:{port}").as_str()) {
        return Err(Rejection::BadRequest);
    }
    match fetch_modes.as_slice() {
        [] => Ok(()),
        [mode] if mode.eq_ignore_ascii_case("navigate") => Ok(()),
        _ => Err(Rejection::Forbidden),
    }
}

fn same_login_id(presented: &str, expected: &str) -> bool {
    presented.as_bytes().ct_eq(expected.as_bytes()).into()
}

fn parse_query(query: &str, login_id: &str) -> Result<Callback, Rejection> {
    let mut presented_id: Option<String> = None;
    let mut code: Option<String> = None;
    let mut error: Option<String> = None;
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        let slot = match name.as_ref() {
            "login_id" => &mut presented_id,
            "code" => &mut code,
            "error" => &mut error,
            _ => continue,
        };
        if slot.is_some() {
            return Err(Rejection::BadRequest);
        }
        *slot = Some(value.into_owned());
    }
    match presented_id {
        Some(presented) if same_login_id(&presented, login_id) => {}
        _ => return Err(Rejection::BadRequest),
    }
    match (code, error) {
        (None, Some(error)) => Ok(Callback::Failed(if error == "access_denied" {
            FailureCode::AccessDenied
        } else {
            FailureCode::Other
        })),
        (Some(code), None) if is_plausible_code(&code) => Ok(Callback::Approved(Secret::new(code))),
        _ => Err(Rejection::BadRequest),
    }
}

fn is_plausible_code(code: &str) -> bool {
    (1..=MAX_CODE_LEN).contains(&code.len()) && code.bytes().all(|byte| byte.is_ascii_graphic())
}

fn respond_best_effort(stream: &mut TcpStream, status: &str, text: &str) {
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Jaunt</title></head><body><p>{text}</p></body></html>"
    );
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let written = stream
        .set_write_timeout(Some(READ_TIMEOUT))
        .and_then(|()| stream.write_all(head.as_bytes()))
        .and_then(|()| stream.write_all(body.as_bytes()))
        .and_then(|()| stream.flush());
    drop(written);
}

fn drain(stream: &mut TcpStream) {
    if stream.shutdown(Shutdown::Write).is_err() {
        return;
    }
    let Some(deadline) = Instant::now().checked_add(DRAIN_TIMEOUT) else {
        return;
    };
    let mut sink = [0_u8; READ_CHUNK_BYTES];
    let mut total = 0_usize;
    while total < DRAIN_LIMIT_BYTES {
        let Some(remaining) = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
        else {
            return;
        };
        if stream.set_read_timeout(Some(remaining)).is_err() {
            return;
        }
        match stream.read(&mut sink) {
            Ok(0) | Err(_) => return,
            Ok(count) => total += count,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{
        Callback, FailureCode, LoopbackError, LoopbackLimits, LoopbackListener, Rejection,
        parse_head,
    };

    const LOGIN_ID: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
    const OTHER_ID: &str = "00000000-0000-0000-0000-000000000000";
    const CODE: &str = "Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmE";
    const PORT: u16 = 40123;

    fn head(target: &str, extra: &str) -> String {
        format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}{extra}")
    }

    fn parse(raw: &str) -> Result<Callback, Rejection> {
        parse_head(raw.as_bytes(), PORT, LOGIN_ID)
    }

    fn good_target() -> String {
        format!("/callback?login_id={LOGIN_ID}&code={CODE}")
    }

    #[test]
    fn well_formed_callbacks_are_accepted() {
        match parse(&head(&good_target(), "")) {
            Ok(Callback::Approved(code)) => assert_eq!(code.expose(), CODE),
            other => panic!("unexpected: {other:?}"),
        }
        let denied = parse(&head(
            &format!("/callback?login_id={LOGIN_ID}&error=access_denied"),
            "",
        ));
        assert!(matches!(
            denied,
            Ok(Callback::Failed(FailureCode::AccessDenied))
        ));
        let other = parse(&head(
            &format!("/callback?login_id={LOGIN_ID}&error=server_error"),
            "",
        ));
        assert!(matches!(other, Ok(Callback::Failed(FailureCode::Other))));
        let navigated = parse(&head(
            &good_target(),
            "\r\nSec-Fetch-Mode: navigate\r\nsec-fetch-site: cross-site",
        ));
        assert!(matches!(navigated, Ok(Callback::Approved(_))));
        let longest = "a".repeat(256);
        let boundary = parse(&head(
            &format!("/callback?login_id={LOGIN_ID}&code={longest}"),
            "",
        ));
        assert!(matches!(boundary, Ok(Callback::Approved(_))));
    }

    #[test]
    fn malformed_or_foreign_requests_are_rejected() {
        let good = good_target();
        let too_long = "a".repeat(257);
        let cases: Vec<(String, Rejection)> = vec![
            (
                format!("POST {good} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}"),
                Rejection::MethodNotAllowed,
            ),
            (
                head(&format!("/callback/?login_id={LOGIN_ID}&code={CODE}"), ""),
                Rejection::NotFound,
            ),
            (
                head(&format!("/other?login_id={LOGIN_ID}&code={CODE}"), ""),
                Rejection::NotFound,
            ),
            (
                format!("GET {good} HTTP/1.1\r\nHost: localhost:{PORT}"),
                Rejection::BadRequest,
            ),
            (
                format!("GET {good} HTTP/1.1\r\nHost: 127.0.0.1:{}", PORT + 1),
                Rejection::BadRequest,
            ),
            (
                format!("GET {good} HTTP/1.1\r\nHost: evil.example"),
                Rejection::BadRequest,
            ),
            (
                format!("GET {good} HTTP/1.1\r\nAccept: */*"),
                Rejection::BadRequest,
            ),
            (
                head(&good, &format!("\r\nHost: 127.0.0.1:{PORT}")),
                Rejection::BadRequest,
            ),
            (
                format!("GET {good} HTTP/2\r\nHost: 127.0.0.1:{PORT}"),
                Rejection::BadRequest,
            ),
            (
                head(&format!("/callback?login_id={OTHER_ID}&code={CODE}"), ""),
                Rejection::BadRequest,
            ),
            (
                head(&format!("/callback?login_id={LOGIN_ID}"), ""),
                Rejection::BadRequest,
            ),
            (
                head(&format!("/callback?code={CODE}"), ""),
                Rejection::BadRequest,
            ),
            (
                head(&format!("{good}&code={CODE}"), ""),
                Rejection::BadRequest,
            ),
            (head(&format!("{good}&error=x"), ""), Rejection::BadRequest),
            (
                head("/callback?error=access_denied", ""),
                Rejection::BadRequest,
            ),
            (
                head(
                    &format!("/callback?error=access_denied&login_id={OTHER_ID}"),
                    "",
                ),
                Rejection::BadRequest,
            ),
            (head("/callback", ""), Rejection::BadRequest),
            (
                head(
                    &format!("/callback?login_id={LOGIN_ID}&code={too_long}"),
                    "",
                ),
                Rejection::BadRequest,
            ),
            (
                head(&format!("/callback?login_id={LOGIN_ID}&code=a%20b"), ""),
                Rejection::BadRequest,
            ),
            (
                head(&format!("/callback?login_id={LOGIN_ID}&code=a%00b"), ""),
                Rejection::BadRequest,
            ),
            (
                head(&format!("/callback?login_id={LOGIN_ID}&code="), ""),
                Rejection::BadRequest,
            ),
            (
                head(&good, "\r\nSec-Fetch-Mode: cors"),
                Rejection::Forbidden,
            ),
            (
                head(&good, "\r\nSec-Fetch-Mode: no-cors"),
                Rejection::Forbidden,
            ),
            (
                head(&good, "\r\nSec-Fetch-Mode: same-origin"),
                Rejection::Forbidden,
            ),
            (head(&good, "\r\nSec-Fetch-Mode:"), Rejection::Forbidden),
            (
                head(
                    &good,
                    "\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Mode: navigate",
                ),
                Rejection::Forbidden,
            ),
            (
                format!("GET {good} HTTP/1.1\r\nHost: evil.example\r\nSec-Fetch-Mode: cors"),
                Rejection::BadRequest,
            ),
        ];
        for (raw, expected) in cases {
            assert_eq!(parse(&raw).err(), Some(expected), "{raw:?}");
        }
    }

    #[test]
    fn default_limits_match_the_documented_constants() {
        let limits = LoopbackLimits::default();
        assert_eq!(limits.max_request_bytes, 8192);
        assert_eq!(limits.read_timeout, Duration::from_secs(5));
        assert_eq!(limits.max_connections, 16);
    }

    fn exchange(port: u16, raw: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(raw.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    fn request(port: u16, target: &str, extra: &str) -> String {
        format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}{extra}\r\n\r\n")
    }

    fn callback_request(port: u16, login_id: &str) -> String {
        request(
            port,
            &format!("/callback?login_id={login_id}&code={CODE}"),
            "",
        )
    }

    fn spawn_wait(
        listener: LoopbackListener,
        timeout: Duration,
    ) -> thread::JoinHandle<Result<Callback, LoopbackError>> {
        thread::spawn(move || listener.wait_for_callback(LOGIN_ID, timeout))
    }

    #[test]
    fn listener_binds_an_unprivileged_ipv4_loopback_port() {
        let listener = LoopbackListener::bind().unwrap();
        assert!(listener.port() >= 1024);
        assert!(listener.listener.local_addr().unwrap().ip().is_loopback());
        assert!(listener.listener.local_addr().unwrap().is_ipv4());
    }

    #[test]
    fn a_mismatched_login_id_is_ignored_and_the_right_one_is_accepted_with_safe_headers() {
        let listener = LoopbackListener::bind().unwrap();
        let port = listener.port();
        let waiter = spawn_wait(listener, Duration::from_secs(20));

        let wrong = exchange(port, &callback_request(port, OTHER_ID));
        assert!(wrong.starts_with("HTTP/1.1 400 "), "{wrong}");
        assert!(!wrong.contains(CODE));

        let right = exchange(port, &callback_request(port, LOGIN_ID));
        assert!(right.starts_with("HTTP/1.1 200 OK\r\n"), "{right}");
        for header in [
            "Content-Type: text/html; charset=utf-8\r\n",
            "Cache-Control: no-store\r\n",
            "Content-Security-Policy: default-src 'none'\r\n",
            "X-Content-Type-Options: nosniff\r\n",
            "Connection: close\r\n",
        ] {
            assert!(right.contains(header), "missing {header:?} in {right}");
        }
        assert!(right.contains("Signed in. You can close this tab."));

        match waiter.join().unwrap() {
            Ok(Callback::Approved(code)) => assert_eq!(code.expose(), CODE),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn an_error_callback_needs_the_exact_login_id_and_is_otherwise_ignored() {
        let listener = LoopbackListener::bind().unwrap();
        let port = listener.port();
        let waiter = spawn_wait(listener, Duration::from_secs(20));

        for target in [
            "/callback?error=access_denied".to_owned(),
            format!("/callback?error=access_denied&login_id={OTHER_ID}"),
        ] {
            let ignored = exchange(port, &request(port, &target, ""));
            assert!(ignored.starts_with("HTTP/1.1 400 "), "{ignored}");
        }
        let accepted = exchange(
            port,
            &request(
                port,
                &format!("/callback?login_id={LOGIN_ID}&error=access_denied"),
                "",
            ),
        );
        assert!(accepted.starts_with("HTTP/1.1 200 OK\r\n"), "{accepted}");
        assert!(matches!(
            waiter.join().unwrap(),
            Ok(Callback::Failed(FailureCode::AccessDenied))
        ));
    }

    #[test]
    fn a_request_that_is_not_a_navigation_is_forbidden_and_the_listener_keeps_waiting() {
        let listener = LoopbackListener::bind().unwrap();
        let port = listener.port();
        let waiter = spawn_wait(listener, Duration::from_secs(20));

        let target = format!("/callback?login_id={LOGIN_ID}&code={CODE}");
        let forbidden = exchange(port, &request(port, &target, "\r\nSec-Fetch-Mode: no-cors"));
        assert!(forbidden.starts_with("HTTP/1.1 403 "), "{forbidden}");
        assert!(!forbidden.contains(CODE));

        let navigated = exchange(
            port,
            &request(port, &target, "\r\nSec-Fetch-Mode: navigate"),
        );
        assert!(navigated.starts_with("HTTP/1.1 200 OK\r\n"), "{navigated}");
        assert!(matches!(waiter.join().unwrap(), Ok(Callback::Approved(_))));
    }

    #[test]
    fn an_oversized_request_is_refused_and_the_listener_keeps_waiting() {
        let listener = LoopbackListener::bind().unwrap();
        let port = listener.port();
        let waiter = spawn_wait(listener, Duration::from_secs(20));

        let padding = "a".repeat(9 * 1024);
        let refused = exchange(port, &request(port, &format!("/callback?x={padding}"), ""));
        assert!(refused.starts_with("HTTP/1.1 431 "), "{refused}");

        let right = exchange(port, &callback_request(port, LOGIN_ID));
        assert!(right.starts_with("HTTP/1.1 200 OK\r\n"), "{right}");
        assert!(matches!(waiter.join().unwrap(), Ok(Callback::Approved(_))));
    }

    #[test]
    fn a_stalled_client_does_not_block_a_valid_one_and_is_cut_off_after_the_read_timeout() {
        let limits = LoopbackLimits {
            read_timeout: Duration::from_millis(300),
            ..LoopbackLimits::default()
        };
        let listener = LoopbackListener::bind_with(limits).unwrap();
        let port = listener.port();
        let waiter = spawn_wait(listener, Duration::from_secs(20));

        let mut stalled = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stalled
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stalled.write_all(b"GET /callback?login_id=").unwrap();

        let right = exchange(port, &callback_request(port, LOGIN_ID));
        assert!(right.starts_with("HTTP/1.1 200 OK\r\n"), "{right}");
        assert!(matches!(waiter.join().unwrap(), Ok(Callback::Approved(_))));

        let mut response = String::new();
        stalled.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 408 "), "{response}");
    }

    #[test]
    fn a_client_that_drips_bytes_still_hits_the_overall_read_deadline() {
        let limits = LoopbackLimits {
            read_timeout: Duration::from_millis(300),
            ..LoopbackLimits::default()
        };
        let listener = LoopbackListener::bind_with(limits).unwrap();
        let port = listener.port();
        let waiter = spawn_wait(listener, Duration::from_secs(20));

        let mut dripper = TcpStream::connect(("127.0.0.1", port)).unwrap();
        dripper
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut writer = dripper.try_clone().unwrap();
        let drip = thread::spawn(move || {
            for byte in b"GET /callback" {
                if writer.write_all(&[*byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        });
        let mut response = String::new();
        dripper.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 408 "), "{response}");
        drip.join().unwrap();

        let right = exchange(port, &callback_request(port, LOGIN_ID));
        assert!(right.starts_with("HTTP/1.1 200 OK\r\n"), "{right}");
        assert!(matches!(waiter.join().unwrap(), Ok(Callback::Approved(_))));
    }

    #[test]
    fn a_client_that_drips_after_a_bad_request_cannot_hold_its_slot_past_the_drain_deadline() {
        let limits = LoopbackLimits {
            max_connections: 1,
            ..LoopbackLimits::default()
        };
        let listener = LoopbackListener::bind_with(limits).unwrap();
        let port = listener.port();
        let waiter = spawn_wait(listener, Duration::from_secs(20));

        let mut dripper = TcpStream::connect(("127.0.0.1", port)).unwrap();
        dripper
            .write_all(b"GET /nope HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut writer = dripper.try_clone().unwrap();
        let drip = thread::spawn(move || {
            for _ in 0..80 {
                if writer.write_all(b"x").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
        });

        let started = Instant::now();
        let right = exchange(port, &callback_request(port, LOGIN_ID));
        let waited = started.elapsed();
        assert!(right.starts_with("HTTP/1.1 200 OK\r\n"), "{right}");
        assert!(waited < Duration::from_secs(3), "{waited:?}");
        assert!(matches!(waiter.join().unwrap(), Ok(Callback::Approved(_))));
        drip.join().unwrap();
        drop(dripper);
    }

    #[test]
    fn the_connection_cap_counts_concurrent_connections_not_a_lifetime_total() {
        let limits = LoopbackLimits {
            max_connections: 2,
            read_timeout: Duration::from_millis(1000),
            ..LoopbackLimits::default()
        };
        let listener = LoopbackListener::bind_with(limits).unwrap();
        let port = listener.port();
        let waiter = spawn_wait(listener, Duration::from_secs(20));

        for _ in 0..4 {
            let response = exchange(port, "GET /nope HTTP/1.1\r\nHost: x\r\n\r\n");
            assert!(response.starts_with("HTTP/1.1 400 "), "{response}");
        }

        let mut holders = Vec::new();
        for _ in 0..2 {
            let mut stalled = TcpStream::connect(("127.0.0.1", port)).unwrap();
            stalled.write_all(b"GET /callback?login_id=").unwrap();
            holders.push(stalled);
        }

        let mut third = TcpStream::connect(("127.0.0.1", port)).unwrap();
        third
            .write_all(callback_request(port, LOGIN_ID).as_bytes())
            .unwrap();
        third
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let mut early = [0_u8; 16];
        let early_read = third.read(&mut early);
        assert!(
            matches!(&early_read, Err(err) if matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            )),
            "answered while both slots were held: {early_read:?}"
        );

        third
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut right = String::new();
        third.read_to_string(&mut right).unwrap();
        assert!(right.starts_with("HTTP/1.1 200 OK\r\n"), "{right}");
        assert!(matches!(waiter.join().unwrap(), Ok(Callback::Approved(_))));
        for mut holder in holders {
            let mut response = String::new();
            holder
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            holder.read_to_string(&mut response).unwrap();
            assert!(response.starts_with("HTTP/1.1 408 "), "{response}");
        }
    }

    #[test]
    fn the_wait_ends_at_the_deadline() {
        let listener = LoopbackListener::bind().unwrap();
        let timed_out = listener.wait_for_callback(LOGIN_ID, Duration::from_millis(100));
        assert!(matches!(timed_out, Err(LoopbackError::TimedOut)));
    }
}
