use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use jaunt_host_users::{
    EnsureRequest, FailedStage, HostUsersSection, Name, Reason, Response, encode_response,
    parse_request,
};
use jaunt_proto::{AGENT_SESSION_ACCOUNT_PATH, AccountEventKind, AccountReport};
use jaunt_ssh::{AgentLimits, InnerCa, InnerTarget, NoObserver, UserCaKeys};
use jaunt_tunnel::{BoxFuture, H2Io, IncomingStream, StreamHandler};
use russh::client::{self, AuthResult};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, UnixListener};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::super::api::AgentApi;
use super::super::ssh_service;
use super::{HOUR, HostCertificates, User, enrolled, stream_meta, user};
use crate::accounts::{
    ACCOUNT_TIMINGS, AccountParts, AccountTimings, Availability, HostUsersPaths, LookupError,
    PasswdLookup, Presence,
};
use crate::ssh::SshService;
use crate::state::StateDir;
use crate::testkit::{
    AUTHORIZE_PATH, ApiStep, FakeGate, LogCapture, ManualClock, TestPki, eventually, gate_and_api,
    soon, sshd_host_key_file, unix_now,
};

const LOGIN: &str = "deploy";

const TIMINGS: AccountTimings = AccountTimings {
    helper: Duration::from_secs(5),
    report: Duration::from_millis(500),
    ..ACCOUNT_TIMINGS
};

struct NoAccounts;

impl PasswdLookup for NoAccounts {
    fn passwd<'a>(&'a self, _login: &'a Name) -> BoxFuture<'a, Result<Presence, LookupError>> {
        Box::pin(async { Ok(Presence::Absent) })
    }
}

struct Helper {
    requests: Arc<Mutex<Vec<EnsureRequest>>>,
    task: JoinHandle<()>,
}

impl Drop for Helper {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Helper {
    fn start(socket: &Path, reply: Option<Response>) -> Self {
        let listener = UnixListener::bind(socket).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut line = Vec::new();
                let mut byte = [0_u8; 1];
                while stream.read_exact(&mut byte).await.is_ok() && byte[0] != b'\n' {
                    line.push(byte[0]);
                }
                seen.lock().unwrap().push(parse_request(&line).unwrap());
                match &reply {
                    Some(response) => {
                        let encoded = encode_response(response).unwrap();
                        stream.write_all(&encoded).await.unwrap();
                    }
                    None => held.push(stream),
                }
            }
        });
        Self { requests, task }
    }

    fn requests(&self) -> Vec<EnsureRequest> {
        self.requests.lock().unwrap().clone()
    }
}

struct Node {
    service: SshService,
    helper: Helper,
    _closed: TcpSocket,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

async fn node(api: &Arc<AgentApi>, user: &User, reply: Option<Response>) -> Node {
    let helper_dir = tempfile::tempdir().unwrap();
    let paths = HostUsersPaths {
        socket: helper_dir.path().join("h.sock"),
        nsswitch: helper_dir.path().join("nsswitch.conf"),
        sssd_conf: helper_dir.path().join("sssd.conf"),
    };
    let helper = Helper::start(&paths.socket, reply);
    let closed = TcpSocket::new_v4().unwrap();
    closed.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let target = InnerTarget {
        sshd_addr: closed.local_addr().unwrap(),
        sshd_host_key: sshd_host_key_file(helper_dir.path()),
    };
    let section = HostUsersSection {
        enabled: true,
        ..HostUsersSection::default()
    };
    let service = ssh_service(
        InnerCa::generate().unwrap(),
        target,
        Arc::clone(api),
        AgentLimits::default(),
        Arc::new(NoObserver),
        AccountParts {
            availability: Arc::new(Availability::new(&section, paths)),
            lookup: Arc::new(NoAccounts),
            api: Arc::clone(api),
            clock: ManualClock::new(SystemTime::now()),
            timings: TIMINGS,
        },
    );
    let t0 = unix_now();
    let node = enrolled(&TestPki::new(), "localhost:1", t0 - HOUR, t0 + HOUR);
    let state = StateDir::open(node.dir.path(), false).unwrap();
    service.install_trust(UserCaKeys::from_openssh_lines([user.ca_line.clone()]).unwrap());
    service.reload_host_identity(&state, u64::try_from(t0).unwrap());
    Node {
        service,
        helper,
        _closed: closed,
        _dirs: (helper_dir, node.dir),
    }
}

async fn stream_pair() -> (H2Io, H2Io, h2::client::SendRequest<Bytes>) {
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let (halves, accepted) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        let send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        drop(halves.send(H2Io::new(request.into_body(), send)));
        while connection.accept().await.is_some() {}
    });
    let (sender, connection) = h2::client::handshake(client_io).await.unwrap();
    tokio::spawn(connection);
    let mut ready = sender.clone().ready().await.unwrap();
    let request = http::Request::post("http://node/stream").body(()).unwrap();
    let (response, upload) = ready.send_request(request, false).unwrap();
    let server = accepted.await.unwrap();
    let response = response.await.unwrap();
    (server, H2Io::new(response.into_body(), upload), sender)
}

struct Attempt {
    served: JoinHandle<()>,
    login: JoinHandle<(
        client::Handle<HostCertificates>,
        Result<AuthResult, russh::Error>,
    )>,
    cancel: CancellationToken,
    _sender: h2::client::SendRequest<Bytes>,
}

async fn attempt(node: &Node, session: &str, user: &User) -> Attempt {
    let (server, client_io, sender) = stream_pair().await;
    let cancel = CancellationToken::new();
    let served = tokio::spawn(node.service.handle(IncomingStream {
        meta: stream_meta(session),
        io: server,
        cancel: cancel.clone(),
    }));
    let mut handle = soon(
        "the SSH handshake",
        client::connect_stream(
            Arc::new(client::Config::default()),
            client_io,
            HostCertificates(Arc::default()),
        ),
    )
    .await
    .unwrap();
    let (key, certificate) = (Arc::clone(&user.key), user.certificate.clone());
    let login = tokio::spawn(async move {
        let outcome = handle
            .authenticate_openssh_cert(LOGIN, key, certificate)
            .await;
        (handle, outcome)
    });
    Attempt {
        served,
        login,
        cancel,
        _sender: sender,
    }
}

impl Attempt {
    async fn denied(self) -> AuthResult {
        let (handle, outcome) = soon("the login", self.login).await.unwrap();
        drop(handle);
        soon("the session to end", self.served).await.unwrap();
        outcome.unwrap()
    }
}

fn audit_lines(logs: &LogCapture, event: &str, session: &str) -> Vec<Value> {
    logs.text()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .map(|line| line["fields"].clone())
        .filter(|fields| fields["event"] == event && fields["session_id"] == session)
        .collect()
}

fn reports(gate: &FakeGate, session: &str) -> Vec<AccountEventKind> {
    gate.requests(AGENT_SESSION_ACCOUNT_PATH)
        .iter()
        .map(|seen| serde_json::from_slice::<AccountReport>(&seen.body).unwrap())
        .filter(|report| report.session_id == session)
        .map(|report| report.event)
        .collect()
}

fn allow() -> ApiStep {
    ApiStep::Json(
        200,
        json!({"decision": "allow", "permissions": {
            "pty": false, "port_forwarding": false, "record_input": false,
            "max_duration_secs": 3600,
        }}),
    )
}

#[tokio::test]
async fn the_agent_service_ends_a_missing_account_with_the_generic_denial_and_its_reason() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let (gate, api) = gate_and_api().await;
    let user = user();
    gate.script(
        AUTHORIZE_PATH,
        vec![ApiStep::Json(200, json!({"decision": "deny"}))],
    );
    let baseline = node(&api, &user, Some(Response::Exists)).await;
    let generic = attempt(&baseline, "policy", &user).await.denied().await;
    assert!(!generic.success());

    let cases = [
        (
            "no-account",
            Response::Disabled,
            "no_account",
            AccountEventKind::Missing,
        ),
        (
            "refused",
            Response::Refused {
                reason: Reason::MaxUsers,
            },
            "account_refused",
            AccountEventKind::Refused,
        ),
        (
            "failed",
            Response::Failed {
                stage: FailedStage::Useradd,
                exit_code: Some(1),
            },
            "account_failed",
            AccountEventKind::Failed,
        ),
    ];
    for (session, reply, reason, report) in cases {
        gate.script(AUTHORIZE_PATH, vec![allow()]);
        let node = node(&api, &user, Some(reply)).await;
        let outcome = attempt(&node, session, &user).await.denied().await;
        assert_eq!(outcome, generic, "{session}");
        let requests = node.helper.requests();
        assert_eq!(requests.len(), 1, "{session}");
        assert_eq!(requests[0].login, LOGIN, "{session}");
        assert_eq!(requests[0].session.as_str(), session, "{session}");
        let auth = audit_lines(&logs, "agent.ssh.auth", session);
        assert_eq!(auth.len(), 1, "{session}: {auth:?}");
        assert_eq!(auth[0]["outcome"], "denied", "{session}");
        assert_eq!(auth[0]["reason"], reason, "{session}");
        assert!(audit_lines(&logs, "agent.ssh.inner_login", session).is_empty());
        eventually("the final account report", || {
            reports(&gate, session).last() == Some(&report)
        })
        .await;
    }
    gate.stop().await;
}

#[tokio::test]
async fn a_session_cancelled_while_the_account_step_waits_never_tries_the_inner_login() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let (gate, api) = gate_and_api().await;
    let user = user();
    gate.script(AUTHORIZE_PATH, vec![allow()]);
    let node = node(&api, &user, None).await;
    let attempt = attempt(&node, "stopped", &user).await;
    eventually("the helper to hold the request", || {
        node.helper.requests().len() == 1
    })
    .await;
    attempt.cancel.cancel();
    soon("the session to end", attempt.served).await.unwrap();
    let auth = audit_lines(&logs, "agent.ssh.auth", "stopped");
    assert_eq!(auth.len(), 1, "{auth:?}");
    assert_eq!(auth[0]["outcome"], "denied");
    assert_eq!(auth[0]["reason"], "stopped");
    assert!(audit_lines(&logs, "agent.ssh.inner_login", "stopped").is_empty());
    attempt.login.abort();
    gate.stop().await;
}
