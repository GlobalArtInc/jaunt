use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt::gate_config::sha256_hex;
use jaunt::gate_tls::{GateError, GateRoute, connect};
use jaunt::profile::ProfileName;
use jaunt::proxy::{RelayError, relay};
use jaunt::ssh_config::{EnsureCommand, render_ssh_config, validate};
use jaunt_proto::{ClientConfig, ClientTransport, GATE_ALPN_SSH, GATE_ALPN_SVC, GateEndpoint};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::ServerConfig;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::version::{TLS12, TLS13};
use serde_json::{Value, json};
use ssh_key::PublicKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::cli::{base_command, stderr, stdout};
use crate::support::{GATE_HOST, GATE_PORT, SUFFIX, ca_key};
use crate::tls_setup::ssh_available;

pub const GATE_NAME: &str = "localhost";
pub const INTERCEPTION: &str = "the gate's certificate is not signed by the pinned root: a network device may be intercepting TLS; in such networks only the web console works; if the server's TLS roots changed, run `jaunt login` again";
const PROCESS_DEADLINE: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(20);

pub struct TestCa {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl TestCa {
    pub fn new(name: &str) -> TestCa {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CommonName, name);
        TestCa {
            issuer: CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap(),
        }
    }

    pub fn expired(name: &str) -> TestCa {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CommonName, name);
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        TestCa {
            issuer: CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap(),
        }
    }

    pub fn der(&self) -> Vec<u8> {
        self.issuer.der().to_vec()
    }

    pub fn key_der(&self) -> Vec<u8> {
        self.issuer.key().serialize_der()
    }

    pub fn client_leaf(&self) -> (Vec<u8>, Vec<u8>) {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![rcgen::SanType::URI(
            format!("urn:jaunt:user:{}", crate::support::USER_ID)
                .try_into()
                .unwrap(),
        )];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let key = KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, &*self.issuer).unwrap();
        (certificate.der().to_vec(), key.serialize_der())
    }

    pub fn pem(&self) -> String {
        self.issuer.pem()
    }

    pub fn pinned(&self) -> Value {
        json!({
            "certificate_der": STANDARD.encode(self.der()),
            "sha256": sha256_hex(&self.der()),
            "not_before": 0,
            "not_after": 0,
        })
    }

    pub fn server_leaf(&self, name: &str) -> Leaf {
        self.leaf(name, false)
    }

    pub fn leaf(&self, name: &str, expired: bool) -> Leaf {
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        if expired {
            params.not_before = rcgen::date_time_ymd(2000, 1, 1);
            params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        }
        let key = KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, &*self.issuer).unwrap();
        (
            vec![certificate.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
    }
}

pub type Leaf = (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

pub fn gate_config(ca: &TestCa, tls12_only: bool, alpn: &[&str]) -> ServerConfig {
    leaf_config(ca.server_leaf(GATE_NAME), tls12_only, alpn)
}

pub fn leaf_config((chain, key): Leaf, tls12_only: bool, alpn: &[&str]) -> ServerConfig {
    let versions: &[&rustls::SupportedProtocolVersion] =
        if tls12_only { &[&TLS12] } else { &[&TLS13] };
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    config.alpn_protocols = alpn.iter().map(|name| name.as_bytes().to_vec()).collect();
    config
}

#[derive(Clone, Copy)]
pub enum Script {
    WaitForTheEnd,
    EndFirst,
    DropTcpAfterTheEnd,
    FirstLine,
}

#[derive(Default)]
pub struct GateLog {
    pub accepted: usize,
    pub handshakes: usize,
    pub received: Vec<u8>,
    pub clean_eof: Option<bool>,
    pub closed: bool,
}

pub struct FakeGate {
    pub port: u16,
    log: Arc<Mutex<GateLog>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

pub const REPLY: &[u8] = b"reply from the gate";

async fn serve(
    tcp: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    script: Script,
    log: Arc<Mutex<GateLog>>,
) {
    let Ok(mut tls) = acceptor.accept(tcp).await else {
        return;
    };
    log.lock().unwrap().handshakes += 1;
    if matches!(script, Script::FirstLine) {
        let mut line = Vec::new();
        let mut byte = [0_u8; 1];
        while !line.ends_with(b"\n") && line.len() < 1024 {
            match tls.read(&mut byte).await {
                Ok(1) => line.push(byte[0]),
                _ => break,
            }
        }
        log.lock().unwrap().received = line;
        drop(tls.shutdown().await);
        return;
    }
    if matches!(script, Script::WaitForTheEnd | Script::DropTcpAfterTheEnd) {
        let mut received = Vec::new();
        let clean = tls.read_to_end(&mut received).await.is_ok();
        let mut log = log.lock().unwrap();
        log.received = received;
        log.clean_eof = Some(clean);
    }
    if tls.write_all(REPLY).await.is_err() || tls.flush().await.is_err() {
        return;
    }
    let closed = match script {
        Script::WaitForTheEnd | Script::EndFirst | Script::FirstLine => tls.shutdown().await,
        Script::DropTcpAfterTheEnd => tls.get_mut().0.shutdown().await,
    };
    log.lock().unwrap().closed = closed.is_ok();
}

impl FakeGate {
    pub fn start(config: ServerConfig, script: Script) -> FakeGate {
        let log = Arc::new(Mutex::new(GateLog::default()));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
        let thread_log = Arc::clone(&log);
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let thread = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                ready_tx.send(listener.local_addr().unwrap().port()).unwrap();
                loop {
                    tokio::select! {
                        _ = &mut stop_rx => break,
                        accepted = listener.accept() => {
                            let (tcp, _) = accepted.unwrap();
                            thread_log.lock().unwrap().accepted += 1;
                            tokio::spawn(serve(tcp, acceptor.clone(), script, Arc::clone(&thread_log)));
                        }
                    }
                }
            });
        });
        let port = ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        FakeGate {
            port,
            log,
            stop: Some(stop_tx),
            thread: Some(thread),
        }
    }

    pub fn log<T>(&self, read: impl FnOnce(&GateLog) -> T) -> T {
        read(&self.log.lock().unwrap())
    }

    pub fn route(&self, pinned: &TestCa) -> GateRoute {
        GateRoute::new(GATE_NAME.to_owned(), self.port, vec![pinned.der()])
    }
}

impl Drop for FakeGate {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop.send(()).ok();
        }
        if let Some(thread) = self.thread.take() {
            thread.join().ok();
        }
    }
}

pub fn services_json(port: u16, roots: &[Value]) -> Value {
    json!({
        "client_transport": "tls",
        "services": {
            "domain": GATE_NAME,
            "gate_tls_name": GATE_NAME,
            "port": port,
            "alpn": [GATE_ALPN_SSH, GATE_ALPN_SVC],
            "roots": roots,
        }
    })
}

fn within_deadline<T>(work: impl Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(20), work)
                .await
                .expect("the exchange with the gate did not finish")
        })
}

#[test]
fn input_end_sends_close_notify_and_the_reply_that_follows_is_still_relayed() {
    let pinned = TestCa::new("pinned root");
    let gate = FakeGate::start(
        gate_config(&pinned, false, &[GATE_ALPN_SSH]),
        Script::WaitForTheEnd,
    );
    let mut output = Vec::new();

    let outcome = within_deadline(async {
        let stream = connect(&gate.route(&pinned)).await.unwrap();
        relay(&b"hello gate"[..], &mut output, stream).await
    });

    outcome.unwrap();
    assert_eq!(output, REPLY);
    gate.log(|log| {
        assert_eq!(log.received, b"hello gate");
        assert_eq!(log.clean_eof, Some(true));
        assert_eq!(log.accepted, 1);
    });
}

#[test]
fn a_gate_that_ends_first_finishes_the_relay_while_input_is_still_open() {
    let pinned = TestCa::new("pinned root");
    let gate = FakeGate::start(
        gate_config(&pinned, false, &[GATE_ALPN_SSH]),
        Script::EndFirst,
    );
    let (_keep_open, input) = tokio::io::duplex(64);
    let mut output = Vec::new();

    let outcome = within_deadline(async {
        let stream = connect(&gate.route(&pinned)).await.unwrap();
        relay(input, &mut output, stream).await
    });

    outcome.unwrap();
    assert_eq!(output, REPLY);
}

#[test]
fn a_gate_that_drops_the_connection_without_ending_tls_is_an_error_after_the_data() {
    let pinned = TestCa::new("pinned root");
    let gate = FakeGate::start(
        gate_config(&pinned, false, &[GATE_ALPN_SSH]),
        Script::DropTcpAfterTheEnd,
    );
    let mut output = Vec::new();

    let outcome = within_deadline(async {
        let stream = connect(&gate.route(&pinned)).await.unwrap();
        relay(&b""[..], &mut output, stream).await
    });

    assert!(matches!(outcome, Err(RelayError::CutOff)), "{outcome:?}");
    assert_eq!(output, REPLY);
}

#[test]
fn handshakes_that_break_a_rule_are_refused_once_without_weaker_retries() {
    let pinned = TestCa::new("pinned root");
    let other = TestCa::new("intercepting root");
    type Expected = fn(&GateError) -> bool;
    let ssh = &[GATE_ALPN_SSH];
    let cases: Vec<(&str, ServerConfig, &str, Expected)> = vec![
        (
            "certificate under another root",
            gate_config(&other, false, ssh),
            GATE_NAME,
            |err| matches!(err, GateError::Intercepted),
        ),
        (
            "pinned certificate for the name localhost, reached as 127.0.0.1",
            gate_config(&pinned, false, ssh),
            "127.0.0.1",
            |err| matches!(err, GateError::Intercepted),
        ),
        (
            "pinned certificate for other.test",
            leaf_config(pinned.server_leaf("other.test"), false, ssh),
            GATE_NAME,
            |err| matches!(err, GateError::Intercepted),
        ),
        (
            "expired pinned certificate",
            leaf_config(pinned.leaf(GATE_NAME, true), false, ssh),
            GATE_NAME,
            |err| matches!(err, GateError::CertificateTime),
        ),
        (
            "TLS 1.2 only",
            gate_config(&pinned, true, ssh),
            GATE_NAME,
            |err| matches!(err, GateError::Protocol),
        ),
        (
            "only the service protocol",
            gate_config(&pinned, false, &[GATE_ALPN_SVC]),
            GATE_NAME,
            |err| matches!(err, GateError::Alpn),
        ),
        (
            "no protocol negotiated",
            gate_config(&pinned, false, &[]),
            GATE_NAME,
            |err| matches!(err, GateError::Alpn),
        ),
    ];
    for (case, config, host, expected) in cases {
        let gate = FakeGate::start(config, Script::EndFirst);
        let mut route = gate.route(&pinned);
        route.host = host.to_owned();

        let outcome = within_deadline(connect(&route));

        let err = outcome.err().unwrap_or_else(|| panic!("{case}: connected"));
        assert!(expected(&err), "{case}: {err:?}");
        assert_eq!(gate.log(|log| log.accepted), 1, "{case}");
    }
    assert_eq!(GateError::Intercepted.to_string(), INTERCEPTION);
}

fn write_services(home: &Path, services: &Value) {
    let dir = home.join("default");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("services.json"), services.to_string()).unwrap();
}

fn collect(mut pipe: impl Read + Send + 'static) -> mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        drop(pipe.read_to_end(&mut bytes));
        drop(sender.send(bytes));
    });
    receiver
}

pub fn run_bounded(mut command: Command, input: &[u8], hold_input: bool) -> Output {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input).unwrap();
    let held = if hold_input {
        Some(stdin)
    } else {
        drop(stdin);
        None
    };
    let out = collect(child.stdout.take().unwrap());
    let err = collect(child.stderr.take().unwrap());
    let deadline = Instant::now() + PROCESS_DEADLINE;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            drop(child.kill());
            drop(child.wait());
            let seen = err.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
            panic!(
                "the process did not finish within {PROCESS_DEADLINE:?}; stderr: {}",
                String::from_utf8_lossy(&seen)
            );
        }
        thread::sleep(POLL);
    };
    drop(held);
    let rest = deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_secs(5));
    Output {
        status,
        stdout: out
            .recv_timeout(rest)
            .expect("standard output was not closed"),
        stderr: err
            .recv_timeout(rest)
            .expect("standard error was not closed"),
    }
}

fn run_proxy(home: &Path, input: &[u8], envs: &[(&str, &Path)]) -> Output {
    let mut command = base_command(home);
    command.args(["proxy", "ssh"]);
    for (name, value) in envs {
        command.env(name, value);
    }
    run_bounded(command, input, false)
}

#[test]
fn the_proxy_command_writes_only_relayed_bytes_to_standard_output() {
    let pinned = TestCa::new("pinned root");
    let gate = FakeGate::start(
        gate_config(&pinned, false, &[GATE_ALPN_SSH]),
        Script::WaitForTheEnd,
    );
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    write_services(&home, &services_json(gate.port, &[pinned.pinned()]));

    let output = run_proxy(&home, b"SSH-2.0-client\r\n", &[]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, REPLY);
    assert_eq!(stderr(&output), "");
    gate.log(|log| {
        assert_eq!(log.received, b"SSH-2.0-client\r\n");
        assert_eq!(log.clean_eof, Some(true));
    });
}

#[test]
fn the_proxy_command_ignores_roots_the_system_trusts_and_reports_interception_on_stderr() {
    let pinned = TestCa::new("pinned root");
    let system = TestCa::new("system-trusted root");
    let gate = FakeGate::start(
        gate_config(&system, false, &[GATE_ALPN_SSH]),
        Script::EndFirst,
    );
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    write_services(&home, &services_json(gate.port, &[pinned.pinned()]));
    let trust_dir = root.path().join("trust");
    fs::create_dir(&trust_dir).unwrap();
    let bundle = trust_dir.join("ca.pem");
    fs::write(&bundle, system.pem()).unwrap();

    let output = run_proxy(
        &home,
        b"",
        &[("SSL_CERT_FILE", &bundle), ("SSL_CERT_DIR", &trust_dir)],
    );

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert_eq!(stdout(&output), "");
    assert_eq!(stderr(&output), format!("jaunt: {INTERCEPTION}\n"));
    assert_eq!(gate.log(|log| (log.accepted, log.handshakes)), (1, 0));
}

#[test]
fn the_proxy_command_without_a_tls_route_says_how_to_get_one() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");

    let output = run_proxy(&home, b"", &[]);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        "jaunt: profile `default` has no TLS route to the gate: run `jaunt login --profile default`\n"
    );
}

#[test]
fn a_gate_that_accepts_tcp_and_stays_silent_hits_the_handshake_deadline() {
    let pinned = TestCa::new("pinned root");
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut route = GateRoute::new(
        GATE_NAME.to_owned(),
        silent.local_addr().unwrap().port(),
        vec![pinned.der()],
    );
    route.handshake_timeout = Duration::from_millis(300);

    let err = within_deadline(connect(&route)).err().unwrap();

    assert!(matches!(err, GateError::HandshakeTimeout), "{err:?}");
    assert_eq!(err.to_string(), "the TLS handshake with the gate timed out");
}

#[test]
fn the_proxy_command_gives_up_on_a_silent_gate_after_ten_seconds() {
    let pinned = TestCa::new("pinned root");
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    write_services(
        &home,
        &services_json(silent.local_addr().unwrap().port(), &[pinned.pinned()]),
    );
    let started = Instant::now();

    let output = run_proxy(&home, b"", &[]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr(&output),
        "jaunt: the TLS handshake with the gate timed out\n"
    );
    assert!(started.elapsed() >= Duration::from_secs(9));
}

#[test]
fn the_proxy_command_ends_when_the_gate_ends_although_its_input_stays_open() {
    let pinned = TestCa::new("pinned root");
    let gate = FakeGate::start(
        gate_config(&pinned, false, &[GATE_ALPN_SSH]),
        Script::EndFirst,
    );
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    write_services(&home, &services_json(gate.port, &[pinned.pinned()]));
    let mut command = base_command(&home);
    command.args(["proxy", "ssh"]);

    let output = run_bounded(command, b"SSH-2.0-client\r\n", true);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, REPLY);
}

#[test]
fn the_proxy_command_checks_the_stored_settings_again_before_connecting() {
    let pinned = TestCa::new("pinned root");
    let gate = FakeGate::start(
        gate_config(&pinned, false, &[GATE_ALPN_SSH]),
        Script::EndFirst,
    );
    let other = TestCa::new("other root");
    let mut changed = pinned.pinned();
    changed["certificate_der"] = json!(STANDARD.encode(other.der()));
    let mut wrong_digest = pinned.pinned();
    wrong_digest["sha256"] = json!("00".repeat(32));
    let expired = TestCa::expired("expired root").pinned();
    let cases: Vec<(&str, Option<Value>, &str)> = vec![
        (
            "changed root",
            Some(changed),
            "jaunt: the stored gate settings of profile `default` cannot be used: a stored pinned root does not match its SHA-256; run `jaunt login --profile default`",
        ),
        (
            "wrong digest",
            Some(wrong_digest),
            "jaunt: the stored gate settings of profile `default` cannot be used: a stored pinned root does not match its SHA-256; run `jaunt login --profile default`",
        ),
        (
            "expired root",
            Some(expired),
            "jaunt: the stored gate settings of profile `default` cannot be used: a stored pinned root is not valid at this time (check the system clock); run `jaunt login --profile default`",
        ),
        ("symbolic link", None, "is not a regular file"),
        ("oversized file", None, "is too large"),
    ];
    for (case, root_entry, expected) in cases {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("state");
        let dir = home.join("default");
        fs::create_dir_all(&dir).unwrap();
        let valid = services_json(gate.port, &[pinned.pinned()]).to_string();
        match (case, root_entry) {
            (_, Some(entry)) => write_services(&home, &services_json(gate.port, &[entry])),
            ("symbolic link", None) => {
                let elsewhere = root.path().join("elsewhere.json");
                fs::write(&elsewhere, &valid).unwrap();
                symlink(&elsewhere, dir.join("services.json")).unwrap();
            }
            (_, None) => {
                let padded = format!("{valid}{}", " ".repeat(1024 * 1024));
                fs::write(dir.join("services.json"), padded).unwrap();
            }
        }

        let output = run_proxy(&home, b"", &[]);

        assert_eq!(output.status.code(), Some(1), "{case}");
        assert_eq!(stdout(&output), "", "{case}");
        let text = stderr(&output);
        assert_eq!(text.lines().count(), 1, "{case}: {text}");
        assert!(
            text.starts_with("jaunt: ") && text.contains(expected),
            "{case}: {text}"
        );
    }
    assert_eq!(gate.log(|log| log.accepted), 0);
}

#[test]
fn ssh_runs_the_generated_proxy_command_through_a_shell_from_an_awkward_profile_path() {
    if !ssh_available() {
        eprintln!("skipped: no ssh client found");
        return;
    }
    let pinned = TestCa::new("pinned root");
    let gate = FakeGate::start(
        gate_config(&pinned, false, &[GATE_ALPN_SSH]),
        Script::FirstLine,
    );
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("Jörg ,=+@: Müller").join("jaunt home");
    let profile_dir = home.join("default");
    write_services(&home, &services_json(gate.port, &[pinned.pinned()]));
    let config = validate(ClientConfig {
        ssh_suffix: SUFFIX.to_owned(),
        gate: GateEndpoint {
            host: GATE_HOST.to_owned(),
            port: GATE_PORT,
        },
        host_ca_keys: vec![
            PublicKey::from(ca_key().public_key().key_data().clone())
                .to_openssh()
                .unwrap(),
        ],
    })
    .unwrap();
    let profile = ProfileName::default_name();
    let text = render_ssh_config(
        &config,
        ClientTransport::Tls,
        &profile_dir,
        &EnsureCommand {
            program: Path::new(env!("CARGO_BIN_EXE_jaunt")),
            home: Some(&home),
            profile: &profile,
        },
    )
    .unwrap();
    let ssh_config = profile_dir.join("ssh_config");
    fs::write(&ssh_config, text).unwrap();
    let user_home = root.path().join("userhome");
    fs::create_dir(&user_home).unwrap();
    let mut command = Command::new("ssh");
    command
        .arg("-F")
        .arg(&ssh_config)
        .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=20"])
        .arg(format!("jaunt@{GATE_HOST}"))
        .arg("true")
        .env("HOME", &user_home)
        .env("SHELL", "/bin/sh")
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("JAUNT_HOME")
        .env_remove("JAUNT_PROFILE");

    let output = run_bounded(command, b"", false);

    let received = gate.log(|log| log.received.clone());
    assert!(
        received.starts_with(b"SSH-2.0-"),
        "{:?} / {}",
        String::from_utf8_lossy(&received),
        stderr(&output)
    );
}
