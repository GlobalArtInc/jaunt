use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::version::{TLS12, TLS13};
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use x509_parser::parse_x509_certificate;

pub const SERVER_NAME: &str = "db.test";
const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];
const CANCEL_CODE: u32 = (1234 << 16) | 5678;
const READ_PIECE: usize = 8 * 1024;

pub struct Authority {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl Authority {
    pub fn new(name: &str) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CommonName, name);
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        Self {
            issuer: CertifiedIssuer::self_signed(params, key).unwrap(),
        }
    }

    pub fn pem(&self) -> String {
        let encoded = STANDARD.encode(self.issuer.der());
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    }

    pub fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.issuer.der().clone()).unwrap();
        roots
    }

    pub fn server_leaf(
        &self,
        names: &[&str],
    ) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        let mut params = CertificateParams::new(names).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let der = params.signed_by(&key, &*self.issuer).unwrap().der().clone();
        (
            vec![der],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
    }

    pub fn client_leaf(&self, spki: &[u8], role: &str) -> Vec<u8> {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.distinguished_name.push(DnType::CommonName, role);
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(1);
        params.not_after = now + time::Duration::minutes(5);
        let subject = rcgen::SubjectPublicKeyInfo::from_der(spki).unwrap();
        params
            .signed_by(&subject, &*self.issuer)
            .unwrap()
            .der()
            .to_vec()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Password(i32),
    Refuse(&'static str),
    Silent,
    NoTls,
    Greeting(usize),
}

#[derive(Debug, Clone, Default)]
pub struct Seen {
    pub connections: usize,
    pub handshakes: usize,
    pub startups: Vec<Vec<(String, String)>>,
    pub client_names: Vec<Option<String>>,
    pub messages: Vec<(u8, Vec<u8>)>,
    pub cancels: Vec<(i32, Vec<u8>)>,
    pub closed: usize,
    pub query_bytes: usize,
    pub copied: Vec<u8>,
}

struct Shared {
    seen: Mutex<Seen>,
    mode: Mutex<Mode>,
    config: Arc<ServerConfig>,
    changes: watch::Sender<u64>,
    key_bytes: usize,
}

impl Shared {
    fn record(&self, change: impl FnOnce(&mut Seen)) {
        change(&mut self.seen.lock().unwrap());
        self.changes.send_modify(|version| *version += 1);
    }
}

pub struct FakePg {
    pub address: String,
    shared: Arc<Shared>,
    task: JoinHandle<()>,
}

impl Drop for FakePg {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub struct FakePgOptions<'a> {
    pub server: &'a Authority,
    pub names: &'a [&'a str],
    pub clients: &'a Authority,
    pub tls12_only: bool,
    pub key_bytes: usize,
}

impl FakePg {
    pub async fn start(options: FakePgOptions<'_>) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(options.clients.roots()),
            provider.clone(),
        )
        .allow_unauthenticated()
        .build()
        .unwrap();
        let versions: &[&rustls::SupportedProtocolVersion] = if options.tls12_only {
            &[&TLS12]
        } else {
            &[&TLS13, &TLS12]
        };
        let (chain, key) = options.server.server_leaf(options.names);
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let shared = Arc::new(Shared {
            seen: Mutex::new(Seen::default()),
            mode: Mutex::new(Mode::Normal),
            config: Arc::new(config),
            changes: watch::Sender::new(0),
            key_bytes: options.key_bytes,
        });
        let accepting = shared.clone();
        let task = tokio::spawn(async move {
            let mut index = 0_usize;
            let mut sessions = tokio::task::JoinSet::new();
            while let Ok((tcp, _)) = listener.accept().await {
                index += 1;
                accepting.record(|seen| seen.connections += 1);
                sessions.spawn(serve(tcp, accepting.clone(), index));
            }
        });
        Self {
            address,
            shared,
            task,
        }
    }

    pub fn set_mode(&self, mode: Mode) {
        *self.shared.mode.lock().unwrap() = mode;
    }

    pub fn seen(&self) -> Seen {
        self.shared.seen.lock().unwrap().clone()
    }

    pub async fn wait(&self, what: &str, mut condition: impl FnMut(&Seen) -> bool) -> Seen {
        let mut changes = self.shared.changes.subscribe();
        crate::testkit::soon(what, async {
            loop {
                let seen = self.seen();
                if condition(&seen) {
                    return seen;
                }
                drop(changes.changed().await);
            }
        })
        .await
    }

    pub fn process_id(index: usize) -> i32 {
        4000 + i32::try_from(index).unwrap()
    }

    pub fn secret_key(&self, index: usize) -> Vec<u8> {
        (0..self.shared.key_bytes)
            .map(|offset| u8::try_from((index * 31 + offset) % 251).unwrap())
            .collect()
    }
}

pub fn message(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&u32::try_from(body.len() + 4).unwrap().to_be_bytes());
    out.extend_from_slice(body);
    out
}

pub fn cstr(text: &str) -> Vec<u8> {
    let mut out = text.as_bytes().to_vec();
    out.push(0);
    out
}

pub fn notice(severity: &str, code: &str, text: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for (field, value) in [
        (b'S', severity),
        (b'V', severity),
        (b'C', code),
        (b'M', text),
    ] {
        body.push(field);
        body.extend(cstr(value));
    }
    body.push(0);
    body
}

fn parameter(name: &str, value: &str) -> Vec<u8> {
    let mut body = cstr(name);
    body.extend(cstr(value));
    message(b'S', &body)
}

fn ready() -> Vec<u8> {
    message(b'Z', b"I")
}

fn complete(tag: &str) -> Vec<u8> {
    message(b'C', &cstr(tag))
}

async fn read_packet<S: AsyncRead + Unpin>(stream: &mut S) -> Option<Vec<u8>> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length).await.ok()?;
    let length = usize::try_from(u32::from_be_bytes(length)).ok()?;
    let mut body = vec![0_u8; length.checked_sub(4)?];
    stream.read_exact(&mut body).await.ok()?;
    Some(body)
}

fn client_name(tls: &TlsStream<TcpStream>) -> Option<String> {
    let der = tls.get_ref().1.peer_certificates()?.first()?.clone();
    let (_, certificate) = parse_x509_certificate(&der).ok()?;
    let name = certificate.subject().iter_common_name().next()?;
    name.as_str().ok().map(str::to_owned)
}

fn parameters(body: &[u8]) -> Vec<(String, String)> {
    let mut parts = body
        .split(|byte| *byte == 0)
        .map(|part| String::from_utf8_lossy(part).into_owned());
    let mut out = Vec::new();
    while let (Some(name), Some(value)) = (parts.next(), parts.next()) {
        if name.is_empty() {
            break;
        }
        out.push((name, value));
    }
    out
}

async fn serve(mut tcp: TcpStream, shared: Arc<Shared>, index: usize) {
    let mut head = [0_u8; 8];
    if tcp.read_exact(&mut head).await.is_err() || head != SSL_REQUEST {
        return;
    }
    let mode = *shared.mode.lock().unwrap();
    match mode {
        Mode::NoTls => {
            drop(tcp.write_all(b"N").await);
            return;
        }
        Mode::Silent => {
            let mut rest = Vec::new();
            drop(tcp.read_to_end(&mut rest).await);
            shared.record(|seen| seen.closed += 1);
            return;
        }
        Mode::Normal | Mode::Password(_) | Mode::Refuse(_) | Mode::Greeting(_) => {}
    }
    if tcp.write_all(b"S").await.is_err() {
        return;
    }
    let Ok(mut tls) = TlsAcceptor::from(shared.config.clone()).accept(tcp).await else {
        return;
    };
    shared.record(|seen| seen.handshakes += 1);
    let Some(packet) = read_packet(&mut tls).await else {
        return;
    };
    let code = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
    if code == CANCEL_CODE {
        let process_id = i32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        let key = packet[8..].to_vec();
        shared.record(|seen| seen.cancels.push((process_id, key)));
        return;
    }
    let startup = parameters(&packet[4..]);
    let name = client_name(&tls);
    let user = startup
        .iter()
        .find(|(key, _)| key == "user")
        .map(|(_, value)| value.clone());
    shared.record(|seen| {
        seen.startups.push(startup.clone());
        seen.client_names.push(name.clone());
    });
    let mut out = Vec::new();
    if name.is_none() || name != user {
        out.extend(message(
            b'E',
            &notice("FATAL", "28000", "certificate authentication failed"),
        ));
        drop(tls.write_all(&out).await);
        return;
    }
    match mode {
        Mode::Password(code) => {
            let mut body = code.to_be_bytes().to_vec();
            match code {
                5 => body.extend_from_slice(&[1, 2, 3, 4]),
                10 => body.extend_from_slice(b"SCRAM-SHA-256\0\0"),
                _ => {}
            }
            drop(tls.write_all(&message(b'R', &body)).await);
            let mut rest = Vec::new();
            drop(tls.read_to_end(&mut rest).await);
            return;
        }
        Mode::Refuse(code) => {
            out.extend(message(
                b'E',
                &notice(
                    "FATAL",
                    code,
                    "database \"main\" does not exist on 10.9.8.7",
                ),
            ));
            drop(tls.write_all(&out).await);
            return;
        }
        Mode::Normal | Mode::Silent | Mode::NoTls | Mode::Greeting(_) => {}
    }
    out.extend(message(b'R', &0_i32.to_be_bytes()));
    out.extend(parameter("server_version", "17.2"));
    out.extend(parameter("client_encoding", "UTF8"));
    let visible = out.len();
    out.extend(parameter("jaunt_internal_hint", "10.9.8.7"));
    let mut key = FakePg::process_id(index).to_be_bytes().to_vec();
    key.extend(
        (0..shared.key_bytes).map(|offset| u8::try_from((index * 31 + offset) % 251).unwrap()),
    );
    let key = message(b'K', &key);
    if let Mode::Greeting(target) = mode {
        let rest = visible + key.len() + ready().len();
        let mut body = b"SNOTICE\0VNOTICE\0C00000\0M".to_vec();
        body.resize(target - rest - 5 - 2, b'n');
        body.extend_from_slice(b"\0\0");
        out.extend(message(b'N', &body));
    }
    out.extend(key);
    out.extend(ready());
    if tls.write_all(&out).await.is_err() {
        return;
    }
    queries(&mut tls, &shared, index).await;
    shared.record(|seen| seen.closed += 1);
}

async fn read_message(tls: &mut TlsStream<TcpStream>, shared: &Shared) -> Option<(u8, Vec<u8>)> {
    let mut head = [0_u8; 5];
    tls.read_exact(&mut head).await.ok()?;
    let length = usize::try_from(u32::from_be_bytes([head[1], head[2], head[3], head[4]])).ok()?;
    let mut body = Vec::with_capacity(length.saturating_sub(4));
    let mut left = length.checked_sub(4)?;
    if head[0] == b'Q' {
        shared.record(|seen| seen.query_bytes = 0);
    }
    while left > 0 {
        let mut piece = vec![0_u8; left.min(READ_PIECE)];
        let read = tls.read(&mut piece).await.ok()?;
        if read == 0 {
            return None;
        }
        body.extend_from_slice(&piece[..read]);
        left -= read;
        if head[0] == b'Q' {
            shared.record(|seen| seen.query_bytes += read);
        }
    }
    shared.record(|seen| seen.messages.push((head[0], body.clone())));
    Some((head[0], body))
}

async fn queries(tls: &mut TlsStream<TcpStream>, shared: &Arc<Shared>, index: usize) {
    let mut skipping = false;
    let mut prepared: std::collections::HashMap<Vec<u8>, Vec<u8>> =
        std::collections::HashMap::new();
    let mut bound: Vec<u8> = Vec::new();
    while let Some((tag, body)) = read_message(tls, shared).await {
        let mut out = Vec::new();
        if skipping && tag != b'S' && tag != b'X' {
            continue;
        }
        match tag {
            b'Q' => {
                let text =
                    String::from_utf8_lossy(&body[..body.len().saturating_sub(1)]).into_owned();
                if text == "SELECT 1" {
                    let mut row = 1_u16.to_be_bytes().to_vec();
                    row.extend(1_u32.to_be_bytes());
                    row.push(b'1');
                    out.extend(message(b'D', &row));
                    out.extend(complete("SELECT 1"));
                } else if text.starts_with("FAIL") {
                    out.extend(message(
                        b'E',
                        &notice("ERROR", "42601", "syntax error at or near \"hunter2\""),
                    ));
                } else if text.starts_with("COPY t FROM STDIN") {
                    drop(tls.write_all(&message(b'G', &[0, 0, 0])).await);
                    let mut rows = 0;
                    while let Some((tag, body)) = read_message(tls, shared).await {
                        match tag {
                            b'd' => {
                                rows += 1;
                                shared.record(|seen| seen.copied.extend_from_slice(&body));
                            }
                            b'c' => break,
                            _ => return,
                        }
                    }
                    out.extend(complete(&format!("COPY {rows}")));
                } else if text.starts_with("COPY t TO STDOUT") {
                    out.extend(message(b'H', &[0, 0, 0]));
                    out.extend(message(b'd', b"a\n"));
                    out.extend(message(b'd', b"b\n"));
                    out.extend(message(b'c', &[]));
                    out.extend(complete("COPY 2"));
                } else if text == "SLEEP" {
                    let process_id = FakePg::process_id(index);
                    let mut changes = shared.changes.subscribe();
                    loop {
                        let cancelled = shared
                            .seen
                            .lock()
                            .unwrap()
                            .cancels
                            .iter()
                            .any(|(id, _)| *id == process_id);
                        if cancelled {
                            break;
                        }
                        if changes.changed().await.is_err() {
                            return;
                        }
                    }
                    out.extend(message(
                        b'E',
                        &notice("ERROR", "57014", "canceling statement due to user request"),
                    ));
                } else if text == "WRONG STATE" {
                    out.extend(message(b'R', &0_i32.to_be_bytes()));
                } else if text == "SEND K" {
                    out.extend(message(b'K', &[0, 0, 0, 9, 1, 2, 3, 4]));
                } else if text == "SEND v" {
                    out.extend(message(b'v', &[0, 3, 0, 0, 0, 0, 0, 0]));
                } else if text == "SET hint" {
                    out.extend(parameter("jaunt_internal_hint", "10.9.8.7"));
                    out.extend(parameter("application_name", "report"));
                    out.extend(complete("SET"));
                } else {
                    out.extend(complete("OK"));
                }
                out.extend(ready());
            }
            b'P' => {
                let mut parts = body.split(|byte| *byte == 0);
                let name = parts.next().unwrap_or_default().to_vec();
                let statement = parts.next().unwrap_or_default();
                if statement.starts_with(b"FAIL") {
                    skipping = true;
                    out.extend(message(
                        b'E',
                        &notice("ERROR", "42601", "syntax error at or near \"hunter2\""),
                    ));
                } else {
                    prepared.insert(name, statement.to_vec());
                    out.extend(message(b'1', &[]));
                }
            }
            b'B' => {
                let name = body.split(|byte| *byte == 0).nth(1).unwrap_or_default();
                match prepared.get(name) {
                    Some(statement) => {
                        bound = statement.clone();
                        out.extend(message(b'2', &[]));
                    }
                    None => {
                        skipping = true;
                        out.extend(message(
                            b'E',
                            &notice("ERROR", "26000", "prepared statement does not exist"),
                        ));
                    }
                }
            }
            b'C' => {
                if body.first() == Some(&b'S') {
                    let name = body[1..]
                        .split(|byte| *byte == 0)
                        .next()
                        .unwrap_or_default();
                    prepared.remove(name);
                }
                out.extend(message(b'3', &[]));
            }
            b'D' => out.extend(message(b'n', &[])),
            b'E' => {
                if bound.starts_with(b"EXECFAIL") {
                    skipping = true;
                    out.extend(message(
                        b'E',
                        &notice("ERROR", "42601", "syntax error at or near \"hunter2\""),
                    ));
                } else {
                    out.extend(complete("SELECT 0"));
                }
            }
            b'S' => {
                skipping = false;
                out.extend(ready());
            }
            b'X' => return,
            _ => {}
        }
        if !out.is_empty() && tls.write_all(&out).await.is_err() {
            return;
        }
    }
}
