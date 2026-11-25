mod inbox;
mod spool;

use std::borrow::Cow;
use std::fmt;
use std::sync::{Arc, Weak};

use bytes::Bytes;
use russh::client::{self, Handle};
use russh::keys::key::safe_rng;
use russh::keys::ssh_key::certificate::CertType;
use russh::keys::ssh_key::public::KeyData;
use russh::keys::{Algorithm, Certificate, PrivateKey, PublicKey, PublicKeyOrCertificate};
use russh::{Channel, ChannelId, ChannelOpenFailure, ChannelWriteHalf, Disconnect, Preferred};
use russh::{Sig, SshId};
use tokio::io::WriteHalf;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::cert::sha256_hex;
use crate::outer::TunnelStream;

use inbox::{Inbox, Peer, Window, read_node};
use spool::{Grants, Inlet, Spool, Tunnel, carry_down, carry_in};

pub const WEB_WINDOW: u32 = 256 * 1024;
const TUNNEL_WINDOW: u32 = 128 * 1024;
const MAX_PACKET: u32 = 32 * 1024;
const CHANNEL_BUFFER: usize = 2;
const REPLIES: usize = 2;
const GRANT_STEP: usize = 32 * 1024;
const CONTROL_SLACK: usize = 64 * 1024;
const UP_LIMIT: usize = 256 * 1024;
const INPUT_ADMIT: usize = 64 * 1024;
const CARRY_CHUNK: usize = 32 * 1024;
const CLIENT_ID: &str = "SSH-2.0-Jaunt-web";
const GATE_LOGIN: &str = "jaunt";
const TERM: &str = "xterm-256color";
const NODE_PORT: u32 = 22;
const ORIGINATOR: &str = "127.0.0.1";
const MAX_SIGNAL_NAME: usize = 32;
const HOST_KEY_ALGORITHMS: &[Algorithm] = &[Algorithm::Ed25519];
const UNKNOWN_SIGNAL: &str = "unknown";

pub struct EphemeralKey {
    key: Arc<PrivateKey>,
}

impl EphemeralKey {
    pub fn generate() -> Result<Self, JumpError> {
        let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519)
            .map_err(|_| JumpError::KeyGeneration)?;
        Ok(Self { key: Arc::new(key) })
    }

    pub fn public_openssh(&self) -> Result<String, JumpError> {
        self.key
            .public_key()
            .to_openssh()
            .map_err(|_| JumpError::KeyEncoding)
    }

    pub fn fingerprint(&self) -> String {
        sha256_hex(self.key.public_key().key_data())
    }

    #[cfg(feature = "test-support")]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let keypair = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(seed);
        Self {
            key: Arc::new(PrivateKey::from(keypair)),
        }
    }

    #[cfg(feature = "test-support")]
    pub fn watch(&self) -> KeyWatch {
        KeyWatch(Arc::downgrade(&self.key))
    }
}

impl fmt::Debug for EphemeralKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EphemeralKey")
            .field("fingerprint", &self.fingerprint())
            .field("private_key", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "test-support")]
pub struct KeyWatch(std::sync::Weak<PrivateKey>);

#[cfg(feature = "test-support")]
impl KeyWatch {
    pub fn released(&self) -> bool {
        self.0.strong_count() == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAuthorities {
    keys: Vec<KeyData>,
}

impl HostAuthorities {
    pub fn from_openssh_lines<I, S>(lines: I) -> Result<Self, JumpError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut keys = Vec::new();
        for line in lines {
            let key = PublicKey::from_openssh(line.as_ref().trim())
                .map_err(|_| JumpError::HostAuthority)?;
            if key.algorithm() != Algorithm::Ed25519 {
                return Err(JumpError::HostAuthority);
            }
            keys.push(key.key_data().clone());
        }
        if keys.is_empty() {
            return Err(JumpError::NoHostAuthority);
        }
        Ok(Self { keys })
    }

    fn trusts(&self, signer: &KeyData) -> bool {
        self.keys.iter().any(|key| key == signer)
    }
}

pub(crate) fn host_is_certified(
    presented: &PublicKeyOrCertificate,
    authorities: &HostAuthorities,
    principal: Option<&str>,
    now_unix: u64,
) -> bool {
    let PublicKeyOrCertificate::Certificate(certificate) = presented else {
        return false;
    };
    certificate.cert_type() == CertType::Host
        && authorities.trusts(certificate.signature_key())
        && certificate.verify_signature().is_ok()
        && now_unix >= certificate.valid_after()
        && now_unix < certificate.valid_before()
        && principal.is_none_or(|name| {
            certificate
                .valid_principals()
                .iter()
                .any(|listed| listed == name)
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalDimensions {
    pub cols: u32,
    pub rows: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JumpHop {
    Gate,
    Node,
}

impl fmt::Display for JumpHop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Gate => "gate",
            Self::Node => "node",
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JumpError {
    #[error("the ephemeral key could not be generated")]
    KeyGeneration,
    #[error("the ephemeral key could not be encoded")]
    KeyEncoding,
    #[error("the user certificate is not an OpenSSH certificate")]
    Certificate,
    #[error("a host CA key is not an Ed25519 OpenSSH public key")]
    HostAuthority,
    #[error("no host CA key is trusted")]
    NoHostAuthority,
    #[error("the gate presented a host key that no trusted host CA certified")]
    GateHostKey,
    #[error("the gate refused the user certificate")]
    GateRefused,
    #[error("the gate refused to reach the node")]
    ForwardRefused,
    #[error("the node presented a host key that is not certified for its name")]
    NodeHostKey,
    #[error("the node refused the login")]
    NodeRefused,
    #[error("the node refused the terminal")]
    TerminalRefused,
    #[error("the node broke the ssh flow control")]
    NodeViolation,
    #[error("the ssh exchange with the {hop} failed")]
    Protocol {
        hop: JumpHop,
        #[source]
        source: russh::Error,
    },
}

impl JumpError {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::KeyGeneration => "key_generation",
            Self::KeyEncoding => "key_encoding",
            Self::Certificate => "certificate",
            Self::HostAuthority => "host_authority",
            Self::NoHostAuthority => "no_host_authority",
            Self::GateHostKey => "gate_host_key",
            Self::GateRefused => "gate_refused",
            Self::ForwardRefused => "forward_refused",
            Self::NodeHostKey => "node_host_key",
            Self::NodeRefused => "node_refused",
            Self::TerminalRefused => "terminal_refused",
            Self::NodeViolation => "node_violation",
            Self::Protocol { .. } => "protocol",
        }
    }
}

pub struct JumpRequest<'a> {
    pub gate_host: &'a str,
    pub node_host: &'a str,
    pub login: &'a str,
    pub certificate: &'a str,
    pub authorities: &'a HostAuthorities,
    pub size: TerminalDimensions,
    pub now_unix: u64,
}

struct HostCheck {
    authorities: HostAuthorities,
    principal: Option<String>,
    now_unix: u64,
}

async fn refuse(reply: client::ChannelOpenHandle) -> Result<(), russh::Error> {
    reply
        .reject(ChannelOpenFailure::AdministrativelyProhibited)
        .await;
    Ok(())
}

impl client::Handler for HostCheck {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(host_is_certified(
            key,
            &self.authorities,
            self.principal.as_deref(),
            self.now_unix,
        ))
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<client::Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        refuse(reply).await
    }

    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        _channel: Channel<client::Msg>,
        _socket_path: &str,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        refuse(reply).await
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        _channel: Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        refuse(reply).await
    }

    async fn should_accept_unknown_server_channel(
        &mut self,
        _id: ChannelId,
        _channel_type: &str,
    ) -> bool {
        false
    }

    async fn server_channel_open_unknown(
        &mut self,
        _channel: Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        refuse(reply).await
    }

    async fn server_channel_open_session(
        &mut self,
        _channel: Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        refuse(reply).await
    }

    async fn server_channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<client::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        refuse(reply).await
    }

    async fn server_channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<client::Msg>,
        _socket_path: &str,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        refuse(reply).await
    }

    async fn server_channel_open_x11(
        &mut self,
        _channel: Channel<client::Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        refuse(reply).await
    }
}

fn client_config(window_size: u32) -> client::Config {
    client::Config {
        client_id: SshId::Standard(Cow::Borrowed(CLIENT_ID)),
        window_size,
        maximum_packet_size: MAX_PACKET,
        manual_window: true,
        channel_buffer_size: CHANNEL_BUFFER,
        preferred: Preferred {
            key: Cow::Borrowed(HOST_KEY_ALGORITHMS),
            host_key_certificates: Cow::Borrowed(HOST_KEY_ALGORITHMS),
            ..Preferred::DEFAULT
        },
        inactivity_timeout: None,
        nodelay: true,
        ..client::Config::default()
    }
}

fn protocol(hop: JumpHop) -> impl FnOnce(russh::Error) -> JumpError {
    move |source| JumpError::Protocol { hop, source }
}

fn handshake(hop: JumpHop) -> impl FnOnce(russh::Error) -> JumpError {
    move |source| match (source, hop) {
        (russh::Error::UnknownKey, JumpHop::Gate) => JumpError::GateHostKey,
        (russh::Error::UnknownKey, JumpHop::Node) => JumpError::NodeHostKey,
        (source, hop) => JumpError::Protocol { hop, source },
    }
}

pub async fn open_terminal<S: TunnelStream>(
    gate: S,
    key: EphemeralKey,
    request: JumpRequest<'_>,
) -> Result<WebTerminal, JumpError> {
    let certificate = Certificate::from_openssh(request.certificate.trim())
        .map_err(|_| JumpError::Certificate)?;
    let check = |principal: Option<&str>| HostCheck {
        authorities: request.authorities.clone(),
        principal: principal.map(str::to_owned),
        now_unix: request.now_unix,
    };
    let mut carriers = Carriers::default();
    let inlet = carriers.inlet(gate);
    let mut outer = client::connect_stream(
        Arc::new(client_config(TUNNEL_WINDOW)),
        inlet,
        check(Some(request.gate_host)),
    )
    .await
    .map_err(handshake(JumpHop::Gate))?;
    let accepted = outer
        .authenticate_openssh_cert(GATE_LOGIN, Arc::clone(&key.key), certificate.clone())
        .await
        .map_err(protocol(JumpHop::Gate))?;
    if !accepted.success() {
        return Err(JumpError::GateRefused);
    }
    let tunnel = outer
        .channel_open_direct_tcpip(request.node_host, NODE_PORT, ORIGINATOR, 0)
        .await
        .map_err(|error| match error {
            russh::Error::ChannelOpenFailure(_) => JumpError::ForwardRefused,
            other => JumpError::Protocol {
                hop: JumpHop::Gate,
                source: other,
            },
        })?;
    let outer = Arc::new(outer);
    let (stream, up) = carriers.tunnel(tunnel, &outer);
    let mut inner = client::connect_stream(
        Arc::new(client_config(WEB_WINDOW)),
        stream,
        check(Some(request.node_host)),
    )
    .await
    .map_err(handshake(JumpHop::Node))?;
    let accepted = inner
        .authenticate_openssh_cert(request.login, Arc::clone(&key.key), certificate)
        .await
        .map_err(protocol(JumpHop::Node))?;
    drop(key);
    if !accepted.success() {
        return Err(JumpError::NodeRefused);
    }
    let channel = inner
        .channel_open_session()
        .await
        .map_err(|error| match error {
            russh::Error::ChannelOpenFailure(_) => JumpError::TerminalRefused,
            other => JumpError::Protocol {
                hop: JumpHop::Node,
                source: other,
            },
        })?;
    let id = channel.id();
    let (read, write) = channel.split();
    let link = Arc::new(Link {
        outer,
        inner,
        _carriers: carriers,
    });
    let inbox = Arc::new(Inbox::default());
    let window = Arc::new(Window::new(WEB_WINDOW));
    let (answers, mut replies) = mpsc::channel(REPLIES);
    let reader = Task(tokio::spawn({
        let peer = NodeLink {
            link: Arc::clone(&link),
            channel: id,
        };
        let inbox = Arc::clone(&inbox);
        let window = Arc::clone(&window);
        async move { read_node(read, peer, &inbox, &window, answers).await }
    }));
    write
        .request_pty(true, TERM, request.size.cols, request.size.rows, 0, 0, &[])
        .await
        .map_err(protocol(JumpHop::Node))?;
    reply(&mut replies, &inbox).await?;
    write
        .request_shell(true)
        .await
        .map_err(protocol(JumpHop::Node))?;
    reply(&mut replies, &inbox).await?;
    Ok(WebTerminal {
        input: TerminalInput {
            write,
            up,
            link: Arc::clone(&link),
        },
        output: TerminalOutput {
            inbox,
            grant: WindowGrant {
                link,
                channel: id,
                window,
            },
            _reader: reader,
        },
    })
}

async fn reply(replies: &mut mpsc::Receiver<bool>, inbox: &Inbox) -> Result<(), JumpError> {
    match replies.recv().await {
        Some(true) => Ok(()),
        Some(false) => Err(JumpError::TerminalRefused),
        None if inbox.violated() => Err(JumpError::NodeViolation),
        None => Err(JumpError::TerminalRefused),
    }
}

struct Task(JoinHandle<()>);

impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct OuterGrants {
    outer: Weak<Handle<HostCheck>>,
    channel: ChannelId,
}

impl Grants for OuterGrants {
    fn grant(&self, bytes: u32) {
        let Some(outer) = self.outer.upgrade() else {
            return;
        };
        if outer.grant_window(self.channel, bytes).is_err() {
            tracing::debug!(target: "jaunt::web", "a tunnel window grant found the gate connection gone");
        }
    }
}

#[derive(Default)]
struct Carriers(Vec<Task>);

impl Carriers {
    fn inlet<S: TunnelStream>(&mut self, gate: S) -> Inlet<WriteHalf<S>> {
        let (read, write) = tokio::io::split(gate);
        let spool = Arc::new(Spool::new(
            usize::try_from(TUNNEL_WINDOW)
                .unwrap_or(usize::MAX)
                .saturating_add(CONTROL_SLACK),
        ));
        self.0.push(Task(tokio::spawn(carry_in(
            read,
            Arc::clone(&spool),
            CARRY_CHUNK,
        ))));
        Inlet::new(spool, write)
    }

    fn tunnel(
        &mut self,
        channel: Channel<client::Msg>,
        outer: &Arc<Handle<HostCheck>>,
    ) -> (Tunnel<OuterGrants>, Arc<Spool>) {
        let id = channel.id();
        let (read, write) = channel.split();
        let down = Arc::new(Spool::new(
            usize::try_from(TUNNEL_WINDOW).unwrap_or(usize::MAX),
        ));
        let up = Arc::new(Spool::new(UP_LIMIT));
        let window = Arc::new(Window::new(TUNNEL_WINDOW));
        self.0.push(Task(tokio::spawn(carry_down(
            read,
            Arc::clone(&down),
            Arc::clone(&window),
        ))));
        self.0
            .push(Task(tokio::spawn(carry_up(Arc::clone(&up), write))));
        let grants = OuterGrants {
            outer: Arc::downgrade(outer),
            channel: id,
        };
        (
            Tunnel::new(down, Arc::clone(&up), window, grants, GRANT_STEP),
            up,
        )
    }
}

async fn carry_up(up: Arc<Spool>, tunnel: ChannelWriteHalf<client::Msg>) {
    loop {
        match up.take(CARRY_CHUNK).await {
            Ok(Some(chunk)) => {
                if tunnel.data_bytes(chunk).await.is_err() {
                    up.break_off();
                    return;
                }
            }
            Ok(None) => {
                if tunnel.eof().await.is_err() {
                    tracing::debug!(target: "jaunt::web", "the tunnel of a web terminal was gone before its end");
                }
                return;
            }
            Err(_) => {
                if tunnel.close().await.is_err() {
                    tracing::debug!(target: "jaunt::web", "the tunnel of a web terminal was gone before it was cut");
                }
                return;
            }
        }
    }
}

struct NodeLink {
    link: Arc<Link>,
    channel: ChannelId,
}

impl Peer for NodeLink {
    fn grant(&self, bytes: usize) {
        self.link.grant(self.channel, bytes);
    }

    async fn cut(&self) {
        self.link.cut().await;
    }
}

struct Link {
    outer: Arc<Handle<HostCheck>>,
    inner: Handle<HostCheck>,
    _carriers: Carriers,
}

impl Link {
    fn grant(&self, channel: ChannelId, bytes: usize) {
        let Ok(bytes) = u32::try_from(bytes) else {
            return;
        };
        if bytes > 0 && self.inner.grant_window(channel, bytes).is_err() {
            tracing::debug!(target: "jaunt::web", "a window grant found the node connection gone");
        }
    }

    async fn cut(&self) {
        self.close(|| Disconnect::ProtocolError).await;
    }

    async fn disconnect(&self) {
        self.close(|| Disconnect::ByApplication).await;
    }

    async fn close(&self, reason: impl Fn() -> Disconnect) {
        for handle in [&self.inner, &*self.outer] {
            if handle.disconnect(reason(), "", "en").await.is_err() {
                tracing::debug!(target: "jaunt::web", "an ssh connection of a web terminal was already gone");
            }
        }
    }
}

pub struct WebTerminal {
    input: TerminalInput,
    output: TerminalOutput,
}

impl WebTerminal {
    pub fn split(self) -> (TerminalInput, TerminalOutput) {
        (self.input, self.output)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the terminal connection is gone")]
pub struct TerminalGone;

pub struct TerminalInput {
    write: ChannelWriteHalf<client::Msg>,
    up: Arc<Spool>,
    link: Arc<Link>,
}

impl TerminalInput {
    pub async fn send(&self, data: Bytes) -> Result<(), TerminalGone> {
        if data.is_empty() {
            return Ok(());
        }
        let length = u64::try_from(data.len()).unwrap_or(u64::MAX);
        self.up
            .drained_to(INPUT_ADMIT)
            .await
            .map_err(|_| TerminalGone)?;
        let mark = self.up.written();
        self.write
            .data_bytes(data)
            .await
            .map_err(|_| TerminalGone)?;
        self.up
            .written_up_to(mark.saturating_add(length))
            .await
            .map_err(|_| TerminalGone)
    }

    pub async fn resize(&self, size: TerminalDimensions) -> Result<(), TerminalGone> {
        self.write
            .window_change(size.cols, size.rows, 0, 0)
            .await
            .map_err(|_| TerminalGone)
    }

    pub async fn disconnect(&self) {
        self.link.disconnect().await;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalExit {
    Status(u32),
    Signal(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalEvent {
    Output(Bytes),
    Exit(TerminalExit),
}

#[derive(Clone)]
pub struct WindowGrant {
    link: Arc<Link>,
    channel: ChannelId,
    window: Arc<Window>,
}

impl WindowGrant {
    pub fn consumed(&self, bytes: usize) {
        self.window.grant(bytes);
        self.link.grant(self.channel, bytes);
    }

    pub fn kept(&self) -> u64 {
        self.window.kept()
    }
}

pub struct TerminalOutput {
    inbox: Arc<Inbox>,
    grant: WindowGrant,
    _reader: Task,
}

impl TerminalOutput {
    pub fn window(&self) -> WindowGrant {
        self.grant.clone()
    }

    pub fn violated(&self) -> bool {
        self.inbox.violated()
    }

    pub async fn next(&mut self) -> Option<TerminalEvent> {
        self.inbox.next().await
    }
}

pub(crate) fn signal_text(signal: &Sig) -> String {
    let name = match signal {
        Sig::ABRT => "ABRT",
        Sig::ALRM => "ALRM",
        Sig::FPE => "FPE",
        Sig::HUP => "HUP",
        Sig::ILL => "ILL",
        Sig::INT => "INT",
        Sig::KILL => "KILL",
        Sig::PIPE => "PIPE",
        Sig::QUIT => "QUIT",
        Sig::SEGV => "SEGV",
        Sig::TERM => "TERM",
        Sig::USR1 => "USR1",
        Sig::Custom(name) => {
            let plain = !name.is_empty()
                && name.len() <= MAX_SIGNAL_NAME
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit());
            if plain { name.as_str() } else { UNKNOWN_SIGNAL }
        }
    };
    name.to_owned()
}

#[cfg(test)]
mod tests {
    use russh::Sig;
    use russh::keys::ssh_key::certificate::{Builder, CertType};
    use russh::keys::{Algorithm, Certificate, PrivateKey, PublicKeyOrCertificate};

    use super::{
        CHANNEL_BUFFER, CONTROL_SLACK, EphemeralKey, GRANT_STEP, HostAuthorities, INPUT_ADMIT,
        JumpError, MAX_PACKET, TUNNEL_WINDOW, UP_LIMIT, WEB_WINDOW, client_config,
        host_is_certified, signal_text,
    };
    use crate::test_support::{NOW, key, rng};

    fn host_certificate(
        ca: &PrivateKey,
        subject: &PrivateKey,
        cert_type: CertType,
        principals: &[&str],
    ) -> Certificate {
        let mut builder = Builder::new_with_random_nonce(
            &mut rng(),
            subject.public_key().key_data().clone(),
            NOW - 60,
            NOW + 60,
        )
        .unwrap();
        builder.serial(1).unwrap();
        builder.cert_type(cert_type).unwrap();
        builder.key_id("jaunt-host:web-01.jaunt.test:1").unwrap();
        for principal in principals {
            builder.valid_principal(*principal).unwrap();
        }
        builder.sign(ca).unwrap()
    }

    fn authorities(ca: &PrivateKey) -> HostAuthorities {
        HostAuthorities::from_openssh_lines([ca.public_key().to_openssh().unwrap()]).unwrap()
    }

    #[test]
    fn a_node_must_present_a_host_certificate_for_its_name_from_a_trusted_authority() {
        let ca = key(Algorithm::Ed25519);
        let other = key(Algorithm::Ed25519);
        let subject = key(Algorithm::Ed25519);
        let trusted = authorities(&ca);
        let presented = |certificate| PublicKeyOrCertificate::Certificate(certificate);
        let good = host_certificate(&ca, &subject, CertType::Host, &["web-01.jaunt.test"]);
        let forged = {
            let mut bytes = good.to_bytes().unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 0x01;
            Certificate::from_bytes(&bytes).unwrap()
        };
        assert_eq!(forged.signature_key(), good.signature_key());
        let cases = [
            ("certified", presented(good.clone()), NOW, true),
            ("forged signature", presented(forged), NOW, false),
            ("expired", presented(good.clone()), NOW + 60, false),
            ("not yet valid", presented(good.clone()), NOW - 61, false),
            (
                "another name",
                presented(host_certificate(
                    &ca,
                    &subject,
                    CertType::Host,
                    &["db-01.jaunt.test"],
                )),
                NOW,
                false,
            ),
            (
                "untrusted authority",
                presented(host_certificate(
                    &other,
                    &subject,
                    CertType::Host,
                    &["web-01.jaunt.test"],
                )),
                NOW,
                false,
            ),
            (
                "user certificate",
                presented(host_certificate(
                    &ca,
                    &subject,
                    CertType::User,
                    &["web-01.jaunt.test"],
                )),
                NOW,
                false,
            ),
            (
                "bare key",
                PublicKeyOrCertificate::PublicKey {
                    key: subject.public_key().clone(),
                    hash_alg: None,
                },
                NOW,
                false,
            ),
        ];
        for (name, presented, now, accepted) in cases {
            assert_eq!(
                host_is_certified(&presented, &trusted, Some("web-01.jaunt.test"), now),
                accepted,
                "{name}"
            );
        }
        assert!(host_is_certified(
            &PublicKeyOrCertificate::Certificate(good),
            &trusted,
            None,
            NOW
        ));
    }

    #[test]
    fn every_listed_authority_is_trusted_during_a_rotation_and_a_retired_one_is_not() {
        let current = key(Algorithm::Ed25519);
        let next = key(Algorithm::Ed25519);
        let retired = key(Algorithm::Ed25519);
        let subject = key(Algorithm::Ed25519);
        let during_rotation = HostAuthorities::from_openssh_lines([
            current.public_key().to_openssh().unwrap(),
            next.public_key().to_openssh().unwrap(),
        ])
        .unwrap();
        for (ca, trusted) in [(&current, true), (&next, true), (&retired, false)] {
            let presented = PublicKeyOrCertificate::Certificate(host_certificate(
                ca,
                &subject,
                CertType::Host,
                &["web-01.jaunt.test"],
            ));
            assert_eq!(
                host_is_certified(&presented, &during_rotation, Some("web-01.jaunt.test"), NOW),
                trusted
            );
        }
    }

    #[test]
    fn only_the_exact_host_name_is_a_matching_principal() {
        let ca = key(Algorithm::Ed25519);
        let subject = key(Algorithm::Ed25519);
        let trusted = authorities(&ca);
        for (principal, accepted) in [
            ("web-01.jaunt.test", true),
            ("*.jaunt.test", false),
            ("WEB-01.jaunt.test", false),
            ("web-01.JAUNT.TEST", false),
            ("web-01.jaunt.test.", false),
            ("web-01@jaunt.test", false),
            ("deploy@web-01.jaunt.test", false),
            ("web-01", false),
            ("web-01.jaunt.test.evil.example", false),
            ("", false),
        ] {
            let presented = PublicKeyOrCertificate::Certificate(host_certificate(
                &ca,
                &subject,
                CertType::Host,
                &[principal],
            ));
            assert_eq!(
                host_is_certified(&presented, &trusted, Some("web-01.jaunt.test"), NOW),
                accepted,
                "{principal:?}"
            );
        }
    }

    #[test]
    fn host_authorities_are_ed25519_keys_and_at_least_one() {
        assert!(matches!(
            HostAuthorities::from_openssh_lines(Vec::<String>::new()),
            Err(JumpError::NoHostAuthority)
        ));
        assert!(matches!(
            HostAuthorities::from_openssh_lines(["ssh-ed25519 AAAA"]),
            Err(JumpError::HostAuthority)
        ));
        let ecdsa = key(Algorithm::Ecdsa {
            curve: russh::keys::EcdsaCurve::NistP256,
        });
        assert!(matches!(
            HostAuthorities::from_openssh_lines([ecdsa.public_key().to_openssh().unwrap()]),
            Err(JumpError::HostAuthority)
        ));
    }

    #[test]
    fn the_ephemeral_key_is_redacted_in_debug_output() {
        let generated = EphemeralKey::generate().unwrap();
        let text = format!("{generated:?}");
        assert!(text.contains("<redacted>"));
        assert!(text.contains(&generated.fingerprint()));
        let private = generated
            .key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap();
        let body: String = private
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        assert!(!text.contains(&body));
        assert!(!text.contains("PRIVATE"));
        assert_eq!(generated.key.public_key().algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn only_plain_signal_names_from_the_node_reach_the_browser() {
        for (signal, expected) in [
            (Sig::TERM, "TERM"),
            (Sig::KILL, "KILL"),
            (Sig::Custom("WINCH".to_owned()), "WINCH"),
            (Sig::Custom("RTMIN1".to_owned()), "RTMIN1"),
            (Sig::Custom(String::new()), "unknown"),
            (Sig::Custom("\u{1b}[2J".to_owned()), "unknown"),
            (Sig::Custom("term".to_owned()), "unknown"),
            (Sig::Custom("A".repeat(33)), "unknown"),
            (Sig::Custom("\"}".to_owned()), "unknown"),
        ] {
            assert_eq!(signal_text(&signal), expected, "{signal:?}");
        }
    }

    #[test]
    fn both_connections_give_window_only_by_hand_and_want_host_certificates() {
        for (window, connection) in [
            (WEB_WINDOW, client_config(WEB_WINDOW)),
            (TUNNEL_WINDOW, client_config(TUNNEL_WINDOW)),
        ] {
            assert!(connection.manual_window);
            assert_eq!(connection.window_size, window);
            assert_eq!(connection.maximum_packet_size, 32 * 1024);
            assert_eq!(connection.channel_buffer_size, CHANNEL_BUFFER);
            assert_eq!(connection.preferred.key.as_ref(), [Algorithm::Ed25519]);
            assert_eq!(
                connection.preferred.host_key_certificates.as_ref(),
                [Algorithm::Ed25519]
            );
        }
    }

    #[test]
    fn the_buffers_one_terminal_can_be_made_to_hold_stay_within_the_budget() {
        const BUDGET: usize = 1280 * 1024;
        const LARGEST_SSH_PACKET: usize = 256 * 1024;
        let node_output =
            usize::try_from(WEB_WINDOW).unwrap() + CHANNEL_BUFFER * LARGEST_SSH_PACKET;
        let tunnel = usize::try_from(TUNNEL_WINDOW).unwrap() + CONTROL_SLACK;
        assert!(node_output + tunnel + UP_LIMIT <= BUDGET);
        assert!(INPUT_ADMIT + 2 * usize::try_from(MAX_PACKET).unwrap() < UP_LIMIT);
        assert!(GRANT_STEP < usize::try_from(TUNNEL_WINDOW).unwrap());
    }

    #[test]
    fn the_refusal_reasons_written_to_the_audit_log_are_stable() {
        assert_eq!(JumpError::GateHostKey.reason(), "gate_host_key");
        assert_eq!(JumpError::NodeHostKey.reason(), "node_host_key");
        assert_eq!(JumpError::NodeViolation.reason(), "node_violation");
    }
}
