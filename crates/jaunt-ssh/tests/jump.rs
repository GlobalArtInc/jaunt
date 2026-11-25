use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use jaunt_ssh::{
    EphemeralKey, HostAuthorities, JumpError, JumpRequest, TerminalDimensions, TerminalEvent,
    WebTerminal, open_terminal,
};
use russh::keys::key::safe_rng;
use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::keys::{Algorithm, Certificate, PrivateKey, PublicKey};
use russh::server::{self, Auth, ChannelOpenHandle, Msg, PublicKeyOffer};
use russh::{Channel, ChannelId, ChannelMsg};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

const NODE_HOST: &str = "web-01.jaunt.test";
const GATE_HOST: &str = "gate.jaunt.test";
const STEP: Duration = Duration::from_secs(20);
const FLOOD_PER_KIND: usize = 300;
const KINDS: usize = 7;

fn key() -> PrivateKey {
    PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn certificate(
    ca: &PrivateKey,
    subject: &PublicKey,
    cert_type: CertType,
    principal: &str,
    window: (u64, u64),
) -> Certificate {
    let mut builder = Builder::new_with_random_nonce(
        &mut safe_rng(),
        subject.key_data().clone(),
        window.0,
        window.1,
    )
    .unwrap();
    builder.serial(7).unwrap();
    builder.cert_type(cert_type).unwrap();
    builder.key_id("jaunt:alice@example.com:7").unwrap();
    builder.valid_principal(principal).unwrap();
    builder.sign(ca).unwrap()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presented {
    Certified,
    OtherName,
    OtherCa,
    Bare,
    Forged,
    Expired,
    NotYetValid,
}

struct Authorities {
    host_ca: PrivateKey,
    stranger_ca: PrivateKey,
    user_ca: PrivateKey,
}

impl Authorities {
    fn new() -> Authorities {
        Authorities {
            host_ca: key(),
            stranger_ca: key(),
            user_ca: key(),
        }
    }

    fn host(&self, presented: Presented, name: &str) -> Arc<server::Config> {
        let host_key = key();
        let public = host_key.public_key();
        let now = now();
        let valid = (now - 60, now + 3600);
        let certified = |ca: &PrivateKey, principal: &str, window: (u64, u64)| {
            Some(certificate(ca, public, CertType::Host, principal, window))
        };
        let presented = match presented {
            Presented::Certified => certified(&self.host_ca, name, valid),
            Presented::OtherName => certified(&self.host_ca, "db-01.jaunt.test", valid),
            Presented::OtherCa => certified(&self.stranger_ca, name, valid),
            Presented::Bare => None,
            Presented::Forged => certified(&self.host_ca, name, valid).map(|good| {
                let mut bytes = good.to_bytes().unwrap();
                let last = bytes.len() - 1;
                bytes[last] ^= 0x01;
                Certificate::from_bytes(&bytes).unwrap()
            }),
            Presented::Expired => certified(&self.host_ca, name, (now - 7200, now - 3600)),
            Presented::NotYetValid => certified(&self.host_ca, name, (now + 3600, now + 7200)),
        };
        Arc::new(server::Config {
            keys: vec![host_key],
            certificates: presented.into_iter().collect(),
            auth_rejection_time: Duration::from_millis(10),
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..server::Config::default()
        })
    }

    fn trusted(&self) -> HostAuthorities {
        HostAuthorities::from_openssh_lines([self.host_ca.public_key().to_openssh().unwrap()])
            .unwrap()
    }
}

#[derive(Clone, Default)]
struct Node {
    flood: Option<usize>,
    flooded: Arc<Mutex<Option<Flooded>>>,
}

impl server::Handler for Node {
    type Error = russh::Error;

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _offer: PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_openssh_certificate(
        &mut self,
        _user: &str,
        _certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if let Some(per_kind) = self.flood {
            let handle = session.handle();
            let flooded = Arc::clone(&self.flooded);
            tokio::spawn(async move {
                let outcome = flood(handle, per_kind).await;
                *flooded.lock().unwrap() = Some(outcome);
            });
        }
        session.channel_success(channel)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.data(channel, Bytes::copy_from_slice(data))
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Flooded {
    accepted: usize,
    refused: usize,
}

struct Gate {
    node: Arc<server::Config>,
    node_handler: Node,
    flood: Option<usize>,
    flooded: Arc<Mutex<Option<Flooded>>>,
    node_ended: Arc<AtomicBool>,
    stalled: Arc<AtomicBool>,
}

async fn flood(handle: server::Handle, per_kind: usize) -> Flooded {
    let mut opens: JoinSet<bool> = JoinSet::new();
    for _ in 0..per_kind {
        let each = handle.clone();
        opens.spawn(async move { each.channel_open_session().await.is_ok() });
        let each = handle.clone();
        opens.spawn(async move {
            each.channel_open_direct_tcpip("10.0.0.1", 22, "127.0.0.1", 1)
                .await
                .is_ok()
        });
        let each = handle.clone();
        opens.spawn(async move {
            each.channel_open_direct_streamlocal("/run/socket")
                .await
                .is_ok()
        });
        let each = handle.clone();
        opens.spawn(async move {
            each.channel_open_forwarded_tcpip("127.0.0.1", 8080, "10.0.0.2", 40_000)
                .await
                .is_ok()
        });
        let each = handle.clone();
        opens.spawn(async move {
            each.channel_open_forwarded_streamlocal("/run/forwarded")
                .await
                .is_ok()
        });
        let each = handle.clone();
        opens.spawn(async move { each.channel_open_x11("127.0.0.1", 6010).await.is_ok() });
        let each = handle.clone();
        opens.spawn(async move { each.channel_open_agent().await.is_ok() });
    }
    let mut flooded = Flooded::default();
    while let Some(opened) = opens.join_next().await {
        if opened.unwrap() {
            flooded.accepted += 1;
        } else {
            flooded.refused += 1;
        }
    }
    flooded
}

impl server::Handler for Gate {
    type Error = russh::Error;

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _offer: PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_openssh_certificate(
        &mut self,
        _user: &str,
        _certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let node = Arc::clone(&self.node);
        let node_handler = self.node_handler.clone();
        let per_kind = self.flood;
        let flooded = Arc::clone(&self.flooded);
        let handle = session.handle();
        let node_ended = Arc::clone(&self.node_ended);
        let stalled = Arc::clone(&self.stalled);
        tokio::spawn(async move {
            if let Some(per_kind) = per_kind {
                let outcome = flood(handle, per_kind).await;
                *flooded.lock().unwrap() = Some(outcome);
            }
            reply.accept().await;
            if let Ok(running) =
                server::run_stream(node, carried(channel, stalled), node_handler).await
            {
                drop(running.await);
            }
            node_ended.store(true, Ordering::SeqCst);
        });
        Ok(())
    }
}

fn carried(channel: Channel<Msg>, stalled: Arc<AtomicBool>) -> DuplexStream {
    let (near, far) = tokio::io::duplex(64 * 1024);
    let (mut from_node, mut to_node) = tokio::io::split(near);
    let (mut read, write) = channel.split();
    let (queue, mut queued) = mpsc::unbounded_channel::<Bytes>();
    tokio::spawn(async move {
        while let Some(message) = read.wait().await {
            if stalled.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            match message {
                ChannelMsg::Data { data } => {
                    if queue.send(data).is_err() {
                        return;
                    }
                }
                ChannelMsg::Eof | ChannelMsg::Close => return,
                _ => {}
            }
        }
    });
    tokio::spawn(async move {
        while let Some(data) = queued.recv().await {
            if to_node.write_all(&data).await.is_err() {
                return;
            }
        }
        drop(to_node.shutdown().await);
    });
    tokio::spawn(async move {
        let mut buffer = vec![0; 32 * 1024];
        loop {
            match from_node.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(got) => {
                    if write
                        .data_bytes(Bytes::copy_from_slice(&buffer[..got]))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
        drop(write.eof().await);
        drop(write.close().await);
    });
    far
}

struct Attempt {
    opened: Result<WebTerminal, JumpError>,
    flooded: Option<Flooded>,
    node_flooded: Arc<Mutex<Option<Flooded>>>,
    node_ended: Arc<AtomicBool>,
    stalled: Arc<AtomicBool>,
}

#[derive(Clone, Copy)]
struct Setup {
    gate: Presented,
    gate_name: &'static str,
    node: Presented,
    gate_flood: Option<usize>,
    node_flood: Option<usize>,
    node_window: Option<u32>,
}

impl Setup {
    fn presenting(gate: Presented, node: Presented) -> Setup {
        Setup {
            gate,
            gate_name: GATE_HOST,
            node,
            gate_flood: None,
            node_flood: None,
            node_window: None,
        }
    }
}

async fn attempt(gate: Presented, node: Presented, flood: Option<usize>) -> Attempt {
    attempt_with(Setup {
        gate_flood: flood,
        ..Setup::presenting(gate, node)
    })
    .await
}

async fn attempt_with(setup: Setup) -> Attempt {
    let authorities = Authorities::new();
    let gate_config = authorities.host(setup.gate, setup.gate_name);
    let mut node_config = authorities.host(setup.node, NODE_HOST);
    if let Some(window) = setup.node_window {
        Arc::get_mut(&mut node_config).unwrap().window_size = window;
    }
    let flooded = Arc::new(Mutex::new(None));
    let node_handler = Node {
        flood: setup.node_flood,
        flooded: Arc::new(Mutex::new(None)),
    };
    let node_flooded = Arc::clone(&node_handler.flooded);
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let node_ended = Arc::new(AtomicBool::new(false));
    let stalled = Arc::new(AtomicBool::new(false));
    let server = Gate {
        node: node_config,
        node_handler,
        flood: setup.gate_flood,
        flooded: Arc::clone(&flooded),
        node_ended: Arc::clone(&node_ended),
        stalled: Arc::clone(&stalled),
    };
    tokio::spawn(async move {
        if let Ok(running) = server::run_stream(gate_config, server_io, server).await {
            drop(running.await);
        }
    });
    let ephemeral = EphemeralKey::generate().unwrap();
    let subject = PublicKey::from_openssh(&ephemeral.public_openssh().unwrap()).unwrap();
    let now = now();
    let user_certificate = certificate(
        &authorities.user_ca,
        &subject,
        CertType::User,
        "67e55044-10b1-426f-9247-bb680e5fe0c8",
        (now - 120, now + 120),
    )
    .to_openssh()
    .unwrap();
    let trusted = authorities.trusted();
    let opened = tokio::time::timeout(
        STEP,
        open_terminal(
            client_io,
            ephemeral,
            JumpRequest {
                gate_host: GATE_HOST,
                node_host: NODE_HOST,
                login: "deploy",
                certificate: &user_certificate,
                authorities: &trusted,
                size: TerminalDimensions { cols: 80, rows: 24 },
                now_unix: now,
            },
        ),
    )
    .await
    .expect("the terminal did not open or fail in time");
    let flooded = *flooded.lock().unwrap();
    Attempt {
        opened,
        flooded,
        node_flooded,
        node_ended,
        stalled,
    }
}

async fn still_usable(terminal: WebTerminal) {
    let (input, mut output) = terminal.split();
    let window = output.window();
    input.send(Bytes::from_static(b"still here")).await.unwrap();
    let mut echoed = Vec::new();
    let deadline = tokio::time::Instant::now() + STEP;
    while !echoed.ends_with(b"still here") {
        let event = tokio::time::timeout_at(deadline, output.next())
            .await
            .expect("the terminal stopped answering");
        match event {
            Some(TerminalEvent::Output(data)) => {
                window.consumed(data.len());
                echoed.extend_from_slice(&data);
            }
            other => panic!("the terminal ended: {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_certified_gate_and_node_open_a_terminal() {
    let outcome = attempt(Presented::Certified, Presented::Certified, None).await;
    assert!(outcome.opened.is_ok(), "{:?}", outcome.opened.err());
}

#[tokio::test]
async fn a_gate_without_a_valid_certificate_from_the_host_authority_is_refused() {
    for presented in [
        Presented::OtherName,
        Presented::OtherCa,
        Presented::Bare,
        Presented::Forged,
        Presented::Expired,
        Presented::NotYetValid,
    ] {
        let outcome = attempt(presented, Presented::Certified, None).await;
        assert!(
            matches!(outcome.opened, Err(JumpError::GateHostKey)),
            "{presented:?}: {:?}",
            outcome.opened.err()
        );
    }
}

#[tokio::test]
async fn a_node_without_a_valid_certificate_for_its_own_name_is_refused() {
    for presented in [
        Presented::OtherName,
        Presented::OtherCa,
        Presented::Bare,
        Presented::Forged,
        Presented::Expired,
        Presented::NotYetValid,
    ] {
        let outcome = attempt(Presented::Certified, presented, None).await;
        assert!(
            matches!(outcome.opened, Err(JumpError::NodeHostKey)),
            "{presented:?}: {:?}",
            outcome.opened.err()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn channels_the_far_side_opens_toward_the_terminal_are_all_refused() {
    let outcome = attempt(
        Presented::Certified,
        Presented::Certified,
        Some(FLOOD_PER_KIND),
    )
    .await;
    assert_eq!(
        outcome.flooded,
        Some(Flooded {
            accepted: 0,
            refused: FLOOD_PER_KIND * KINDS,
        })
    );
    still_usable(outcome.opened.unwrap()).await;
}

#[tokio::test]
async fn a_node_certificate_presented_as_the_gate_is_refused() {
    let outcome = attempt_with(Setup {
        gate_name: NODE_HOST,
        ..Setup::presenting(Presented::Certified, Presented::Certified)
    })
    .await;
    assert!(
        matches!(outcome.opened, Err(JumpError::GateHostKey)),
        "{:?}",
        outcome.opened.err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn channels_the_node_opens_toward_the_terminal_are_all_refused() {
    let outcome = attempt_with(Setup {
        node_flood: Some(FLOOD_PER_KIND),
        ..Setup::presenting(Presented::Certified, Presented::Certified)
    })
    .await;
    assert!(outcome.opened.is_ok(), "{:?}", outcome.opened.err());
    let deadline = tokio::time::Instant::now() + STEP;
    loop {
        if let Some(flooded) = *outcome.node_flooded.lock().unwrap() {
            assert_eq!(
                flooded,
                Flooded {
                    accepted: 0,
                    refused: FLOOD_PER_KIND * KINDS,
                }
            );
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the node flood never finished"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    still_usable(outcome.opened.unwrap()).await;
}

#[tokio::test]
async fn dropping_the_terminal_ends_the_node_connection() {
    let outcome = attempt(Presented::Certified, Presented::Certified, None).await;
    let terminal = outcome.opened.unwrap();
    assert!(!outcome.node_ended.load(Ordering::SeqCst));
    drop(terminal);
    let deadline = tokio::time::Instant::now() + STEP;
    while !outcome.node_ended.load(Ordering::SeqCst) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the node connection outlived the terminal"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn input_waits_for_a_tunnel_that_stopped_moving_instead_of_piling_up() {
    let outcome = attempt_with(Setup {
        node_window: Some(64 << 20),
        ..Setup::presenting(Presented::Certified, Presented::Certified)
    })
    .await;
    let (input, _output) = outcome.opened.unwrap().split();
    outcome.stalled.store(true, Ordering::SeqCst);
    let frame = Bytes::from(vec![b'i'; 32 * 1024]);
    let mut sent = 0_usize;
    loop {
        match tokio::time::timeout(Duration::from_secs(1), input.send(frame.clone())).await {
            Ok(Ok(())) => sent += frame.len(),
            Ok(Err(gone)) => panic!("the terminal was cut after {sent} bytes: {gone}"),
            Err(_) => break,
        }
        assert!(sent < 64 << 20, "the input never waited");
    }
}
