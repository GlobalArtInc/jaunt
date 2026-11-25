use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use jaunt_ca::ssh_key::PublicKey as CaPublicKey;
use jaunt_ca::{UserCertParams, Uuid, fingerprint_hex, sign_user_certificate};
use jaunt_control::{RevokeRequest, Revoked};
use jaunt_gate::DEFAULT_SSH_CLIENT_LIMITS;
use jaunt_proto::{
    AuthorizeDecision, AuthorizeRequest, ControlPlane, NodeCaller, SessionEnd, SessionEndOutcome,
};
use jaunt_ssh::{UserCaKeys, UserCaSource, verify_user_certificate};
use jaunt_store::{NewCertificate, NewUser, RevocationKind, Session, SessionEndReason};
use jaunt_tunnel::{BoxFuture, IncomingStream, NodeId, StreamHandler};
use jauntd::gate_ssh::{GateSshParts, GateSshServer, GateSshSettings, HostAuthorityIssuer};
use jauntd::killer::InProcessKiller;
use jauntd::presence::RegistryPresence;
use russh::keys::key::safe_rng;
use russh::keys::{Algorithm, Certificate, PrivateKey, PublicKeyOrCertificate};
use russh::server::{self, Auth, ChannelOpenHandle, Msg, PublicKeyOffer};
use russh::{Channel, ChannelId, ChannelMsg, client};
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use tokio::net::TcpStream;

use crate::support::{
    EnrolledAgent, Harness, Options, TestAgent, eventually, spawn_agent_with, unix_secs, within,
};

pub const SUFFIX: &str = "jaunt.test";
pub const LOGIN: &str = "deploy";
const GATE_NAME: &str = "gate.jaunt.test";
const EMAIL: &str = "alice@example.com";
const ROLE: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: ops }\nspec:\n  \
    members: { users: [alice@example.com] }\n  ssh: { nodes: { env: [test] }, logins: [deploy] }\n";
const ADMIN_ROLE: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: admins }\nspec:\n  \
    members: { users: [alice@example.com] }\n  admin: [nodes.approve]\n";

#[derive(Default)]
pub struct AgentLog {
    authorized: Mutex<Vec<String>>,
    ends: Mutex<Vec<(String, SessionEndOutcome)>>,
    silent: AtomicBool,
}

impl AgentLog {
    pub fn fall_silent(&self) {
        self.silent.store(true, Ordering::SeqCst);
    }

    pub fn last_authorized(&self) -> String {
        self.authorized.lock().unwrap().last().cloned().unwrap()
    }

    pub fn ends_of(&self, session_id: &str) -> Vec<SessionEndOutcome> {
        self.ends
            .lock()
            .unwrap()
            .iter()
            .filter(|(id, _)| id == session_id)
            .map(|(_, outcome)| *outcome)
            .collect()
    }
}

struct SessionAgent {
    node_id: String,
    control: Arc<dyn ControlPlane>,
    cas: Arc<UserCaSource>,
    config: Arc<server::Config>,
    log: Arc<AgentLog>,
}

impl StreamHandler for SessionAgent {
    fn handle(&self, stream: IncomingStream) -> BoxFuture<'static, ()> {
        let session_id = stream.meta.session().as_str().to_owned();
        let authorized = Arc::new(AtomicBool::new(false));
        let handler = AgentSession {
            node_id: self.node_id.clone(),
            session_id: session_id.clone(),
            client_addr: stream.meta.client().to_owned(),
            control: Arc::clone(&self.control),
            cas: Arc::clone(&self.cas),
            log: Arc::clone(&self.log),
            authorized: Arc::clone(&authorized),
            channels: HashMap::new(),
        };
        let config = Arc::clone(&self.config);
        let control = Arc::clone(&self.control);
        let log = Arc::clone(&self.log);
        let node_id = self.node_id.clone();
        Box::pin(async move {
            if let Ok(running) = server::run_stream(config, stream.io, handler).await {
                let _ = running.await;
            }
            if !authorized.load(Ordering::SeqCst) || log.silent.load(Ordering::SeqCst) {
                return;
            }
            let outcome = control
                .session_end(
                    NodeCaller(node_id),
                    SessionEnd {
                        session_id: session_id.clone(),
                        exit_status: None,
                        bytes_in: 0,
                        bytes_out: 0,
                        recording_incomplete: false,
                    },
                )
                .await
                .unwrap();
            log.ends.lock().unwrap().push((session_id, outcome));
        })
    }
}

struct AgentSession {
    node_id: String,
    session_id: String,
    client_addr: String,
    control: Arc<dyn ControlPlane>,
    cas: Arc<UserCaSource>,
    log: Arc<AgentLog>,
    authorized: Arc<AtomicBool>,
    channels: HashMap<ChannelId, Channel<Msg>>,
}

impl server::Handler for AgentSession {
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
        user: &str,
        certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        let now = unix_secs(SystemTime::now());
        let Ok(identity) = verify_user_certificate(certificate, &self.cas.current(), now) else {
            return Ok(Auth::reject());
        };
        let decision = self
            .control
            .authorize(
                NodeCaller(self.node_id.clone()),
                AuthorizeRequest {
                    session_id: self.session_id.clone(),
                    user_id: identity.user_id,
                    serial: identity.serial,
                    key_id: identity.key_id,
                    login: user.to_owned(),
                    client_addr: self.client_addr.clone(),
                    subject_fingerprint: Some(identity.subject_fingerprint),
                },
            )
            .await;
        match decision {
            Ok(AuthorizeDecision::Allow { .. }) => {
                self.authorized.store(true, Ordering::SeqCst);
                self.log
                    .authorized
                    .lock()
                    .unwrap()
                    .push(self.session_id.clone());
                Ok(Auth::Accept)
            }
            _ => Ok(Auth::reject()),
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        if data == b"echo ok" {
            session.data(channel, b"ok\n".to_vec())?;
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
        }
        Ok(())
    }
}

pub struct Quiet;

impl client::Handler for Quiet {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

pub struct Identity {
    pub serial: u64,
    pub key: PrivateKey,
    pub certificate: Certificate,
}

pub struct Outer {
    pub handle: client::Handle<Quiet>,
}

pub struct Inner {
    pub handle: client::Handle<Quiet>,
    pub channel: Channel<client::Msg>,
}

pub struct StandNode {
    pub node_id: String,
    pub log: Arc<AgentLog>,
    enrolled: EnrolledAgent,
    agent: Option<TestAgent>,
}

pub struct Stand {
    pub harness: Harness,
    pub gate: GateSshServer,
    pub user_id: String,
    pub nodes: Vec<StandNode>,
}

impl Stand {
    pub async fn start(names: &[&str]) -> Stand {
        Stand::start_with(names, Options::default()).await
    }

    pub async fn start_with(names: &[&str], options: Options) -> Stand {
        let harness = Harness::start(options).await;
        let policy = tempfile::tempdir().unwrap();
        std::fs::write(policy.path().join("roles.yaml"), ROLE).unwrap();
        assert!(harness.control.policy().reload(policy.path()).applied);
        let user_id = harness
            .store
            .users()
            .upsert(
                &NewUser {
                    issuer: "https://idp.example".to_owned(),
                    subject: "alice".to_owned(),
                    email: EMAIL.to_owned(),
                    username: "alice".to_owned(),
                    display_name: None,
                    groups: Vec::new(),
                },
                i64::try_from(unix_secs(SystemTime::now())).unwrap(),
            )
            .await
            .unwrap()
            .id;
        let cas = Arc::new(UserCaSource::new(
            UserCaKeys::from_openssh_lines(harness.authorities.user_lines.clone()).unwrap(),
        ));
        let mut nodes = Vec::new();
        for name in names {
            let enrolled = harness.enroll(name).await;
            let mut node = StandNode {
                node_id: enrolled.node_id.clone(),
                log: Arc::new(AgentLog::default()),
                enrolled,
                agent: None,
            };
            node.agent = Some(spawn_session_agent(&harness, &node, &cas));
            let registry = harness.server.registry().clone();
            let id = NodeId::new(node.node_id.clone()).unwrap();
            eventually("the agent tunnel", || registry.is_connected(&id)).await;
            nodes.push(node);
        }
        let gate = GateSshServer::start(GateSshParts {
            settings: GateSshSettings {
                listen: "127.0.0.1:0".parse().unwrap(),
                hostnames: vec![GATE_NAME.to_owned()],
                proxy_protocol: false,
                trusted_proxies: Vec::new(),
                max_unauthenticated: 16,
                write_stall: Some(Duration::from_secs(900)),
                client_limits: DEFAULT_SSH_CLIENT_LIMITS,
            },
            ssh_suffix: SUFFIX.to_owned(),
            issuer: Arc::new(HostAuthorityIssuer::following(
                harness.control.clone(),
                harness.store.clone(),
                Arc::new(SystemTime::now),
            )),
            user_cas: cas,
            control: Arc::new(harness.control.clone()),
            registry: harness.server.registry().clone(),
        })
        .await
        .unwrap();
        harness
            .control
            .install_session_killer(Arc::new(InProcessKiller::new(
                harness.server.agents(),
                Some(Arc::clone(gate.gate())),
            )));
        harness
            .control
            .install_agent_presence(Arc::new(RegistryPresence::new(harness.server.agents())));
        Stand {
            harness,
            gate,
            user_id,
            nodes,
        }
    }

    pub fn grant_node_admin(&self) {
        let policy = tempfile::tempdir().unwrap();
        std::fs::write(
            policy.path().join("roles.yaml"),
            format!("{ROLE}---\n{ADMIN_ROLE}"),
        )
        .unwrap();
        assert!(self.harness.control.policy().reload(policy.path()).applied);
    }

    pub fn kill_without_the_gate(&self) {
        self.harness
            .control
            .install_session_killer(Arc::new(InProcessKiller::new(
                self.harness.server.agents(),
                None,
            )));
    }

    pub fn connected(&self, index: usize) -> bool {
        let id = NodeId::new(self.nodes[index].node_id.clone()).unwrap();
        self.harness.server.registry().is_connected(&id)
    }

    pub async fn stop_agent(&mut self, index: usize) {
        if let Some(agent) = self.nodes[index].agent.take() {
            agent.stop().await;
        }
    }

    pub async fn restart_agent(&mut self, index: usize) {
        let cas = Arc::new(UserCaSource::new(
            UserCaKeys::from_openssh_lines(self.harness.authorities.user_lines.clone()).unwrap(),
        ));
        let node = &mut self.nodes[index];
        if let Some(agent) = node.agent.take() {
            agent.stop().await;
        }
        let registry = self.harness.server.registry().clone();
        let id = NodeId::new(node.node_id.clone()).unwrap();
        eventually("the old tunnel to close", || !registry.is_connected(&id)).await;
        node.agent = Some(spawn_session_agent(&self.harness, node, &cas));
        eventually("the new tunnel", || registry.is_connected(&id)).await;
    }

    pub async fn identity(&self) -> Identity {
        let certificates = self.harness.store.certificates();
        let serial = certificates.allocate_serial().await.unwrap();
        let now = SystemTime::now();
        let now_secs = i64::try_from(unix_secs(now)).unwrap();
        let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
        let subject = CaPublicKey::from_openssh(&key.public_key().to_openssh().unwrap()).unwrap();
        certificates
            .record(&NewCertificate {
                serial,
                user_id: self.user_id.clone(),
                kind: "user".to_owned(),
                key_id: format!("jaunt:{EMAIL}:{serial}"),
                valid_after: now_secs - 120,
                valid_before: now_secs + 3600,
                issued_at: now_secs,
                ca_fingerprint: None,
                host_trust_id: None,
                subject_fingerprint: Some(fingerprint_hex(&subject)),
            })
            .await
            .unwrap();
        self.signed(key, u64::try_from(serial).unwrap(), now)
    }

    pub fn forged_for(&self, victim: &Identity) -> Identity {
        let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
        self.signed(key, victim.serial, SystemTime::now())
    }

    fn signed(&self, key: PrivateKey, serial: u64, now: SystemTime) -> Identity {
        let subject = CaPublicKey::from_openssh(&key.public_key().to_openssh().unwrap()).unwrap();
        let signed = sign_user_certificate(
            self.harness.control.ca_snapshot().user_signer().as_ref(),
            UserCertParams {
                subject_public_key: subject,
                user_id: Uuid::parse_str(&self.user_id).unwrap(),
                email: EMAIL.to_owned(),
                serial,
                validity: Duration::from_secs(3600),
            },
            now,
        )
        .unwrap();
        Identity {
            serial,
            key,
            certificate: Certificate::from_openssh(&signed.to_openssh().unwrap()).unwrap(),
        }
    }

    pub async fn connect(&self, identity: &Identity) -> Outer {
        let tcp = TcpStream::connect(self.gate.local_addr()).await.unwrap();
        let mut handle = within(
            "the gate handshake",
            client::connect_stream(Arc::new(client::Config::default()), tcp, Quiet),
        )
        .await
        .unwrap();
        let login = handle
            .authenticate_openssh_cert(
                "jaunt",
                Arc::new(identity.key.clone()),
                identity.certificate.clone(),
            )
            .await
            .unwrap();
        assert!(login.success());
        Outer { handle }
    }

    pub async fn session(&self, identity: &Identity, node: &str) -> (Outer, Inner) {
        let outer = self.connect(identity).await;
        let inner = outer.open(identity, node).await.expect("the gate refused");
        (outer, inner)
    }

    pub async fn revoke(&self, kind: RevocationKind, subject: &str) -> Revoked {
        self.harness
            .control
            .revocations()
            .revoke(
                &RevokeRequest {
                    kind,
                    subject: subject.to_owned(),
                    reason: "stand".to_owned(),
                },
                "cli:stand",
            )
            .await
            .unwrap()
    }

    pub async fn stored(&self, session_id: &str) -> Session {
        self.harness
            .store
            .sessions()
            .get(session_id)
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn sessions_of_user(&self) -> Vec<Session> {
        let pool = self.raw().await;
        let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM sessions WHERE user_id = ?")
            .bind(&self.user_id)
            .fetch_all(&pool)
            .await
            .unwrap();
        pool.close().await;
        let mut sessions = Vec::new();
        for id in ids {
            sessions.push(self.stored(&id).await);
        }
        sessions
    }

    pub async fn backdate(&self, session_id: &str, secs: i64) {
        let pool = self.raw().await;
        sqlx::query("UPDATE sessions SET created_at = created_at - ? WHERE id = ?")
            .bind(secs)
            .bind(session_id)
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }

    pub async fn settles(&self, session_id: &str, reason: SessionEndReason) -> Session {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let session = self.stored(session_id).await;
            if session.end_reason == Some(reason) {
                return session;
            }
            assert!(
                Instant::now() < deadline,
                "the session never ended as {reason:?}: {session:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn raw(&self) -> SqlitePool {
        SqlitePool::connect_with(SqliteConnectOptions::new().filename(&self.harness.db_path))
            .await
            .unwrap()
    }

    pub async fn stop(mut self) {
        assert!(self.gate.shutdown(Duration::from_secs(10)).await);
        for node in &mut self.nodes {
            if let Some(agent) = node.agent.take() {
                agent.stop().await;
            }
        }
    }
}

impl Outer {
    pub async fn forward(&self, node: &str) -> Result<Channel<client::Msg>, russh::Error> {
        within(
            "the forward answer",
            self.handle.channel_open_direct_tcpip(
                format!("{node}.{SUFFIX}"),
                22,
                "127.0.0.1",
                50_000,
            ),
        )
        .await
    }

    pub async fn open(&self, identity: &Identity, node: &str) -> Result<Inner, russh::Error> {
        let forward = self.forward(node).await?;
        let mut handle = within(
            "the node handshake",
            client::connect_stream(
                Arc::new(client::Config::default()),
                forward.into_stream(),
                Quiet,
            ),
        )
        .await?;
        let login = handle
            .authenticate_openssh_cert(
                LOGIN,
                Arc::new(identity.key.clone()),
                identity.certificate.clone(),
            )
            .await?;
        assert!(login.success(), "the node refused the login");
        let mut channel = handle.channel_open_session().await?;
        channel.exec(true, "wait").await?;
        loop {
            match within("the exec answer", channel.wait()).await {
                Some(ChannelMsg::Success) => break,
                Some(_) => {}
                None => panic!("the session closed before the command started"),
            }
        }
        Ok(Inner { handle, channel })
    }
}

impl Inner {
    pub async fn ended(&mut self) {
        loop {
            match within("the session channel to end", self.channel.wait()).await {
                Some(ChannelMsg::Close) | None => return,
                Some(_) => {}
            }
        }
    }

    pub async fn echo(&self) -> Vec<u8> {
        let mut channel = within("a second channel", self.handle.channel_open_session())
            .await
            .unwrap();
        channel.exec(true, "echo ok").await.unwrap();
        let mut output = Vec::new();
        loop {
            match within("the echo", channel.wait()).await {
                Some(ChannelMsg::Data { data }) => output.extend_from_slice(&data),
                Some(ChannelMsg::Close) | None => return output,
                Some(_) => {}
            }
        }
    }
}

fn spawn_session_agent(harness: &Harness, node: &StandNode, cas: &Arc<UserCaSource>) -> TestAgent {
    let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
    let config = server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..server::Config::default()
    };
    let handler = SessionAgent {
        node_id: node.node_id.clone(),
        control: Arc::new(harness.control.clone()),
        cas: Arc::clone(cas),
        config: Arc::new(config),
        log: Arc::clone(&node.log),
    };
    spawn_agent_with(harness, &node.enrolled, Arc::new(handler))
}
