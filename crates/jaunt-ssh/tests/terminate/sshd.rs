use std::borrow::Cow;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use russh::keys::ssh_key::public::KeyData;
use russh::keys::{Algorithm, Certificate, PublicKey};
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, ChannelWriteHalf, MethodKind, MethodSet, Preferred, Pty, Sig};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::support::key;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginMode {
    Accept,
    Refuse,
    Stall,
}

#[derive(Debug, Clone, Copy)]
pub struct SshdOptions {
    pub login: LoginMode,
    pub window: u32,
    pub open_delay: Option<Duration>,
}

impl Default for SshdOptions {
    fn default() -> Self {
        Self {
            login: LoginMode::Accept,
            window: 2 * 1024 * 1024,
            open_delay: None,
        }
    }
}

#[derive(Default)]
pub struct SshdStats {
    pub connections: AtomicUsize,
    pub live: AtomicUsize,
    pub attempts: AtomicUsize,
    pub logins: AtomicUsize,
    pub stalled: AtomicUsize,
    pub written: AtomicUsize,
    pub opens: AtomicUsize,
    pub closes: AtomicUsize,
    pub finished: AtomicUsize,
    pub certificates: Mutex<Vec<(String, Certificate)>>,
    pub requests: Mutex<Vec<String>>,
}

impl SshdStats {
    pub fn count(counter: &AtomicUsize) -> usize {
        counter.load(Ordering::SeqCst)
    }

    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    fn note(&self, request: String) {
        self.requests.lock().unwrap().push(request);
    }
}

pub struct FakeSshd {
    pub addr: SocketAddr,
    pub host_key: PublicKey,
    pub stats: Arc<SshdStats>,
    listener: JoinHandle<()>,
}

impl Drop for FakeSshd {
    fn drop(&mut self) {
        self.listener.abort();
    }
}

impl FakeSshd {
    pub async fn start(inner_ca: &PublicKey, options: SshdOptions) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let host = key();
        let host_key = host.public_key().clone();
        let config = Arc::new(server::Config {
            keys: vec![host],
            methods: MethodSet::from(&[MethodKind::PublicKey][..]),
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            window_size: options.window,
            manual_window: true,
            inactivity_timeout: None,
            preferred: Preferred {
                key: Cow::Borrowed(&[Algorithm::Ed25519]),
                ..Preferred::DEFAULT
            },
            ..server::Config::default()
        });
        let stats = Arc::new(SshdStats::default());
        let accepting = Arc::clone(&stats);
        let ca = inner_ca.key_data().clone();
        let listener = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                accepting.connections.fetch_add(1, Ordering::SeqCst);
                accepting.live.fetch_add(1, Ordering::SeqCst);
                let handler = Sshd {
                    stats: Arc::clone(&accepting),
                    ca: ca.clone(),
                    mode: options.login,
                    open_delay: options.open_delay,
                    channels: HashMap::new(),
                };
                let config = Arc::clone(&config);
                let stats = Arc::clone(&accepting);
                tokio::spawn(async move {
                    if let Ok(running) = server::run_stream(config, tcp, handler).await {
                        let _ = running.await;
                    }
                    stats.live.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        Self {
            addr,
            host_key,
            stats,
            listener,
        }
    }
}

enum Input {
    Data(Bytes),
    Eof,
    Resize(u32, u32),
    Signal(Sig),
}

struct Script {
    input: mpsc::UnboundedSender<Input>,
    pending: Option<(mpsc::UnboundedReceiver<Input>, ChannelWriteHalf<Msg>)>,
    env: Vec<String>,
    pty: Option<String>,
}

struct Sshd {
    stats: Arc<SshdStats>,
    ca: KeyData,
    mode: LoginMode,
    open_delay: Option<Duration>,
    channels: HashMap<ChannelId, Script>,
}

struct Program {
    input: mpsc::UnboundedReceiver<Input>,
    out: ChannelWriteHalf<Msg>,
    server: server::Handle,
    id: ChannelId,
    stats: Arc<SshdStats>,
}

impl Program {
    async fn say(&self, text: impl Into<String>) {
        let _ = self.out.data_bytes(Bytes::from(text.into())).await;
    }

    async fn write_records(&self, mib: &str, record: usize) -> bool {
        let chunk = Bytes::from(vec![b'y'; record]);
        for _ in 0..mib.parse::<usize>().unwrap() * 1024 * 1024 / record {
            if self.out.data_bytes(chunk.clone()).await.is_err() {
                return false;
            }
            self.stats.written.fetch_add(chunk.len(), Ordering::SeqCst);
        }
        true
    }

    async fn finish(self, status: u32) {
        let _ = self.out.eof().await;
        let _ = self.out.exit_status(status).await;
        let _ = self.out.close().await;
        self.stats.finished.fetch_add(1, Ordering::SeqCst);
    }

    async fn cat(&mut self) {
        while let Some(input) = self.input.recv().await {
            match input {
                Input::Data(data) => {
                    let len = u32::try_from(data.len()).unwrap();
                    if self.out.data_bytes(data).await.is_err() {
                        return;
                    }
                    let _ = self.server.grant_window(self.id, len);
                }
                Input::Eof => return,
                Input::Resize(columns, rows) => {
                    self.say(format!("size {columns}x{rows}\r\n")).await
                }
                Input::Signal(_) => {}
            }
        }
    }

    async fn run(mut self, command: &str) {
        let mut words = command.split_whitespace();
        match (words.next(), words.next()) {
            (Some("echo"), Some(text)) => {
                self.say(format!("{text}\n")).await;
                self.finish(0).await;
            }
            (Some("exit"), Some(code)) => self.finish(code.parse().unwrap()).await,
            (Some("cat"), None) => {
                self.cat().await;
                self.finish(0).await;
            }
            (Some("count"), None) => {
                let _ = self.out.eof().await;
                let mut total = 0;
                while let Some(input) = self.input.recv().await {
                    match input {
                        Input::Data(data) => {
                            total += data.len();
                            let _ = self
                                .server
                                .grant_window(self.id, u32::try_from(data.len()).unwrap());
                        }
                        Input::Eof => break,
                        _ => {}
                    }
                }
                let _ = self
                    .out
                    .exit_status(u32::try_from(total.min(255)).unwrap())
                    .await;
                let _ = self.out.close().await;
            }
            (Some("kill"), Some(name)) => {
                let signal = match name {
                    "TERM" => Sig::TERM,
                    "KILL" => Sig::KILL,
                    other => Sig::Custom(other.to_owned()),
                };
                let _ = self.out.eof().await;
                let _ = self
                    .server
                    .exit_signal_request(self.id, signal, false, String::new(), String::new())
                    .await;
                let _ = self.out.close().await;
            }
            (Some("wait-signal"), None) => {
                while let Some(input) = self.input.recv().await {
                    if let Input::Signal(signal) = input {
                        self.say(format!("got {signal:?}\n")).await;
                        break;
                    }
                }
                self.finish(0).await;
            }
            (Some("flood"), Some(mib)) => {
                if self.write_records(mib, 32 * 1024).await {
                    self.finish(0).await;
                }
            }
            (Some("floodsmall"), Some(mib)) => {
                if self.write_records(mib, 512).await {
                    self.finish(0).await;
                }
            }
            (Some("spill"), Some(kib)) => {
                let status = words.next().unwrap().parse().unwrap();
                let chunk = Bytes::from(vec![b's'; 1024]);
                for _ in 0..kib.parse::<usize>().unwrap() {
                    if self.out.data_bytes(chunk.clone()).await.is_err() {
                        return;
                    }
                }
                self.finish(status).await;
            }
            (Some("ext2"), Some(chunks)) => {
                let chunk = Bytes::from(vec![b'z'; 32 * 1024]);
                for _ in 0..chunks.parse::<usize>().unwrap() {
                    if self
                        .out
                        .extended_data_bytes(2, chunk.clone())
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                self.say("ok\n").await;
                self.finish(0).await;
            }
            (Some("late"), None) => {
                tokio::time::sleep(Duration::from_millis(800)).await;
                let _ = self.server.channel_success(self.id).await;
                self.say("late\n").await;
                self.finish(0).await;
            }
            (Some("stall"), None) => {
                while let Some(input) = self.input.recv().await {
                    match input {
                        Input::Data(data) => {
                            self.stats.stalled.fetch_add(data.len(), Ordering::SeqCst);
                        }
                        Input::Eof => break,
                        _ => {}
                    }
                }
                self.finish(0).await;
            }
            other => panic!("the fake sshd has no program {other:?}"),
        }
    }
}

impl Sshd {
    fn launch(&mut self, channel: ChannelId, session: &mut Session, command: String) -> bool {
        let Some(script) = self.channels.get_mut(&channel) else {
            return false;
        };
        let Some((input, out)) = script.pending.take() else {
            return false;
        };
        let program = Program {
            input,
            out,
            server: session.handle(),
            id: channel,
            stats: Arc::clone(&self.stats),
        };
        let command = match command.as_str() {
            "env" => format!("echo [{}]", script.env.join(",")),
            "shell" => {
                let pty = script.pty.clone();
                tokio::spawn(async move {
                    let mut program = program;
                    if let Some(pty) = pty {
                        program.say(format!("pty {pty}\r\n")).await;
                    }
                    program.cat().await;
                    program.finish(0).await;
                });
                return true;
            }
            _ => command,
        };
        tokio::spawn(async move { program.run(&command).await });
        true
    }

    fn reply(session: &mut Session, channel: ChannelId, ok: bool) -> Result<(), russh::Error> {
        if ok {
            session.channel_success(channel)
        } else {
            session.channel_failure(channel)
        }
    }

    fn push(&self, channel: ChannelId, input: Input) {
        if let Some(script) = self.channels.get(&channel) {
            let _ = script.input.send(input);
        }
    }
}

impl server::Handler for Sshd {
    type Error = russh::Error;

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        self.stats.attempts.fetch_add(1, Ordering::SeqCst);
        match self.mode {
            LoginMode::Stall => Ok(std::future::pending::<Auth>().await),
            LoginMode::Refuse => Ok(Auth::reject()),
            LoginMode::Accept => {
                let trusted = certificate.signature_key() == &self.ca
                    && certificate.valid_principals() == [user];
                if !trusted {
                    return Ok(Auth::reject());
                }
                self.stats.logins.fetch_add(1, Ordering::SeqCst);
                self.stats
                    .certificates
                    .lock()
                    .unwrap()
                    .push((user.to_owned(), certificate.clone()));
                Ok(Auth::Accept)
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let id = channel.id();
        let (read_half, write_half) = channel.split();
        drop(read_half);
        let (input, receiver) = mpsc::unbounded_channel();
        self.channels.insert(
            id,
            Script {
                input,
                pending: Some((receiver, write_half)),
                env: Vec::new(),
                pty: None,
            },
        );
        let first = self.stats.opens.fetch_add(1, Ordering::SeqCst) == 0;
        match self.open_delay.filter(|_| first) {
            Some(delay) => {
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    reply.accept().await;
                });
            }
            None => reply.accept().await,
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.stats.note("pty".to_owned());
        if term == "hang" {
            return Ok(());
        }
        if let Some(script) = self.channels.get_mut(&channel) {
            script.pty = Some(format!("{term} {col_width}x{row_height}"));
        }
        session.channel_success(channel)
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.stats.note(format!("env:{name}"));
        if let Some(script) = self.channels.get_mut(&channel) {
            script.env.push(format!("{name}={value}"));
        }
        session.channel_success(channel)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.stats.note("shell".to_owned());
        let ok = self.launch(channel, session, "shell".to_owned());
        Self::reply(session, channel, ok)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8(data.to_vec()).unwrap();
        self.stats.note(format!("exec:{command}"));
        match command.as_str() {
            "hang" => Ok(()),
            "late" => {
                self.launch(channel, session, command);
                Ok(())
            }
            "crash" => Err(russh::Error::Disconnect),
            _ => {
                let ok = self.launch(channel, session, command);
                Self::reply(session, channel, ok)
            }
        }
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.stats.note(format!("subsystem:{name}"));
        let ok = name == "sftp" && self.launch(channel, session, "cat".to_owned());
        Self::reply(session, channel, ok)
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.stats.note("window-change".to_owned());
        self.push(channel, Input::Resize(col_width, row_height));
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.stats.note("signal".to_owned());
        self.push(channel, Input::Signal(signal));
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.push(channel, Input::Data(Bytes::copy_from_slice(data)));
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.push(channel, Input::Eof);
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        self.stats.closes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
