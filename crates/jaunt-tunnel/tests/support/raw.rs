use super::*;

pub struct FrameTap<IO> {
    inner: IO,
    preface_left: usize,
    header: Vec<u8>,
    payload_left: usize,
    payload_is_goaway: bool,
    goaway_payload: Vec<u8>,
    seen: Arc<Mutex<Vec<u32>>>,
}

impl<IO> FrameTap<IO> {
    pub fn new(inner: IO) -> (Self, Arc<Mutex<Vec<u32>>>) {
        Self::watching(inner, 24)
    }

    pub fn without_preface(inner: IO) -> (Self, Arc<Mutex<Vec<u32>>>) {
        Self::watching(inner, 0)
    }

    fn watching(inner: IO, preface_left: usize) -> (Self, Arc<Mutex<Vec<u32>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let tap = Self {
            inner,
            preface_left,
            header: Vec::new(),
            payload_left: 0,
            payload_is_goaway: false,
            goaway_payload: Vec::new(),
            seen: seen.clone(),
        };
        (tap, seen)
    }

    fn feed(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            if self.preface_left > 0 {
                let skip = bytes.len().min(self.preface_left);
                self.preface_left -= skip;
                bytes = &bytes[skip..];
            } else if self.payload_left > 0 {
                let take = bytes.len().min(self.payload_left);
                if self.payload_is_goaway {
                    self.goaway_payload.extend_from_slice(&bytes[..take]);
                }
                self.payload_left -= take;
                bytes = &bytes[take..];
                if self.payload_left == 0 {
                    self.finish_frame();
                }
            } else {
                let need = 9 - self.header.len();
                let take = bytes.len().min(need);
                self.header.extend_from_slice(&bytes[..take]);
                bytes = &bytes[take..];
                if self.header.len() == 9 {
                    let length = (usize::from(self.header[0]) << 16)
                        | (usize::from(self.header[1]) << 8)
                        | usize::from(self.header[2]);
                    self.payload_is_goaway = self.header[3] == 7;
                    self.payload_left = length;
                    self.header.clear();
                    self.goaway_payload.clear();
                    if length == 0 {
                        self.finish_frame();
                    }
                }
            }
        }
    }

    fn finish_frame(&mut self) {
        if self.payload_is_goaway && self.goaway_payload.len() >= 8 {
            let code = u32::from_be_bytes([
                self.goaway_payload[4],
                self.goaway_payload[5],
                self.goaway_payload[6],
                self.goaway_payload[7],
            ]);
            self.seen.lock().unwrap().push(code);
        }
        self.payload_is_goaway = false;
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for FrameTap<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) {
            let fresh = buf.filled()[before..].to_vec();
            self.feed(&fresh);
        }
        result
    }
}

impl<IO: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for FrameTap<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub type Incoming = (Request<RecvStream>, SendResponse<Bytes>);

pub struct FakeAgent {
    pub control: Option<ControlPeer>,
    pub requests: mpsc::UnboundedReceiver<Incoming>,
    pub goaway_codes: Arc<Mutex<Vec<u32>>>,
    pub closed: Arc<AtomicBool>,
    pub driver: JoinHandle<()>,
}

pub async fn connect_fake_agent(
    addr: SocketAddr,
    pki: &Pki,
    leaf: &Leaf,
    alpn: &[&[u8]],
) -> FakeAgent {
    let config = raw_client_config(pki.roots(), Some(leaf), &[&TLS13], alpn);
    let tls = tls_connect(addr, config, dns_name(AGENT_SNI))
        .await
        .unwrap();
    let (tap, goaway_codes) = FrameTap::new(tls);
    let mut connection = h2::server::handshake(tap).await.unwrap();
    let (tx, requests) = mpsc::unbounded_channel();
    let closed = Arc::new(AtomicBool::new(false));
    let closed_flag = closed.clone();
    let driver = tokio::spawn(async move {
        while let Some(Ok(incoming)) = connection.accept().await {
            if tx.send(incoming).is_err() {
                break;
            }
        }
        closed_flag.store(true, Ordering::SeqCst);
    });
    FakeAgent {
        control: None,
        requests,
        goaway_codes,
        closed,
        driver,
    }
}

pub struct ControlPeer {
    reader: BufReader<ReadHalf<H2Io>>,
    writer: WriteHalf<H2Io>,
}

impl ControlPeer {
    pub async fn send_raw(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).await.unwrap();
        self.writer.flush().await.unwrap();
    }

    pub async fn send_line(&mut self, json: &str) {
        self.send_raw(format!("{json}\n").as_bytes()).await;
    }

    pub async fn say_hello(&mut self) {
        self.send_line(r#"{"type":"hello","version":1,"agent_version":"fake/1"}"#)
            .await;
    }

    pub async fn next_line(&mut self) -> Option<String> {
        let mut line = String::new();
        let read = tokio::time::timeout(WAIT_LIMIT, self.reader.read_line(&mut line))
            .await
            .expect("timed out waiting for a control line")
            .ok()?;
        (read > 0).then(|| line.trim_end().to_owned())
    }
}

impl FakeAgent {
    pub async fn next_request(&mut self) -> Incoming {
        tokio::time::timeout(WAIT_LIMIT, self.requests.recv())
            .await
            .expect("timed out waiting for a request")
            .expect("connection ended before the request")
    }

    pub async fn accept_control(&mut self) -> ControlPeer {
        let (request, mut respond) = self.next_request().await;
        assert_eq!(request.uri().path(), "/v1/control");
        let send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        let (reader, writer) = tokio::io::split(H2Io::new(request.into_body(), send));
        ControlPeer {
            reader: BufReader::new(reader),
            writer,
        }
    }

    pub fn goaway_seen(&self) -> bool {
        !self.goaway_codes.lock().unwrap().is_empty()
    }
}

pub struct FakeGate {
    pub send_request: h2::client::SendRequest<Bytes>,
    pub goaway_codes: Arc<Mutex<Vec<u32>>>,
    driver: JoinHandle<()>,
}

pub async fn start_fake_gate(pki: &Pki) -> (SocketAddr, oneshot::Receiver<FakeGate>) {
    let server = pki.server_leaf();
    let config = agent_server_config(server.chain.clone(), server.key(), pki.roots()).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        let (tap, goaway_codes) = FrameTap::without_preface(tls);
        let (send_request, connection) = h2::client::handshake(tap).await.unwrap();
        let driver = tokio::spawn(async move { drop(connection.await) });
        tx.send(FakeGate {
            send_request,
            goaway_codes,
            driver,
        })
        .ok();
    });
    (addr, rx)
}

impl FakeGate {
    pub async fn request(
        &mut self,
        method: http::Method,
        path: &str,
        headers: &[(&str, &[u8])],
        end_of_stream: bool,
    ) -> (http::StatusCode, h2::SendStream<Bytes>) {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("https://fake.test{path}"));
        for (name, value) in headers {
            builder = builder.header(*name, http::HeaderValue::from_bytes(value).unwrap());
        }
        let request = builder.body(()).unwrap();
        let mut sender = self.send_request.clone().ready().await.unwrap();
        let (response, send) = sender.send_request(request, end_of_stream).unwrap();
        let response = tokio::time::timeout(WAIT_LIMIT, response)
            .await
            .expect("timed out waiting for the agent response")
            .unwrap();
        (response.status(), send)
    }
}

impl Drop for FakeGate {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

pub struct PausableProxy {
    pub addr: SocketAddr,
    paused: tokio::sync::watch::Sender<bool>,
    accept: JoinHandle<()>,
}

impl PausableProxy {
    pub async fn start(target: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (paused, pause_rx) = tokio::sync::watch::channel(false);
        let accept = tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let upstream = TcpStream::connect(target).await.unwrap();
                let (client_read, client_write) = client.into_split();
                let (upstream_read, upstream_write) = upstream.into_split();
                tokio::spawn(forward(client_read, upstream_write, pause_rx.clone()));
                tokio::spawn(forward(upstream_read, client_write, pause_rx.clone()));
            }
        });
        Self {
            addr,
            paused,
            accept,
        }
    }

    pub fn pause(&self) {
        self.paused.send(true).unwrap();
    }
}

impl Drop for PausableProxy {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

async fn forward(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    mut paused: tokio::sync::watch::Receiver<bool>,
) {
    let mut buffer = vec![0_u8; 16 * 1024];
    loop {
        let Ok(count) = from.read(&mut buffer).await else {
            return;
        };
        if count == 0 {
            return;
        }
        while *paused.borrow_and_update() {
            if paused.changed().await.is_err() {
                return;
            }
        }
        if to.write_all(&buffer[..count]).await.is_err() {
            return;
        }
    }
}

pub async fn start_alpnless_gate(pki: &Pki) -> SocketAddr {
    let server = pki.server_leaf();
    let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(server.chain.clone(), server.key())
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    let mut sink = Vec::new();
                    drop(tls.read_to_end(&mut sink).await);
                }
            });
        }
    });
    addr
}

pub async fn start_ticket_server(pki: &Pki) -> SocketAddr {
    let server = pki.server_leaf();
    let provider = Arc::new(default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(pki.roots()),
        provider.clone(),
    )
    .build()
    .unwrap();
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server.chain.clone(), server.key())
        .unwrap();
    config.alpn_protocols = vec![jaunt_tunnel::ALPN_AGENT_API.to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(tcp).await
                    && tls.write_all(b"x").await.is_ok()
                    && tls.flush().await.is_ok()
                {
                    let mut sink = Vec::new();
                    drop(tls.read_to_end(&mut sink).await);
                }
            });
        }
    });
    addr
}

pub async fn client_handshake_kinds(
    addr: SocketAddr,
    config: Arc<ClientConfig>,
    rounds: usize,
) -> Vec<rustls::HandshakeKind> {
    let mut kinds = Vec::new();
    for _ in 0..rounds {
        let mut stream = soon(
            "a tls handshake",
            tls_connect(addr, config.clone(), dns_name(AGENT_SNI)),
        )
        .await
        .unwrap();
        let mut greeting = [0_u8; 1];
        soon("the server greeting", stream.read_exact(&mut greeting))
            .await
            .unwrap();
        kinds.push(stream.get_ref().1.handshake_kind().unwrap());
    }
    kinds
}

pub fn client_hello_bytes(config: Arc<ClientConfig>, name: ServerName<'static>) -> Vec<u8> {
    let mut connection = rustls::ClientConnection::new(config, name).unwrap();
    let mut bytes = Vec::new();
    while connection.wants_write() {
        connection.write_tls(&mut bytes).unwrap();
    }
    bytes
}

fn bump_u16(bytes: &mut [u8], at: usize, delta: i64) {
    let value = i64::from(u16::from_be_bytes([bytes[at], bytes[at + 1]])) + delta;
    bytes[at..at + 2].copy_from_slice(&u16::try_from(value).unwrap().to_be_bytes());
}

fn bump_u24(bytes: &mut [u8], at: usize, delta: i64) {
    let value =
        (i64::from(bytes[at]) << 16 | i64::from(bytes[at + 1]) << 8 | i64::from(bytes[at + 2]))
            + delta;
    let value = u32::try_from(value).unwrap().to_be_bytes();
    bytes[at..at + 3].copy_from_slice(&value[1..]);
}

pub fn with_server_name(hello: &[u8], name: &[u8]) -> Vec<u8> {
    let mut at = 5 + 4 + 2 + 32;
    at += 1 + usize::from(hello[at]);
    at += 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
    at += 1 + usize::from(hello[at]);
    let extensions_length_at = at;
    let extensions_end = at + 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
    let mut cursor = at + 2;
    while cursor < extensions_end {
        let kind = u16::from_be_bytes([hello[cursor], hello[cursor + 1]]);
        let length = usize::from(u16::from_be_bytes([hello[cursor + 2], hello[cursor + 3]]));
        if kind == 0 {
            let name_start = cursor + 9;
            let old_length =
                usize::from(u16::from_be_bytes([hello[cursor + 7], hello[cursor + 8]]));
            assert_eq!(cursor + 4 + length, name_start + old_length);
            let mut patched = hello[..name_start].to_vec();
            patched.extend_from_slice(name);
            patched.extend_from_slice(&hello[name_start + old_length..]);
            let delta = i64::try_from(name.len()).unwrap() - i64::try_from(old_length).unwrap();
            bump_u16(&mut patched, cursor + 7, delta);
            bump_u16(&mut patched, cursor + 4, delta);
            bump_u16(&mut patched, cursor + 2, delta);
            bump_u16(&mut patched, extensions_length_at, delta);
            bump_u24(&mut patched, 6, delta);
            bump_u16(&mut patched, 3, delta);
            return patched;
        }
        cursor += 4 + length;
    }
    panic!("the client hello carries no server name");
}

pub fn block_on_without_runtime<F: Future>(future: F) -> F::Output {
    struct Unparker(std::thread::Thread);

    impl std::task::Wake for Unparker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }

    let waker = std::task::Waker::from(Arc::new(Unparker(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        assert!(Instant::now() < deadline, "the future never completed");
        std::thread::park_timeout(Duration::from_millis(50));
    }
}

pub fn spawn_duplex_agent(io: tokio::io::DuplexStream) {
    tokio::spawn(async move {
        let Ok(mut connection) = h2::server::handshake(io).await else {
            return;
        };
        let mut held = Vec::new();
        while let Some(Ok((request, mut respond))) = connection.accept().await {
            if request.uri().path() != "/v1/control" {
                continue;
            }
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let hello = br#"{"type":"hello","version":1,"agent_version":"fake/1"}"#;
            send.send_data(Bytes::from([hello.as_slice(), b"\n"].concat()), false)
                .unwrap();
            held.push((request, send));
        }
    });
}
