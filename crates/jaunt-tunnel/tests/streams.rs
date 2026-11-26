mod support;

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use jaunt_tunnel::{
    DEFAULT_STREAM_WINDOW, H2Io, IncomingStream, OpenError, ServedKinds, ServiceName, SessionId,
    StreamAborted, StreamKind, StreamMeta, TunnelOptions,
};
use sha2::{Digest, Sha256};
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

const STREAMS: usize = 100;
const BYTES_PER_DIRECTION: usize = 4 * 1024 * 1024;
const INTEGRITY_DEADLINE: Duration = Duration::from_secs(120);
const CHUNK: usize = 32 * 1024;

type Hash = [u8; 32];

struct Xorshift(u64);

impl Xorshift {
    fn random() -> Self {
        Self(rand::random::<u64>() | 1)
    }

    fn fill(&mut self, buffer: &mut [u8]) {
        for byte in buffer {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *byte = (self.0 >> 24) as u8;
        }
    }
}

async fn pump(io: H2Io, total: usize) -> (Hash, Hash) {
    let (mut reader, mut writer) = tokio::io::split(io);
    let sender = tokio::spawn(async move {
        let mut random = Xorshift::random();
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; CHUNK];
        let mut left = total;
        while left > 0 {
            let size = left.min(CHUNK);
            random.fill(&mut buffer[..size]);
            hasher.update(&buffer[..size]);
            writer.write_all(&buffer[..size]).await.unwrap();
            left -= size;
        }
        writer.shutdown().await.unwrap();
        Hash::from(hasher.finalize())
    });
    let receiver = tokio::spawn(async move {
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; CHUNK];
        let mut received = 0;
        loop {
            let count = reader.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            received += count;
        }
        assert_eq!(received, total);
        Hash::from(hasher.finalize())
    });
    (sender.await.unwrap(), receiver.await.unwrap())
}

struct Harness {
    gate: TestGate,
    agent: TestAgent,
}

async fn connect(
    handler: Arc<dyn jaunt_tunnel::StreamHandler>,
    gate_options: GateOptions,
    agent_options: AgentOptions,
) -> Harness {
    let pki = Pki::new("ca");
    let leaf = pki.client_leaf("node-a");
    let auth = MapAuthenticator::new();
    auth.allow(&leaf, "node-a");
    let mut gate = TestGate::start(&pki, auth, gate_options).await;
    let agent = spawn_agent(gate.addr, &pki, &leaf, handler, agent_options);
    wait_connected(&mut gate, "node-a").await;
    Harness { gate, agent }
}

impl Harness {
    async fn open(&self, session: &str) -> H2Io {
        self.gate
            .registry
            .open_stream(&node("node-a"), &meta(session))
            .await
            .unwrap()
    }

    async fn finish(self) {
        self.agent.stop().await;
        self.gate.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_hundred_concurrent_streams_keep_their_bytes_intact_in_both_directions() {
    let (results_tx, mut results) = mpsc::unbounded_channel::<(String, Hash, Hash)>();
    let agent_side = handler(move |stream: IncomingStream| {
        let results = results_tx.clone();
        async move {
            let session = stream.meta.session().to_string();
            let (sent, received) = pump(stream.io, BYTES_PER_DIRECTION).await;
            results.send((session, sent, received)).unwrap();
        }
    });
    let harness = connect(agent_side, GateOptions::default(), AgentOptions::default()).await;

    let started = Instant::now();
    let mut gate_side = JoinSet::new();
    for index in 0..STREAMS {
        let io = harness.open(&format!("s-{index}")).await;
        gate_side.spawn(async move { (index, pump(io, BYTES_PER_DIRECTION).await) });
    }
    let mut gate_hashes = vec![None; STREAMS];
    within("the gate side of every stream", INTEGRITY_DEADLINE, async {
        while let Some(done) = gate_side.join_next().await {
            let (index, hashes) = done.unwrap();
            gate_hashes[index] = Some(hashes);
        }
    })
    .await;
    let mut agent_hashes = std::collections::HashMap::new();
    for _ in 0..STREAMS {
        let (session, sent, received) = soon("an agent side result", results.recv()).await.unwrap();
        agent_hashes.insert(session, (sent, received));
    }
    eprintln!("integrity run took {:?}", started.elapsed());

    for (index, hashes) in gate_hashes.into_iter().enumerate() {
        let (gate_sent, gate_received) = hashes.unwrap();
        let (agent_sent, agent_received) = agent_hashes[&format!("s-{index}")];
        assert_eq!(gate_sent, agent_received, "stream {index} gate to agent");
        assert_eq!(agent_sent, gate_received, "stream {index} agent to gate");
    }
    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_that_does_not_read_stalls_the_writer_and_loses_nothing() {
    const TOTAL: usize = 4 * 1024 * 1024;
    let resume = CancellationToken::new();
    let (digest_tx, digest_rx) = oneshot::channel::<(usize, Hash)>();
    let digest_slot = std::sync::Mutex::new(Some(digest_tx));
    let gate_resume = resume.clone();
    let agent_side = handler(move |mut stream: IncomingStream| {
        let resume = gate_resume.clone();
        let digest = digest_slot.lock().unwrap().take();
        async move {
            resume.cancelled().await;
            let mut hasher = Sha256::new();
            let mut buffer = vec![0_u8; CHUNK];
            let mut received = 0;
            loop {
                let count = stream.io.read(&mut buffer).await.unwrap();
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
                received += count;
            }
            if let Some(digest) = digest {
                digest
                    .send((received, Hash::from(hasher.finalize())))
                    .unwrap();
            }
        }
    });
    let harness = connect(agent_side, GateOptions::default(), AgentOptions::default()).await;
    let mut io = harness.open("slow").await;

    let (stalled_at, sent_digest) = within("the whole transfer", Duration::from_secs(30), async {
        let mut random = Xorshift::random();
        let mut hasher = Sha256::new();
        let mut chunk = vec![0_u8; 16 * 1024];
        let mut written = 0;
        let mut stalled_at = None;
        while written < TOTAL {
            random.fill(&mut chunk);
            let mut offset = 0;
            while offset < chunk.len() {
                let attempt =
                    tokio::time::timeout(Duration::from_millis(500), io.write(&chunk[offset..]));
                match attempt.await {
                    Ok(count) => offset += count.unwrap(),
                    Err(_) if written + offset > 0 => {
                        stalled_at.get_or_insert(written + offset);
                        resume.cancel();
                    }
                    Err(_) => {}
                }
            }
            hasher.update(&chunk);
            written += chunk.len();
        }
        io.shutdown().await.unwrap();
        (stalled_at, Hash::from(hasher.finalize()))
    })
    .await;

    let stalled_at = stalled_at.expect("the writer never had to wait");
    eprintln!("writer stalled after {stalled_at} bytes");
    assert!(stalled_at > 0);
    assert!(
        stalled_at <= DEFAULT_STREAM_WINDOW as usize + 64 * 1024,
        "writer was allowed {stalled_at} bytes before waiting"
    );
    let (received, digest) = soon("the reader digest", digest_rx).await.unwrap();
    assert_eq!(received, TOTAL);
    assert_eq!(digest, sent_digest);
    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consuming_in_small_steps_opens_the_window_no_faster_than_consumption() {
    const STEP: usize = 1024;
    let consumed_bytes = DEFAULT_STREAM_WINDOW as usize / 2 - 512;
    let consumed = Arc::new(AtomicBool::new(false));
    let resume = CancellationToken::new();
    let (consumed_flag, resume_signal) = (consumed.clone(), resume.clone());
    let agent_side = handler(move |mut stream: IncomingStream| {
        let (consumed, resume) = (consumed_flag.clone(), resume_signal.clone());
        async move {
            let mut buffer = [0_u8; STEP];
            let mut left = consumed_bytes;
            while left > 0 {
                let size = left.min(STEP);
                stream.io.read_exact(&mut buffer[..size]).await.unwrap();
                left -= size;
            }
            consumed.store(true, Ordering::SeqCst);
            resume.cancelled().await;
        }
    });
    let harness = connect(agent_side, GateOptions::default(), AgentOptions::default()).await;
    let mut io = harness.open("small-steps").await;

    let window = DEFAULT_STREAM_WINDOW as usize;
    let accepted = within("the writer to stall", Duration::from_secs(30), async {
        let chunk = vec![7_u8; 16 * 1024];
        let mut accepted = 0;
        let mut stalls_after_consumption = 0;
        while stalls_after_consumption < 2 {
            let attempt = tokio::time::timeout(Duration::from_millis(500), io.write(&chunk));
            match attempt.await {
                Ok(count) => {
                    accepted += count.unwrap();
                    stalls_after_consumption = 0;
                }
                Err(_) if consumed.load(Ordering::SeqCst) && accepted >= window => {
                    stalls_after_consumption += 1;
                }
                Err(_) => {}
            }
        }
        accepted
    })
    .await;

    assert!(accepted >= window, "{accepted} bytes accepted");
    assert!(
        accepted <= window + consumed_bytes,
        "{consumed_bytes} bytes consumed in {STEP} byte steps let {accepted} bytes through a {window} byte window"
    );
    resume.cancel();
    drop(io);
    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn half_close_keeps_the_other_direction_flowing() {
    let (seen_tx, seen_rx) = oneshot::channel::<Vec<u8>>();
    let seen_slot = std::sync::Mutex::new(Some(seen_tx));
    let agent_side = handler(move |mut stream: IncomingStream| {
        let seen = seen_slot.lock().unwrap().take();
        async move {
            let mut request = Vec::new();
            soon("the request", stream.io.read_to_end(&mut request))
                .await
                .unwrap();
            if let Some(seen) = seen {
                seen.send(request).unwrap();
            }
            stream.io.write_all(b"late reply").await.unwrap();
            stream.io.shutdown().await.unwrap();
        }
    });
    let harness = connect(agent_side, GateOptions::default(), AgentOptions::default()).await;
    let mut io = harness.open("half").await;
    io.write_all(b"request").await.unwrap();
    io.shutdown().await.unwrap();
    assert_eq!(soon("the request", seen_rx).await.unwrap(), b"request");
    let mut reply = Vec::new();
    soon("the late reply", io.read_to_end(&mut reply))
        .await
        .unwrap();
    assert_eq!(reply, b"late reply");
    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_returning_handler_resets_the_peer_and_releases_its_session() {
    let agent_side = handler(|mut stream: IncomingStream| async move {
        let mut first = [0_u8; 4];
        drop(stream.io.read_exact(&mut first).await);
    });
    let harness = connect(agent_side, GateOptions::default(), AgentOptions::default()).await;
    let mut io = harness.open("short-lived").await;
    io.write_all(b"ping").await.unwrap();

    let mut buffer = [0_u8; 16];
    let error = soon("the reset", io.read(&mut buffer)).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    let deadline = Instant::now() + Duration::from_secs(10);
    while io.write_all(&[0_u8; 1024]).await.is_ok() {
        assert!(
            Instant::now() < deadline,
            "writing to a reset stream kept succeeding"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    eventually("the session to be released", || {
        harness.agent.sessions.active().is_empty()
    })
    .await;
    let again = harness.open("next").await;
    drop(again);
    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streams_beyond_the_concurrency_limit_are_refused_and_the_others_keep_working() {
    let release = CancellationToken::new();
    let held = release.clone();
    let agent_side = handler(move |stream: IncomingStream| {
        let held = held.clone();
        async move {
            let (mut reader, mut writer) = tokio::io::split(stream.io);
            tokio::select! {
                () = held.cancelled() => {}
                copied = tokio::io::copy(&mut reader, &mut writer) => drop(copied),
            }
        }
    });
    let agent_options = AgentOptions {
        tunnel: TunnelOptions {
            max_concurrent_streams: 3,
            ..TunnelOptions::default()
        },
        ..AgentOptions::default()
    };
    let harness = connect(agent_side, GateOptions::default(), agent_options).await;
    let mut open = Vec::new();
    for index in 0..3 {
        open.push(harness.open(&format!("held-{index}")).await);
    }
    let refused = harness
        .gate
        .registry
        .open_stream(&node("node-a"), &meta("one-too-many"))
        .await;
    assert_eq!(refused.unwrap_err(), OpenError::AtCapacity);

    for (index, io) in open.iter_mut().enumerate() {
        let message = format!("still alive {index}");
        io.write_all(message.as_bytes()).await.unwrap();
        let mut echoed = vec![0_u8; message.len()];
        soon("the echo", io.read_exact(&mut echoed)).await.unwrap();
        assert_eq!(echoed, message.as_bytes());
    }

    drop(open.pop());
    let registry = harness.gate.registry.clone();
    let mut reopened = None;
    let deadline = Instant::now() + Duration::from_secs(10);
    while reopened.is_none() {
        assert!(
            Instant::now() < deadline,
            "the freed slot never became usable"
        );
        match registry
            .open_stream(&node("node-a"), &meta("replacement"))
            .await
        {
            Ok(io) => reopened = Some(io),
            Err(OpenError::AtCapacity) => tokio::time::sleep(Duration::from_millis(10)).await,
            Err(other) => panic!("unexpected error {other:?}"),
        }
    }
    release.cancel();
    drop(open);
    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_aborted_stream_reports_a_typed_abort_error() {
    let (observed_tx, observed_rx) = oneshot::channel::<(io::ErrorKind, bool)>();
    let observed_slot = std::sync::Mutex::new(Some(observed_tx));
    let agent_side = handler(move |mut stream: IncomingStream| {
        let observed = observed_slot.lock().unwrap().take();
        async move {
            let mut buffer = [0_u8; 8];
            let error = stream.io.read(&mut buffer).await.unwrap_err();
            let typed = error
                .get_ref()
                .is_some_and(|inner| inner.is::<StreamAborted>());
            if let Some(observed) = observed {
                observed.send((error.kind(), typed)).unwrap();
            }
        }
    });
    let harness = connect(agent_side, GateOptions::default(), AgentOptions::default()).await;
    let io = harness.open("abort-me").await;
    eventually("the session to start", || {
        !harness.agent.sessions.active().is_empty()
    })
    .await;
    harness
        .gate
        .registry
        .terminate_session(
            &node("node-a"),
            &jaunt_tunnel::SessionId::new("abort-me").unwrap(),
        )
        .unwrap();
    let (kind, typed) = soon("the abort to be observed", observed_rx).await.unwrap();
    assert_eq!(kind, io::ErrorKind::ConnectionAborted);
    assert!(typed);
    drop(io);
    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_active_session_id_cannot_be_opened_twice() {
    let harness = connect(
        echo_handler(),
        GateOptions::default(),
        AgentOptions::default(),
    )
    .await;
    let mut first = harness.open("shared-id").await;
    let second = harness
        .gate
        .registry
        .open_stream(&node("node-a"), &meta("shared-id"))
        .await;
    assert_eq!(second.unwrap_err(), OpenError::Refused(409));

    first.write_all(b"still mine").await.unwrap();
    let mut echoed = [0_u8; 10];
    soon("the echo", first.read_exact(&mut echoed))
        .await
        .unwrap();
    assert_eq!(&echoed, b"still mine");
    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kube_stream_reaches_the_agent_with_its_service() {
    let (meta_tx, mut meta_rx) = mpsc::unbounded_channel::<StreamMeta>();
    let agent_side = handler(move |stream: IncomingStream| {
        meta_tx.send(stream.meta.clone()).unwrap();
        async move { drop(stream) }
    });
    let agent_options = AgentOptions {
        served_kinds: Some(ServedKinds::new([StreamKind::Ssh, StreamKind::Kube]).unwrap()),
        ..AgentOptions::default()
    };
    let harness = connect(agent_side, GateOptions::default(), agent_options).await;
    let sent = StreamMeta::with_service(
        SessionId::new("k-0123456789abcdef0123456789abcdef").unwrap(),
        StreamKind::Kube,
        ServiceName::new("main-cluster").unwrap(),
        "203.0.113.5:40000",
    )
    .unwrap();
    let io = harness
        .gate
        .registry
        .open_stream(&node("node-a"), &sent)
        .await
        .unwrap();
    let received = soon("the kube stream meta", meta_rx.recv()).await.unwrap();
    assert_eq!(received, sent);
    assert_eq!(received.kind(), StreamKind::Kube);
    assert_eq!(
        received.service().map(ServiceName::as_str),
        Some("main-cluster")
    );
    drop(io);
    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ssh_only_agent_refuses_a_kube_stream_and_keeps_serving_ssh() {
    let harness = connect(
        echo_handler(),
        GateOptions::default(),
        AgentOptions::default(),
    )
    .await;
    let kube = StreamMeta::with_service(
        SessionId::new("k-0123456789abcdef0123456789abcdef").unwrap(),
        StreamKind::Kube,
        ServiceName::new("main-cluster").unwrap(),
        "203.0.113.5:40000",
    )
    .unwrap();
    let refused = harness
        .gate
        .registry
        .open_stream(&node("node-a"), &kube)
        .await;
    assert_eq!(refused.unwrap_err(), OpenError::Refused(400));
    assert!(harness.agent.sessions.active().is_empty());

    let mut ssh = harness.open("still-ssh").await;
    ssh.write_all(b"ping").await.unwrap();
    let mut echoed = [0_u8; 4];
    soon("the echo", ssh.read_exact(&mut echoed)).await.unwrap();
    assert_eq!(&echoed, b"ping");
    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unserved_kind_is_refused_before_its_session_is_checked() {
    let harness = connect(
        echo_handler(),
        GateOptions::default(),
        AgentOptions::default(),
    )
    .await;
    let _ssh = harness.open("shared-id").await;
    let kube = StreamMeta::with_service(
        SessionId::new("shared-id").unwrap(),
        StreamKind::Kube,
        ServiceName::new("main-cluster").unwrap(),
        "203.0.113.5:40000",
    )
    .unwrap();
    let refused = harness
        .gate
        .registry
        .open_stream(&node("node-a"), &kube)
        .await;
    assert_eq!(refused.unwrap_err(), OpenError::Refused(400));
    harness.finish().await;
}
