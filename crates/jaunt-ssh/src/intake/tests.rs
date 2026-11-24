use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use russh::keys::Algorithm;
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, ChannelMsg, ChannelWriteHalf, MethodKind, MethodSet, client};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{
    ChannelGrant, ChannelIntake, IntakeError, IntakeEvent, IntakeReader, SessionGone, WindowGrant,
};
use crate::config::ServerProfile;
use crate::test_support::{host_identity, key};

#[derive(Clone, Default)]
struct Grants {
    log: Arc<Mutex<Vec<u32>>>,
    gone: Arc<AtomicBool>,
}

impl Grants {
    fn granted(&self) -> Vec<u32> {
        self.log.lock().unwrap().clone()
    }
}

impl WindowGrant for Grants {
    fn grant(&self, bytes: u32) -> Result<(), SessionGone> {
        if self.gone.load(Ordering::SeqCst) {
            return Err(SessionGone);
        }
        self.log.lock().unwrap().push(bytes);
        Ok(())
    }
}

fn data(event: Option<IntakeEvent>) -> Bytes {
    match event {
        Some(IntakeEvent::Data(bytes)) => bytes,
        other => panic!("expected data, got {other:?}"),
    }
}

const STEP: Duration = Duration::from_secs(10);

async fn next(reader: &mut IntakeReader) -> Option<IntakeEvent> {
    tokio::time::timeout(STEP, reader.next())
        .await
        .expect("the intake reader hung")
}

async fn until(what: &str, condition: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + STEP;
    while !condition() {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

#[tokio::test]
async fn events_keep_their_order_and_end_after_close() {
    let (intake, mut reader) = ChannelIntake::new(1024, Grants::default());
    intake.push_data(b"ab").unwrap();
    intake.push_data(b"").unwrap();
    intake.push_data(b"cd").unwrap();
    intake.push_eof();
    intake.push_eof();
    intake.push_close();
    assert_eq!(data(next(&mut reader).await), Bytes::from_static(b"abcd"));
    assert_eq!(next(&mut reader).await, Some(IntakeEvent::Eof));
    assert_eq!(next(&mut reader).await, Some(IntakeEvent::Close));
    assert_eq!(next(&mut reader).await, None);
    assert_eq!(intake.push_data(b"x"), Err(IntakeError::DataAfterEof));
}

#[tokio::test]
async fn data_is_handed_out_in_bounded_chunks() {
    let window = 200 * 1024;
    let (intake, mut reader) = ChannelIntake::new(window, Grants::default());
    intake.push_data(&vec![7; 100 * 1024]).unwrap();
    assert_eq!(data(next(&mut reader).await).len(), 64 * 1024);
    assert_eq!(data(next(&mut reader).await).len(), 36 * 1024);
}

#[tokio::test]
async fn a_dropped_handler_ends_the_reader_after_buffered_data() {
    let (intake, mut reader) = ChannelIntake::new(1024, Grants::default());
    intake.push_data(b"tail").unwrap();
    drop(intake);
    assert_eq!(data(next(&mut reader).await), Bytes::from_static(b"tail"));
    assert_eq!(next(&mut reader).await, None);
}

#[tokio::test]
async fn data_after_eof_is_a_protocol_violation() {
    let (intake, _reader) = ChannelIntake::new(1024, Grants::default());
    intake.push_eof();
    assert_eq!(intake.push_data(b"late"), Err(IntakeError::DataAfterEof));
}

#[tokio::test]
async fn the_window_is_granted_only_after_consumption_in_batches() {
    let grants = Grants::default();
    let (intake, mut reader) = ChannelIntake::new(1000, grants.clone());
    intake.push_data(&[1; 600]).unwrap();
    assert_eq!(data(next(&mut reader).await).len(), 600);
    assert!(grants.granted().is_empty());
    reader.consumed(100).unwrap();
    assert!(grants.granted().is_empty());
    reader.consumed(200).unwrap();
    assert_eq!(grants.granted(), [300]);
    reader.consumed(100).unwrap();
    assert_eq!(grants.granted(), [300]);
    let waiting = tokio::spawn(async move {
        let event = next(&mut reader).await;
        (reader, event)
    });
    until("idle flush", || grants.granted() == [300, 100]).await;
    intake.push_close();
    let (_, event) = tokio::time::timeout(STEP, waiting)
        .await
        .expect("the intake reader hung")
        .unwrap();
    assert_eq!(event, Some(IntakeEvent::Close));
}

#[tokio::test]
async fn a_grant_fires_exactly_at_a_quarter_of_the_window() {
    let grants = Grants::default();
    let (intake, mut reader) = ChannelIntake::new(1000, grants.clone());
    intake.push_data(&[1; 600]).unwrap();
    assert_eq!(data(next(&mut reader).await).len(), 600);
    reader.consumed(249).unwrap();
    assert!(grants.granted().is_empty());
    reader.consumed(1).unwrap();
    assert_eq!(grants.granted(), [250]);
}

struct RefillingGrants {
    intake: Arc<OnceLock<ChannelIntake>>,
    refill: usize,
    outcomes: Arc<Mutex<Vec<Result<(), IntakeError>>>>,
}

impl WindowGrant for RefillingGrants {
    fn grant(&self, _bytes: u32) -> Result<(), SessionGone> {
        let outcome = match self.intake.get() {
            Some(intake) => intake.push_data(&vec![0; self.refill]),
            None => Err(IntakeError::SessionGone),
        };
        self.outcomes.lock().unwrap().push(outcome);
        Ok(())
    }
}

#[tokio::test]
async fn a_peer_may_refill_the_whole_window_as_soon_as_it_is_granted() {
    let slot = Arc::new(OnceLock::new());
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let grants = RefillingGrants {
        intake: Arc::clone(&slot),
        refill: 1000,
        outcomes: Arc::clone(&outcomes),
    };
    let (intake, mut reader) = ChannelIntake::new(1000, grants);
    intake.push_data(&[0; 1000]).unwrap();
    assert!(slot.set(intake).is_ok());
    assert_eq!(data(next(&mut reader).await).len(), 1000);
    reader.consumed(1000).unwrap();
    assert_eq!(*outcomes.lock().unwrap(), [Ok(())]);
    assert_eq!(data(next(&mut reader).await).len(), 1000);
}

#[tokio::test]
async fn the_granted_window_never_exceeds_the_configured_window() {
    let grants = Grants::default();
    let (intake, mut reader) = ChannelIntake::new(1000, grants.clone());
    assert_eq!(
        intake.push_data(&[0; 1001]),
        Err(IntakeError::WindowOverrun)
    );
    intake.push_data(&[0; 1000]).unwrap();
    assert_eq!(intake.push_data(&[0; 1]), Err(IntakeError::WindowOverrun));
    assert_eq!(data(next(&mut reader).await).len(), 1000);
    reader.consumed(5000).unwrap();
    reader.consumed(5000).unwrap();
    assert_eq!(grants.granted().iter().sum::<u32>(), 1000);
    intake.push_data(&[0; 1000]).unwrap();
    assert_eq!(intake.push_data(&[0; 1]), Err(IntakeError::WindowOverrun));
}

#[tokio::test]
async fn extended_data_is_counted_and_released_at_once() {
    let grants = Grants::default();
    let (intake, _reader) = ChannelIntake::new(1000, grants.clone());
    intake.push_data(&[0; 900]).unwrap();
    intake.consume_extended(100).unwrap();
    assert_eq!(grants.granted(), [100]);
    assert_eq!(
        intake.consume_extended(101),
        Err(IntakeError::WindowOverrun)
    );
    intake.consume_extended(0).unwrap();
    assert_eq!(grants.granted(), [100]);
}

#[tokio::test]
async fn a_gone_session_ends_the_reader() {
    let grants = Grants::default();
    let (intake, mut reader) = ChannelIntake::new(1000, grants.clone());
    intake.push_data(&[0; 10]).unwrap();
    assert_eq!(data(next(&mut reader).await).len(), 10);
    grants.gone.store(true, Ordering::SeqCst);
    reader.consumed(10).unwrap();
    assert_eq!(next(&mut reader).await, None);
    assert_eq!(intake.consume_extended(1), Err(IntakeError::SessionGone));
}

#[tokio::test]
async fn tiny_packets_cannot_grow_memory_past_the_window() {
    let window = 256 * 1024;
    let (intake, reader) = ChannelIntake::new(window, Grants::default());
    for _ in 0..window {
        intake.push_data(&[0]).unwrap();
    }
    assert_eq!(intake.push_data(&[0]), Err(IntakeError::WindowOverrun));
    let capacity = reader.buffered_capacity();
    assert!(
        capacity <= 2 * window as usize,
        "{capacity} bytes buffered for a {window} byte window"
    );
}

const TOTAL: usize = 64 * 1024 * 1024;
const CHUNK: usize = 32 * 1024;
const BRIDGE_BUFFER: usize = 64 * 1024;
const TRANSPORT_BUFFER: usize = 8 * 1024 * 1024;

fn pattern(offset: usize, len: usize) -> Vec<u8> {
    (offset..offset + len)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect()
}

struct EchoBridge {
    intakes: HashMap<ChannelId, ChannelIntake>,
    window: u32,
}

impl server::Handler for EchoBridge {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        let id = channel.id();
        let (read_half, write_half) = channel.split();
        drop(read_half);
        let (intake, reader) =
            ChannelIntake::new(self.window, ChannelGrant::new(session.handle(), id));
        self.intakes.insert(id, intake);
        let (up_near, up_far) = tokio::io::duplex(BRIDGE_BUFFER);
        let (down_near, down_far) = tokio::io::duplex(BRIDGE_BUFFER);
        tokio::spawn(pump_in(reader, up_near));
        tokio::spawn(cat(up_far, down_far));
        tokio::spawn(pump_out(down_near, write_half));
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        match self.intakes.get(&channel) {
            Some(intake) => intake
                .push_data(data)
                .map_err(|_| russh::Error::Inconsistent),
            None => Ok(()),
        }
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(intake) = self.intakes.get(&channel) {
            intake.push_eof();
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(intake) = self.intakes.remove(&channel) {
            intake.push_close();
        }
        Ok(())
    }
}

async fn pump_in(mut reader: IntakeReader, mut up: impl AsyncWrite + Unpin) {
    while let Some(event) = reader.next().await {
        match event {
            IntakeEvent::Data(bytes) => {
                if up.write_all(&bytes).await.is_err() || reader.consumed(bytes.len()).is_err() {
                    return;
                }
            }
            IntakeEvent::Eof => {
                if up.shutdown().await.is_err() {
                    return;
                }
            }
            IntakeEvent::Close => return,
        }
    }
}

async fn cat(mut input: impl AsyncRead + Unpin, mut output: impl AsyncWrite + Unpin) {
    let mut buffer = vec![0; 4096];
    loop {
        match input.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if output.write_all(&buffer[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = output.shutdown().await;
}

async fn pump_out(mut down: impl AsyncRead + Unpin, write_half: ChannelWriteHalf<Msg>) {
    let mut buffer = vec![0; CHUNK];
    loop {
        match down.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if write_half
                    .data_bytes(Bytes::copy_from_slice(&buffer[..n]))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    }
    let _ = write_half.eof().await;
    let _ = write_half.close().await;
}

struct TrustingClient;

impl client::Handler for TrustingClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_reader_behind_a_bridge_does_not_deadlock_a_large_transfer() {
    let ca = key(Algorithm::Ed25519);
    let mut server_config = ServerProfile::Agent.config(host_identity(&ca).0);
    server_config.methods = MethodSet::from(&[MethodKind::None][..]);
    let window = server_config.window_size;
    let (client_io, server_io) = tokio::io::duplex(TRANSPORT_BUFFER);
    let server = tokio::spawn(async move {
        let handler = EchoBridge {
            intakes: HashMap::new(),
            window,
        };
        server::run_stream(Arc::new(server_config), server_io, handler)
            .await?
            .await
    });

    let transfer = async move {
        let config = client::Config {
            window_size: 512 * 1024,
            channel_buffer_size: 8,
            ..client::Config::default()
        };
        let mut handle = client::connect_stream(Arc::new(config), client_io, TrustingClient)
            .await
            .unwrap();
        assert!(handle.authenticate_none("tester").await.unwrap().success());
        let channel = handle.channel_open_session().await.unwrap();
        let (mut read_half, write_half) = channel.split();
        let writer = tokio::spawn(async move {
            for offset in (0..TOTAL).step_by(CHUNK) {
                write_half
                    .data_bytes(Bytes::from(pattern(offset, CHUNK)))
                    .await
                    .unwrap();
            }
            write_half.eof().await.unwrap();
        });
        let mut received = 0;
        while let Some(message) = read_half.wait().await {
            match message {
                ChannelMsg::Data { data } => {
                    assert_eq!(data.as_ref(), pattern(received, data.len()).as_slice());
                    received += data.len();
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                ChannelMsg::Eof => break,
                _ => {}
            }
        }
        writer.await.unwrap();
        received
    };
    let received = tokio::time::timeout(Duration::from_secs(60), transfer)
        .await
        .expect("the bridge deadlocked");
    assert_eq!(received, TOTAL);
    server.abort();
}
