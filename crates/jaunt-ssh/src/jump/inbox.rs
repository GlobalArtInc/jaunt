use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use bytes::BytesMut;
use russh::{ChannelMsg, ChannelReadHalf};
use tokio::sync::Notify;
use tokio::sync::mpsc::{self, error::TrySendError};

use super::{TerminalEvent, TerminalExit, signal_text};

pub(super) const MAX_DATA_PACKET: usize = 32 * 1024;
const STDERR: u32 = 1;

pub(super) trait Inbound: Send {
    fn receive(&mut self) -> impl Future<Output = Option<ChannelMsg>> + Send;
}

impl Inbound for ChannelReadHalf {
    fn receive(&mut self) -> impl Future<Output = Option<ChannelMsg>> + Send {
        self.wait()
    }
}

pub(super) trait Peer: Send + Sync {
    fn grant(&self, bytes: usize);

    fn cut(&self) -> impl Future<Output = ()> + Send;
}

pub(super) struct Window {
    allowed: AtomicU64,
    kept: AtomicU64,
}

impl Window {
    pub(super) fn new(initial: u32) -> Window {
        Window {
            allowed: AtomicU64::new(u64::from(initial)),
            kept: AtomicU64::new(0),
        }
    }

    pub(super) fn grant(&self, bytes: usize) {
        self.allowed
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::SeqCst);
    }

    pub(super) fn admits(&self, received: u64) -> bool {
        received <= self.allowed.load(Ordering::SeqCst)
    }

    fn keep(&self, bytes: usize) {
        self.kept
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::SeqCst);
    }

    pub(super) fn kept(&self) -> u64 {
        self.kept.load(Ordering::SeqCst)
    }
}

#[derive(Default)]
struct State {
    data: BytesMut,
    exit: Option<TerminalExit>,
    exit_seen: bool,
    closed: bool,
    violated: bool,
    peak: usize,
}

#[derive(Default)]
pub(super) struct Inbox {
    state: Mutex<State>,
    changed: Notify,
}

impl Inbox {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn push(&self, data: &[u8]) {
        let mut state = self.lock();
        state.data.extend_from_slice(data);
        state.peak = state.peak.max(state.data.len());
        drop(state);
        self.changed.notify_one();
    }

    fn exit(&self, exit: TerminalExit) {
        let mut state = self.lock();
        if !state.exit_seen {
            state.exit_seen = true;
            state.exit = Some(exit);
        }
        drop(state);
        self.changed.notify_one();
    }

    fn close(&self, violated: bool) {
        let mut state = self.lock();
        state.closed = true;
        if violated {
            state.violated = true;
            state.data = BytesMut::new();
            state.exit = None;
        }
        drop(state);
        self.changed.notify_one();
    }

    pub(super) fn violated(&self) -> bool {
        self.lock().violated
    }

    #[cfg(test)]
    pub(super) fn peak(&self) -> usize {
        self.lock().peak
    }

    #[cfg(test)]
    pub(super) fn buffered(&self) -> usize {
        self.lock().data.len()
    }

    pub(super) async fn next(&self) -> Option<TerminalEvent> {
        loop {
            {
                let mut state = self.lock();
                if state.violated {
                    return None;
                }
                if !state.data.is_empty() {
                    let take = state.data.len().min(MAX_DATA_PACKET);
                    return Some(TerminalEvent::Output(state.data.split_to(take).freeze()));
                }
                if let Some(exit) = state.exit.take() {
                    return Some(TerminalEvent::Exit(exit));
                }
                if state.closed {
                    return None;
                }
            }
            self.changed.notified().await;
        }
    }
}

fn admit(received: &mut u64, window: &Window, length: usize) -> bool {
    *received = received.saturating_add(u64::try_from(length).unwrap_or(u64::MAX));
    length <= MAX_DATA_PACKET && window.admits(*received)
}

fn answer(replies: &mpsc::Sender<bool>, accepted: bool) {
    if let Err(TrySendError::Full(_)) = replies.try_send(accepted) {
        tracing::debug!(target: "jaunt::web", "an unrequested reply from the node was dropped");
    }
}

pub(super) async fn read_node<I: Inbound, P: Peer>(
    mut inbound: I,
    peer: P,
    inbox: &Inbox,
    window: &Window,
    replies: mpsc::Sender<bool>,
) {
    let mut received = 0_u64;
    loop {
        let Some(message) = inbound.receive().await else {
            inbox.close(false);
            return;
        };
        match message {
            ChannelMsg::Data { data } => {
                if !admit(&mut received, window, data.len()) {
                    break;
                }
                window.keep(data.len());
                inbox.push(&data);
            }
            ChannelMsg::ExtendedData { data, ext } => {
                if !admit(&mut received, window, data.len()) {
                    break;
                }
                if ext == STDERR {
                    window.keep(data.len());
                    inbox.push(&data);
                } else {
                    window.grant(data.len());
                    peer.grant(data.len());
                }
            }
            ChannelMsg::ExitStatus { exit_status } => {
                inbox.exit(TerminalExit::Status(exit_status));
            }
            ChannelMsg::ExitSignal { signal_name, .. } => {
                inbox.exit(TerminalExit::Signal(signal_text(&signal_name)));
            }
            ChannelMsg::Close => {
                inbox.close(false);
                return;
            }
            ChannelMsg::Success => answer(&replies, true),
            ChannelMsg::Failure => answer(&replies, false),
            _ => {}
        }
    }
    inbox.close(true);
    peer.cut().await;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use bytes::Bytes;
    use russh::ChannelMsg;
    use tokio::sync::mpsc;

    use super::{Inbound, Inbox, MAX_DATA_PACKET, Peer, Window, read_node};
    use crate::jump::{MAX_PACKET, TerminalEvent, TerminalExit, WEB_WINDOW};

    impl Inbound for mpsc::Receiver<ChannelMsg> {
        fn receive(&mut self) -> impl std::future::Future<Output = Option<ChannelMsg>> + Send {
            self.recv()
        }
    }

    #[derive(Default)]
    struct Recorder {
        granted: AtomicUsize,
        cut: AtomicBool,
    }

    impl Peer for Arc<Recorder> {
        fn grant(&self, bytes: usize) {
            self.granted.fetch_add(bytes, Ordering::SeqCst);
        }

        async fn cut(&self) {
            self.cut.store(true, Ordering::SeqCst);
        }
    }

    struct Fixture {
        sender: mpsc::Sender<ChannelMsg>,
        replies: mpsc::Receiver<bool>,
        inbox: Arc<Inbox>,
        window: Arc<Window>,
        peer: Arc<Recorder>,
        reader: tokio::task::JoinHandle<()>,
    }

    fn start() -> Fixture {
        let (sender, receiver) = mpsc::channel(1);
        let (answers, replies) = mpsc::channel(2);
        let inbox = Arc::new(Inbox::default());
        let window = Arc::new(Window::new(WEB_WINDOW));
        let peer = Arc::new(Recorder::default());
        let reader = {
            let inbox = Arc::clone(&inbox);
            let window = Arc::clone(&window);
            let peer = Arc::clone(&peer);
            tokio::spawn(async move { read_node(receiver, peer, &inbox, &window, answers).await })
        };
        Fixture {
            sender,
            replies,
            inbox,
            window,
            peer,
            reader,
        }
    }

    async fn ended(reader: tokio::task::JoinHandle<()>) {
        tokio::time::timeout(std::time::Duration::from_secs(10), reader)
            .await
            .expect("the reader kept accepting what it must refuse")
            .unwrap();
    }

    fn data(length: usize) -> ChannelMsg {
        ChannelMsg::Data {
            data: Bytes::from(vec![b'x'; length]),
        }
    }

    async fn drained(inbox: &Inbox) -> usize {
        let mut total = 0;
        while let Some(TerminalEvent::Output(chunk)) = inbox.next().await {
            assert!(chunk.len() <= MAX_DATA_PACKET);
            total += chunk.len();
            if total >= MAX_DATA_PACKET {
                break;
            }
        }
        total
    }

    #[tokio::test]
    async fn a_packet_larger_than_the_negotiated_size_cuts_the_connection_unbuffered() {
        let negotiated = usize::try_from(MAX_PACKET).unwrap();
        let fixture = start();
        fixture.sender.send(data(negotiated)).await.unwrap();
        fixture.sender.send(data(negotiated + 1)).await.unwrap();
        ended(fixture.reader).await;
        assert!(fixture.peer.cut.load(Ordering::SeqCst));
        assert!(fixture.inbox.violated());
        assert_eq!(fixture.inbox.peak(), negotiated);
        assert_eq!(fixture.inbox.buffered(), 0);
        assert_eq!(fixture.inbox.next().await, None);
    }

    #[tokio::test]
    async fn a_flood_of_huge_packets_is_cut_at_the_first_one_and_nothing_is_kept() {
        let fixture = start();
        let mut sent = 0;
        for _ in 0..1024 {
            if fixture.sender.send(data(250_000)).await.is_err() {
                break;
            }
            sent += 1;
        }
        ended(fixture.reader).await;
        assert!(sent <= 2, "{sent}");
        assert!(fixture.peer.cut.load(Ordering::SeqCst));
        assert_eq!(fixture.inbox.peak(), 0);
    }

    #[tokio::test]
    async fn data_beyond_the_window_cuts_the_connection_and_never_buffers_past_it() {
        let fixture = start();
        let per_window = usize::try_from(WEB_WINDOW).unwrap() / MAX_DATA_PACKET;
        for _ in 0..per_window {
            fixture.sender.send(data(MAX_DATA_PACKET)).await.unwrap();
        }
        fixture.sender.send(data(1)).await.unwrap();
        ended(fixture.reader).await;
        assert!(fixture.peer.cut.load(Ordering::SeqCst));
        assert_eq!(fixture.inbox.peak(), usize::try_from(WEB_WINDOW).unwrap());
        assert_eq!(fixture.inbox.buffered(), 0);
        assert_eq!(fixture.window.kept(), u64::from(WEB_WINDOW));
    }

    #[tokio::test]
    async fn delivered_and_granted_bytes_let_the_node_send_more() {
        let fixture = start();
        let per_window = usize::try_from(WEB_WINDOW).unwrap() / MAX_DATA_PACKET;
        for round in 0..3 {
            for _ in 0..per_window {
                fixture.sender.send(data(MAX_DATA_PACKET)).await.unwrap();
            }
            for _ in 0..per_window {
                let delivered = drained(&fixture.inbox).await;
                fixture.window.grant(delivered);
            }
            assert!(!fixture.inbox.violated(), "{round}");
        }
        assert!(fixture.inbox.peak() <= usize::try_from(WEB_WINDOW).unwrap());
        assert!(!fixture.peer.cut.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn tiny_packets_are_kept_as_one_buffer_and_handed_out_in_bounded_chunks() {
        let fixture = start();
        for _ in 0..(MAX_DATA_PACKET + 10) {
            fixture.sender.send(data(1)).await.unwrap();
        }
        let first = fixture.inbox.next().await;
        let Some(TerminalEvent::Output(first)) = first else {
            panic!("no output");
        };
        assert!(first.len() <= MAX_DATA_PACKET);
        assert!(!fixture.inbox.violated());
    }

    #[tokio::test]
    async fn stderr_is_merged_other_streams_are_granted_back_and_the_exit_comes_after_the_data() {
        let mut fixture = start();
        let send = |message| fixture.sender.send(message);
        send(ChannelMsg::Success).await.unwrap();
        send(data(3)).await.unwrap();
        send(ChannelMsg::ExtendedData {
            data: Bytes::from_static(b"err"),
            ext: 1,
        })
        .await
        .unwrap();
        send(ChannelMsg::ExtendedData {
            data: Bytes::from_static(b"other"),
            ext: 7,
        })
        .await
        .unwrap();
        send(ChannelMsg::ExitStatus { exit_status: 3 })
            .await
            .unwrap();
        send(ChannelMsg::ExitStatus { exit_status: 9 })
            .await
            .unwrap();
        send(ChannelMsg::Failure).await.unwrap();
        send(ChannelMsg::Failure).await.unwrap();
        send(ChannelMsg::Failure).await.unwrap();
        send(ChannelMsg::Close).await.unwrap();
        ended(fixture.reader).await;
        assert_eq!(fixture.replies.recv().await, Some(true));
        assert_eq!(fixture.replies.recv().await, Some(false));
        assert_eq!(
            fixture.inbox.next().await,
            Some(TerminalEvent::Output(Bytes::from_static(b"xxxerr")))
        );
        assert_eq!(
            fixture.inbox.next().await,
            Some(TerminalEvent::Exit(TerminalExit::Status(3)))
        );
        assert_eq!(fixture.inbox.next().await, None);
        assert_eq!(fixture.peer.granted.load(Ordering::SeqCst), 5);
        assert!(!fixture.peer.cut.load(Ordering::SeqCst));
    }
}
