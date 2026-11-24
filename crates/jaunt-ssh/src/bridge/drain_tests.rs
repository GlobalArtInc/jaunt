use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::Algorithm;
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, ChannelMsg, MethodKind, MethodSet, client};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

use super::{LiveChannels, OutputDrain, OutputPump, Replies, Traffic};
use crate::config::ServerProfile;
use crate::intake::{SessionGone, WindowGrant};
use crate::observer::{ChannelExit, ObserverCell};
use crate::output::OutputQueue;
use crate::test_support::{host_identity, key};

const STEP: Duration = Duration::from_secs(10);
const VIOLATION: &str = "agent.ssh.node_protocol_violation";

struct Peer {
    opened: mpsc::UnboundedSender<(Channel<Msg>, server::Handle)>,
    closed: mpsc::UnboundedSender<ChannelId>,
}

impl server::Handler for Peer {
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
        let _ = self.opened.send((channel, session.handle()));
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = self.closed.send(channel);
        Ok(())
    }
}

struct Trusting;

impl client::Handler for Trusting {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct NoGrants;

impl WindowGrant for NoGrants {
    fn grant(&self, _bytes: u32) -> Result<(), SessionGone> {
        Ok(())
    }
}

struct EventNames {
    names: Arc<Mutex<Vec<String>>>,
    cancel_on_violation: Option<CancellationToken>,
}

struct EventName(Option<String>);

impl Visit for EventName {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "event" {
            self.0 = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}
}

impl Subscriber for EventNames {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut name = EventName(None);
        event.record(&mut name);
        if let Some(name) = name.0 {
            if let Some(cancel) = self
                .cancel_on_violation
                .as_ref()
                .filter(|_| name == VIOLATION)
            {
                cancel.cancel();
            }
            self.names.lock().unwrap().push(name);
        }
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

async fn overrun(cancel_at_warning: bool) {
    let cancel = CancellationToken::new();
    let names = Arc::new(Mutex::new(Vec::new()));
    let _logging = tracing::subscriber::set_default(EventNames {
        names: Arc::clone(&names),
        cancel_on_violation: cancel_at_warning.then(|| cancel.clone()),
    });
    let mut config = ServerProfile::Agent.config(host_identity(&key(Algorithm::Ed25519)).0);
    config.methods = MethodSet::from(&[MethodKind::None][..]);
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let (opened, mut open) = mpsc::unbounded_channel();
    let (closed, mut close) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        server::run_stream(Arc::new(config), server_io, Peer { opened, closed })
            .await?
            .await
    });
    let mut handle =
        client::connect_stream(Arc::new(client::Config::default()), client_io, Trusting)
            .await
            .unwrap();
    assert!(handle.authenticate_none("tester").await.unwrap().success());
    let (inner, inner_write) = handle.channel_open_session().await.unwrap().split();
    let (sshd, _) = open.recv().await.unwrap();
    let mut user = handle.channel_open_session().await.unwrap();
    let (outer, server) = open.recv().await.unwrap();
    let outer_id = outer.id();
    let (_outer_read, outer_write) = outer.split();
    let (output, events) = OutputQueue::new(16, NoGrants);
    let observer = Arc::new(ObserverCell::new(CancellationToken::new()));
    let traffic = Arc::new(Traffic::default());
    let drain = OutputDrain {
        inner,
        inner_write: Arc::new(inner_write),
        output,
        replies: Replies::default(),
        observer: Arc::clone(&observer),
        traffic: Arc::clone(&traffic),
        number: 0,
        session_id: Arc::from("s1"),
        cancel: cancel.clone(),
        started: false,
        exit: ChannelExit::Unknown,
    };
    let pump = OutputPump {
        events,
        drained: tokio::spawn(drain.run()),
        outer: outer_write,
        server,
        id: outer_id,
        traffic,
        observer,
        live: Arc::new(LiveChannels::default()),
        cancel: cancel.clone(),
    };
    let pumped = tokio::spawn(pump.run());
    sshd.data(&[7u8; 17][..]).await.unwrap();
    let inner_closed = async {
        while let Some(id) = close.recv().await {
            if id == sshd.id() {
                return true;
            }
        }
        false
    };
    assert!(
        tokio::time::timeout(STEP, inner_closed)
            .await
            .expect("sshd never saw the inner close")
    );
    tokio::time::timeout(STEP, pumped)
        .await
        .expect("the output pump did not end")
        .unwrap();
    if !cancel_at_warning {
        let user_closed = async {
            loop {
                match user.wait().await {
                    Some(ChannelMsg::Close) | None => return,
                    Some(_) => {}
                }
            }
        };
        tokio::time::timeout(STEP, user_closed)
            .await
            .expect("the user channel was not closed");
    }
    assert!(cancel.is_cancelled());
    assert!(names.lock().unwrap().iter().any(|name| name == VIOLATION));
}

#[tokio::test]
async fn an_output_overrun_by_sshd_closes_the_inner_and_the_user_channel() {
    overrun(false).await;
}

#[tokio::test]
async fn an_output_overrun_still_closes_the_inner_channel_when_the_bridge_ends_at_once() {
    overrun(true).await;
}
