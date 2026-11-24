use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use russh::server::{self, ChannelOpenHandle, Msg};
use russh::{Channel, ChannelOpenFailure};
use tokio_util::sync::CancellationToken;

use crate::bridge::{
    BridgeContext, ChannelKind, DataPath, InnerOpen, InnerOpened, Replies, Traffic, audit_forward,
    close_late, wait_open,
};
use crate::intake::{ChannelGrant, ChannelIntake, IntakeError};
use crate::observer::ForwardTarget;

const LOCALHOST: &str = "localhost";
const IPV6_LOOPBACK: &str = "::1";
const IPV6_LOOPBACK_BRACKETED: &str = "[::1]";
const UNKNOWN_ORIGINATOR: &str = "0.0.0.0";

pub(crate) fn loopback_destination(host: &str, port: u32) -> Option<ForwardTarget> {
    let port = u16::try_from(port).ok().filter(|port| *port != 0)?;
    let name = host.strip_suffix('.').unwrap_or(host);
    let host = if name.eq_ignore_ascii_case(LOCALHOST) {
        LOCALHOST.to_owned()
    } else if host == IPV6_LOOPBACK || host == IPV6_LOOPBACK_BRACKETED {
        IPV6_LOOPBACK.to_owned()
    } else {
        host.parse::<Ipv4Addr>()
            .ok()
            .filter(Ipv4Addr::is_loopback)?
            .to_string()
    };
    Some(ForwardTarget { host, port })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Originator {
    address: String,
    port: u32,
}

impl Originator {
    pub(crate) fn of_client(client_addr: &str) -> Self {
        let ip = client_addr
            .parse::<SocketAddr>()
            .map(|socket| socket.ip())
            .or_else(|_| client_addr.parse::<IpAddr>());
        Self {
            address: ip.map_or_else(|_| UNKNOWN_ORIGINATOR.to_owned(), |ip| ip.to_string()),
            port: 0,
        }
    }
}

pub(crate) struct ForwardOpen {
    pub(crate) inner: InnerOpen,
    pub(crate) target: ForwardTarget,
    pub(crate) originator: Originator,
}

pub(crate) struct ForwardBridge {
    intake: ChannelIntake,
    cancel: CancellationToken,
    closing: CancellationToken,
    settled: CancellationToken,
    traffic: Arc<Traffic>,
}

impl ForwardBridge {
    pub(crate) fn open(
        outer: Channel<Msg>,
        reply: ChannelOpenHandle,
        open: ForwardOpen,
        server: server::Handle,
        window: u32,
        context: &BridgeContext,
    ) -> Self {
        let id = outer.id();
        let (outer_read, outer_write) = outer.split();
        drop(outer_read);
        let cancel = context.stop.child_token();
        let closing = CancellationToken::new();
        let settled = CancellationToken::new();
        let (intake, reader) = ChannelIntake::new(window, ChannelGrant::new(server.clone(), id));
        let path = DataPath {
            outer: outer_write,
            server,
            id,
            reader,
            replies: Replies::default(),
            kind: ChannelKind::Forward,
            cancel: cancel.clone(),
            closing: closing.clone(),
        };
        context.tracker.spawn(establish(
            path,
            reply,
            open,
            settled.clone(),
            context.clone(),
        ));
        Self {
            intake,
            cancel,
            closing,
            settled,
            traffic: Arc::clone(&context.traffic),
        }
    }

    pub(crate) fn finished(&self) -> bool {
        self.cancel.is_cancelled() && self.settled.is_cancelled()
    }

    pub(crate) fn data(&self, data: &[u8]) -> Result<(), IntakeError> {
        self.intake.push_data(data)?;
        self.traffic.add_in(data.len());
        Ok(())
    }

    pub(crate) fn extended_data(&self, len: usize) -> Result<(), IntakeError> {
        self.intake.consume_extended(len)
    }

    pub(crate) fn eof(&self) {
        self.intake.push_eof();
    }

    pub(crate) fn close(self) {
        self.intake.push_close();
        self.closing.cancel();
    }
}

async fn establish(
    path: DataPath,
    reply: ChannelOpenHandle,
    open: ForwardOpen,
    settled: CancellationToken,
    context: BridgeContext,
) {
    let settling = settled.drop_guard();
    let ForwardOpen {
        inner,
        target,
        originator,
    } = open;
    let opening = inner.handle.channel_open_direct_tcpip(
        target.host.clone(),
        u32::from(target.port),
        originator.address,
        originator.port,
    );
    tokio::pin!(opening);
    let session_id = &context.session_id;
    let port = u32::from(target.port);
    let channel = match wait_open(opening.as_mut(), &path.cancel, inner.deadline).await {
        InnerOpened::Ready(channel) => channel,
        InnerOpened::Cancelled => return,
        InnerOpened::Refused(error) => {
            path.cancel.cancel();
            drop(settling);
            reply.reject(node_refusal(&error)).await;
            audit_forward(session_id, port, "refused_by_node");
            return;
        }
        InnerOpened::TimedOut => {
            path.cancel.cancel();
            reply.reject(ChannelOpenFailure::ConnectFailed).await;
            audit_forward(session_id, port, "timeout");
            close_late(opening, inner.deadline, &context.stop).await;
            return;
        }
    };
    reply.accept().await;
    audit_forward(session_id, port, "opened");
    let number = path.id.number();
    context
        .observer
        .call(|observer| observer.forward_open(number, &target));
    path.spawn(channel, &inner.handle, &context);
}

fn node_refusal(error: &russh::Error) -> ChannelOpenFailure {
    match error {
        russh::Error::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited) => {
            ChannelOpenFailure::AdministrativelyProhibited
        }
        russh::Error::ChannelOpenFailure(ChannelOpenFailure::ResourceShortage) => {
            ChannelOpenFailure::ResourceShortage
        }
        _ => ChannelOpenFailure::ConnectFailed,
    }
}

#[cfg(test)]
mod tests {
    use russh::ChannelOpenFailure;

    use super::{Originator, loopback_destination, node_refusal};

    #[test]
    fn only_the_loopback_of_the_node_is_a_forwarding_destination() {
        for (host, port, expected) in [
            ("localhost", 8080, Some(("localhost", 8080))),
            ("LocalHost", 1, Some(("localhost", 1))),
            ("localhost.", 65535, Some(("localhost", 65535))),
            ("127.0.0.1", 22, Some(("127.0.0.1", 22))),
            ("127.255.3.4", 80, Some(("127.255.3.4", 80))),
            ("::1", 5432, Some(("::1", 5432))),
            ("[::1]", 5432, Some(("::1", 5432))),
            ("localhost..", 80, None),
            ("localhost.localdomain", 80, None),
            ("ip6-localhost", 80, None),
            ("node1.jaunt.test", 80, None),
            ("127.0.0.1.", 80, None),
            ("127.1", 80, None),
            ("0177.0.0.1", 80, None),
            ("127.000.000.001", 80, None),
            ("2130706433", 80, None),
            ("0x7f.0.0.1", 80, None),
            (" 127.0.0.1", 80, None),
            ("128.0.0.1", 80, None),
            ("10.0.0.1", 80, None),
            ("0.0.0.0", 80, None),
            ("0:0:0:0:0:0:0:1", 80, None),
            ("::ffff:127.0.0.1", 80, None),
            ("[::1]:80", 80, None),
            ("::", 80, None),
            ("", 80, None),
            ("localhost", 0, None),
            ("localhost", 65536, None),
            ("127.0.0.1", u32::MAX, None),
        ] {
            let found = loopback_destination(host, port);
            let found = found
                .as_ref()
                .map(|target| (target.host.as_str(), target.port));
            assert_eq!(found, expected, "{host}:{port}");
        }
    }

    #[test]
    fn sshd_learns_the_address_of_the_real_client_and_nothing_else() {
        for (client, expected) in [
            ("203.0.113.5:40000", "203.0.113.5"),
            ("[2001:db8::7]:22", "2001:db8::7"),
            ("198.51.100.1", "198.51.100.1"),
            ("evil\nhost", "0.0.0.0"),
            ("", "0.0.0.0"),
        ] {
            let originator = Originator::of_client(client);
            assert_eq!(
                (originator.address.as_str(), originator.port),
                (expected, 0),
                "{client:?}"
            );
        }
    }

    #[test]
    fn the_refusal_of_sshd_reaches_the_user_with_its_kind() {
        let refusal = |reason| node_refusal(&russh::Error::ChannelOpenFailure(reason));
        assert_eq!(
            refusal(ChannelOpenFailure::AdministrativelyProhibited),
            ChannelOpenFailure::AdministrativelyProhibited
        );
        assert_eq!(
            refusal(ChannelOpenFailure::ResourceShortage),
            ChannelOpenFailure::ResourceShortage
        );
        assert_eq!(
            refusal(ChannelOpenFailure::Other {
                code: 77,
                reason: "anything".to_owned()
            }),
            ChannelOpenFailure::ConnectFailed
        );
        assert_eq!(
            node_refusal(&russh::Error::Disconnect),
            ChannelOpenFailure::ConnectFailed
        );
    }
}
