use std::net::SocketAddr;
use std::time::Duration;

use jaunt_limits::{ClientKey, Refused};
use jaunt_ssh::OuterEvent;
use jaunt_tunnel::{DisconnectReason, NodeId, RejectReason, Rejection};

use crate::live::TerminationReason;

pub(crate) fn ssh_limited(client: ClientKey, refused: Refused, suppressed: u64) {
    tracing::info!(
        target: "jaunt::audit",
        event = "gate.ssh.limited",
        client = %client,
        reason = refused.reason(),
        suppressed
    );
}

pub(crate) fn agent_limited(client: ClientKey, refused: Refused, suppressed: u64) {
    tracing::info!(
        target: "jaunt::audit",
        event = "agent.limited",
        client = %client,
        reason = refused.reason(),
        suppressed
    );
}

pub(crate) fn tls_refused(client: ClientKey, reason: &'static str, suppressed: u64) {
    tracing::info!(
        target: "jaunt::audit",
        event = "gate.tls.refused",
        client = %client,
        reason,
        suppressed
    );
}

pub(crate) struct KubeStream<'a> {
    pub(crate) client_addr: SocketAddr,
    pub(crate) cluster: &'a str,
    pub(crate) node_id: Option<&'a str>,
    pub(crate) session_id: Option<&'a str>,
}

pub(crate) struct SvcStream<'a> {
    pub(crate) client_addr: SocketAddr,
    pub(crate) user_id: &'a str,
    pub(crate) serial: u64,
    pub(crate) kind: Option<&'static str>,
    pub(crate) service: Option<&'a str>,
    pub(crate) node_id: Option<&'a str>,
    pub(crate) session_id: Option<&'a str>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Carried {
    pub(crate) reason: &'static str,
    pub(crate) bytes_up: u64,
    pub(crate) bytes_down: u64,
    pub(crate) duration: Duration,
}

impl Carried {
    fn duration_ms(&self) -> u64 {
        u64::try_from(self.duration.as_millis()).unwrap_or(u64::MAX)
    }
}

pub(crate) fn kube_stream_refused(stream: &KubeStream<'_>, reason: &'static str, suppressed: u64) {
    tracing::info!(
        target: "jaunt::audit",
        event = "gate.kube.stream",
        outcome = "refused",
        reason,
        client_addr = %stream.client_addr,
        service = stream.cluster,
        node_id = stream.node_id,
        session_id = stream.session_id,
        suppressed
    );
}

pub(crate) fn kube_stream_closed(stream: &KubeStream<'_>, carried: Carried) {
    tracing::info!(
        target: "jaunt::audit",
        event = "gate.kube.stream",
        outcome = "closed",
        reason = carried.reason,
        client_addr = %stream.client_addr,
        service = stream.cluster,
        node_id = stream.node_id,
        session_id = stream.session_id,
        bytes_up = carried.bytes_up,
        bytes_down = carried.bytes_down,
        duration_ms = carried.duration_ms()
    );
}

pub(crate) fn svc_stream_refused(stream: &SvcStream<'_>, reason: &'static str, suppressed: u64) {
    tracing::info!(
        target: "jaunt::audit",
        event = "gate.svc.stream",
        outcome = "refused",
        reason,
        client_addr = %stream.client_addr,
        user_id = stream.user_id,
        serial = stream.serial,
        kind = stream.kind,
        service = stream.service,
        node_id = stream.node_id,
        session_id = stream.session_id,
        suppressed
    );
}

pub(crate) fn svc_stream_closed(stream: &SvcStream<'_>, carried: Carried) {
    tracing::info!(
        target: "jaunt::audit",
        event = "gate.svc.stream",
        outcome = "closed",
        reason = carried.reason,
        client_addr = %stream.client_addr,
        user_id = stream.user_id,
        serial = stream.serial,
        kind = stream.kind,
        service = stream.service,
        node_id = stream.node_id,
        session_id = stream.session_id,
        bytes_up = carried.bytes_up,
        bytes_down = carried.bytes_down,
        duration_ms = carried.duration_ms()
    );
}

pub(crate) fn ssh_connected(client_addr: SocketAddr, peer_addr: SocketAddr, proxied: bool) {
    tracing::info!(
        target: "jaunt::audit",
        event = "gate.ssh.connect",
        client_addr = %client_addr,
        peer_addr = %peer_addr,
        proxied
    );
}

pub(crate) fn ssh_connected_in_process(client_addr: SocketAddr) {
    tracing::info!(
        target: "jaunt::audit",
        event = "gate.ssh.connect",
        client_addr = %client_addr,
        peer_addr = "in-process",
        proxied = false
    );
}

pub(crate) fn ssh_terminated(
    user_id: &str,
    serial: Option<u64>,
    reason: TerminationReason,
    connections: usize,
) {
    tracing::info!(
        target: "jaunt::audit",
        event = "gate.ssh.terminated",
        user_id,
        serial,
        reason = reason.as_str(),
        connections
    );
}

pub(crate) fn ssh_event(client_addr: SocketAddr, event: OuterEvent) {
    match event {
        OuterEvent::Connected { .. } => {}
        OuterEvent::AuthAccepted {
            user_id,
            serial,
            login,
        } => tracing::info!(
            target: "jaunt::audit",
            event = "gate.ssh.auth",
            outcome = "ok",
            client_addr = %client_addr,
            user_id,
            serial,
            login
        ),
        OuterEvent::AuthDenied { reason, login } => tracing::info!(
            target: "jaunt::audit",
            event = "gate.ssh.auth",
            outcome = "denied",
            reason = reason.reason(),
            client_addr = %client_addr,
            login
        ),
        OuterEvent::SessionRefused => tracing::info!(
            target: "jaunt::audit",
            event = "gate.ssh.session_refused",
            client_addr = %client_addr
        ),
        OuterEvent::ForwardRefused { node, refusal } => tracing::info!(
            target: "jaunt::audit",
            event = "gate.ssh.forward",
            outcome = refusal.reason(),
            client_addr = %client_addr,
            node
        ),
        OuterEvent::ForwardOpened { node, session_id } => tracing::info!(
            target: "jaunt::audit",
            event = "gate.ssh.forward",
            outcome = "allowed",
            client_addr = %client_addr,
            node,
            session_id
        ),
        OuterEvent::ForwardClosed {
            node,
            session_id,
            bytes_up,
            bytes_down,
            duration,
            reason,
        } => tracing::info!(
            target: "jaunt::audit",
            event = "gate.ssh.stream_end",
            client_addr = %client_addr,
            node,
            session_id,
            bytes_up,
            bytes_down,
            duration_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
            reason = reason.reason()
        ),
        OuterEvent::Disconnected { reason } => tracing::info!(
            target: "jaunt::audit",
            event = "gate.ssh.disconnect",
            client_addr = %client_addr,
            reason = reason.reason()
        ),
    }
}

pub(crate) fn connected(node: &NodeId, remote_addr: SocketAddr, alpn: &[u8], replaced: bool) {
    tracing::info!(
        target: "jaunt::audit",
        event = "agent.connected",
        node_id = node.as_str(),
        remote_addr = %remote_addr,
        alpn = %String::from_utf8_lossy(alpn),
        replaced
    );
}

pub(crate) fn disconnected(node: &NodeId, reason: DisconnectReason, alpn: &[u8]) {
    tracing::info!(
        target: "jaunt::audit",
        event = "agent.disconnected",
        node_id = node.as_str(),
        reason = reason.as_str(),
        alpn = %String::from_utf8_lossy(alpn)
    );
}

pub(crate) fn rejected(remote_addr: SocketAddr, rejection: &Rejection) {
    let reason = rejection.reason.as_str();
    let node_id = rejection.node.as_ref().map(NodeId::as_str);
    if matches!(
        rejection.reason,
        RejectReason::NoCertificate | RejectReason::TooManySessions
    ) {
        tracing::debug!(
            target: "jaunt::audit",
            event = "agent.rejected",
            reason,
            remote_addr = %remote_addr,
            node_id
        );
    } else {
        tracing::info!(
            target: "jaunt::audit",
            event = "agent.rejected",
            reason,
            remote_addr = %remote_addr,
            node_id
        );
    }
}
