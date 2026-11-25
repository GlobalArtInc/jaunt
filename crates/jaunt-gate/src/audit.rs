use std::net::SocketAddr;

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
