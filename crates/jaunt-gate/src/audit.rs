use std::net::SocketAddr;

use jaunt_tunnel::{DisconnectReason, NodeId, RejectReason, Rejection};

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
