use jaunt_ca::parse_node_identity;
use jaunt_store::{NodeState, Nodes};
use jaunt_tunnel::{BoxFuture, NodeId, PeerAuthenticator, RejectReason, Rejection};

pub(crate) struct NodeAuthenticator {
    nodes: Nodes,
}

impl NodeAuthenticator {
    pub(crate) fn new(nodes: Nodes) -> Self {
        Self { nodes }
    }

    async fn check(&self, peer_cert_der: &[u8]) -> Result<NodeId, Rejection> {
        let identity = parse_node_identity(peer_cert_der)
            .map_err(|_| Rejection::new(RejectReason::UnknownNode))?;
        let node = NodeId::new(identity.node_id.hyphenated().to_string())?;
        let reject = |reason| Rejection::of_node(reason, node.clone());
        let stored = match self.nodes.get(node.as_str()).await {
            Ok(Some(stored)) => stored,
            Ok(None) => return Err(reject(RejectReason::UnknownNode)),
            Err(error) => {
                tracing::error!(
                    target: "jaunt::agents",
                    node_id = node.as_str(),
                    error = %error,
                    "loading the node of an agent connection failed"
                );
                return Err(reject(RejectReason::Unavailable));
            }
        };
        if stored.state != NodeState::Active {
            return Err(reject(RejectReason::Inactive));
        }
        if hex(&identity.subject_public_key_sha256) != stored.tls_spki_sha256 {
            return Err(reject(RejectReason::KeyMismatch));
        }
        Ok(node)
    }
}

impl PeerAuthenticator for NodeAuthenticator {
    fn authenticate<'a>(
        &'a self,
        peer_cert_der: &'a [u8],
    ) -> BoxFuture<'a, Result<NodeId, Rejection>> {
        Box::pin(self.check(peer_cert_der))
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}
