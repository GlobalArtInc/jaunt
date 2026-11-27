use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jaunt_limits::{ClientKey, ConcurrencyLimiter, DEFAULT_CAPACITY};
use jaunt_proto::{ControlPlane, KUBE_SESSION_ID_PREFIX, LocateServiceRequest, ServiceKind};
use jaunt_tunnel::{
    AgentRegistry, BoxFuture, H2Io, NodeId, OpenError, ServiceName, SessionId, StreamKind,
    StreamMeta,
};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use super::locate::{Located, LocationCache, MAX_CACHED_CLUSTERS};
use super::refusals::{StreamRefusal, StreamRefusals};
use super::splice::{Ledger, splice};
use super::{Gauge, Held, close_quietly};
use crate::audit::{self, KubeStream};
use crate::entry::{ClassConnection, ClassHandler, EntryClass, EntryIo, EntryStream};
use crate::route::{CONTROL_TIMEOUT, OPEN_TIMEOUT};

const MAX_TRACKED_CLUSTERS: usize = 4096;
const SESSION_ID_BYTES: usize = 16;

#[derive(Debug, Clone, Copy)]
pub(crate) struct KubeLimits {
    pub(crate) per_address: usize,
    pub(crate) per_cluster: usize,
    pub(crate) half_close_grace: Duration,
}

pub(crate) struct KubeGate {
    control: Arc<dyn ControlPlane>,
    registry: AgentRegistry,
    cache: LocationCache,
    per_address: ConcurrencyLimiter<ClientKey>,
    per_cluster: ConcurrencyLimiter<String>,
    refusals: StreamRefusals,
    streams: Gauge,
    half_close_grace: Duration,
}

impl KubeGate {
    pub(crate) fn new(
        control: Arc<dyn ControlPlane>,
        registry: AgentRegistry,
        limits: KubeLimits,
    ) -> Self {
        Self {
            control,
            registry,
            cache: LocationCache::new(MAX_CACHED_CLUSTERS, Arc::new(Instant::now)),
            per_address: ConcurrencyLimiter::new(limits.per_address, DEFAULT_CAPACITY),
            per_cluster: ConcurrencyLimiter::new(limits.per_cluster, MAX_TRACKED_CLUSTERS),
            refusals: StreamRefusals::new(),
            streams: Gauge::default(),
            half_close_grace: limits.half_close_grace,
        }
    }

    pub(crate) fn refused(&self, reason: StreamRefusal) -> u64 {
        self.refusals.refused(reason)
    }

    pub(super) fn stats(&self) -> Held {
        Held {
            streams: self.streams.current(),
            keys: self.per_address.tracked(),
            groups: self.per_cluster.tracked(),
        }
    }

    async fn serve(
        &self,
        connection: ClassConnection<Box<dyn EntryIo>>,
        shutdown: CancellationToken,
    ) {
        let ClassConnection {
            route,
            stream,
            stream_slot,
            ..
        } = connection;
        let _stream_slot = stream_slot;
        let EntryClass::Kube(cluster) = &route.class else {
            close_quietly(stream).await;
            return;
        };
        let mut record = KubeStream {
            client_addr: route.client_addr,
            cluster,
            node_id: None,
            session_id: None,
        };
        let _address = if route.local {
            None
        } else {
            let Ok(address) = self
                .per_address
                .try_acquire(ClientKey::of(route.client_addr.ip()))
            else {
                return self
                    .refuse(stream, &record, StreamRefusal::AddressLimit)
                    .await;
            };
            Some(address)
        };
        let located = tokio::select! {
            biased;
            () = shutdown.cancelled() => return,
            located = self.cache.locate(cluster, || self.fetch(cluster)) => located,
        };
        let node = match located {
            Located::Node(node) => node,
            Located::Unknown => {
                return self
                    .refuse(stream, &record, StreamRefusal::UnknownCluster)
                    .await;
            }
            Located::Unavailable => {
                return self
                    .refuse(stream, &record, StreamRefusal::ControlUnavailable)
                    .await;
            }
        };
        record.node_id = Some(node.as_str());
        let Ok(_cluster) = self.per_cluster.try_acquire(cluster.clone()) else {
            return self
                .refuse(stream, &record, StreamRefusal::ClusterLimit)
                .await;
        };
        let session = kube_session_id();
        record.session_id = Some(session.as_str());
        let opened = tokio::select! {
            biased;
            () = shutdown.cancelled() => return,
            opened = self.open(&node, cluster, &session, route.client_addr) => opened,
        };
        let io = match opened {
            Ok(io) => io,
            Err(reason) => {
                if reason == StreamRefusal::NodeNotConnected {
                    self.cache.forget(cluster, &node);
                }
                return self.refuse(stream, &record, reason).await;
            }
        };
        let _open = self.streams.enter();
        let (client_addr, cluster, node_id) =
            (route.client_addr, cluster.clone(), node.as_str().to_owned());
        let mut ledger = Ledger::new(move |carried| {
            let stream = KubeStream {
                client_addr,
                cluster: &cluster,
                node_id: Some(&node_id),
                session_id: Some(&session),
            };
            audit::kube_stream_closed(&stream, carried);
        });
        splice(stream, io, &shutdown, self.half_close_grace, &mut ledger).await;
    }

    async fn fetch(&self, cluster: &str) -> Located {
        let request = LocateServiceRequest {
            kind: ServiceKind::Kubernetes,
            name: cluster.to_owned(),
        };
        match timeout(CONTROL_TIMEOUT, self.control.locate_service(request)).await {
            Ok(Ok(Some(location))) => match NodeId::new(location.node_id) {
                Ok(node) if location.kind == ServiceKind::Kubernetes => Located::Node(node),
                Ok(_) | Err(_) => Located::Unavailable,
            },
            Ok(Ok(None)) => Located::Unknown,
            Ok(Err(_)) | Err(_) => Located::Unavailable,
        }
    }

    async fn open(
        &self,
        node: &NodeId,
        cluster: &str,
        session: &str,
        client: SocketAddr,
    ) -> Result<H2Io, StreamRefusal> {
        let meta = SessionId::new(session)
            .and_then(|session| {
                ServiceName::new(cluster).and_then(|service| {
                    StreamMeta::with_service(session, StreamKind::Kube, service, client.to_string())
                })
            })
            .map_err(|_| StreamRefusal::AgentUnavailable)?;
        match timeout(OPEN_TIMEOUT, self.registry.open_stream(node, &meta)).await {
            Ok(Ok(io)) => Ok(io),
            Ok(Err(error)) => Err(open_refusal(&error)),
            Err(_) => Err(StreamRefusal::AgentUnavailable),
        }
    }

    async fn refuse(&self, stream: EntryStream, record: &KubeStream<'_>, reason: StreamRefusal) {
        if let Some(suppressed) = self.refusals.throttled(reason) {
            audit::kube_stream_refused(record, reason.as_str(), suppressed);
        }
        close_quietly(stream).await;
    }
}

pub(crate) fn open_refusal(error: &OpenError) -> StreamRefusal {
    match error {
        OpenError::NotConnected => StreamRefusal::NodeNotConnected,
        OpenError::Refused(400) => StreamRefusal::KindNotServed,
        OpenError::Refused(_)
        | OpenError::InvalidMetadata(_)
        | OpenError::AtCapacity
        | OpenError::Closed
        | OpenError::Timeout => StreamRefusal::AgentUnavailable,
    }
}

fn kube_session_id() -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let random: [u8; SESSION_ID_BYTES] = rand::random();
    let mut id = String::with_capacity(KUBE_SESSION_ID_PREFIX.len() + 2 * SESSION_ID_BYTES);
    id.push_str(KUBE_SESSION_ID_PREFIX);
    for byte in random {
        id.push(char::from(DIGITS[usize::from(byte >> 4)]));
        id.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    id
}

pub(crate) struct KubeHandler {
    gate: Arc<KubeGate>,
}

impl KubeHandler {
    pub(crate) fn new(gate: Arc<KubeGate>) -> Self {
        Self { gate }
    }
}

impl ClassHandler for KubeHandler {
    fn serve(
        &self,
        connection: ClassConnection<Box<dyn EntryIo>>,
        shutdown: CancellationToken,
    ) -> BoxFuture<'static, ()> {
        let gate = Arc::clone(&self.gate);
        Box::pin(async move { gate.serve(connection, shutdown).await })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use jaunt_proto::is_kube_session_id;
    use jaunt_tunnel::{OpenError, SessionId};

    use super::{StreamRefusal, kube_session_id, open_refusal};

    #[test]
    fn session_ids_have_the_shape_control_expects_and_do_not_repeat() {
        let ids: HashSet<String> = (0..256).map(|_| kube_session_id()).collect();
        assert_eq!(ids.len(), 256);
        for id in &ids {
            assert!(is_kube_session_id(id), "{id}");
            assert!(SessionId::new(id.clone()).is_ok(), "{id}");
        }
    }

    #[test]
    fn an_agent_that_does_not_serve_the_kind_is_told_apart_from_other_failures() {
        assert_eq!(
            open_refusal(&OpenError::NotConnected),
            StreamRefusal::NodeNotConnected
        );
        assert_eq!(
            open_refusal(&OpenError::Refused(400)),
            StreamRefusal::KindNotServed
        );
        for other in [
            OpenError::Refused(503),
            OpenError::AtCapacity,
            OpenError::Closed,
            OpenError::Timeout,
        ] {
            assert_eq!(
                open_refusal(&other),
                StreamRefusal::AgentUnavailable,
                "{other:?}"
            );
        }
    }
}
