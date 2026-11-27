mod certificate;
mod gate_class;
mod identity;
mod kube;
mod locate;
mod refusals;
mod splice;
mod svc;
mod target;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use jaunt_proto::{ControlPlane, GateTlsIssuer};
use jaunt_tunnel::{AgentRegistry, DEFAULT_MAX_HANDSHAKING, MAX_HANDSHAKING_LIMIT, MAX_TIMER};
use thiserror::Error;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

pub use certificate::GateCertificateError;
pub use identity::{
    ClientIdentityError, MAX_USER_X509_ROOTS, UserX509Roots, UserX509RootsError, UserX509Source,
};
pub use locate::{KUBE_LOCATION_CACHE, KUBE_MISS_CACHE};
pub use refusals::StreamRefusal;
pub use splice::HALF_CLOSE_GRACE;

use crate::entry::{ClassHandlers, EntryNames, EntryNamesError};
use crate::host_cert::Clock;
use crate::ssh::{DEFAULT_RENEWAL_CHECK, DEFAULT_RENEWAL_RETRY, SshGate};
use certificate::GateCertificate;
use gate_class::{GateClass, GateClassHandler};
use kube::{KubeGate, KubeHandler};
use svc::SvcGate;

pub const DEFAULT_KUBE_STREAMS_PER_ADDRESS: usize = 32;
pub const DEFAULT_KUBE_STREAMS_PER_CLUSTER: usize = 512;
pub const DEFAULT_SVC_STREAMS_PER_ADDRESS: usize = 32;
pub const DEFAULT_SVC_STREAMS_PER_USER: usize = 32;
pub const INNER_HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const CLOSE_GRACE: Duration = Duration::from_secs(2);
const MAX_STREAMS_LIMIT: usize = 1 << 20;

#[derive(Debug, Clone)]
pub struct ServiceGateConfig {
    pub domain: String,
    pub max_handshaking: usize,
    pub kube_streams_per_address: usize,
    pub kube_streams_per_cluster: usize,
    pub svc_streams_per_address: usize,
    pub svc_streams_per_user: usize,
    pub renewal_check: Duration,
    pub renewal_retry: Duration,
    pub inner_hello_timeout: Duration,
    pub half_close_grace: Duration,
}

impl ServiceGateConfig {
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            max_handshaking: DEFAULT_MAX_HANDSHAKING,
            kube_streams_per_address: DEFAULT_KUBE_STREAMS_PER_ADDRESS,
            kube_streams_per_cluster: DEFAULT_KUBE_STREAMS_PER_CLUSTER,
            svc_streams_per_address: DEFAULT_SVC_STREAMS_PER_ADDRESS,
            svc_streams_per_user: DEFAULT_SVC_STREAMS_PER_USER,
            renewal_check: DEFAULT_RENEWAL_CHECK,
            renewal_retry: DEFAULT_RENEWAL_RETRY,
            inner_hello_timeout: INNER_HELLO_TIMEOUT,
            half_close_grace: HALF_CLOSE_GRACE,
        }
    }
}

pub struct ServiceGateParts {
    pub config: ServiceGateConfig,
    pub issuer: Arc<dyn GateTlsIssuer>,
    pub user_x509: Arc<dyn UserX509Source>,
    pub control: Arc<dyn ControlPlane>,
    pub registry: AgentRegistry,
    pub ssh: Option<Arc<SshGate>>,
    pub clock: Clock,
}

#[derive(Debug, Error)]
pub enum ServiceGateError {
    #[error(transparent)]
    Domain(#[from] EntryNamesError),
    #[error("max_handshaking must be between 1 and {MAX_HANDSHAKING_LIMIT}")]
    HandshakeLimit,
    #[error("the kube and service stream limits must be between 1 and {MAX_STREAMS_LIMIT}")]
    StreamLimits,
    #[error("the renewal check and retry intervals must not be zero")]
    RenewalInterval,
    #[error(
        "the inner hello timeout and the half-close grace must be longer than zero and at most a day"
    )]
    Timers,
    #[error(transparent)]
    Certificate(#[from] GateCertificateError),
    #[error("the gate tls configuration cannot be built")]
    Tls,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServiceGateStats {
    pub handshaking: usize,
    pub kube_streams: usize,
    pub kube_addresses: usize,
    pub kube_clusters: usize,
    pub svc_streams: usize,
    pub svc_addresses: usize,
    pub svc_users: usize,
}

pub struct ServiceGate {
    certificate: Arc<GateCertificate>,
    gate: Arc<GateClass>,
    kube: Arc<KubeGate>,
    renewal_check: Duration,
    renewal_retry: Duration,
}

impl ServiceGate {
    pub async fn new(parts: ServiceGateParts) -> Result<Self, ServiceGateError> {
        let ServiceGateParts {
            config,
            issuer,
            user_x509,
            control,
            registry,
            ssh,
            clock,
        } = parts;
        let names = EntryNames::new(&[], Some(&config.domain))?;
        let domain = names
            .domain()
            .ok_or(EntryNamesError::InvalidDomain)?
            .to_owned();
        if !(1..=MAX_HANDSHAKING_LIMIT).contains(&config.max_handshaking) {
            return Err(ServiceGateError::HandshakeLimit);
        }
        let limits = [
            config.kube_streams_per_address,
            config.kube_streams_per_cluster,
            config.svc_streams_per_address,
            config.svc_streams_per_user,
        ];
        if !limits
            .iter()
            .all(|limit| (1..=MAX_STREAMS_LIMIT).contains(limit))
        {
            return Err(ServiceGateError::StreamLimits);
        }
        if config.renewal_check.is_zero() || config.renewal_retry.is_zero() {
            return Err(ServiceGateError::RenewalInterval);
        }
        let timers = [config.inner_hello_timeout, config.half_close_grace];
        if !timers
            .iter()
            .all(|timer| !timer.is_zero() && *timer <= MAX_TIMER)
        {
            return Err(ServiceGateError::Timers);
        }
        let certificate =
            Arc::new(GateCertificate::obtain(issuer, domain.clone(), Arc::clone(&clock)).await?);
        let svc = SvcGate::new(svc::SvcParts {
            domain,
            resolver: certificate.resolver(),
            user_x509,
            control: Arc::clone(&control),
            registry: registry.clone(),
            per_address: config.svc_streams_per_address,
            per_user: config.svc_streams_per_user,
            inner_hello_timeout: config.inner_hello_timeout,
            half_close_grace: config.half_close_grace,
            clock,
        });
        let gate = Arc::new(
            GateClass::new(ssh, Arc::clone(&certificate), svc, config.max_handshaking)
                .map_err(|_| ServiceGateError::Tls)?,
        );
        let kube = Arc::new(KubeGate::new(
            control,
            registry,
            kube::KubeLimits {
                per_address: config.kube_streams_per_address,
                per_cluster: config.kube_streams_per_cluster,
                half_close_grace: config.half_close_grace,
            },
        ));
        Ok(Self {
            certificate,
            gate,
            kube,
            renewal_check: config.renewal_check,
            renewal_retry: config.renewal_retry,
        })
    }

    pub fn handlers(&self) -> ClassHandlers {
        ClassHandlers {
            gate: Some(Arc::new(GateClassHandler::new(Arc::clone(&self.gate)))),
            kube: Some(Arc::new(KubeHandler::new(Arc::clone(&self.kube)))),
        }
    }

    pub async fn renew_if_due(&self) -> Result<bool, ServiceGateError> {
        Ok(self.certificate.renew_if_due().await?)
    }

    pub async fn renew_forever(&self, stop: CancellationToken) {
        self.certificate
            .renew_forever(self.renewal_check, self.renewal_retry, stop)
            .await;
    }

    pub fn certificate_serial(&self) -> u64 {
        self.certificate.serial()
    }

    pub fn certificate_valid_before(&self) -> u64 {
        self.certificate.valid_before()
    }

    pub fn kube_refused(&self, reason: StreamRefusal) -> u64 {
        self.kube.refused(reason)
    }

    pub fn svc_refused(&self, reason: StreamRefusal) -> u64 {
        self.gate.svc().refused(reason)
    }

    pub fn stats(&self) -> ServiceGateStats {
        let kube = self.kube.stats();
        let svc = self.gate.svc().stats();
        ServiceGateStats {
            handshaking: self.gate.handshaking(),
            kube_streams: kube.streams,
            kube_addresses: kube.keys,
            kube_clusters: kube.groups,
            svc_streams: svc.streams,
            svc_addresses: svc.keys,
            svc_users: svc.groups,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Held {
    streams: usize,
    keys: usize,
    groups: usize,
}

#[derive(Default)]
struct Gauge(Arc<AtomicUsize>);

impl Gauge {
    fn enter(&self) -> GaugeGuard {
        self.0.fetch_add(1, Ordering::AcqRel);
        GaugeGuard(Arc::clone(&self.0))
    }

    fn current(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }
}

struct GaugeGuard(Arc<AtomicUsize>);

impl Drop for GaugeGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

async fn close_quietly<S: AsyncWrite + Unpin>(mut stream: S) {
    match timeout(CLOSE_GRACE, stream.shutdown()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::debug!(
            target: "jaunt::gate",
            error = %error,
            "closing a refused connection failed"
        ),
        Err(_) => tracing::debug!(target: "jaunt::gate", "closing a refused connection timed out"),
    }
}
