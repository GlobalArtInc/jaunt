use std::io;
use std::sync::Arc;
use std::time::Duration;

use jaunt_proto::{GATE_ALPN_SSH, GATE_ALPN_SVC};
use rustls::client::{Resumption, WantsClientCert};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{AlertDescription, CertificateError, ClientConfig, ConfigBuilder, RootCertStore};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const INNER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateRoute {
    pub host: String,
    pub port: u16,
    pub roots: Vec<Vec<u8>>,
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
}

impl GateRoute {
    pub fn new(host: String, port: u16, roots: Vec<Vec<u8>>) -> GateRoute {
        GateRoute {
            host,
            port,
            roots,
            connect_timeout: CONNECT_TIMEOUT,
            handshake_timeout: HANDSHAKE_TIMEOUT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceGate {
    pub route: GateRoute,
    pub domain: String,
    pub inner_handshake_timeout: Duration,
}

impl ServiceGate {
    pub fn new(route: GateRoute, domain: String) -> ServiceGate {
        ServiceGate {
            route,
            domain,
            inner_handshake_timeout: INNER_HANDSHAKE_TIMEOUT,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateProtocol {
    Ssh,
    Svc,
}

impl GateProtocol {
    pub const fn alpn(self) -> &'static str {
        match self {
            GateProtocol::Ssh => GATE_ALPN_SSH,
            GateProtocol::Svc => GATE_ALPN_SVC,
        }
    }

    const fn refused(self) -> GateError {
        match self {
            GateProtocol::Ssh => GateError::Alpn,
            GateProtocol::Svc => GateError::SvcAlpn,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("the pinned roots of the gate cannot be used: run `jaunt login` again")]
    Roots,
    #[error("the TLS name of the gate cannot be used: run `jaunt login` again")]
    Name,
    #[error("cannot reach the gate at {host}:{port}: {source}")]
    Connect {
        host: String,
        port: u16,
        source: io::Error,
    },
    #[error("connecting to the gate at {host}:{port} timed out")]
    ConnectTimeout { host: String, port: u16 },
    #[error("the TLS handshake with the gate timed out")]
    HandshakeTimeout,
    #[error(
        "the gate's certificate is not signed by the pinned root: a network device may be intercepting TLS; in such networks only the web console works; if the server's TLS roots changed, run `jaunt login` again"
    )]
    Intercepted,
    #[error(
        "the gate's certificate is not valid at this time: check the system clock; if it is right, a network device may be intercepting TLS, and in such networks only the web console works"
    )]
    CertificateTime,
    #[error("the gate does not offer TLS 1.3, which jaunt requires")]
    Protocol,
    #[error("the gate does not accept SSH over TLS ({GATE_ALPN_SSH})")]
    Alpn,
    #[error("the gate does not accept database and TCP connections over TLS ({GATE_ALPN_SVC})")]
    SvcAlpn,
    #[error("the TLS handshake with the gate failed")]
    Handshake,
    #[error("the TLS handshake with the gate failed: {source}")]
    HandshakeIo { source: io::Error },
}

pub fn pinned_config(
    roots: &[Vec<u8>],
) -> Result<ConfigBuilder<ClientConfig, WantsClientCert>, GateError> {
    let mut store = RootCertStore::empty();
    for root in roots {
        store
            .add(CertificateDer::from(root.clone()))
            .map_err(|_| GateError::Roots)?;
    }
    if store.is_empty() {
        return Err(GateError::Roots);
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| GateError::Roots)?
        .with_root_certificates(store))
}

pub fn finish_config(mut config: ClientConfig, alpn: Option<&str>) -> Arc<ClientConfig> {
    config.alpn_protocols = alpn
        .map(|name| name.as_bytes().to_vec())
        .into_iter()
        .collect();
    config.resumption = Resumption::disabled();
    Arc::new(config)
}

pub fn tls_config(roots: &[Vec<u8>]) -> Result<Arc<ClientConfig>, GateError> {
    let config = pinned_config(roots)?.with_no_client_auth();
    Ok(finish_config(config, Some(GATE_ALPN_SSH)))
}

pub async fn connect(route: &GateRoute) -> Result<TlsStream<TcpStream>, GateError> {
    connect_with(route, tls_config(&route.roots)?, GateProtocol::Ssh).await
}

pub async fn connect_with(
    route: &GateRoute,
    config: Arc<ClientConfig>,
    protocol: GateProtocol,
) -> Result<TlsStream<TcpStream>, GateError> {
    let name = ServerName::try_from(route.host.clone()).map_err(|_| GateError::Name)?;
    let tcp = match timeout(
        route.connect_timeout,
        TcpStream::connect((route.host.as_str(), route.port)),
    )
    .await
    {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(source)) => {
            return Err(GateError::Connect {
                host: route.host.clone(),
                port: route.port,
                source,
            });
        }
        Err(_) => {
            return Err(GateError::ConnectTimeout {
                host: route.host.clone(),
                port: route.port,
            });
        }
    };
    tcp.set_nodelay(true).map_err(|source| GateError::Connect {
        host: route.host.clone(),
        port: route.port,
        source,
    })?;
    let stream = match timeout(
        route.handshake_timeout,
        TlsConnector::from(config).connect(name, tcp),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => return Err(classify(err, protocol)),
        Err(_) => return Err(GateError::HandshakeTimeout),
    };
    if stream.get_ref().1.alpn_protocol() != Some(protocol.alpn().as_bytes()) {
        return Err(protocol.refused());
    }
    Ok(stream)
}

pub fn tls_error(err: &io::Error) -> Option<&rustls::Error> {
    err.get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
}

pub fn certificate_problem(tls: &rustls::Error) -> Option<GateError> {
    match tls {
        rustls::Error::InvalidCertificate(
            CertificateError::Expired
            | CertificateError::ExpiredContext { .. }
            | CertificateError::NotValidYet
            | CertificateError::NotValidYetContext { .. },
        ) => Some(GateError::CertificateTime),
        rustls::Error::InvalidCertificate(_) => Some(GateError::Intercepted),
        _ => None,
    }
}

fn classify(err: io::Error, protocol: GateProtocol) -> GateError {
    let Some(tls) = tls_error(&err) else {
        return GateError::HandshakeIo { source: err };
    };
    if let Some(problem) = certificate_problem(tls) {
        return problem;
    }
    match tls {
        rustls::Error::AlertReceived(AlertDescription::ProtocolVersion)
        | rustls::Error::PeerIncompatible(_) => GateError::Protocol,
        rustls::Error::AlertReceived(AlertDescription::NoApplicationProtocol)
        | rustls::Error::NoApplicationProtocol => protocol.refused(),
        _ => GateError::Handshake,
    }
}
