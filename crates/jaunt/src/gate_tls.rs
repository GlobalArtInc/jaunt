use std::io;
use std::sync::Arc;
use std::time::Duration;

use jaunt_proto::GATE_ALPN_SSH;
use rustls::client::Resumption;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{AlertDescription, CertificateError, ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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
    #[error("the TLS handshake with the gate failed")]
    Handshake,
    #[error("the TLS handshake with the gate failed: {source}")]
    HandshakeIo { source: io::Error },
}

pub fn tls_config(roots: &[Vec<u8>]) -> Result<Arc<ClientConfig>, GateError> {
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
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| GateError::Roots)?
        .with_root_certificates(store)
        .with_no_client_auth();
    config.alpn_protocols = vec![GATE_ALPN_SSH.as_bytes().to_vec()];
    config.resumption = Resumption::disabled();
    Ok(Arc::new(config))
}

pub async fn connect(route: &GateRoute) -> Result<TlsStream<TcpStream>, GateError> {
    let config = tls_config(&route.roots)?;
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
        Ok(Err(err)) => return Err(classify(err)),
        Err(_) => return Err(GateError::HandshakeTimeout),
    };
    if stream.get_ref().1.alpn_protocol() != Some(GATE_ALPN_SSH.as_bytes()) {
        return Err(GateError::Alpn);
    }
    Ok(stream)
}

fn classify(err: io::Error) -> GateError {
    let Some(tls) = err
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    else {
        return GateError::HandshakeIo { source: err };
    };
    match tls {
        rustls::Error::InvalidCertificate(
            CertificateError::Expired
            | CertificateError::ExpiredContext { .. }
            | CertificateError::NotValidYet
            | CertificateError::NotValidYetContext { .. },
        ) => GateError::CertificateTime,
        rustls::Error::InvalidCertificate(_) => GateError::Intercepted,
        rustls::Error::AlertReceived(AlertDescription::ProtocolVersion)
        | rustls::Error::PeerIncompatible(_) => GateError::Protocol,
        rustls::Error::AlertReceived(AlertDescription::NoApplicationProtocol)
        | rustls::Error::NoApplicationProtocol => GateError::Alpn,
        _ => GateError::Handshake,
    }
}
