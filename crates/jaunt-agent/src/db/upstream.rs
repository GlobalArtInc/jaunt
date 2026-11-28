use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use jaunt_pgwire::{
    BackendDecoder, BackendKeyData, BackendMessage, DecodeError, Event, Limits, Notice,
    StartupMessage,
};
use jaunt_proto::PostgresTls;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::audit::ProtocolProblem;
use super::cancel::CancelTarget;
use super::wire::{AUTHENTICATION_OK, SSL_ACCEPTED, SSL_REQUEST, cancel_request};
use crate::clock::Clock;
use crate::keys::TlsKey;
use crate::verify::decode_der;

pub type Upstream = TlsStream<TcpStream>;

const MAX_CA_FILE_BYTES: u64 = 1024 * 1024;
const READ_CHUNK: usize = 16 * 1024;
const MAX_GREETING_BYTES: usize = 64 * 1024;
const ALPN: &[u8] = b"postgresql";

pub const SAFE_PARAMETERS: &[&str] = &[
    "application_name",
    "client_encoding",
    "DateStyle",
    "default_transaction_read_only",
    "in_hot_standby",
    "integer_datetimes",
    "IntervalStyle",
    "is_superuser",
    "scram_iterations",
    "search_path",
    "server_encoding",
    "server_version",
    "session_authorization",
    "standard_conforming_strings",
    "TimeZone",
];

pub const STANDARD_CONFORMING_STRINGS: &str = "standard_conforming_strings";

pub fn is_safe_parameter(name: &str) -> bool {
    SAFE_PARAMETERS.contains(&name)
}

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("the service has no PostgreSQL settings in the local configuration")]
    NotConfigured,
    #[error("the database user or name granted by control cannot be sent to the database")]
    GrantedNames,
    #[error("postgres.tls.ca_file is not set; the agent trusts only the configured CA")]
    NoCaFile,
    #[error("cannot read postgres.tls.ca_file: {0}")]
    CaFileRead(std::io::ErrorKind),
    #[error("postgres.tls.ca_file is larger than 1 MiB")]
    CaFileTooLarge,
    #[error("postgres.tls.ca_file holds no usable PEM certificate")]
    CaFileUnusable,
    #[error("the database name to verify is not a DNS name or an IP address")]
    ServerName,
    #[error("the db-client certificate from control is malformed or not for the session key")]
    Certificate,
    #[error("the TLS settings for the database cannot be built")]
    TlsConfig,
    #[error("connecting to the database failed: {0}")]
    Connect(std::io::ErrorKind),
    #[error("the database did not accept the connection in time")]
    Timeout,
    #[error("the database refused TLS")]
    TlsRefused,
    #[error("the TLS handshake with the database failed: {0}")]
    Handshake(&'static str),
    #[error("the connection to the database failed: {0}")]
    Io(std::io::ErrorKind),
    #[error("the database closed the connection during the startup")]
    Closed,
}

pub enum LoginError {
    Password,
    Refused(Notice),
    Protocol(ProtocolProblem),
    Upstream(UpstreamError),
}

pub struct Login {
    pub client_bytes: Vec<u8>,
    pub key_data: Option<BackendKeyData>,
    pub decoder: BackendDecoder,
    pub backslash_escapes: bool,
}

pub struct Trust {
    pub roots: Arc<RootCertStore>,
    pub server_name: ServerName<'static>,
}

pub async fn load_trust(tls: &PostgresTls, address: &str) -> Result<Trust, UpstreamError> {
    let path = PathBuf::from(tls.ca_file.as_deref().ok_or(UpstreamError::NoCaFile)?);
    let name = match &tls.server_name {
        Some(name) => name.clone(),
        None => host_of(address).to_owned(),
    };
    let server_name = ServerName::try_from(name).map_err(|_| UpstreamError::ServerName)?;
    let roots = tokio::task::spawn_blocking(move || read_roots(&path))
        .await
        .map_err(|_| UpstreamError::CaFileRead(std::io::ErrorKind::Other))??;
    Ok(Trust {
        roots: Arc::new(roots),
        server_name,
    })
}

fn host_of(address: &str) -> &str {
    let host = address.rsplit_once(':').map_or(address, |(host, _)| host);
    host.strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host)
}

fn read_roots(path: &std::path::Path) -> Result<RootCertStore, UpstreamError> {
    let file =
        std::fs::File::open(path).map_err(|error| UpstreamError::CaFileRead(error.kind()))?;
    let mut bytes = Vec::new();
    file.take(MAX_CA_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| UpstreamError::CaFileRead(error.kind()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CA_FILE_BYTES {
        return Err(UpstreamError::CaFileTooLarge);
    }
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(&bytes) {
        let certificate = certificate.map_err(|_| UpstreamError::CaFileUnusable)?;
        roots
            .add(certificate)
            .map_err(|_| UpstreamError::CaFileUnusable)?;
    }
    if roots.is_empty() {
        return Err(UpstreamError::CaFileUnusable);
    }
    Ok(roots)
}

fn builder(
    provider: &Arc<CryptoProvider>,
    roots: &Arc<RootCertStore>,
) -> Result<rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert>, UpstreamError> {
    Ok(ClientConfig::builder_with_provider(Arc::clone(provider))
        .with_protocol_versions(&[&TLS13, &TLS12])
        .map_err(|_| UpstreamError::TlsConfig)?
        .with_root_certificates(Arc::clone(roots)))
}

pub fn session_config(
    provider: &Arc<CryptoProvider>,
    roots: &Arc<RootCertStore>,
    certificate_der: &str,
    key: &TlsKey,
) -> Result<Arc<ClientConfig>, UpstreamError> {
    let der = decode_der(certificate_der).ok_or(UpstreamError::Certificate)?;
    let signing =
        rustls::crypto::ring::sign::any_eddsa_type(&PrivatePkcs8KeyDer::from(key.pkcs8_der()))
            .map_err(|_| UpstreamError::Certificate)?;
    let certified = CertifiedKey::new(vec![CertificateDer::from(der)], signing);
    certified
        .keys_match()
        .map_err(|_| UpstreamError::Certificate)?;
    let mut config = builder(provider, roots)?
        .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}

pub fn cancel_config(
    provider: &Arc<CryptoProvider>,
    roots: &Arc<RootCertStore>,
) -> Result<Arc<ClientConfig>, UpstreamError> {
    let mut config = builder(provider, roots)?.with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}

async fn bounded<T>(
    clock: &Arc<dyn Clock>,
    deadline: SystemTime,
    work: impl Future<Output = Result<T, UpstreamError>>,
) -> Result<T, UpstreamError> {
    tokio::select! {
        biased;
        result = work => result,
        () = clock.sleep_until(deadline) => Err(UpstreamError::Timeout),
    }
}

pub fn deadline(clock: &Arc<dyn Clock>, after: Duration) -> SystemTime {
    let now = clock.now();
    now.checked_add(after).unwrap_or(now)
}

pub async fn open(
    address: &str,
    server_name: &ServerName<'static>,
    config: Arc<ClientConfig>,
    clock: &Arc<dyn Clock>,
    timeout: Duration,
) -> Result<Upstream, UpstreamError> {
    let deadline = deadline(clock, timeout);
    bounded(clock, deadline, async {
        let mut tcp = TcpStream::connect(address)
            .await
            .map_err(|error| UpstreamError::Connect(error.kind()))?;
        tcp.set_nodelay(true)
            .map_err(|error| UpstreamError::Io(error.kind()))?;
        tcp.write_all(&SSL_REQUEST)
            .await
            .map_err(|error| UpstreamError::Io(error.kind()))?;
        let mut answer = [0_u8; 1];
        tcp.read_exact(&mut answer)
            .await
            .map_err(|error| UpstreamError::Io(error.kind()))?;
        if answer[0] != SSL_ACCEPTED {
            return Err(UpstreamError::TlsRefused);
        }
        TlsConnector::from(config)
            .connect(server_name.clone(), tcp)
            .await
            .map_err(|error| UpstreamError::Handshake(handshake_reason(&error)))
    })
    .await
}

fn handshake_reason(error: &std::io::Error) -> &'static str {
    use rustls::CertificateError;
    match error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        Some(rustls::Error::InvalidCertificate(reason)) => match reason {
            CertificateError::UnknownIssuer => "the database certificate is not signed by ca_file",
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                "the database certificate does not carry the expected name"
            }
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                "the database certificate has expired"
            }
            _ => "the database certificate is not valid",
        },
        Some(rustls::Error::AlertReceived(_)) => "the database sent a TLS alert",
        Some(_) => "the TLS protocol failed",
        None => "the connection failed",
    }
}

pub fn server_problem(error: &DecodeError) -> ProtocolProblem {
    match error {
        DecodeError::TooLarge { .. }
        | DecodeError::PendingTooLarge { .. }
        | DecodeError::BindPrefixTooLarge { .. } => ProtocolProblem::ServerTooLarge,
        _ => ProtocolProblem::ServerMalformed,
    }
}

fn greet(client_bytes: &mut Vec<u8>, bytes: &[u8]) -> Result<(), LoginError> {
    if client_bytes.len().saturating_add(bytes.len()) > MAX_GREETING_BYTES {
        return Err(LoginError::Protocol(ProtocolProblem::ServerTooLarge));
    }
    client_bytes.extend_from_slice(bytes);
    Ok(())
}

pub async fn login(
    upstream: &mut Upstream,
    startup: &StartupMessage,
    clock: &Arc<dyn Clock>,
    timeout: Duration,
) -> Result<Login, LoginError> {
    let encoded = startup
        .encode()
        .map_err(|_| LoginError::Protocol(ProtocolProblem::ClientTooLarge))?;
    let deadline = deadline(clock, timeout);
    let exchange = async {
        upstream
            .write_all(&encoded)
            .await
            .map_err(|error| LoginError::Upstream(UpstreamError::Io(error.kind())))?;
        upstream
            .flush()
            .await
            .map_err(|error| LoginError::Upstream(UpstreamError::Io(error.kind())))?;
        let mut decoder = BackendDecoder::new(Limits::default())
            .map_err(|_| LoginError::Upstream(UpstreamError::TlsConfig))?;
        let mut client_bytes = Vec::new();
        let mut key_data = None;
        let mut authenticated = false;
        let mut backslash_escapes = false;
        let mut buffer = vec![0_u8; READ_CHUNK];
        loop {
            loop {
                let frame = match decoder.next_event() {
                    Ok(Some(Event::Frame(frame))) => frame,
                    Ok(Some(Event::Continuation(_))) => {
                        return Err(LoginError::Protocol(ProtocolProblem::ServerUnexpected));
                    }
                    Ok(None) => break,
                    Err(DecodeError::UnknownAuthentication { .. }) => {
                        return Err(LoginError::Password);
                    }
                    Err(error) => return Err(LoginError::Protocol(server_problem(&error))),
                };
                match (authenticated, frame.message()) {
                    (false, BackendMessage::NegotiateProtocolVersion(_))
                    | (_, BackendMessage::NoticeResponse(_)) => {
                        greet(&mut client_bytes, frame.raw())?;
                    }
                    (false, BackendMessage::Authentication(auth)) if auth.is_ok() => {
                        authenticated = true;
                        greet(&mut client_bytes, &AUTHENTICATION_OK)?;
                    }
                    (false, BackendMessage::Authentication(_)) => {
                        return Err(LoginError::Password);
                    }
                    (_, BackendMessage::ErrorResponse(notice)) => {
                        return Err(LoginError::Refused(notice.clone()));
                    }
                    (true, BackendMessage::ParameterStatus(status)) => {
                        if status.name == STANDARD_CONFORMING_STRINGS {
                            backslash_escapes = status.value.eq_ignore_ascii_case("off");
                        }
                        if is_safe_parameter(&status.name) {
                            greet(&mut client_bytes, frame.raw())?;
                        }
                    }
                    (true, BackendMessage::BackendKeyData(key)) if key_data.is_none() => {
                        key_data = Some(key.clone());
                        greet(&mut client_bytes, frame.raw())?;
                    }
                    (true, BackendMessage::ReadyForQuery(_)) => {
                        greet(&mut client_bytes, frame.raw())?;
                        return Ok(Login {
                            client_bytes,
                            key_data,
                            decoder,
                            backslash_escapes,
                        });
                    }
                    _ => return Err(LoginError::Protocol(ProtocolProblem::ServerUnexpected)),
                }
            }
            let read = upstream
                .read(&mut buffer)
                .await
                .map_err(|error| LoginError::Upstream(UpstreamError::Io(error.kind())))?;
            if read == 0 {
                return Err(LoginError::Upstream(UpstreamError::Closed));
            }
            decoder
                .push(&buffer[..read])
                .map_err(|error| LoginError::Protocol(server_problem(&error)))?;
        }
    };
    tokio::select! {
        biased;
        result = exchange => result,
        () = clock.sleep_until(deadline) => Err(LoginError::Upstream(UpstreamError::Timeout)),
    }
}

pub async fn send_cancel(
    target: &CancelTarget,
    key: &BackendKeyData,
    clock: &Arc<dyn Clock>,
    timeout: Duration,
) -> Result<(), UpstreamError> {
    let deadline = deadline(clock, timeout);
    let mut upstream = open(
        &target.address,
        &target.server_name,
        Arc::clone(&target.config),
        clock,
        timeout,
    )
    .await?;
    let request = cancel_request(key.process_id(), key.secret_key());
    bounded(clock, deadline, async {
        upstream
            .write_all(&request)
            .await
            .map_err(|error| UpstreamError::Io(error.kind()))?;
        upstream
            .flush()
            .await
            .map_err(|error| UpstreamError::Io(error.kind()))?;
        let mut sink = [0_u8; 64];
        while let Ok(read) = upstream.read(&mut sink).await {
            if read == 0 {
                break;
            }
        }
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::host_of;

    #[test]
    fn the_host_of_an_address_is_the_name_to_verify() {
        for (address, host) in [
            ("db.internal:5432", "db.internal"),
            ("10.0.0.5:5432", "10.0.0.5"),
            ("[2001:db8::1]:5432", "2001:db8::1"),
        ] {
            assert_eq!(host_of(address), host);
        }
    }
}
