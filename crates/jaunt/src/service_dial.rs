use std::fmt;
use std::io;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use jaunt_proto::{GATE_ALPN_SVC, ServiceKind};
use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::gate_config::{StoredGateError, service_gate};
use crate::gate_tls::{
    GateError, GateProtocol, ServiceGate, certificate_problem, connect_with, finish_config,
    pinned_config, tls_error,
};
use crate::ls::kind_label;
use crate::profile::ProfileName;
use crate::service_identity::{IdentityError, ProfileIdentity};
use crate::ssh_config::{is_dns_label, is_dns_name};
use crate::store::{ProfileStore, StoreError};
use crate::user_x509::X509Identity;

pub type ServiceStream = TlsStream<TlsStream<TcpStream>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialKind {
    Db,
    Tcp,
}

impl DialKind {
    pub const fn service_kind(self) -> ServiceKind {
        match self {
            DialKind::Db => ServiceKind::Postgres,
            DialKind::Tcp => ServiceKind::Tcp,
        }
    }

    pub fn label(self) -> &'static str {
        kind_label(self.service_kind())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceName(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "a service name is one DNS label: 1 to 63 characters of a-z, 0-9 and '-', starting and ending with a letter or digit"
)]
pub struct ServiceNameError;

impl ServiceName {
    pub fn parse(text: &str) -> Result<ServiceName, ServiceNameError> {
        if is_dns_label(text) {
            Ok(ServiceName(text.to_owned()))
        } else {
            Err(ServiceNameError)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ServiceName {
    type Err = ServiceNameError;

    fn from_str(text: &str) -> Result<ServiceName, ServiceNameError> {
        ServiceName::parse(text)
    }
}

impl fmt::Display for ServiceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub struct ClientIdentity {
    key: Arc<CertifiedKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the stored X.509 certificate cannot be used with its key: run `jaunt login` again")]
pub struct UnusableIdentity;

impl ClientIdentity {
    pub fn new(
        certificate_der: Vec<u8>,
        key_pkcs8: Vec<u8>,
    ) -> Result<ClientIdentity, UnusableIdentity> {
        let provider = rustls::crypto::ring::default_provider();
        let key = CertifiedKey::from_der(
            vec![CertificateDer::from(certificate_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pkcs8)),
            &provider,
        )
        .map_err(|_| UnusableIdentity)?;
        Ok(ClientIdentity { key: Arc::new(key) })
    }

    pub fn from_x509(identity: &X509Identity) -> Result<ClientIdentity, UnusableIdentity> {
        ClientIdentity::new(
            identity.certificate_der().to_vec(),
            identity.key_pkcs8().to_vec(),
        )
    }

    pub fn certificate_der(&self) -> &[u8] {
        self.key
            .cert
            .first()
            .map_or(&[], |certificate| certificate.as_ref())
    }
}

impl fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("certificate_bytes", &self.certificate_der().len())
            .field("key", &"[redacted]")
            .finish()
    }
}

pub struct Prepared {
    pub gate: ServiceGate,
    pub identity: ClientIdentity,
}

#[derive(Debug, thiserror::Error)]
pub enum DialError {
    #[error(transparent)]
    Gate(#[from] GateError),
    #[error("the name `{name}` does not fit in a TLS name under the service domain {domain}")]
    Name { name: String, domain: String },
    #[error(
        "the gate refused the connection (no access, service unavailable or revoked): run `jaunt ls --kind {kind}` to see what you can reach"
    )]
    Refused { kind: &'static str },
    #[error("the TLS handshake with the service timed out")]
    InnerTimeout,
}

pub fn inner_server_name(
    gate: &ServiceGate,
    kind: DialKind,
    name: &ServiceName,
) -> Result<ServerName<'static>, DialError> {
    let full = format!("{}.{}.{}", name.as_str(), kind.label(), gate.domain);
    let unfit = || DialError::Name {
        name: name.as_str().to_owned(),
        domain: gate.domain.clone(),
    };
    if !is_dns_name(&full) {
        return Err(unfit());
    }
    ServerName::try_from(full).map_err(|_| unfit())
}

pub fn service_config(
    roots: &[Vec<u8>],
    identity: &ClientIdentity,
    alpn: Option<&str>,
) -> Result<Arc<ClientConfig>, DialError> {
    let config = pinned_config(roots)?
        .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(Arc::clone(&identity.key))));
    Ok(finish_config(config, alpn))
}

pub async fn dial(
    gate: &ServiceGate,
    identity: &ClientIdentity,
    kind: DialKind,
    name: &ServiceName,
) -> Result<ServiceStream, DialError> {
    let server_name = inner_server_name(gate, kind, name)?;
    let outer_config = service_config(&gate.route.roots, identity, Some(GATE_ALPN_SVC))?;
    let inner_config = service_config(&gate.route.roots, identity, None)?;
    let outer = connect_with(&gate.route, outer_config, GateProtocol::Svc).await?;
    match timeout(
        gate.inner_handshake_timeout,
        TlsConnector::from(inner_config).connect(server_name, outer),
    )
    .await
    {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(err)) => Err(inner_failure(&err, kind)),
        Err(_) => Err(DialError::InnerTimeout),
    }
}

fn inner_failure(err: &io::Error, kind: DialKind) -> DialError {
    match tls_error(err).and_then(certificate_problem) {
        Some(problem) => DialError::Gate(problem),
        None => DialError::Refused { kind: kind.label() },
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ServiceSetupError {
    #[error(
        "profile `{profile}` holds no TLS settings of the gate, so databases and TCP services cannot be reached: run `jaunt login --profile {profile}`; if this message stays, the server does not offer them"
    )]
    NotOffered { profile: ProfileName },
    #[error(
        "the gate of profile `{profile}` does not accept database and TCP connections ({GATE_ALPN_SVC}): if the server offers them now, run `jaunt login --profile {profile}`"
    )]
    NoSvc { profile: ProfileName },
    #[error(
        "the stored gate settings of profile `{profile}` cannot be used: {source}; run `jaunt login --profile {profile}`"
    )]
    Settings {
        profile: ProfileName,
        source: StoredGateError,
    },
    #[error(transparent)]
    Store(#[from] StoreError),
}

pub fn service_gate_for(
    store: &ProfileStore,
    profile: &ProfileName,
    now: i64,
) -> Result<ServiceGate, ServiceSetupError> {
    let stored = store
        .read_gate_services()?
        .ok_or_else(|| ServiceSetupError::NotOffered {
            profile: profile.clone(),
        })?;
    service_gate(&stored, now).map_err(|source| match source {
        StoredGateError::NoSvc => ServiceSetupError::NoSvc {
            profile: profile.clone(),
        },
        source => ServiceSetupError::Settings {
            profile: profile.clone(),
            source,
        },
    })
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Dial(#[from] DialError),
    #[error("the profile is busy (a sign-in may be in progress); try again")]
    Busy,
    #[error("the certificate check before the connection was interrupted")]
    Interrupted,
}

pub const PREPARE_DEADLINE: Duration = Duration::from_secs(60);

pub struct ServiceDialer {
    identity: Arc<ProfileIdentity>,
    turn: Arc<Mutex<()>>,
    prepare_deadline: Duration,
}

impl ServiceDialer {
    pub fn new(identity: Arc<ProfileIdentity>) -> ServiceDialer {
        ServiceDialer {
            identity,
            turn: Arc::new(Mutex::new(())),
            prepare_deadline: PREPARE_DEADLINE,
        }
    }

    pub fn with_prepare_deadline(mut self, deadline: Duration) -> ServiceDialer {
        self.prepare_deadline = deadline;
        self
    }

    pub async fn connect(
        &self,
        kind: DialKind,
        name: &ServiceName,
    ) -> Result<ServiceStream, ConnectError> {
        let identity = Arc::clone(&self.identity);
        let turn = Arc::clone(&self.turn);
        let prepared = timeout(self.prepare_deadline, async move {
            let held = turn.lock_owned().await;
            tokio::task::spawn_blocking(move || {
                let outcome = identity.load();
                drop(held);
                outcome
            })
            .await
        })
        .await;
        let prepared = match prepared {
            Err(_) => return Err(ConnectError::Busy),
            Ok(Err(_)) => return Err(ConnectError::Interrupted),
            Ok(Ok(prepared)) => prepared?,
        };
        Ok(dial(&prepared.gate, &prepared.identity, kind, name).await?)
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair};

    use super::{
        ClientIdentity, DialError, DialKind, ServiceName, UnusableIdentity, inner_server_name,
        service_config,
    };
    use crate::gate_tls::{GateRoute, ServiceGate};

    fn gate(domain: &str) -> ServiceGate {
        ServiceGate::new(
            GateRoute::new("svc.example.test".to_owned(), 443, Vec::new()),
            domain.to_owned(),
        )
    }

    #[test]
    fn a_service_name_is_one_lowercase_dns_label() {
        let longest = "a".repeat(63);
        for good in ["orders", "a", "lk-ru-prod", "0db", longest.as_str()] {
            assert_eq!(ServiceName::parse(good).unwrap().as_str(), good);
        }
        let too_long = "a".repeat(64);
        for bad in [
            "",
            "Orders",
            "a_b",
            "a.b",
            "-a",
            "a-",
            "../etc",
            "a/b",
            "a b",
            "ä",
            "a\n",
            too_long.as_str(),
        ] {
            assert!(ServiceName::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_inner_name_is_the_service_then_the_kind_then_the_domain() {
        let name = ServiceName::parse("orders").unwrap();
        let tcp = ServiceName::parse("grafana").unwrap();

        let db = inner_server_name(&gate("svc.example.test"), DialKind::Db, &name).unwrap();
        let grafana = inner_server_name(&gate("svc.example.test"), DialKind::Tcp, &tcp).unwrap();

        assert_eq!(db.to_str(), "orders.db.svc.example.test");
        assert_eq!(grafana.to_str(), "grafana.tcp.svc.example.test");
        let long_domain = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(56)
        );
        let short = ServiceName::parse("x").unwrap();
        assert!(inner_server_name(&gate(&long_domain), DialKind::Db, &short).is_ok());
        let longer = ServiceName::parse("xy").unwrap();
        assert!(matches!(
            inner_server_name(&gate(&long_domain), DialKind::Db, &longer),
            Err(DialError::Name { .. })
        ));
    }

    #[test]
    fn both_layers_present_the_client_certificate_and_only_the_outer_one_names_a_protocol() {
        let mut root = CertificateParams::new(Vec::<String>::new()).unwrap();
        root.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root = root.self_signed(&KeyPair::generate().unwrap()).unwrap();
        let key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let identity = ClientIdentity::new(leaf.der().to_vec(), key.serialize_der()).unwrap();
        let roots = vec![root.der().to_vec()];

        let outer = service_config(&roots, &identity, Some("jaunt-svc/1")).unwrap();
        let inner = service_config(&roots, &identity, None).unwrap();

        assert!(outer.client_auth_cert_resolver.has_certs());
        assert!(inner.client_auth_cert_resolver.has_certs());
        assert_eq!(outer.alpn_protocols, [b"jaunt-svc/1".to_vec()]);
        assert!(inner.alpn_protocols.is_empty());
        assert_eq!(identity.certificate_der(), leaf.der().as_ref());
        let mismatched = ClientIdentity::new(
            leaf.der().to_vec(),
            KeyPair::generate().unwrap().serialize_der(),
        );
        assert_eq!(mismatched.err(), Some(UnusableIdentity));
        assert!(format!("{identity:?}").contains("[redacted]"));
    }
}
