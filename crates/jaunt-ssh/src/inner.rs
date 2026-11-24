use std::borrow::Cow;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use russh::client::{self, Handle};
use russh::keys::ssh_key::public::KeyData;
use russh::keys::{Algorithm, PublicKeyOrCertificate};
use russh::{Preferred, SshId};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::error::SshError;
use crate::host::read_pinned_host_key;
use crate::inner_ca::{InnerCa, InnerCertRequest};

const CLIENT_ID: &str = "SSH-2.0-Jaunt-agent";
const CHANNEL_BUFFER: usize = 32;
const HOST_KEY_ALGORITHMS: &[Algorithm] = &[Algorithm::Ed25519];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerTarget {
    pub sshd_addr: SocketAddr,
    pub sshd_host_key: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum InnerLoginError {
    #[error("the sshd address is not a loopback address")]
    NotLoopback,
    #[error("cannot read the pinned sshd host key")]
    HostKeyFile(#[source] SshError),
    #[error("the pinned sshd host key is not an Ed25519 OpenSSH public key")]
    HostKeyFormat,
    #[error("cannot issue the inner certificate")]
    Certificate(#[source] SshError),
    #[error("cannot connect to sshd")]
    Connect(#[source] std::io::Error),
    #[error("sshd presented a host key other than the pinned one")]
    HostKeyMismatch,
    #[error("the SSH exchange with sshd failed")]
    Protocol(#[source] russh::Error),
    #[error("sshd refused the inner certificate")]
    Refused,
}

impl InnerLoginError {
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::NotLoopback => "not_loopback",
            Self::HostKeyFile(_) => "host_key_file",
            Self::HostKeyFormat => "host_key_format",
            Self::Certificate(_) => "certificate",
            Self::Connect(_) => "connect",
            Self::HostKeyMismatch => "host_key_mismatch",
            Self::Protocol(_) => "protocol",
            Self::Refused => "refused",
        }
    }
}

pub(crate) struct InnerClient {
    pinned: KeyData,
    gone: CancellationToken,
}

impl client::Handler for InnerClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.key_data() == &self.pinned,
            PublicKeyOrCertificate::Certificate(_) => false,
        })
    }
}

impl Drop for InnerClient {
    fn drop(&mut self) {
        self.gone.cancel();
    }
}

pub(crate) struct InnerSession {
    pub(crate) handle: Handle<InnerClient>,
    pub(crate) gone: CancellationToken,
}

pub(crate) fn client_config() -> client::Config {
    client::Config {
        client_id: SshId::Standard(Cow::Borrowed(CLIENT_ID)),
        channel_buffer_size: CHANNEL_BUFFER,
        preferred: Preferred {
            key: Cow::Borrowed(HOST_KEY_ALGORITHMS),
            host_key_certificates: Cow::Borrowed(&[]),
            ..Preferred::DEFAULT
        },
        inactivity_timeout: None,
        nodelay: true,
        ..client::Config::default()
    }
}

pub(crate) async fn login(
    config: Arc<client::Config>,
    target: &InnerTarget,
    ca: &InnerCa,
    request: &InnerCertRequest,
    now_unix: u64,
) -> Result<InnerSession, InnerLoginError> {
    if !target.sshd_addr.ip().is_loopback() {
        return Err(InnerLoginError::NotLoopback);
    }
    let pinned = read_pin(&target.sshd_host_key)?;
    let (key, certificate) = ca
        .issue(request, now_unix)
        .map_err(InnerLoginError::Certificate)?;
    let tcp = TcpStream::connect(target.sshd_addr)
        .await
        .map_err(InnerLoginError::Connect)?;
    tcp.set_nodelay(true).map_err(InnerLoginError::Connect)?;
    let gone = CancellationToken::new();
    let client = InnerClient {
        pinned,
        gone: gone.clone(),
    };
    let mut handle =
        client::connect_stream(config, tcp, client)
            .await
            .map_err(|error| match error {
                russh::Error::UnknownKey => InnerLoginError::HostKeyMismatch,
                other => InnerLoginError::Protocol(other),
            })?;
    let result = handle
        .authenticate_openssh_cert(request.login.as_str(), Arc::new(key), certificate)
        .await
        .map_err(InnerLoginError::Protocol)?;
    if !result.success() {
        return Err(InnerLoginError::Refused);
    }
    Ok(InnerSession { handle, gone })
}

fn read_pin(path: &Path) -> Result<KeyData, InnerLoginError> {
    read_pinned_host_key(path).map_err(|error| match error {
        SshError::PinnedHostKey => InnerLoginError::HostKeyFormat,
        other => InnerLoginError::HostKeyFile(other),
    })
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use russh::client::Handler;
    use russh::keys::ssh_key::certificate::CertType;
    use russh::keys::{Algorithm, EcdsaCurve, PublicKeyOrCertificate};
    use tokio_util::sync::CancellationToken;

    use super::{InnerClient, InnerLoginError, InnerTarget, client_config, login, read_pin};
    use crate::inner_ca::{InnerCa, InnerCertRequest};
    use crate::test_support::{NOW, host_certificate, key};

    #[tokio::test]
    async fn only_the_bare_pinned_key_is_accepted_as_the_sshd_host_key() {
        let pinned = key(Algorithm::Ed25519).public_key().clone();
        let mut client = InnerClient {
            pinned: pinned.key_data().clone(),
            gone: CancellationToken::new(),
        };
        let certified = host_certificate(
            &key(Algorithm::Ed25519),
            &pinned,
            CertType::Host,
            NOW - 60,
            NOW + 60,
        );
        let bare = |key| PublicKeyOrCertificate::PublicKey {
            key,
            hash_alg: None,
        };
        for (presented, accepted) in [
            (bare(pinned.clone()), true),
            (bare(key(Algorithm::Ed25519).public_key().clone()), false),
            (PublicKeyOrCertificate::Certificate(certified), false),
        ] {
            assert_eq!(client.check_server_key(&presented).await.unwrap(), accepted);
        }
        assert!(client_config().preferred.host_key_certificates.is_empty());
    }

    #[test]
    fn the_pin_is_one_ed25519_public_key() {
        let dir = tempfile::tempdir().unwrap();
        let ed = key(Algorithm::Ed25519).public_key().clone();
        let ecdsa = key(Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        })
        .public_key()
        .to_openssh()
        .unwrap();
        let good = dir.path().join("good.pub");
        std::fs::write(&good, format!("{} root@node\n", ed.to_openssh().unwrap())).unwrap();
        assert_eq!(read_pin(&good).unwrap(), *ed.key_data());
        for (name, content) in [
            ("ecdsa.pub", ecdsa.as_bytes().to_vec()),
            ("garbage.pub", b"ssh-ed25519 AAAA".to_vec()),
            ("binary.pub", vec![0xff, 0xfe]),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, content).unwrap();
            assert!(
                matches!(read_pin(&path), Err(InnerLoginError::HostKeyFormat)),
                "{name}"
            );
        }
        assert!(matches!(
            read_pin(&dir.path().join("missing.pub")),
            Err(InnerLoginError::HostKeyFile(_))
        ));
    }

    #[tokio::test]
    async fn a_non_loopback_sshd_never_receives_a_certificate() {
        let ca = InnerCa::generate().unwrap();
        let request = InnerCertRequest {
            login: "deploy".to_owned(),
            session_id: "s1".to_owned(),
            email: "alice@example.com".to_owned(),
            pty: false,
            port_forwarding: false,
        };
        for addr in ["10.0.0.1:22", "0.0.0.0:22", "[2001:db8::1]:22"] {
            let target = InnerTarget {
                sshd_addr: addr.parse::<SocketAddr>().unwrap(),
                sshd_host_key: "/nonexistent".into(),
            };
            let outcome = login(Arc::new(client_config()), &target, &ca, &request, NOW).await;
            assert!(
                matches!(outcome, Err(InnerLoginError::NotLoopback)),
                "{addr}"
            );
        }
    }
}
