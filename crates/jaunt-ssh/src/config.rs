use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use russh::keys::Algorithm;
use russh::server::Config;
use russh::{MethodKind, MethodSet, Preferred, SshId, cipher, compression, kex, mac};

use crate::host::HostIdentity;

const SERVER_ID: &str = "SSH-2.0-Jaunt";
const WINDOW_SIZE: u32 = 2 * 1024 * 1024;
const MAXIMUM_PACKET_SIZE: u32 = 32 * 1024;
const GATE_AUTH_DEADLINE: Duration = Duration::from_secs(30);
const AGENT_AUTH_DEADLINE: Duration = Duration::from_secs(45);
const AUTH_REJECTION_TIME: Duration = Duration::from_secs(1);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const KEEPALIVE_MAX: usize = 3;
const HOST_KEY_ALGORITHMS: &[Algorithm] = &[Algorithm::Ed25519];
const KEX_ALGORITHMS: &[kex::Name] = &[
    kex::MLKEM768X25519_SHA256,
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::EXTENSION_SUPPORT_AS_SERVER,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
];
const CIPHER_ALGORITHMS: &[cipher::Name] = &[
    cipher::CHACHA20_POLY1305,
    cipher::AES_256_GCM,
    cipher::AES_256_CTR,
    cipher::AES_192_CTR,
    cipher::AES_128_CTR,
];
const MAC_ALGORITHMS: &[mac::Name] = &[
    mac::HMAC_SHA512_ETM,
    mac::HMAC_SHA256_ETM,
    mac::HMAC_SHA512,
    mac::HMAC_SHA256,
];
const COMPRESSION_ALGORITHMS: &[compression::Name] = &[compression::NONE];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerProfile {
    Gate,
    Agent,
}

impl ServerProfile {
    pub fn auth_deadline(self) -> Duration {
        match self {
            Self::Gate => GATE_AUTH_DEADLINE,
            Self::Agent => AGENT_AUTH_DEADLINE,
        }
    }

    pub fn max_auth_attempts(self) -> usize {
        match self {
            Self::Gate => 3,
            Self::Agent => 2,
        }
    }

    pub(crate) fn config(self, identity: HostIdentity) -> Config {
        let (key, certificate) = identity.into_parts();
        Config {
            server_id: SshId::Standard(Cow::Borrowed(SERVER_ID)),
            methods: MethodSet::from(&[MethodKind::PublicKey][..]),
            auth_rejection_time: AUTH_REJECTION_TIME,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![key],
            certificates: vec![certificate],
            window_size: WINDOW_SIZE,
            maximum_packet_size: MAXIMUM_PACKET_SIZE,
            preferred: Preferred {
                kex: Cow::Borrowed(KEX_ALGORITHMS),
                key: Cow::Borrowed(HOST_KEY_ALGORITHMS),
                host_key_certificates: Cow::Borrowed(&[]),
                cipher: Cow::Borrowed(CIPHER_ALGORITHMS),
                mac: Cow::Borrowed(MAC_ALGORITHMS),
                compression: Cow::Borrowed(COMPRESSION_ALGORITHMS),
            },
            max_auth_attempts: self.max_auth_attempts(),
            inactivity_timeout: None,
            keepalive_interval: Some(KEEPALIVE_INTERVAL),
            keepalive_max: KEEPALIVE_MAX,
            nodelay: true,
            manual_window: true,
            ..Config::default()
        }
    }
}

pub struct ServerConfigCell {
    profile: ServerProfile,
    current: ArcSwap<Config>,
}

impl ServerConfigCell {
    pub fn new(identity: HostIdentity, profile: ServerProfile) -> Self {
        Self {
            profile,
            current: ArcSwap::from_pointee(profile.config(identity)),
        }
    }

    pub fn profile(&self) -> ServerProfile {
        self.profile
    }

    pub fn current(&self) -> Arc<Config> {
        self.current.load_full()
    }

    pub fn replace(&self, identity: HostIdentity) {
        self.current.store(Arc::new(self.profile.config(identity)));
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use russh::keys::{Algorithm, Certificate, HashAlg, PublicKeyOrCertificate};
    use russh::{MethodKind, MethodSet, Preferred, cipher, client, compression, kex, mac, server};

    use super::{ServerConfigCell, ServerProfile};
    use crate::test_support::{host_identity, key};

    #[test]
    fn profiles_share_the_hardened_defaults() {
        let ca = key(Algorithm::Ed25519);
        for (profile, attempts, deadline) in [
            (ServerProfile::Gate, 3, Duration::from_secs(30)),
            (ServerProfile::Agent, 2, Duration::from_secs(45)),
        ] {
            let cell = ServerConfigCell::new(host_identity(&ca).0, profile);
            let config = cell.current();
            assert_eq!(cell.profile(), profile);
            assert_eq!(profile.auth_deadline(), deadline);
            assert_eq!(config.max_auth_attempts, attempts);
            assert_eq!(
                format!("{:?}", config.server_id),
                "Standard(\"SSH-2.0-Jaunt\")"
            );
            assert_eq!(
                config.methods,
                MethodSet::from(&[MethodKind::PublicKey][..])
            );
            assert_eq!(config.auth_rejection_time, Duration::from_secs(1));
            assert_eq!(config.auth_rejection_time_initial, Some(Duration::ZERO));
            assert!(config.manual_window);
            assert_eq!(config.window_size, 2 * 1024 * 1024);
            assert_eq!(config.maximum_packet_size, 32 * 1024);
            assert_eq!(config.inactivity_timeout, None);
            assert_eq!(config.keepalive_interval, Some(Duration::from_secs(30)));
            assert_eq!(config.keepalive_max, 3);
            assert!(config.nodelay);
            assert_eq!((config.keys.len(), config.certificates.len()), (1, 1));
        }
    }

    #[test]
    fn profiles_offer_exactly_the_chosen_algorithms() {
        let ca = key(Algorithm::Ed25519);
        for profile in [ServerProfile::Gate, ServerProfile::Agent] {
            let config = ServerConfigCell::new(host_identity(&ca).0, profile).current();
            let preferred = &config.preferred;
            assert_eq!(
                preferred.kex.as_ref(),
                [
                    kex::MLKEM768X25519_SHA256,
                    kex::CURVE25519,
                    kex::CURVE25519_PRE_RFC_8731,
                    kex::EXTENSION_SUPPORT_AS_SERVER,
                    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
                ]
            );
            assert_eq!(preferred.key.as_ref(), [Algorithm::Ed25519]);
            assert!(preferred.host_key_certificates.is_empty());
            assert_eq!(
                preferred.cipher.as_ref(),
                [
                    cipher::CHACHA20_POLY1305,
                    cipher::AES_256_GCM,
                    cipher::AES_256_CTR,
                    cipher::AES_192_CTR,
                    cipher::AES_128_CTR,
                ]
            );
            assert_eq!(
                preferred.mac.as_ref(),
                [
                    mac::HMAC_SHA512_ETM,
                    mac::HMAC_SHA256_ETM,
                    mac::HMAC_SHA512,
                    mac::HMAC_SHA256,
                ]
            );
            assert_eq!(preferred.compression.as_ref(), [compression::NONE]);
        }
    }

    #[test]
    fn replace_swaps_the_host_identity_for_new_connections() {
        let ca = key(Algorithm::Ed25519);
        let (first, first_public) = host_identity(&ca);
        let (second, second_public) = host_identity(&ca);
        let cell = ServerConfigCell::new(first, ServerProfile::Agent);
        let before = cell.current();
        cell.replace(second);
        let after = cell.current();
        let fingerprint = |config: &russh::server::Config| {
            config.keys[0].public_key().fingerprint(HashAlg::Sha256)
        };
        assert_eq!(
            fingerprint(&before),
            first_public.fingerprint(HashAlg::Sha256)
        );
        assert_eq!(
            fingerprint(&after),
            second_public.fingerprint(HashAlg::Sha256)
        );
        assert_eq!(after.certificates[0].public_key(), second_public.key_data());
        assert!(after.manual_window);
        assert_eq!(after.max_auth_attempts, 2);
    }

    struct Idle;

    impl server::Handler for Idle {
        type Error = russh::Error;
    }

    struct Recorder(Arc<Mutex<Vec<Option<Certificate>>>>);

    impl client::Handler for Recorder {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            key: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            let presented = match key {
                PublicKeyOrCertificate::Certificate(certificate) => Some(certificate.clone()),
                PublicKeyOrCertificate::PublicKey { .. } => None,
            };
            self.0.lock().unwrap().push(presented);
            Ok(true)
        }
    }

    #[tokio::test]
    async fn the_server_presents_its_host_certificate() {
        let ca = key(Algorithm::Ed25519);
        for profile in [ServerProfile::Gate, ServerProfile::Agent] {
            let cell = ServerConfigCell::new(host_identity(&ca).0, profile);
            let config = cell.current();
            let expected: Certificate = config.certificates[0].clone();
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let server =
                tokio::spawn(
                    async move { server::run_stream(config, server_io, Idle).await?.await },
                );
            let seen = Arc::new(Mutex::new(Vec::new()));
            let client_config = client::Config {
                preferred: Preferred {
                    host_key_certificates: Cow::Borrowed(&[Algorithm::Ed25519]),
                    ..Preferred::DEFAULT
                },
                ..client::Config::default()
            };
            let handle = tokio::time::timeout(
                Duration::from_secs(10),
                client::connect_stream(
                    Arc::new(client_config),
                    client_io,
                    Recorder(Arc::clone(&seen)),
                ),
            )
            .await
            .expect("the handshake hung")
            .unwrap();
            assert_eq!(*seen.lock().unwrap(), [Some(expected)], "{profile:?}");
            drop(handle);
            server.abort();
        }
    }
}
