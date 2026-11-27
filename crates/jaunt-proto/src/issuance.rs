use std::fmt;

use serde::{Deserialize, Serialize};

use crate::plane::BoxFuture;

pub const X509_CERTIFICATES_PATH: &str = "/v1/certificates/x509";
pub const AGENT_SERVICE_CERTIFICATE_PATH: &str = "/v1/agent/service-certificate";
pub const GATE_ALPN_SSH: &str = "jaunt-ssh/1";
pub const GATE_ALPN_SVC: &str = "jaunt-svc/1";

const REDACTED: &str = "[redacted]";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X509CertificateRequest {
    pub public_key: String,
}

impl fmt::Debug for X509CertificateRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X509CertificateRequest")
            .field("public_key", &REDACTED)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X509CertificateResponse {
    pub certificate_der: String,
    pub serial: i64,
    pub parent_serial: i64,
    pub valid_after: i64,
    pub valid_before: i64,
}

impl fmt::Debug for X509CertificateResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X509CertificateResponse")
            .field("certificate_der_len", &self.certificate_der.len())
            .field("serial", &self.serial)
            .field("parent_serial", &self.parent_serial)
            .field("valid_after", &self.valid_after)
            .field("valid_before", &self.valid_before)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCertificateRequest {
    pub service_id: String,
    pub public_key: String,
}

impl fmt::Debug for ServiceCertificateRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceCertificateRequest")
            .field("service_id", &self.service_id)
            .field("public_key", &REDACTED)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCertificateResponse {
    pub certificate_der: String,
    pub serial: i64,
    pub dns_name: String,
    pub valid_after: i64,
    pub valid_before: i64,
}

impl fmt::Debug for ServiceCertificateResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceCertificateResponse")
            .field("certificate_der_len", &self.certificate_der.len())
            .field("serial", &self.serial)
            .field("dns_name", &self.dns_name)
            .field("valid_after", &self.valid_after)
            .field("valid_before", &self.valid_before)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct GateTlsCertificate {
    pub certificate_der: Vec<u8>,
    pub serial: u64,
    pub valid_after: u64,
    pub valid_before: u64,
}

impl fmt::Debug for GateTlsCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GateTlsCertificate")
            .field("certificate_der_len", &self.certificate_der.len())
            .field("serial", &self.serial)
            .field("valid_after", &self.valid_after)
            .field("valid_before", &self.valid_before)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GateTlsIssueError {
    #[error("the gate may only hold a certificate for the services domain")]
    NameRefused,
    #[error("the public key is not an Ed25519 subject public key")]
    InvalidKey,
    #[error("the services domain is not configured")]
    NotConfigured,
    #[error("the service certificate authority is unavailable")]
    Unavailable,
}

pub trait GateTlsIssuer: Send + Sync {
    fn issue<'a>(
        &'a self,
        subject_public_key_der: &'a [u8],
        server_name: &'a str,
    ) -> BoxFuture<'a, Result<GateTlsCertificate, GateTlsIssueError>>;
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        GateTlsCertificate, ServiceCertificateRequest, ServiceCertificateResponse,
        X509CertificateRequest, X509CertificateResponse,
    };

    #[test]
    fn requests_reject_unknown_fields_so_a_caller_cannot_name_the_certificate() {
        let x509 = json!({"public_key": "AAAA"});
        assert!(serde_json::from_value::<X509CertificateRequest>(x509.clone()).is_ok());
        for extra in ["email", "user_id", "valid_before", "serial"] {
            let mut body = x509.clone();
            body[extra] = json!("x");
            assert!(
                serde_json::from_value::<X509CertificateRequest>(body).is_err(),
                "{extra}"
            );
        }
        let service = json!({"service_id": "s-1", "public_key": "AAAA"});
        assert!(serde_json::from_value::<ServiceCertificateRequest>(service.clone()).is_ok());
        for extra in ["name", "dns_names", "kind", "node_id", "validity"] {
            let mut body = service.clone();
            body[extra] = json!("x");
            assert!(
                serde_json::from_value::<ServiceCertificateRequest>(body).is_err(),
                "{extra}"
            );
        }
        assert!(
            serde_json::from_value::<ServiceCertificateRequest>(json!({"service_id": "s-1"}))
                .is_err()
        );
    }

    #[test]
    fn debug_output_names_no_key_and_no_certificate_body() {
        let request = X509CertificateRequest {
            public_key: "MCowBQYDK2VwAyEAsecretkeymaterial".to_owned(),
        };
        let service = ServiceCertificateRequest {
            service_id: "s-1".to_owned(),
            public_key: "MCowBQYDK2VwAyEAsecretkeymaterial".to_owned(),
        };
        let x509 = X509CertificateResponse {
            certificate_der: "MIIBcertificatebody".to_owned(),
            serial: 7,
            parent_serial: 3,
            valid_after: 1,
            valid_before: 2,
        };
        let served = ServiceCertificateResponse {
            certificate_der: "MIIBcertificatebody".to_owned(),
            serial: 8,
            dns_name: "grafana.tcp.svc.example.com".to_owned(),
            valid_after: 1,
            valid_before: 2,
        };
        let gate = GateTlsCertificate {
            certificate_der: b"certificatebody".to_vec(),
            serial: 9,
            valid_after: 1,
            valid_before: 2,
        };
        let printed = format!("{request:?} {service:?} {x509:?} {served:?} {gate:?}");
        assert!(!printed.contains("secretkeymaterial"), "{printed}");
        assert!(!printed.contains("certificatebody"), "{printed}");
        assert!(!printed.contains("99, 101, 114"), "{printed}");
        assert!(printed.contains("grafana.tcp.svc.example.com"));
    }
}
