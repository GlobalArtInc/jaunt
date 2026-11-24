use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

const REDACTED: &str = "[redacted]";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollRequest {
    pub name: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    pub hostname: String,
    pub tls_public_key: String,
    pub ssh_host_public_key: String,
    #[serde(default)]
    pub replace: bool,
    pub agent_version: String,
}

#[derive(Serialize, Deserialize)]
pub struct EnrollResponse {
    pub handle: String,
    pub code: String,
    pub expires_at: i64,
    pub poll_interval: u32,
}

impl fmt::Debug for EnrollResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrollResponse")
            .field("handle", &REDACTED)
            .field("code", &REDACTED)
            .field("expires_at", &self.expires_at)
            .field("poll_interval", &self.poll_interval)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollRequest {
    pub handle: String,
}

impl fmt::Debug for PollRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PollRequest")
            .field("handle", &REDACTED)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCertificates {
    pub x509_certificate_der: String,
    pub x509_not_after: i64,
    pub ssh_host_certificate: String,
    pub ssh_not_after: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentApproved {
    pub node_id: String,
    #[serde(flatten)]
    pub certificates: NodeCertificates,
    pub internal_ca_root_der: String,
    pub agent_endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PollResponse {
    Pending,
    Rejected,
    Expired,
    AlreadyDelivered,
    Approved(EnrollmentApproved),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenewRequest {
    #[serde(default)]
    pub tls_public_key: Option<String>,
    #[serde(default)]
    pub ssh_host_public_key: Option<String>,
}

pub type RenewResponse = NodeCertificates;

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        EnrollRequest, EnrollResponse, EnrollmentApproved, NodeCertificates, PollRequest,
        PollResponse, RenewRequest,
    };

    fn enroll_body() -> serde_json::Value {
        json!({
            "name": "web-01",
            "hostname": "web-01.example.com",
            "tls_public_key": "AAAA",
            "ssh_host_public_key": "ssh-ed25519 AAAA",
            "agent_version": "0.1.0",
        })
    }

    #[test]
    fn requests_reject_unknown_fields_and_default_the_optional_ones() {
        let parsed: EnrollRequest = serde_json::from_value(enroll_body()).unwrap();
        assert!(parsed.labels.is_empty() && !parsed.replace);
        let mut extra = enroll_body();
        extra["extra"] = json!(1);
        assert!(serde_json::from_value::<EnrollRequest>(extra).is_err());
        let mut missing = enroll_body();
        missing.as_object_mut().unwrap().remove("hostname");
        assert!(serde_json::from_value::<EnrollRequest>(missing).is_err());

        assert!(serde_json::from_value::<PollRequest>(json!({"handle": "h", "x": 1})).is_err());
        let renew: RenewRequest = serde_json::from_value(json!({})).unwrap();
        assert_eq!(
            (renew.tls_public_key, renew.ssh_host_public_key),
            (None, None)
        );
        assert!(serde_json::from_value::<RenewRequest>(json!({"node_id": "n"})).is_err());
    }

    #[test]
    fn poll_states_have_the_documented_wire_shape() {
        for (response, state) in [
            (PollResponse::Pending, "pending"),
            (PollResponse::Rejected, "rejected"),
            (PollResponse::Expired, "expired"),
            (PollResponse::AlreadyDelivered, "already_delivered"),
        ] {
            assert_eq!(
                serde_json::to_value(&response).unwrap(),
                json!({"state": state})
            );
            let back: PollResponse = serde_json::from_value(json!({"state": state})).unwrap();
            assert_eq!(back, response);
        }
        let approved = PollResponse::Approved(EnrollmentApproved {
            node_id: "n".to_owned(),
            certificates: NodeCertificates {
                x509_certificate_der: "x".to_owned(),
                x509_not_after: 1,
                ssh_host_certificate: "s".to_owned(),
                ssh_not_after: 2,
            },
            internal_ca_root_der: "r".to_owned(),
            agent_endpoint: "agents.example.com:443".to_owned(),
        });
        let wire = serde_json::to_value(&approved).unwrap();
        assert_eq!(
            wire,
            json!({
                "state": "approved",
                "node_id": "n",
                "x509_certificate_der": "x",
                "x509_not_after": 1,
                "ssh_host_certificate": "s",
                "ssh_not_after": 2,
                "internal_ca_root_der": "r",
                "agent_endpoint": "agents.example.com:443",
            })
        );
        assert_eq!(
            serde_json::from_value::<PollResponse>(wire).unwrap(),
            approved
        );
    }

    #[test]
    fn debug_output_hides_the_handle_and_the_code() {
        let response = EnrollResponse {
            handle: "handle-secret".to_owned(),
            code: "ABCD-2345".to_owned(),
            expires_at: 5,
            poll_interval: 3,
        };
        let request = PollRequest {
            handle: "handle-secret".to_owned(),
        };
        let shown = format!("{response:?} {request:?}");
        assert!(!shown.contains("handle-secret") && !shown.contains("ABCD-2345"));
        assert!(shown.contains("expires_at"));
    }
}
