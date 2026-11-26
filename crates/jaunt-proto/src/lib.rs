mod agent_trust;
mod client;
mod db_principal;
mod device;
mod enroll;
mod error;
mod kube_principal;
mod login;
mod plane;
mod recording;
mod session;
mod ssh_login;
mod whoami;

pub use agent_trust::{AgentTrust, AgentTrustV2};
pub use client::{ClientConfig, GateEndpoint, NodeList, NodeSummary};
pub use db_principal::{
    is_db_name, is_db_user, is_valid_substituted_db_name, is_valid_substituted_db_user,
};
pub use device::{DevicePollRequest, DeviceStartRequest, DeviceStartResponse};
pub use enroll::{
    EnrollRequest, EnrollResponse, EnrollmentApproved, NodeCertificates, PollRequest, PollResponse,
    RenewRequest, RenewResponse,
};
pub use error::ErrorBody;
pub use kube_principal::{is_kube_principal, is_valid_substituted_kube_principal};
pub use login::{FinishRequest, FinishResponse, StartRequest, StartResponse};
pub use plane::{BoxFuture, ControlError, ControlPlane};
pub use recording::{
    RECORDING_CHUNKS_SUFFIX, RECORDING_COMPLETE_SUFFIX, RECORDINGS_PATH_PREFIX, RecordingAck,
    RecordingChunk, RecordingComplete, RecordingKind, RecordingManifest, RecordingReceipt,
    RecordingRefusal, RecordingState, recording_chunks_path, recording_complete_path,
};
pub use session::{
    AuthorizeDecision, AuthorizeRequest, AuthorizeResponse, DenyReason, NodeCaller, RouteDecision,
    RouteRequest, SessionEnd, SessionEndOutcome, SessionPermissions,
};
pub use ssh_login::{is_portable_login, is_valid_substituted_login};
pub use whoami::WhoamiResponse;

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{ErrorBody, FinishRequest, FinishResponse, StartRequest, StartResponse};

    #[test]
    fn requests_reject_unknown_fields_and_the_completion_code_may_be_absent() {
        let start = json!({
            "code_challenge": "c",
            "code_challenge_method": "S256",
            "redirect_port": 4000,
        });
        let parsed: StartRequest = serde_json::from_value(start.clone()).unwrap();
        assert_eq!(parsed.client_label, None);
        let mut extra = start;
        extra["extra"] = json!(1);
        assert!(serde_json::from_value::<StartRequest>(extra).is_err());

        let finish = json!({"login_id": "l", "code_verifier": "v", "public_key": "k"});
        let parsed: FinishRequest = serde_json::from_value(finish.clone()).unwrap();
        assert_eq!(parsed.completion_code, None);
        let mut extra = finish;
        extra["extra"] = json!(1);
        assert!(serde_json::from_value::<FinishRequest>(extra).is_err());
    }

    #[test]
    fn responses_round_trip_and_the_error_body_has_one_field() {
        let response = FinishResponse {
            certificate: "cert".to_owned(),
            serial: 7,
            key_id: "jaunt:a@b:7".to_owned(),
            valid_after: 1,
            valid_before: 2,
            api_token: "jt_token".to_owned(),
            token_expires_at: 2,
            user_id: "u".to_owned(),
            email: "a@b".to_owned(),
            host_ca_keys: vec!["ssh-ed25519 AAAA".to_owned()],
        };
        let wire = serde_json::to_value(&response).unwrap();
        let back: FinishResponse = serde_json::from_value(wire).unwrap();
        assert_eq!(back.host_ca_keys, ["ssh-ed25519 AAAA"]);
        assert_eq!(back.serial, 7);

        let error = serde_json::to_value(ErrorBody {
            error: "invalid_grant".to_owned(),
        })
        .unwrap();
        assert_eq!(error, json!({"error": "invalid_grant"}));
    }

    #[test]
    fn debug_output_hides_every_secret_bearing_field() {
        let request = FinishRequest {
            login_id: "login-1".to_owned(),
            code_verifier: "verifier-secret".to_owned(),
            completion_code: Some("completion-secret".to_owned()),
            public_key: "key-material".to_owned(),
        };
        let response = FinishResponse {
            certificate: "certificate-line".to_owned(),
            serial: 7,
            key_id: "jaunt:a@b:7".to_owned(),
            valid_after: 1,
            valid_before: 2,
            api_token: "token-secret".to_owned(),
            token_expires_at: 2,
            user_id: "user-1".to_owned(),
            email: "a@b".to_owned(),
            host_ca_keys: Vec::new(),
        };
        let start = StartResponse {
            login_id: "login-1".to_owned(),
            authorize_url: "https://idp.example/authorize?state=state-secret".to_owned(),
        };
        let shown = format!("{request:?} {response:?} {start:?}");
        for secret in [
            "verifier-secret",
            "completion-secret",
            "key-material",
            "certificate-line",
            "token-secret",
            "state-secret",
        ] {
            assert!(!shown.contains(secret), "{secret} leaked: {shown}");
        }
        assert!(shown.contains("login-1") && shown.contains("user-1"));
    }

    #[test]
    fn client_responses_are_strict_and_round_trip() {
        use super::{ClientConfig, NodeList};

        let config = json!({
            "ssh_suffix": "jaunt.test",
            "gate": {"host": "gate.example.com", "port": 22},
            "host_ca_keys": ["ssh-ed25519 AAAA"],
        });
        let parsed: ClientConfig = serde_json::from_value(config.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), config);
        let mut extra = config.clone();
        extra["extra"] = json!(1);
        assert!(serde_json::from_value::<ClientConfig>(extra).is_err());
        let mut nested = config;
        nested["gate"]["extra"] = json!(1);
        assert!(serde_json::from_value::<ClientConfig>(nested).is_err());

        let list = json!({
            "nodes": [{
                "name": "web-01",
                "labels": {"env": "prod"},
                "hostname": "web-01.internal",
                "connected": false,
            }],
            "truncated": false,
        });
        let parsed: NodeList = serde_json::from_value(list.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), list);
        let mut extra = list.clone();
        extra["nodes"][0]["extra"] = json!(1);
        assert!(serde_json::from_value::<NodeList>(extra).is_err());
        let mut top_level = list.clone();
        top_level["extra"] = json!(1);
        assert!(serde_json::from_value::<NodeList>(top_level).is_err());
        let mut missing = list;
        missing.as_object_mut().unwrap().remove("truncated");
        assert!(serde_json::from_value::<NodeList>(missing).is_err());
    }
}
