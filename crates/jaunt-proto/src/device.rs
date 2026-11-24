use std::fmt;

use serde::{Deserialize, Serialize};

const REDACTED: &str = "[redacted]";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceStartRequest {
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub client_label: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct DeviceStartResponse {
    pub login_id: String,
    pub user_code: String,
    pub verification_url: String,
    pub expires_in: u32,
    pub interval: u32,
}

impl fmt::Debug for DeviceStartResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceStartResponse")
            .field("login_id", &self.login_id)
            .field("user_code", &REDACTED)
            .field("verification_url", &self.verification_url)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePollRequest {
    pub login_id: String,
    pub code_verifier: String,
    pub public_key: String,
}

impl fmt::Debug for DevicePollRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DevicePollRequest")
            .field("login_id", &self.login_id)
            .field("code_verifier", &REDACTED)
            .field("public_key", &REDACTED)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{DevicePollRequest, DeviceStartRequest, DeviceStartResponse};

    #[test]
    fn requests_reject_unknown_fields_and_the_label_may_be_absent() {
        let start = json!({"code_challenge": "c", "code_challenge_method": "S256"});
        let parsed: DeviceStartRequest = serde_json::from_value(start.clone()).unwrap();
        assert_eq!(parsed.client_label, None);
        let mut extra = start;
        extra["extra"] = json!(1);
        assert!(serde_json::from_value::<DeviceStartRequest>(extra).is_err());

        let poll = json!({"login_id": "l", "code_verifier": "v", "public_key": "k"});
        assert!(serde_json::from_value::<DevicePollRequest>(poll.clone()).is_ok());
        let mut extra = poll;
        extra["completion_code"] = json!("c");
        assert!(serde_json::from_value::<DevicePollRequest>(extra).is_err());
    }

    #[test]
    fn debug_output_hides_the_code_the_verifier_and_the_key() {
        let response = DeviceStartResponse {
            login_id: "login-1".to_owned(),
            user_code: "WXYZ-2345".to_owned(),
            verification_url: "https://jaunt.example/login/device".to_owned(),
            expires_in: 300,
            interval: 5,
        };
        let request = DevicePollRequest {
            login_id: "login-1".to_owned(),
            code_verifier: "verifier-secret".to_owned(),
            public_key: "key-material".to_owned(),
        };
        let shown = format!("{response:?} {request:?}");
        for secret in ["WXYZ-2345", "verifier-secret", "key-material"] {
            assert!(!shown.contains(secret), "{secret} leaked: {shown}");
        }
        assert!(shown.contains("login-1") && shown.contains("/login/device"));
    }
}
