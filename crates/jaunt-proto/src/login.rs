use std::fmt;

use serde::{Deserialize, Serialize};

const REDACTED: &str = "[redacted]";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartRequest {
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub redirect_port: u32,
    pub client_label: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct StartResponse {
    pub login_id: String,
    pub authorize_url: String,
}

impl fmt::Debug for StartResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StartResponse")
            .field("login_id", &self.login_id)
            .field("authorize_url", &REDACTED)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishRequest {
    pub login_id: String,
    pub code_verifier: String,
    #[serde(default)]
    pub completion_code: Option<String>,
    pub public_key: String,
}

impl fmt::Debug for FinishRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FinishRequest")
            .field("login_id", &self.login_id)
            .field("code_verifier", &REDACTED)
            .field("completion_code", &REDACTED)
            .field("public_key", &REDACTED)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
pub struct FinishResponse {
    pub certificate: String,
    pub serial: i64,
    pub key_id: String,
    pub valid_after: i64,
    pub valid_before: i64,
    pub api_token: String,
    pub token_expires_at: i64,
    pub user_id: String,
    pub email: String,
    pub host_ca_keys: Vec<String>,
}

impl fmt::Debug for FinishResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FinishResponse")
            .field("certificate", &REDACTED)
            .field("serial", &self.serial)
            .field("key_id", &self.key_id)
            .field("valid_after", &self.valid_after)
            .field("valid_before", &self.valid_before)
            .field("api_token", &REDACTED)
            .field("token_expires_at", &self.token_expires_at)
            .field("user_id", &self.user_id)
            .field("email", &self.email)
            .field("host_ca_keys", &self.host_ca_keys)
            .finish()
    }
}
