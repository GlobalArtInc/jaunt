use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhoamiResponse {
    pub user_id: String,
    pub email: String,
    pub groups: Vec<String>,
    pub cert_serial: i64,
    pub token_expires_at: i64,
}
