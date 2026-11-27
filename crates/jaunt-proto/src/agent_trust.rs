use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentTrust {
    pub user_ca_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentTrustV2 {
    pub trust_id: String,
    pub user_ca_keys: Vec<String>,
    pub host_ca_active: String,
}

pub const AGENT_TRUST_V3_PATH: &str = "/v3/agent/trust";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustRole {
    Active,
    Next,
    Previous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedX509Root {
    pub role: TrustRole,
    pub fingerprint: String,
    pub certificate_der: String,
    pub not_before: i64,
    pub not_after: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentTrustV3 {
    pub trust_id: String,
    pub user_ca_keys: Vec<String>,
    pub host_ca_active: String,
    pub user_x509_roots: Vec<TrustedX509Root>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{AgentTrust, AgentTrustV2, AgentTrustV3, TrustRole};

    #[test]
    fn the_trust_set_round_trips_in_order_and_rejects_unknown_fields() {
        let wire = json!({"user_ca_keys": ["ssh-ed25519 AAAA active", "ssh-ed25519 BBBB retired"]});
        let parsed: AgentTrust = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(
            parsed.user_ca_keys,
            ["ssh-ed25519 AAAA active", "ssh-ed25519 BBBB retired"]
        );
        assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);

        let mut extra = wire;
        extra["host_ca_keys"] = json!([]);
        assert!(serde_json::from_value::<AgentTrust>(extra).is_err());
        assert!(serde_json::from_value::<AgentTrust>(json!({})).is_err());
    }

    #[test]
    fn the_second_version_names_its_set_and_the_active_host_key_and_rejects_unknown_fields() {
        let wire = json!({
            "trust_id": "ab12",
            "user_ca_keys": ["ssh-ed25519 AAAA active"],
            "host_ca_active": "ssh-ed25519 CCCC host",
        });
        let parsed: AgentTrustV2 = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(parsed.trust_id, "ab12");
        assert_eq!(parsed.host_ca_active, "ssh-ed25519 CCCC host");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);

        let mut extra = wire.clone();
        extra["internal_roots"] = json!([]);
        assert!(serde_json::from_value::<AgentTrustV2>(extra).is_err());
        for field in ["trust_id", "user_ca_keys", "host_ca_active"] {
            let mut missing = wire.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<AgentTrustV2>(missing).is_err(),
                "{field}"
            );
        }
        assert!(serde_json::from_value::<AgentTrust>(wire).is_err());
    }

    #[test]
    fn the_third_version_adds_exactly_the_x509_roots_with_their_roles() {
        let wire = json!({
            "trust_id": "ab12",
            "user_ca_keys": ["ssh-ed25519 AAAA active"],
            "host_ca_active": "ssh-ed25519 CCCC host",
            "user_x509_roots": [
                {"role": "active", "fingerprint": "f1", "certificate_der": "MIIB",
                 "not_before": 1, "not_after": 2},
                {"role": "previous", "fingerprint": "f0", "certificate_der": "MIIA",
                 "not_before": 0, "not_after": 1}
            ],
        });
        let parsed: AgentTrustV3 = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(parsed.user_x509_roots[0].role, TrustRole::Active);
        assert_eq!(parsed.user_x509_roots[1].role, TrustRole::Previous);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);
        assert_eq!(
            serde_json::to_value(TrustRole::Next).unwrap(),
            json!("next")
        );

        let mut extra = wire.clone();
        extra["internal_roots"] = json!([]);
        assert!(serde_json::from_value::<AgentTrustV3>(extra).is_err());
        let mut extra_root = wire.clone();
        extra_root["user_x509_roots"][0]["key"] = json!("x");
        assert!(serde_json::from_value::<AgentTrustV3>(extra_root).is_err());
        let mut unknown_role = wire.clone();
        unknown_role["user_x509_roots"][0]["role"] = json!("retired");
        assert!(serde_json::from_value::<AgentTrustV3>(unknown_role).is_err());
        assert!(serde_json::from_value::<AgentTrustV2>(wire).is_err());
    }
}
