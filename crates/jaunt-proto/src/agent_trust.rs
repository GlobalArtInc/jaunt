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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{AgentTrust, AgentTrustV2};

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
}
