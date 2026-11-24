use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentTrust {
    pub user_ca_keys: Vec<String>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::AgentTrust;

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
}
