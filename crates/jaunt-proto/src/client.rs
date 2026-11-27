use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub ssh_suffix: String,
    pub gate: GateEndpoint,
    pub host_ca_keys: Vec<String>,
}

pub const CLIENT_CONFIG_V2_PATH: &str = "/v2/client/config";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientTransport {
    Tls,
    Tcp,
}

impl ClientTransport {
    pub const fn as_str(self) -> &'static str {
        match self {
            ClientTransport::Tls => "tls",
            ClientTransport::Tcp => "tcp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshGateClient {
    pub client_transport: ClientTransport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedRoot {
    pub certificate_der: String,
    pub sha256: String,
    pub not_before: i64,
    pub not_after: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServicesClient {
    pub domain: String,
    pub gate_tls_name: String,
    pub port: u16,
    pub alpn: Vec<String>,
    pub roots: Vec<PinnedRoot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfigV2 {
    pub ssh_suffix: String,
    pub gate: GateEndpoint,
    pub host_ca_keys: Vec<String>,
    pub ssh_gate: SshGateClient,
    pub services: Option<ServicesClient>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSummary {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub hostname: String,
    pub connected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeList {
    pub nodes: Vec<NodeSummary>,
    pub truncated: bool,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{ClientConfig, ClientConfigV2, ClientTransport};

    fn v2() -> serde_json::Value {
        json!({
            "ssh_suffix": "jaunt.example.com",
            "gate": {"host": "gate.example.com", "port": 22},
            "host_ca_keys": ["ssh-ed25519 AAAA host"],
            "ssh_gate": {"client_transport": "tls"},
            "services": {
                "domain": "svc.example.com",
                "gate_tls_name": "svc.example.com",
                "port": 443,
                "alpn": ["jaunt-ssh/1", "jaunt-svc/1"],
                "roots": [{"certificate_der": "MIIB", "sha256": "ab", "not_before": 1, "not_after": 2}]
            }
        })
    }

    #[test]
    fn the_second_client_config_round_trips_and_rejects_unknown_fields() {
        let wire = v2();
        let parsed: ClientConfigV2 = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(parsed.ssh_gate.client_transport, ClientTransport::Tls);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);
        assert!(serde_json::from_value::<ClientConfig>(wire.clone()).is_err());

        let mut without = wire.clone();
        without["services"] = json!(null);
        without["ssh_gate"]["client_transport"] = json!("tcp");
        let parsed: ClientConfigV2 = serde_json::from_value(without).unwrap();
        assert!(parsed.services.is_none());
        assert_eq!(parsed.ssh_gate.client_transport, ClientTransport::Tcp);

        for (pointer, field) in [
            ("", "extra"),
            ("/services", "extra"),
            ("/ssh_gate", "extra"),
        ] {
            let mut extra = wire.clone();
            extra.pointer_mut(pointer).unwrap()[field] = json!(1);
            assert!(
                serde_json::from_value::<ClientConfigV2>(extra).is_err(),
                "{pointer}"
            );
        }
        let mut unknown = wire;
        unknown["ssh_gate"]["client_transport"] = json!("quic");
        assert!(serde_json::from_value::<ClientConfigV2>(unknown).is_err());
        assert_eq!(ClientTransport::Tls.as_str(), "tls");
        assert_eq!(ClientTransport::Tcp.as_str(), "tcp");
    }
}
