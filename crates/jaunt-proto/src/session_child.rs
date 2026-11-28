use serde::{Deserialize, Serialize};

pub const AGENT_SESSION_CHILD_PATH: &str = "/v1/agent/sessions/child";
pub const KUBE_CHILD_SESSION_ID_PREFIX: &str = "kx-";
pub const KUBE_CHILD_SESSION_ID_HEX_LEN: usize = 32;
pub const MAX_KUBE_NAMESPACE_LEN: usize = 63;
pub const MAX_KUBE_POD_LEN: usize = 253;
pub const MAX_KUBE_CONTAINER_LEN: usize = 63;

pub fn is_kube_child_session_id(value: &str) -> bool {
    value
        .strip_prefix(KUBE_CHILD_SESSION_ID_PREFIX)
        .is_some_and(|hex| {
            hex.len() == KUBE_CHILD_SESSION_ID_HEX_LEN
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn is_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    let edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    edge(*first) && edge(*last) && bytes.iter().all(|byte| edge(*byte) || *byte == b'-')
}

pub fn is_kube_namespace(value: &str) -> bool {
    value.len() <= MAX_KUBE_NAMESPACE_LEN && is_label(value)
}

pub fn is_kube_pod_name(value: &str) -> bool {
    value.len() <= MAX_KUBE_POD_LEN && value.split('.').all(is_label)
}

pub fn is_kube_container_name(value: &str) -> bool {
    value.is_empty() || (value.len() <= MAX_KUBE_CONTAINER_LEN && is_label(value))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildSessionKind {
    Exec,
    Attach,
}

impl ChildSessionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            ChildSessionKind::Exec => "exec",
            ChildSessionKind::Attach => "attach",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildSessionRequest {
    pub parent_session_id: String,
    pub namespace: String,
    pub pod: String,
    pub container: String,
    pub tty: bool,
    pub kind: ChildSessionKind,
}

impl ChildSessionRequest {
    pub fn is_well_formed(&self) -> bool {
        is_kube_namespace(&self.namespace)
            && is_kube_pod_name(&self.pod)
            && is_kube_container_name(&self.container)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildSessionGrant {
    pub session_id: String,
    pub record: bool,
    pub record_input: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChildSessionRefusal {
    UnknownParent,
    ParentEnded,
    NotKube,
    TooManyChildren,
    Invalid,
    RateLimited,
}

impl ChildSessionRefusal {
    pub const ALL: [ChildSessionRefusal; 6] = [
        ChildSessionRefusal::UnknownParent,
        ChildSessionRefusal::ParentEnded,
        ChildSessionRefusal::NotKube,
        ChildSessionRefusal::TooManyChildren,
        ChildSessionRefusal::Invalid,
        ChildSessionRefusal::RateLimited,
    ];

    pub const fn code(self) -> &'static str {
        match self {
            ChildSessionRefusal::UnknownParent => "unknown_parent",
            ChildSessionRefusal::ParentEnded => "parent_ended",
            ChildSessionRefusal::NotKube => "not_kube",
            ChildSessionRefusal::TooManyChildren => "too_many_children",
            ChildSessionRefusal::Invalid => "invalid",
            ChildSessionRefusal::RateLimited => "rate_limited",
        }
    }

    pub const fn status(self) -> u16 {
        match self {
            ChildSessionRefusal::Invalid => 400,
            ChildSessionRefusal::UnknownParent => 404,
            ChildSessionRefusal::ParentEnded
            | ChildSessionRefusal::NotKube
            | ChildSessionRefusal::TooManyChildren => 409,
            ChildSessionRefusal::RateLimited => 429,
        }
    }

    pub fn from_code(code: &str) -> Option<ChildSessionRefusal> {
        ChildSessionRefusal::ALL
            .into_iter()
            .find(|refusal| refusal.code() == code)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        ChildSessionGrant, ChildSessionKind, ChildSessionRefusal, ChildSessionRequest,
        is_kube_child_session_id, is_kube_container_name, is_kube_namespace, is_kube_pod_name,
    };

    #[test]
    fn child_session_ids_are_the_prefix_and_exactly_32_lowercase_hex_digits() {
        let hex = "0123456789abcdef0123456789abcdef";
        assert!(is_kube_child_session_id(&format!("kx-{hex}")));
        for bad in [
            String::new(),
            format!("k-{hex}"),
            format!("kx-{}", &hex[..31]),
            format!("kx-{hex}0"),
            format!("kx-{}", hex.to_uppercase()),
            format!("KX-{hex}"),
            format!("kx-{}g", &hex[..31]),
            "67e55044-10b1-426f-9247-bb680e5fe0c8".to_owned(),
        ] {
            assert!(!is_kube_child_session_id(&bad), "{bad}");
        }
    }

    #[test]
    fn kubernetes_names_follow_the_dns_label_and_subdomain_rules() {
        let label = "a".repeat(63);
        let long_label = "a".repeat(64);
        let longest_pod = format!("{}.{}.{}.{}", label, label, label, "a".repeat(61));
        assert_eq!(longest_pod.len(), 253);
        let too_long_pod = format!("{longest_pod}a");
        for (value, namespace, pod, container) in [
            ("default", true, true, true),
            ("web-7d9f8c6b5-x2x4z", true, true, true),
            (label.as_str(), true, true, true),
            ("a", true, true, true),
            ("0abc", true, true, true),
            (long_label.as_str(), false, true, false),
            (longest_pod.as_str(), false, true, false),
            (too_long_pod.as_str(), false, false, false),
            ("web.api", false, true, false),
            ("", false, false, true),
            ("Web", false, false, false),
            ("-web", false, false, false),
            ("web-", false, false, false),
            ("web..api", false, false, false),
            (".web", false, false, false),
            ("web_api", false, false, false),
            ("web/api", false, false, false),
            ("web api", false, false, false),
            ("wéb", false, false, false),
            ("web\n", false, false, false),
        ] {
            assert_eq!(is_kube_namespace(value), namespace, "namespace {value:?}");
            assert_eq!(is_kube_pod_name(value), pod, "pod {value:?}");
            assert_eq!(
                is_kube_container_name(value),
                container,
                "container {value:?}"
            );
        }
    }

    #[test]
    fn the_child_request_and_grant_are_strict_and_round_trip() {
        let request = json!({
            "parent_session_id": "k-0123456789abcdef0123456789abcdef",
            "namespace": "default", "pod": "web-0", "container": "", "tty": true,
            "kind": "attach",
        });
        let parsed: ChildSessionRequest = serde_json::from_value(request.clone()).unwrap();
        assert_eq!(parsed.kind, ChildSessionKind::Attach);
        assert!(parsed.is_well_formed());
        assert_eq!(serde_json::to_value(&parsed).unwrap(), request);
        for (field, value) in [
            ("command", json!(["sh"])),
            ("node_id", json!("n")),
            ("record", json!(false)),
        ] {
            let mut extra = request.clone();
            extra[field] = value;
            assert!(
                serde_json::from_value::<ChildSessionRequest>(extra).is_err(),
                "{field}"
            );
        }
        for missing in ["container", "tty", "kind", "parent_session_id"] {
            let mut without = request.clone();
            without.as_object_mut().unwrap().remove(missing);
            assert!(
                serde_json::from_value::<ChildSessionRequest>(without).is_err(),
                "{missing}"
            );
        }
        let mut portforward = request.clone();
        portforward["kind"] = json!("portforward");
        assert!(serde_json::from_value::<ChildSessionRequest>(portforward).is_err());
        let mut bad_pod = parsed;
        bad_pod.pod = "Web".to_owned();
        assert!(!bad_pod.is_well_formed());

        let grant = json!({
            "session_id": "kx-0123456789abcdef0123456789abcdef",
            "record": true, "record_input": false,
        });
        let parsed: ChildSessionGrant = serde_json::from_value(grant.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), grant);
        let mut extra = grant;
        extra["user"] = json!("alice");
        assert!(serde_json::from_value::<ChildSessionGrant>(extra).is_err());
    }

    #[test]
    fn refusal_codes_are_stable_and_parse_back() {
        let codes: Vec<(&str, u16)> = ChildSessionRefusal::ALL
            .iter()
            .map(|refusal| (refusal.code(), refusal.status()))
            .collect();
        assert_eq!(
            codes,
            [
                ("unknown_parent", 404),
                ("parent_ended", 409),
                ("not_kube", 409),
                ("too_many_children", 409),
                ("invalid", 400),
                ("rate_limited", 429),
            ]
        );
        for refusal in ChildSessionRefusal::ALL {
            assert_eq!(
                ChildSessionRefusal::from_code(refusal.code()),
                Some(refusal)
            );
        }
        assert_eq!(ChildSessionRefusal::from_code("server_error"), None);
    }
}
