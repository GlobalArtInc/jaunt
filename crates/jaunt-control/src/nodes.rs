use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use jaunt_policy::{Identity, NodeInfo, PolicySet};
use jaunt_proto::{NodeList, NodeSummary};
use jaunt_store::{Node, NodeState};

use crate::control::Control;
use crate::http::{json_response, server_error};
use crate::identity::policy_identity;
use crate::whoami::authenticate;

pub(crate) const MAX_NODES: usize = 1000;

pub(crate) async fn handle(State(control): State<Control>, headers: HeaderMap) -> Response {
    let valid = match authenticate(&control, &headers).await {
        Ok(valid) => valid,
        Err(failure) => return failure.into_response(),
    };
    let nodes = match control.store.nodes().list().await {
        Ok(nodes) => nodes,
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "listing the nodes failed");
            return server_error();
        }
    };
    let policy = control.policy_snapshot();
    let identity = policy_identity(&valid.user);
    let connected = |node_id: &str| control.presence.connected_since(node_id).is_some();
    json_response(
        StatusCode::OK,
        &reachable(&nodes, &policy, &identity, MAX_NODES, connected),
    )
}

fn reachable(
    nodes: &[Node],
    policy: &PolicySet,
    identity: &Identity,
    limit: usize,
    connected: impl Fn(&str) -> bool,
) -> NodeList {
    let mut visible: Vec<&Node> = nodes
        .iter()
        .filter(|node| node.state == NodeState::Active)
        .filter(|node| {
            policy.route(
                identity,
                &NodeInfo {
                    name: node.name.clone(),
                    labels: node.labels.clone(),
                },
            )
        })
        .collect();
    visible.sort_by(|left, right| left.name.cmp(&right.name));
    let truncated = visible.len() > limit;
    visible.truncate(limit);
    NodeList {
        nodes: visible
            .into_iter()
            .map(|node| NodeSummary {
                name: node.name.clone(),
                labels: node.labels.clone(),
                hostname: node.hostname.clone(),
                connected: connected(&node.id),
            })
            .collect(),
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use jaunt_policy::{Identity, PolicySet, load_dir};
    use jaunt_store::{Node, NodeState};

    use super::{MAX_NODES, reachable};

    const ROLE: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: prod }\nspec:\n  members: { users: [alice@example.com] }\n  ssh: { nodes: { env: [prod] }, logins: [deploy] }\n";

    fn policy() -> PolicySet {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("role.yaml"), ROLE).unwrap();
        load_dir(dir.path()).unwrap()
    }

    fn identity(email: &str) -> Identity {
        Identity {
            email: email.to_owned(),
            username: String::new(),
            groups: Vec::new(),
        }
    }

    fn node(name: &str, env: &str, state: NodeState) -> Node {
        Node {
            id: format!("id-{name}"),
            name: name.to_owned(),
            labels: [("env".to_owned(), env.to_owned())].into(),
            hostname: format!("{name}.internal"),
            tls_public_key: String::new(),
            ssh_host_public_key: String::new(),
            tls_spki_sha256: String::new(),
            ssh_host_key_fingerprint: String::new(),
            state,
            approved_by: "cli:test".to_owned(),
            created_at: 0,
            removed_at: None,
            agent_version: None,
        }
    }

    #[test]
    fn only_active_nodes_the_policy_routes_are_listed_sorted_by_name() {
        let nodes = [
            node("web-3", "prod", NodeState::Active),
            node("db-1", "dev", NodeState::Active),
            node("web-1", "prod", NodeState::Active),
            node("web-2", "prod", NodeState::Removed),
        ];

        let list = reachable(
            &nodes,
            &policy(),
            &identity("alice@example.com"),
            10,
            |id| id == "id-web-3",
        );

        let names: Vec<&str> = list.nodes.iter().map(|node| node.name.as_str()).collect();
        assert_eq!(names, ["web-1", "web-3"]);
        assert!(!list.truncated);
        let connected: Vec<bool> = list.nodes.iter().map(|node| node.connected).collect();
        assert_eq!(connected, [false, true]);
        assert_eq!(list.nodes[0].hostname, "web-1.internal");
        assert_eq!(list.nodes[0].labels["env"], "prod");
    }

    #[test]
    fn a_user_without_a_matching_role_sees_nothing() {
        let nodes = [node("web-1", "prod", NodeState::Active)];

        let list = reachable(&nodes, &policy(), &identity("bob@example.com"), 10, |_| {
            true
        });

        assert!(list.nodes.is_empty() && !list.truncated);
    }

    #[test]
    fn the_list_is_cut_at_the_limit_and_says_so() {
        let nodes: Vec<Node> = (0..5)
            .rev()
            .map(|index| node(&format!("web-{index}"), "prod", NodeState::Active))
            .collect();

        let at_limit = reachable(&nodes, &policy(), &identity("alice@example.com"), 5, |_| {
            false
        });
        let cut = reachable(&nodes, &policy(), &identity("alice@example.com"), 3, |_| {
            false
        });

        assert_eq!(at_limit.nodes.len(), 5);
        assert!(!at_limit.truncated);
        let names: Vec<&str> = cut.nodes.iter().map(|node| node.name.as_str()).collect();
        assert_eq!(names, ["web-0", "web-1", "web-2"]);
        assert!(cut.truncated);
    }

    #[test]
    fn the_public_limit_is_one_thousand_entries() {
        let nodes: Vec<Node> = (0..=MAX_NODES)
            .map(|index| node(&format!("web-{index:04}"), "prod", NodeState::Active))
            .collect();

        let list = reachable(
            &nodes,
            &policy(),
            &identity("alice@example.com"),
            MAX_NODES,
            |_| false,
        );

        assert_eq!(MAX_NODES, 1000);
        assert_eq!(list.nodes.len(), 1000);
        assert!(list.truncated);
        assert_eq!(list.nodes[999].name, "web-0999");
        let exact = reachable(
            &nodes[..MAX_NODES],
            &policy(),
            &identity("alice@example.com"),
            MAX_NODES,
            |_| false,
        );
        assert_eq!(exact.nodes.len(), 1000);
        assert!(!exact.truncated);
    }
}
