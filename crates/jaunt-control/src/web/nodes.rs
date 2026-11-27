use std::collections::{BTreeMap, BTreeSet};

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jaunt_policy::NodeInfo;
use jaunt_store::{
    CertificateExpiry, CertificateState, Node, NodeCursor, NodeQuery, NodeState, RevocationKind,
    StoreError,
};
use serde::{Deserialize, Serialize};

use crate::admin::RemoveError;
use crate::control::Control;
use crate::http::{json_body, json_response, server_error};
use crate::labels::Labels;
use crate::node_removal;
use crate::revocation::is_identifier;

use super::admin_common::{
    DEFAULT_PAGE, Refusal, conflict, invalid_value, known_id, not_found, once, page_limit,
    unix_secs, web_actor,
};
use super::session::{NodesApprove, RequireAdmin, SessionsRead};

const MAX_PREFIX_CHARS: usize = 128;
const MAX_LABEL_FILTERS: usize = 16;
const RECENT_SESSIONS_SECS: i64 = 86_400;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ListRequest {
    query: NodeQuery,
}

#[derive(Serialize)]
struct CertificatesBody {
    state: &'static str,
    x509_expires_at: Option<i64>,
    ssh_host_expires_at: Option<i64>,
}

#[derive(Serialize)]
struct NodeBody {
    id: String,
    name: String,
    hostname: String,
    labels: BTreeMap<String, String>,
    state: &'static str,
    revoked: bool,
    connected: bool,
    connected_since: Option<i64>,
    creates_accounts: bool,
    agent_version: Option<String>,
    certificates: CertificatesBody,
    approved_by: String,
    created_at: i64,
    removed_at: Option<i64>,
}

#[derive(Serialize)]
struct ListBody {
    nodes: Vec<NodeBody>,
    next: Option<String>,
    pending_enrolments: i64,
}

#[derive(Serialize)]
struct SessionCountsBody {
    open: i64,
    last_24h: i64,
}

#[derive(Serialize)]
struct DetailBody {
    #[serde(flatten)]
    node: NodeBody,
    tls_spki_sha256: String,
    ssh_host_key_fingerprint: String,
    sessions: SessionCountsBody,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveBody {
    confirm_name: String,
}

#[derive(Serialize)]
struct RemovedBody {
    id: String,
    name: String,
    state: &'static str,
    removed_at: Option<i64>,
    sessions_closed: Option<usize>,
}

#[derive(Serialize)]
struct RoleBody {
    role: String,
    users: Vec<String>,
    groups: Vec<String>,
    logins: Vec<String>,
    port_forwarding: bool,
    record_input: bool,
    admin: Vec<&'static str>,
}

#[derive(Serialize)]
struct AccessBody {
    node_id: String,
    node_name: String,
    labels: BTreeMap<String, String>,
    policy_hash: String,
    policy_loaded_at: Option<i64>,
    roles: Vec<RoleBody>,
}

struct Facts {
    revoked: BTreeSet<String>,
    versions: BTreeMap<String, String>,
    expiry: BTreeMap<String, CertificateExpiry>,
    states: BTreeMap<String, CertificateState>,
}

async fn facts(control: &Control, nodes: &[Node], now: i64) -> Result<Facts, StoreError> {
    let ids: Vec<String> = nodes.iter().map(|node| node.id.clone()).collect();
    let unversioned: Vec<String> = nodes
        .iter()
        .filter(|node| node.agent_version.is_none())
        .map(|node| node.id.clone())
        .collect();
    Ok(Facts {
        revoked: control
            .store
            .revocations()
            .revoked_among(RevocationKind::Node, &ids)
            .await?,
        versions: control
            .store
            .enrollments()
            .agent_versions(&unversioned)
            .await?,
        expiry: control.store.nodes().certificate_expiry(&ids).await?,
        states: control.store.nodes().certificate_states(now).await?,
    })
}

fn node_body(control: &Control, node: Node, facts: &Facts) -> NodeBody {
    let connected_at = match node.state {
        NodeState::Active => control.presence.connected_since(&node.id),
        NodeState::Removed => None,
    };
    let connected_since = connected_at.and_then(unix_secs);
    let creates_accounts = connected_since.is_some()
        && control
            .host_accounts
            .capabilities
            .creates_accounts(&node.id, connected_at);
    let expiry = facts.expiry.get(&node.id).copied().unwrap_or_default();
    NodeBody {
        revoked: facts.revoked.contains(&node.id),
        agent_version: node
            .agent_version
            .clone()
            .or_else(|| facts.versions.get(&node.id).cloned()),
        certificates: CertificatesBody {
            state: facts
                .states
                .get(&node.id)
                .copied()
                .unwrap_or(CertificateState::None)
                .as_str(),
            x509_expires_at: expiry.x509,
            ssh_host_expires_at: expiry.ssh_host,
        },
        connected: connected_since.is_some(),
        connected_since,
        creates_accounts,
        state: node.state.as_str(),
        id: node.id,
        name: node.name,
        hostname: node.hostname,
        labels: node.labels,
        approved_by: node.approved_by,
        created_at: node.created_at,
        removed_at: node.removed_at,
    }
}

pub(crate) async fn list(
    State(control): State<Control>,
    _admin: RequireAdmin<NodesApprove>,
    uri: Uri,
) -> Response {
    let request = match list_request(uri.query()) {
        Ok(request) => request,
        Err(refusal) => return refusal.into_response(),
    };
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return server_error();
    };
    let answered = async {
        let page = control.store.nodes().page(&request.query).await?;
        let pending = control.store.enrollments().count_pending(now.secs).await?;
        let facts = facts(&control, &page.nodes, now.secs).await?;
        Ok::<_, StoreError>(ListBody {
            next: page.next.as_ref().map(cursor_text),
            nodes: page
                .nodes
                .into_iter()
                .map(|node| node_body(&control, node, &facts))
                .collect(),
            pending_enrolments: pending,
        })
    }
    .await;
    match answered {
        Ok(body) => json_response(StatusCode::OK, &body),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "listing the nodes failed");
            server_error()
        }
    }
}

pub(crate) async fn detail(
    State(control): State<Control>,
    _admin: RequireAdmin<NodesApprove>,
    Path(id): Path<String>,
) -> Response {
    let Some(id) = known_id(&id) else {
        return not_found();
    };
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return server_error();
    };
    let answered = async {
        let Some(node) = control.store.nodes().get(id).await? else {
            return Ok(None);
        };
        let facts = facts(&control, std::slice::from_ref(&node), now.secs).await?;
        let counts = control
            .store
            .sessions()
            .node_counts(id, now.secs.saturating_sub(RECENT_SESSIONS_SECS))
            .await?;
        Ok::<_, StoreError>(Some(DetailBody {
            tls_spki_sha256: node.tls_spki_sha256.clone(),
            ssh_host_key_fingerprint: node.ssh_host_key_fingerprint.clone(),
            sessions: SessionCountsBody {
                open: counts.open,
                last_24h: counts.since,
            },
            node: node_body(&control, node, &facts),
        }))
    }
    .await;
    match answered {
        Ok(Some(body)) => json_response(StatusCode::OK, &body),
        Ok(None) => not_found(),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "reading a node failed");
            server_error()
        }
    }
}

pub(crate) async fn remove(
    State(control): State<Control>,
    admin: RequireAdmin<NodesApprove>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: RemoveBody = match json_body(&headers, body) {
        Ok(body) => body,
        Err(failure) => return failure.into_response(),
    };
    let Some(id) = known_id(&id).map(str::to_owned) else {
        return not_found();
    };
    let actor = web_actor(&admin.session);
    let finished = tokio::spawn(async move {
        let removed = control
            .node_admin()
            .remove_node_by_id(&id, &body.confirm_name, &actor)
            .await?;
        let closed = match node_removal::cut_off(&control, &removed.id).await {
            Ok(closed) => Some(closed),
            Err(err) => {
                tracing::error!(
                    target: "jaunt::control",
                    error = %err,
                    node_id = %removed.id,
                    "the removed node's sessions were not closed at once; the session sweep closes them"
                );
                None
            }
        };
        Ok::<_, RemoveError>(RemovedBody {
            state: removed.state.as_str(),
            removed_at: removed.removed_at,
            id: removed.id,
            name: removed.name,
            sessions_closed: closed,
        })
    })
    .await;
    match finished {
        Ok(Ok(body)) => json_response(StatusCode::OK, &body),
        Ok(Err(RemoveError::UnknownNode)) => not_found(),
        Ok(Err(RemoveError::NotActive | RemoveError::NoActiveNode)) => conflict("node_not_active"),
        Ok(Err(RemoveError::NameMismatch)) => invalid_value("confirm_name_mismatch"),
        Ok(Err(
            err @ (RemoveError::InvalidOperator | RemoveError::Clock | RemoveError::Store(_)),
        )) => {
            tracing::error!(target: "jaunt::control", error = %err, "removing a node failed");
            server_error()
        }
        Err(_) => {
            tracing::error!(target: "jaunt::control", "the node removal task did not finish");
            server_error()
        }
    }
}

pub(crate) async fn access(
    State(control): State<Control>,
    _admin: RequireAdmin<SessionsRead>,
    Path(id): Path<String>,
) -> Response {
    let Some(id) = known_id(&id) else {
        return not_found();
    };
    let node = match control.store.nodes().get_active(id).await {
        Ok(Some(node)) => node,
        Ok(None) => return not_found(),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "reading a node failed");
            return server_error();
        }
    };
    let loaded = control.policy().loaded();
    let roles = loaded
        .set
        .roles_reaching(&NodeInfo {
            name: node.name.clone(),
            labels: node.labels.clone(),
        })
        .into_iter()
        .map(|role| RoleBody {
            role: role.role,
            users: role.users,
            groups: role.groups,
            logins: role.logins,
            port_forwarding: role.port_forwarding,
            record_input: role.record_input,
            admin: role
                .admin
                .iter()
                .map(|permission| permission.as_str())
                .collect(),
        })
        .collect();
    json_response(
        StatusCode::OK,
        &AccessBody {
            node_id: node.id,
            node_name: node.name,
            labels: node.labels,
            policy_hash: loaded.set.hash().to_owned(),
            policy_loaded_at: loaded.loaded_at.and_then(unix_secs),
            roles,
        },
    )
}

fn list_request(query: Option<&str>) -> Result<ListRequest, Refusal> {
    let mut state = None;
    let mut prefix = None;
    let mut limit = None;
    let mut after = None;
    let mut labels = Vec::new();
    for (key, value) in form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match key.as_ref() {
            "state" => once(&mut state, node_state(&value)?)?,
            "q" => once(&mut prefix, name_prefix(&value)?)?,
            "limit" => once(&mut limit, page_limit(&value)?)?,
            "cursor" => once(&mut after, parse_cursor(&value).ok_or(Refusal::Malformed)?)?,
            "label" => {
                if labels.len() >= MAX_LABEL_FILTERS {
                    return Err(Refusal::Invalid("invalid_label"));
                }
                labels.push(label_filter(&value)?);
            }
            _ => return Err(Refusal::Malformed),
        }
    }
    Ok(ListRequest {
        query: NodeQuery {
            state,
            labels,
            name_prefix: prefix,
            after,
            limit: limit.unwrap_or(DEFAULT_PAGE),
        },
    })
}

fn node_state(value: &str) -> Result<NodeState, Refusal> {
    match value {
        "active" => Ok(NodeState::Active),
        "removed" => Ok(NodeState::Removed),
        _ => Err(Refusal::Invalid("invalid_state")),
    }
}

fn name_prefix(value: &str) -> Result<String, Refusal> {
    if value.is_empty()
        || value.chars().count() > MAX_PREFIX_CHARS
        || value.chars().any(char::is_control)
    {
        return Err(Refusal::Invalid("invalid_prefix"));
    }
    Ok(value.to_owned())
}

fn label_filter(value: &str) -> Result<(String, String), Refusal> {
    let (key, wanted) = value
        .split_once(':')
        .ok_or(Refusal::Invalid("invalid_label"))?;
    Labels::stored(BTreeMap::from([(key.to_owned(), wanted.to_owned())]))
        .map_err(|_| Refusal::Invalid("invalid_label"))?;
    Ok((key.to_owned(), wanted.to_owned()))
}

fn cursor_text(cursor: &NodeCursor) -> String {
    format!("{}.{}", URL_SAFE_NO_PAD.encode(&cursor.name), cursor.id)
}

fn parse_cursor(text: &str) -> Option<NodeCursor> {
    let (name, id) = text.split_once('.')?;
    let name = String::from_utf8(URL_SAFE_NO_PAD.decode(name).ok()?).ok()?;
    (!name.is_empty() && is_identifier(id)).then(|| NodeCursor {
        name,
        id: id.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use jaunt_store::{NodeCursor, NodeState};

    use super::{Refusal, cursor_text, list_request, parse_cursor};

    #[test]
    fn node_list_queries_are_parsed_strictly() {
        let cursor = NodeCursor {
            name: "web.01".to_owned(),
            id: "67e55044-10b1-426f-9247-bb680e5fe0c8".to_owned(),
        };
        let text = cursor_text(&cursor);
        assert_eq!(parse_cursor(&text), Some(cursor.clone()));
        let parsed = list_request(Some(&format!(
            "state=removed&label=env:prod&label=team:web&q=web&limit=5&cursor={text}"
        )))
        .unwrap()
        .query;
        assert_eq!(parsed.state, Some(NodeState::Removed));
        assert_eq!(parsed.labels.len(), 2);
        assert_eq!(parsed.name_prefix.as_deref(), Some("web"));
        assert_eq!((parsed.limit, parsed.after), (5, Some(cursor)));
        assert_eq!(list_request(None).unwrap().query.limit, 50);

        for (query, refusal) in [
            ("state=pending", Refusal::Invalid("invalid_state")),
            ("state=rejected", Refusal::Invalid("invalid_state")),
            ("label=env", Refusal::Invalid("invalid_label")),
            ("label=Env:prod", Refusal::Invalid("invalid_label")),
            ("q=", Refusal::Invalid("invalid_prefix")),
            ("limit=0", Refusal::Invalid("invalid_limit")),
            ("limit=x", Refusal::Malformed),
            ("state=active&state=active", Refusal::Malformed),
            ("cursor=nodot", Refusal::Malformed),
            ("cursor=%2F%2F.id", Refusal::Malformed),
            ("other=1", Refusal::Malformed),
        ] {
            assert_eq!(list_request(Some(query)), Err(refusal), "{query}");
        }
    }
}
