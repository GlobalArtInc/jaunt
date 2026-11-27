use std::collections::BTreeMap;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use jaunt_store::{
    ApprovedHolder, ApprovedService, Node, NodeState, Service, ServiceApproval,
    ServiceApproveOutcome, ServiceCursor, ServiceDecisionOutcome, ServiceQuery, ServiceState,
    StoreError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::control::Control;
use crate::http::{json_body, json_response, server_error};
use crate::labels::Labels;
use crate::revocation::is_identifier;
use crate::service_audit;

use super::admin_common::{
    DEFAULT_PAGE, Refusal, conflict, invalid_value, known_id, not_found, once, page_limit,
};
use super::session::{NodesApprove, RequireAdmin};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveBody {
    labels: Option<BTreeMap<String, String>>,
}

#[derive(Serialize)]
struct NodeRef {
    id: String,
    name: Option<String>,
    active: bool,
    connected: bool,
}

#[derive(Serialize)]
struct RevisionRef {
    id: String,
    revision: i64,
    labels: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct ConflictBody {
    node_id: String,
    node_name: String,
}

#[derive(Serialize)]
struct ServiceBody {
    id: String,
    node: NodeRef,
    kind: &'static str,
    name: String,
    state: &'static str,
    revision: i64,
    announced: bool,
    labels: BTreeMap<String, String>,
    announced_labels: BTreeMap<String, String>,
    settings: Value,
    address_hint: Option<String>,
    approved_by: Option<String>,
    approved_at: Option<i64>,
    created_at: i64,
    last_seen_at: i64,
    replaces: Option<RevisionRef>,
    conflict: Option<ConflictBody>,
}

#[derive(Serialize)]
struct ListBody {
    services: Vec<ServiceBody>,
    next: Option<String>,
}

#[derive(Serialize)]
struct ApprovedBody {
    service: ServiceBody,
    replaced: Option<RevisionRef>,
}

#[derive(Serialize)]
struct DecidedBody {
    service: ServiceBody,
}

#[derive(Serialize)]
struct SavedRef {
    id: String,
    state: &'static str,
}

#[derive(Serialize)]
struct SavedBody {
    service: SavedRef,
}

fn saved(service: &Service, err: &StoreError) -> Response {
    tracing::error!(
        target: "jaunt::control",
        error = %err,
        service_id = service.id.as_str(),
        "the service decision was saved but reading it back failed"
    );
    json_response(
        StatusCode::OK,
        &SavedBody {
            service: SavedRef {
                id: service.id.clone(),
                state: service.state.as_str(),
            },
        },
    )
}

struct Facts {
    nodes: BTreeMap<String, Node>,
    holders: Vec<ApprovedHolder>,
}

async fn facts(control: &Control) -> Result<Facts, StoreError> {
    let nodes = control
        .store
        .nodes()
        .list()
        .await?
        .into_iter()
        .map(|node| (node.id.clone(), node))
        .collect();
    let holders = control.store.services().approved_holders().await?;
    Ok(Facts { nodes, holders })
}

fn revision_ref(service: &Service) -> RevisionRef {
    RevisionRef {
        id: service.id.clone(),
        revision: service.revision,
        labels: service.labels.clone(),
    }
}

fn service_body(
    control: &Control,
    service: Service,
    facts: &Facts,
) -> Result<ServiceBody, StoreError> {
    let node = facts.nodes.get(&service.node_id);
    let active = node.is_some_and(|node| node.state == NodeState::Active);
    let pending = service.state == ServiceState::Pending;
    let mut replaces = None;
    let mut conflict = None;
    for holder in facts
        .holders
        .iter()
        .filter(|holder| pending && holder.kind == service.kind && holder.name == service.name)
    {
        if holder.node_id == service.node_id {
            replaces = Some(RevisionRef {
                id: holder.service_id.clone(),
                revision: holder.revision,
                labels: holder.labels.clone(),
            });
        } else if conflict.is_none() {
            conflict = Some(ConflictBody {
                node_id: holder.node_id.clone(),
                node_name: holder.node_name.clone(),
            });
        }
    }
    let settings = serde_json::from_str(&service.settings)
        .map_err(|_| StoreError::Corrupt("services.settings: not valid JSON".to_owned()))?;
    Ok(ServiceBody {
        node: NodeRef {
            name: node.map(|node| node.name.clone()),
            active,
            connected: active && control.presence.connected_since(&service.node_id).is_some(),
            id: service.node_id.clone(),
        },
        kind: service.kind.as_str(),
        state: service.state.as_str(),
        revision: service.revision,
        announced: service.announced,
        settings,
        replaces,
        conflict,
        id: service.id,
        name: service.name,
        labels: service.labels,
        announced_labels: service.announced_labels,
        address_hint: service.address_hint,
        approved_by: service.approved_by,
        approved_at: service.approved_at,
        created_at: service.created_at,
        last_seen_at: service.last_seen_at,
    })
}

pub(crate) async fn list(
    State(control): State<Control>,
    _admin: RequireAdmin<NodesApprove>,
    uri: Uri,
) -> Response {
    let query = match list_query(uri.query()) {
        Ok(query) => query,
        Err(refusal) => return refusal.into_response(),
    };
    let answered = async {
        let page = control.store.services().page(&query).await?;
        let facts = facts(&control).await?;
        Ok::<_, StoreError>(ListBody {
            next: page.next.as_ref().map(cursor_text),
            services: page
                .services
                .into_iter()
                .map(|service| service_body(&control, service, &facts))
                .collect::<Result<_, _>>()?,
        })
    }
    .await;
    match answered {
        Ok(body) => json_response(StatusCode::OK, &body),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "listing the services failed");
            server_error()
        }
    }
}

enum Decided {
    Approved(Box<ApprovedService>),
    Done(Box<Service>),
    Refused(Response),
}

async fn answer(control: &Control, decided: Result<Decided, StoreError>) -> Response {
    let decided = match decided {
        Ok(decided) => decided,
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "deciding on a service failed");
            return server_error();
        }
    };
    match decided {
        Decided::Approved(approved) => {
            let ApprovedService { service, replaced } = *approved;
            let kept = service.clone();
            let body = async {
                let facts = facts(control).await?;
                Ok::<_, StoreError>(ApprovedBody {
                    service: service_body(control, service, &facts)?,
                    replaced: replaced.as_ref().map(revision_ref),
                })
            }
            .await;
            match body {
                Ok(body) => json_response(StatusCode::OK, &body),
                Err(err) => saved(&kept, &err),
            }
        }
        Decided::Done(service) => {
            let kept = (*service).clone();
            let body = async {
                let facts = facts(control).await?;
                Ok::<_, StoreError>(DecidedBody {
                    service: service_body(control, *service, &facts)?,
                })
            }
            .await;
            match body {
                Ok(body) => json_response(StatusCode::OK, &body),
                Err(err) => saved(&kept, &err),
            }
        }
        Decided::Refused(response) => response,
    }
}

fn wrong_state(state: ServiceState) -> Response {
    match state {
        ServiceState::Pending => conflict("service_pending"),
        ServiceState::Approved => conflict("service_approved"),
        ServiceState::Removed => conflict("service_removed"),
    }
}

pub(crate) async fn approve(
    State(control): State<Control>,
    admin: RequireAdmin<NodesApprove>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: ApproveBody = match json_body(&headers, body) {
        Ok(body) => body,
        Err(failure) => return failure.into_response(),
    };
    let Some(id) = known_id(&id).map(str::to_owned) else {
        return not_found();
    };
    let labels = match body.labels.map(Labels::new).transpose() {
        Ok(labels) => labels.map(Labels::into_map),
        Err(_) => return invalid_value("invalid_labels"),
    };
    let actor = admin.principal.actor();
    let finished = tokio::spawn(async move {
        let decided = async {
            let Some(now) = control.now() else {
                tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
                return Ok(Decided::Refused(server_error()));
            };
            let outcome = control
                .store
                .services()
                .approve(&ServiceApproval {
                    id: &id,
                    approver: &actor,
                    labels_override: labels.as_ref(),
                    now: now.secs,
                })
                .await?;
            Ok(match outcome {
                ServiceApproveOutcome::Approved(approved) => {
                    service_audit::approved(
                        &approved.service,
                        &actor,
                        labels.is_some(),
                        approved.replaced.as_ref(),
                    );
                    Decided::Approved(approved)
                }
                ServiceApproveOutcome::NotFound => Decided::Refused(not_found()),
                ServiceApproveOutcome::NotPending(state) => Decided::Refused(wrong_state(state)),
                ServiceApproveOutcome::NodeNotActive => {
                    Decided::Refused(conflict("node_not_active"))
                }
                ServiceApproveOutcome::NameTaken { .. } => {
                    Decided::Refused(conflict("service_name_taken"))
                }
            })
        }
        .await;
        answer(&control, decided).await
    })
    .await;
    finished.unwrap_or_else(|_| {
        tracing::error!(target: "jaunt::control", "the service approval task did not finish");
        server_error()
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Reject,
    Remove,
}

async fn decide(
    control: Control,
    admin: RequireAdmin<NodesApprove>,
    id: String,
    decision: Decision,
) -> Response {
    let Some(id) = known_id(&id).map(str::to_owned) else {
        return not_found();
    };
    let actor = admin.principal.actor();
    let finished = tokio::spawn(async move {
        let services = control.store.services();
        let outcome = match decision {
            Decision::Reject => services.reject(&id).await,
            Decision::Remove => services.remove(&id).await,
        };
        let decided = outcome.map(|outcome| match outcome {
            ServiceDecisionOutcome::Done(service) => {
                match decision {
                    Decision::Reject => service_audit::rejected(&service, &actor),
                    Decision::Remove => service_audit::removed(&service, &actor),
                }
                Decided::Done(service)
            }
            ServiceDecisionOutcome::NotFound => Decided::Refused(not_found()),
            ServiceDecisionOutcome::WrongState(state) => Decided::Refused(wrong_state(state)),
        });
        answer(&control, decided).await
    })
    .await;
    finished.unwrap_or_else(|_| {
        tracing::error!(target: "jaunt::control", "the service decision task did not finish");
        server_error()
    })
}

pub(crate) async fn reject(
    State(control): State<Control>,
    admin: RequireAdmin<NodesApprove>,
    Path(id): Path<String>,
) -> Response {
    decide(control, admin, id, Decision::Reject).await
}

pub(crate) async fn remove(
    State(control): State<Control>,
    admin: RequireAdmin<NodesApprove>,
    Path(id): Path<String>,
) -> Response {
    decide(control, admin, id, Decision::Remove).await
}

fn list_query(query: Option<&str>) -> Result<ServiceQuery, Refusal> {
    let mut state = None;
    let mut node_id = None;
    let mut limit = None;
    let mut after = None;
    for (key, value) in form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match key.as_ref() {
            "state" => once(&mut state, service_state(&value)?)?,
            "node_id" => once(
                &mut node_id,
                known_id(&value)
                    .map(str::to_owned)
                    .ok_or(Refusal::Invalid("invalid_node_id"))?,
            )?,
            "limit" => once(&mut limit, page_limit(&value)?)?,
            "cursor" => once(&mut after, parse_cursor(&value).ok_or(Refusal::Malformed)?)?,
            _ => return Err(Refusal::Malformed),
        }
    }
    Ok(ServiceQuery {
        state,
        node_id,
        after,
        limit: limit.unwrap_or(DEFAULT_PAGE),
    })
}

fn service_state(value: &str) -> Result<ServiceState, Refusal> {
    match value {
        "pending" => Ok(ServiceState::Pending),
        "approved" => Ok(ServiceState::Approved),
        "removed" => Ok(ServiceState::Removed),
        _ => Err(Refusal::Invalid("invalid_state")),
    }
}

fn cursor_text(cursor: &ServiceCursor) -> String {
    format!("{}.{}", cursor.created_at, cursor.id)
}

fn parse_cursor(text: &str) -> Option<ServiceCursor> {
    let (created_at, id) = text.split_once('.')?;
    let created_at = created_at.parse::<i64>().ok()?;
    is_identifier(id).then(|| ServiceCursor {
        created_at,
        id: id.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use jaunt_store::{ServiceCursor, ServiceState};

    use super::{Refusal, cursor_text, list_query, parse_cursor};

    #[test]
    fn service_list_queries_are_parsed_strictly() {
        let cursor = ServiceCursor {
            created_at: 17,
            id: "67e55044-10b1-426f-9247-bb680e5fe0c8".to_owned(),
        };
        assert_eq!(parse_cursor(&cursor_text(&cursor)), Some(cursor.clone()));
        let parsed = list_query(Some(&format!(
            "state=pending&node_id=n-1&limit=5&cursor={}",
            cursor_text(&cursor)
        )))
        .unwrap();
        assert_eq!(parsed.state, Some(ServiceState::Pending));
        assert_eq!(parsed.node_id.as_deref(), Some("n-1"));
        assert_eq!((parsed.limit, parsed.after), (5, Some(cursor)));
        assert_eq!(list_query(None).unwrap().limit, 50);
        for (query, refusal) in [
            ("state=active", Refusal::Invalid("invalid_state")),
            ("node_id=a/b", Refusal::Invalid("invalid_node_id")),
            ("limit=0", Refusal::Invalid("invalid_limit")),
            ("state=pending&state=pending", Refusal::Malformed),
            ("cursor=x.y", Refusal::Malformed),
            ("other=1", Refusal::Malformed),
        ] {
            assert_eq!(list_query(Some(query)), Err(refusal), "{query}");
        }
    }
}
