use axum::Extension;
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use jaunt_limits::{Decision, Rate, RateLimiter};
use jaunt_policy::{Identity, PolicySet, ResourceInfo};
use jaunt_proto::{
    ServiceAnnouncement, ServiceKind as WireKind, ServiceList, ServiceProblem, ServiceSummary,
};
use jaunt_store::{AnnounceOutcome, AnnouncedService, Announcement, Service, ServiceKind};
use jaunt_tunnel::ServiceName;

use crate::agent::{AuthenticatedNode, node_removed};
use crate::control::Control;
use crate::http::{empty_response, error_response, json_body, json_response, server_error};
use crate::identity::policy_identity;
use crate::labels::Labels;
use crate::limits::too_many_requests;
use crate::service_audit;
use crate::whoami::authenticate;

pub(crate) const ANNOUNCEMENT_BODY_BYTES: usize = 256 * 1024;
pub(crate) const ANNOUNCEMENTS_PER_NODE: Rate = Rate::clamped(6, 6);
pub(crate) const MAX_LISTED_SERVICES: usize = 1000;
const NODES_TRACKED: usize = 10_000;

pub(crate) fn announcement_limiter() -> RateLimiter<String> {
    RateLimiter::new(ANNOUNCEMENTS_PER_NODE, NODES_TRACKED)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Invalid {
    TooMany,
    Duplicate,
    Name,
    Labels,
    Settings,
}

impl Invalid {
    const fn code(self) -> &'static str {
        match self {
            Invalid::TooMany => "too_many_services",
            Invalid::Duplicate => "duplicate_service",
            Invalid::Name => "invalid_service_name",
            Invalid::Labels => "invalid_labels",
            Invalid::Settings => "invalid_settings",
        }
    }
}

pub(crate) fn store_kind(kind: WireKind) -> ServiceKind {
    match kind {
        WireKind::Kubernetes => ServiceKind::Kubernetes,
        WireKind::Postgres => ServiceKind::Postgres,
        WireKind::Tcp => ServiceKind::Tcp,
    }
}

pub(crate) fn wire_kind(kind: ServiceKind) -> WireKind {
    match kind {
        ServiceKind::Kubernetes => WireKind::Kubernetes,
        ServiceKind::Postgres => WireKind::Postgres,
        ServiceKind::Tcp => WireKind::Tcp,
    }
}

pub(crate) fn validate(
    announcement: &ServiceAnnouncement,
) -> Result<Vec<AnnouncedService>, Invalid> {
    announcement.check_set().map_err(|problem| match problem {
        ServiceProblem::TooMany => Invalid::TooMany,
        ServiceProblem::Duplicate { .. } => Invalid::Duplicate,
        _ => Invalid::Settings,
    })?;
    announcement
        .services
        .iter()
        .map(|service| {
            ServiceName::new(service.name.as_str()).map_err(|_| Invalid::Name)?;
            let labels = Labels::new(service.labels.clone()).map_err(|_| Invalid::Labels)?;
            let settings = service.settings().map_err(|_| Invalid::Settings)?;
            let settings = serde_json::to_string(&settings).map_err(|_| Invalid::Settings)?;
            Ok(AnnouncedService {
                kind: store_kind(service.kind),
                name: service.name.clone(),
                labels: labels.into_map(),
                settings,
                address_hint: service.address.clone(),
            })
        })
        .collect()
}

pub(crate) async fn announce(
    State(control): State<Control>,
    authenticated: Option<Extension<AuthenticatedNode>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(Extension(AuthenticatedNode(node_id))) = authenticated else {
        return empty_response(StatusCode::UNAUTHORIZED);
    };
    if let Decision::Limited { retry_after } = control
        .service_announcements
        .check(&node_id, control.tick())
    {
        return too_many_requests(retry_after);
    }
    let announcement = match json_body::<ServiceAnnouncement>(&headers, body) {
        Ok(announcement) => announcement,
        Err(failure) => return failure.into_response(),
    };
    let services = match validate(&announcement) {
        Ok(services) => services,
        Err(invalid) => {
            service_audit::announce_refused(&node_id, invalid.code());
            return error_response(StatusCode::UNPROCESSABLE_ENTITY, invalid.code());
        }
    };
    let ssh_enabled = announcement.ssh_enabled;
    let task = tokio::spawn(async move {
        let Some(now) = control.now() else {
            tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
            return server_error();
        };
        let applied = control
            .store
            .services()
            .announce(&Announcement {
                node_id: &node_id,
                ssh_enabled,
                services: &services,
                now: now.secs,
            })
            .await;
        match applied {
            Ok(AnnounceOutcome::Applied(announced)) => {
                if let Some(enabled) = announced.ssh_changed {
                    service_audit::ssh_changed(&node_id, enabled);
                }
                for change in &announced.changes {
                    service_audit::changed(change);
                }
                empty_response(StatusCode::NO_CONTENT)
            }
            Ok(AnnounceOutcome::NodeNotActive) => node_removed(),
            Ok(AnnounceOutcome::TooMany) => {
                let code = Invalid::TooMany.code();
                service_audit::announce_refused(&node_id, code);
                error_response(StatusCode::UNPROCESSABLE_ENTITY, code)
            }
            Err(err) => {
                tracing::error!(target: "jaunt::control", error = %err, "recording the announced services failed");
                server_error()
            }
        }
    })
    .await;
    task.unwrap_or_else(|_| {
        tracing::error!(target: "jaunt::control", "the service announcement task did not finish");
        server_error()
    })
}

pub(crate) fn reachable(policy: &PolicySet, identity: &Identity, service: &Service) -> bool {
    let resource = ResourceInfo {
        name: service.name.clone(),
        labels: service.labels.clone(),
    };
    match service.kind {
        ServiceKind::Kubernetes => policy.authorize_kube(identity, &resource).allowed,
        ServiceKind::Tcp => policy.authorize_tcp(identity, &resource).allowed,
        ServiceKind::Postgres => policy.reaches_database_server(identity, &resource),
    }
}

pub(crate) fn listed(
    offered: &[Service],
    policy: &PolicySet,
    identity: &Identity,
    limit: usize,
    connected: impl Fn(&str) -> bool,
) -> ServiceList {
    let mut visible: Vec<&Service> = offered
        .iter()
        .filter(|service| reachable(policy, identity, service))
        .collect();
    visible.sort_by(|left, right| {
        (left.kind, &left.name, &left.node_id).cmp(&(right.kind, &right.name, &right.node_id))
    });
    let truncated = visible.len() > limit;
    visible.truncate(limit);
    ServiceList {
        services: visible
            .into_iter()
            .map(|service| ServiceSummary {
                kind: wire_kind(service.kind),
                name: service.name.clone(),
                labels: service.labels.clone(),
                connected: connected(&service.node_id),
            })
            .collect(),
        truncated,
    }
}

pub(crate) async fn list(State(control): State<Control>, headers: HeaderMap) -> Response {
    let valid = match authenticate(&control, &headers).await {
        Ok(valid) => valid,
        Err(failure) => return failure.into_response(),
    };
    let offered = match control.store.services().offered().await {
        Ok(offered) => offered,
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "listing the services failed");
            return server_error();
        }
    };
    let policy = control.policy_snapshot();
    let identity = policy_identity(&valid.user);
    let connected = |node_id: &str| control.presence.connected_since(node_id).is_some();
    json_response(
        StatusCode::OK,
        &listed(&offered, &policy, &identity, MAX_LISTED_SERVICES, connected),
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use jaunt_policy::{Identity, load_dir};
    use jaunt_store::{Service, ServiceKind, ServiceState};

    use super::listed;

    const ROLE: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: ops }\nspec:\n  members: { groups: [ops] }\n  tcp: { services: { team: [ops] } }\n";

    fn service(name: &str) -> Service {
        Service {
            id: format!("id-{name}"),
            node_id: "node-1".to_owned(),
            kind: ServiceKind::Tcp,
            name: name.to_owned(),
            labels: [("team".to_owned(), "ops".to_owned())].into(),
            announced_labels: [("team".to_owned(), "ops".to_owned())].into(),
            settings: "{}".to_owned(),
            address_hint: Some("10.0.0.5:3000".to_owned()),
            state: ServiceState::Approved,
            revision: 1,
            announced: true,
            approved_by: Some("web:admin".to_owned()),
            approved_at: Some(1),
            created_at: 1,
            last_seen_at: 1,
        }
    }

    #[test]
    fn the_list_is_cut_at_the_limit_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("role.yaml"), ROLE).unwrap();
        let policy = load_dir(dir.path()).unwrap();
        let identity = Identity {
            email: "alice@example.com".to_owned(),
            username: "alice".to_owned(),
            groups: vec!["ops".to_owned()],
        };
        let offered = [service("c"), service("a"), service("b")];

        let cut = listed(&offered, &policy, &identity, 2, |_| false);
        let whole = listed(&offered, &policy, &identity, 3, |_| true);

        let names: Vec<&str> = cut.services.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["a", "b"]);
        assert!(cut.truncated);
        assert_eq!(whole.services.len(), 3);
        assert!(!whole.truncated);
        assert!(whole.services.iter().all(|s| s.connected));
    }
}
