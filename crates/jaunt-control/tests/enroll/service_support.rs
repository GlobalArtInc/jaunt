use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use jaunt_ca::fingerprint_hex;
use jaunt_control::AgentPresence;
use jaunt_proto::{
    DbAccessRequest, NodeCaller, RouteDecision, ServiceAuthorizeDecision, ServiceAuthorizeRequest,
    ServiceEnd, ServiceIdentity, ServiceKind, ServiceOutcome, ServiceRouteRequest,
    SessionEndOutcome,
};
use jaunt_store::{NewCertificate, Parent, ServiceApproval, ServiceQuery, ServiceState, Session};
use serde_json::{Value, json};

use crate::issuance_support::{DOMAIN, RecordingKiller, spki};
use crate::session_support::{apply_policy, node, plane, subject_fingerprint, user};
use crate::support::{APPROVER, Harness, Options, RecordingOptions, request, send};

pub const CLIENT: &str = "203.0.113.9:41000";
pub const KUBE_ID: &str = "k-0123456789abcdef0123456789abcdef";
pub const TCP: &str = "grafana";
pub const DB: &str = "lk";
pub const KUBE: &str = "prod-eu";
pub const SHARED: &str = "shared";
pub const METRICS: &str = "metrics";
pub const SERVICE_NODE: &str = "svc-01";

pub const OPS_ROLE: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: ops }\nspec:\n  \
    members: { groups: [ops] }\n  tcp: { services: { team: [ops] } }\n  \
    databases: { servers: { env: [prod] }, users: [app, \"{username}\"], names: ['*'] }\n  \
    kubernetes: { clusters: { env: [prod] }, groups: [view], recordInput: true }\n";

#[derive(Default)]
pub struct Presence(Mutex<Vec<String>>);

impl Presence {
    pub fn disconnect(&self, node_id: &str) {
        self.0.lock().unwrap().push(node_id.to_owned());
    }
}

impl AgentPresence for Presence {
    fn connected_since(&self, node_id: &str) -> Option<SystemTime> {
        let gone = self.0.lock().unwrap().iter().any(|id| id == node_id);
        (!gone).then_some(UNIX_EPOCH + Duration::from_secs(1))
    }
}

pub struct Stand {
    pub harness: Harness,
    pub node_id: String,
    pub other_node_id: String,
    pub killer: Arc<RecordingKiller>,
    pub presence: Arc<Presence>,
}

pub fn tcp_service(name: &str) -> Value {
    json!({"kind": "tcp", "name": name, "labels": {"team": "ops"}, "address": "10.0.0.5:3000"})
}

pub fn db_service(name: &str) -> Value {
    json!({"kind": "postgres", "name": name, "labels": {"env": "prod"},
           "address": "127.0.0.1:5432", "postgres": {"tls": {"ca_file": "/etc/jaunt/pg-ca.pem", "server_name": "db-01"}}})
}

pub fn kube_service(name: &str) -> Value {
    json!({"kind": "kubernetes", "name": name, "labels": {"env": "prod"}})
}

pub async fn announce(harness: &Harness, node_id: &str, services: &[Value]) {
    let reply = send(
        harness.agent_router.clone(),
        request(
            "/v1/agent/services",
            &json!({ "services": services }),
            None,
            Some(node_id),
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT, "{}", reply.text());
}

pub async fn pending_id(harness: &Harness, node_id: &str, kind: &str, name: &str) -> String {
    let page = harness
        .store
        .services()
        .page(&ServiceQuery {
            state: Some(ServiceState::Pending),
            node_id: Some(node_id.to_owned()),
            after: None,
            limit: 100,
        })
        .await
        .unwrap();
    page.services
        .into_iter()
        .find(|service| service.name == name && service.kind.as_str() == kind)
        .unwrap_or_else(|| panic!("no pending {kind}/{name}"))
        .id
}

pub async fn approve(harness: &Harness, node_id: &str, kind: &str, name: &str) -> String {
    let id = pending_id(harness, node_id, kind, name).await;
    harness
        .store
        .services()
        .approve(&ServiceApproval {
            id: &id,
            approver: APPROVER,
            labels_override: None,
            now: harness.clock.now_secs(),
        })
        .await
        .unwrap();
    id
}

pub async fn stand() -> Stand {
    stand_with_policy(&[OPS_ROLE.to_owned()]).await
}

pub async fn stand_with_policy(roles: &[String]) -> Stand {
    stand_built(roles, None, false).await
}

pub async fn recording_stand(roles: &[String]) -> Stand {
    stand_built(roles, Some(RecordingOptions::default()), false).await
}

pub async fn web_recording_stand(roles: &[String]) -> Stand {
    stand_built(roles, Some(RecordingOptions::default()), true).await
}

async fn stand_built(roles: &[String], recordings: Option<RecordingOptions>, web: bool) -> Stand {
    let harness = Harness::with(Options {
        services_domain: Some(DOMAIN),
        user_x509_root_age: Some(Duration::ZERO),
        db_client_root_age: Some(Duration::ZERO),
        recordings,
        web,
        ..Options::default()
    })
    .await;
    let killer = Arc::new(RecordingKiller::default());
    harness.control.install_session_killer(killer.clone());
    let presence = Arc::new(Presence::default());
    harness.control.install_agent_presence(presence.clone());
    apply_policy(&harness, roles);
    let node_id = node(&harness, SERVICE_NODE).await;
    let other_node_id = node(&harness, "svc-02").await;
    announce(
        &harness,
        &node_id,
        &[
            tcp_service(TCP),
            tcp_service(METRICS),
            tcp_service(SHARED),
            db_service(SHARED),
            db_service(DB),
            kube_service(KUBE),
        ],
    )
    .await;
    for (kind, name) in [
        ("tcp", TCP),
        ("tcp", METRICS),
        ("tcp", SHARED),
        ("postgres", SHARED),
        ("postgres", DB),
        ("kubernetes", KUBE),
    ] {
        approve(&harness, &node_id, kind, name).await;
    }
    Stand {
        harness,
        node_id,
        other_node_id,
        killer,
        presence,
    }
}

pub struct X509 {
    pub user_id: String,
    pub parent: i64,
    pub serial: i64,
    pub subject: String,
    pub issuer: String,
}

impl X509 {
    pub fn identity(&self) -> ServiceIdentity {
        ServiceIdentity {
            user_id: self.user_id.clone(),
            serial: u64::try_from(self.serial).unwrap(),
            subject_fingerprint: self.subject.clone(),
            issuer_fingerprint: self.issuer.clone(),
        }
    }
}

pub fn active_issuer(harness: &Harness) -> String {
    fingerprint_hex(harness.control.user_x509().unwrap().trust.active())
}

pub async fn parent_certificate(harness: &Harness, user_id: &str) -> i64 {
    let now = harness.clock.now_secs();
    let certificates = harness.store.certificates();
    let parent = certificates.allocate_serial().await.unwrap();
    certificates
        .record(&NewCertificate {
            serial: parent,
            user_id: user_id.to_owned(),
            kind: "user".to_owned(),
            key_id: format!("jaunt:{user_id}@example.com:{parent}"),
            valid_after: now - 300,
            valid_before: now + 8 * 3600,
            issued_at: now - 300,
            ca_fingerprint: None,
            host_trust_id: None,
            subject_fingerprint: Some(subject_fingerprint()),
        })
        .await
        .unwrap();
    parent
}

pub async fn child_certificate(
    harness: &Harness,
    user_id: &str,
    parent: i64,
    window: (i64, i64),
    issuer: &str,
) -> X509 {
    let certificates = harness.store.certificates();
    let serial = certificates.allocate_serial().await.unwrap();
    let subject = subject_fingerprint();
    let recorded = certificates
        .record_child(
            &NewCertificate {
                serial,
                user_id: user_id.to_owned(),
                kind: "x509".to_owned(),
                key_id: format!("{serial:064x}"),
                valid_after: window.0,
                valid_before: window.1,
                issued_at: window.0,
                ca_fingerprint: Some(issuer.to_owned()),
                host_trust_id: None,
                subject_fingerprint: Some(subject.clone()),
            },
            Parent {
                serial: parent,
                kind: "user",
            },
        )
        .await
        .unwrap();
    assert!(recorded);
    X509 {
        user_id: user_id.to_owned(),
        parent,
        serial,
        subject,
        issuer: issuer.to_owned(),
    }
}

pub async fn person(harness: &Harness, subject: &str, groups: &[&str]) -> X509 {
    let user_id = user(harness, subject, groups).await;
    let parent = parent_certificate(harness, &user_id).await;
    let now = harness.clock.now_secs();
    let issuer = active_issuer(harness);
    child_certificate(
        harness,
        &user_id,
        parent,
        (now - 60, now + 4 * 3600),
        &issuer,
    )
    .await
}

pub fn route_request(holder: &X509, kind: ServiceKind, service: &str) -> ServiceRouteRequest {
    ServiceRouteRequest {
        identity: holder.identity(),
        kind,
        service: service.to_owned(),
        client_addr: CLIENT.to_owned(),
    }
}

pub fn agent_key() -> String {
    spki().0
}

pub fn db_request(user: &str, name: &str) -> Option<DbAccessRequest> {
    Some(DbAccessRequest {
        user: user.to_owned(),
        name: name.to_owned(),
        agent_key: agent_key(),
    })
}

pub fn authorize_request(
    holder: &X509,
    session_id: &str,
    kind: ServiceKind,
    service: &str,
) -> ServiceAuthorizeRequest {
    ServiceAuthorizeRequest {
        session_id: session_id.to_owned(),
        kind,
        service: service.to_owned(),
        identity: holder.identity(),
        client_addr: CLIENT.to_owned(),
        db: (kind == ServiceKind::Postgres)
            .then(|| db_request("app", "main"))
            .flatten(),
    }
}

pub async fn route_service(harness: &Harness, request: ServiceRouteRequest) -> RouteDecision {
    plane(harness).route_service(request).await.unwrap()
}

pub async fn routed_id(
    harness: &Harness,
    holder: &X509,
    kind: ServiceKind,
    service: &str,
) -> String {
    match route_service(harness, route_request(holder, kind, service)).await {
        RouteDecision::Allow { session_id, .. } => session_id,
        RouteDecision::Deny { reason } => panic!("the route was denied: {reason:?}"),
    }
}

pub async fn authorize_service(
    harness: &Harness,
    node_id: &str,
    request: ServiceAuthorizeRequest,
) -> ServiceAuthorizeDecision {
    plane(harness)
        .authorize_service(NodeCaller(node_id.to_owned()), request)
        .await
        .unwrap()
}

pub fn denied(decision: &ServiceAuthorizeDecision) -> Option<jaunt_proto::DenyReason> {
    match decision {
        ServiceAuthorizeDecision::Deny { reason } => Some(*reason),
        ServiceAuthorizeDecision::Allow(_) => None,
    }
}

pub fn route_denied(decision: &RouteDecision) -> Option<jaunt_proto::DenyReason> {
    match decision {
        RouteDecision::Deny { reason } => Some(*reason),
        RouteDecision::Allow { .. } => None,
    }
}

pub async fn open(stand: &Stand, holder: &X509, kind: ServiceKind, service: &str) -> String {
    let session_id = match kind {
        ServiceKind::Kubernetes => format!("k-{:032x}", rand_suffix(stand).await),
        ServiceKind::Postgres | ServiceKind::Tcp => {
            routed_id(&stand.harness, holder, kind, service).await
        }
    };
    let decision = authorize_service(
        &stand.harness,
        &stand.node_id,
        authorize_request(holder, &session_id, kind, service),
    )
    .await;
    assert_eq!(denied(&decision), None, "{kind:?} {service}");
    session_id
}

async fn rand_suffix(stand: &Stand) -> u128 {
    u128::try_from(
        stand
            .harness
            .store
            .certificates()
            .allocate_serial()
            .await
            .unwrap(),
    )
    .unwrap()
}

pub async fn end_service(
    harness: &Harness,
    node_id: &str,
    session_id: &str,
    outcome: ServiceOutcome,
    bytes_out: u64,
) -> SessionEndOutcome {
    plane(harness)
        .service_end(
            NodeCaller(node_id.to_owned()),
            ServiceEnd {
                session_id: session_id.to_owned(),
                outcome,
                bytes_in: 5,
                bytes_out,
            },
        )
        .await
        .unwrap()
}

pub async fn row(harness: &Harness, session_id: &str) -> Session {
    harness
        .store
        .sessions()
        .get(session_id)
        .await
        .unwrap()
        .unwrap()
}

pub async fn ssh_session(stand: &Stand, holder: &crate::session_support::Holder) -> String {
    let RouteDecision::Allow { session_id, .. } =
        crate::session_support::route(&stand.harness, holder.route_to(SERVICE_NODE)).await
    else {
        panic!("the ssh route was denied");
    };
    let decision = crate::session_support::authorize(
        &stand.harness,
        &stand.node_id,
        holder.authorize(&session_id, crate::session_support::LOGIN),
    )
    .await;
    assert!(
        matches!(decision, jaunt_proto::AuthorizeDecision::Allow { .. }),
        "{decision:?}"
    );
    session_id
}
