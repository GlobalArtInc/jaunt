mod audit;
mod catalog;
mod ledger;
pub(crate) mod notices;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Extension;
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use jaunt_audit::EventType;
use jaunt_limits::{Decision, Rate, RateLimiter};
use jaunt_proto::{
    AGENT_EVENTS_INVALID_SESSION, AGENT_EVENTS_MAX_BATCH, AGENT_EVENTS_MAX_DROPPED,
    AGENT_EVENTS_MAX_REFUSED_SESSIONS, AgentEventBatch, AgentEventsAccepted, AgentEventsRefusal,
    is_kube_child_session_id, is_kube_session_id,
};
use jaunt_store::{MAX_AUDIT_LOOKUP, Session, SessionKind, SessionState, is_session_id};

use crate::agent::{AuthenticatedNode, active_node};
use crate::control::Control;
use crate::http::{
    BodyFailure, empty_response, error_response, json_body, json_response, server_error,
};
use crate::limits::too_many_requests;

use audit::{Accepted, DropReason};
use catalog::Fitting;
use ledger::{Budget, Charge, ENDED_GRACE_SECS, Edge, Gate, Ledger, Verdict, WINDOW_SECS};
use notices::Notices;

pub(crate) const REQUESTS_PER_NODE: Rate = Rate::clamped(50, 50 * 60);
pub(crate) const EDGES_PER_NODE: Rate = Rate::clamped(200, 50 * 60);
pub(crate) const LIFECYCLE_PER_NODE: Rate = Rate::clamped(500, 100 * 60);
pub(crate) const MARKS_PER_NODE: Rate = Rate::clamped(100, 20 * 60);
pub(crate) const CRITICAL_FROM_AGENTS: Rate = Rate::clamped(2000, 400 * 60);
pub(crate) const MAX_FITTED_PER_REQUEST: usize = 16;
const NODES_TRACKED: usize = 10_000;
const INVALID_BATCH: &str = "invalid_batch";

pub(crate) struct AgentEvents {
    requests: RateLimiter<String>,
    edges: RateLimiter<String>,
    lifecycle: RateLimiter<String>,
    marks: RateLimiter<String>,
    agents: RateLimiter<()>,
    ledger: Ledger,
    notices: Notices,
    mark_attempts: AtomicU64,
    fittings: AtomicU64,
}

impl AgentEvents {
    pub(crate) fn new() -> AgentEvents {
        AgentEvents {
            requests: RateLimiter::new(REQUESTS_PER_NODE, NODES_TRACKED),
            edges: RateLimiter::new(EDGES_PER_NODE, NODES_TRACKED),
            lifecycle: RateLimiter::new(LIFECYCLE_PER_NODE, NODES_TRACKED),
            marks: RateLimiter::new(MARKS_PER_NODE, NODES_TRACKED),
            agents: RateLimiter::new(CRITICAL_FROM_AGENTS, 1),
            ledger: Ledger::new(),
            notices: Notices::new(),
            mark_attempts: AtomicU64::new(0),
            fittings: AtomicU64::new(0),
        }
    }

    pub(crate) fn sweep_limits(&self, tick: std::time::Duration) {
        self.requests.sweep(tick);
        self.edges.sweep(tick);
        self.lifecycle.sweep(tick);
        self.marks.sweep(tick);
        self.agents.sweep(tick);
        self.notices.sweep(tick);
    }

    fn admit(&self, node: &String, charge: Charge, tick: std::time::Duration) -> Gate {
        let bucket = match charge {
            Charge::Once(_) => &self.edges,
            Charge::Budgeted(_) | Charge::Invalid => &self.lifecycle,
        };
        self.admit_in(bucket, node, tick)
    }

    fn admit_mark(&self, node: &String, tick: std::time::Duration) -> Gate {
        self.admit_in(&self.marks, node, tick)
    }

    fn admit_in(
        &self,
        bucket: &RateLimiter<String>,
        node: &String,
        tick: std::time::Duration,
    ) -> Gate {
        if !bucket.check(node, tick).is_allowed() {
            return Gate::Node;
        }
        if !self.agents.check(&(), tick).is_allowed() {
            return Gate::Agents;
        }
        Gate::Open
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn tracked(&self) -> usize {
        self.ledger.len()
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn mark_attempts(&self) -> u64 {
        self.mark_attempts.load(Ordering::Relaxed)
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn fittings(&self) -> u64 {
        self.fittings.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    Malformed,
    TooLarge,
    TooManyEvents,
    TooManyReports,
    SessionIdShape,
    UnknownSession,
    ForeignSession,
    SshSession,
    NotAuthorized,
}

impl Refusal {
    const fn code(self) -> &'static str {
        match self {
            Refusal::Malformed => "malformed",
            Refusal::TooLarge => "too_large",
            Refusal::TooManyEvents => "too_many_events",
            Refusal::TooManyReports => "too_many_reports",
            Refusal::SessionIdShape => "session_id_shape",
            Refusal::UnknownSession => "unknown_session",
            Refusal::ForeignSession => "foreign_session",
            Refusal::SshSession => "ssh_session",
            Refusal::NotAuthorized => "not_authorized",
        }
    }

    const fn notice(self) -> &'static str {
        match self {
            Refusal::Malformed | Refusal::TooLarge => "body",
            other => other.code(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Standing {
    Live,
    Expired,
}

fn session_ids(batch: &AgentEventBatch) -> BTreeSet<&str> {
    batch
        .events
        .iter()
        .map(|event| event.session_id.as_str())
        .chain(
            batch
                .dropped
                .iter()
                .map(|report| report.session_id.as_str()),
        )
        .collect()
}

fn shape(batch: &AgentEventBatch) -> Result<(), Refusal> {
    if batch.events.len() > AGENT_EVENTS_MAX_BATCH {
        return Err(Refusal::TooManyEvents);
    }
    if batch.dropped.len() > AGENT_EVENTS_MAX_DROPPED {
        return Err(Refusal::TooManyReports);
    }
    let well_formed = session_ids(batch)
        .into_iter()
        .all(|id| is_session_id(id) || is_kube_session_id(id) || is_kube_child_session_id(id));
    if well_formed {
        Ok(())
    } else {
        Err(Refusal::SessionIdShape)
    }
}

fn standing(session: Option<&Session>, node_id: &str, now: i64) -> Result<Standing, Refusal> {
    let session = session.ok_or(Refusal::UnknownSession)?;
    if session.node_id != node_id {
        return Err(Refusal::ForeignSession);
    }
    if session.kind == SessionKind::Ssh {
        return Err(Refusal::SshSession);
    }
    if session.authorized_at.is_none() {
        return Err(Refusal::NotAuthorized);
    }
    if session.state == SessionState::Ended
        && session
            .ended_at
            .is_none_or(|ended| now.saturating_sub(ended) > ENDED_GRACE_SECS)
    {
        return Ok(Standing::Expired);
    }
    Ok(Standing::Live)
}

fn charge_of(kind: EventType) -> Charge {
    match kind {
        EventType::KubeSessionStart | EventType::DbSessionStart | EventType::TcpSessionStart => {
            Charge::Once(Edge::Start)
        }
        EventType::KubeSessionEnd | EventType::DbSessionEnd | EventType::TcpSessionEnd => {
            Charge::Once(Edge::End)
        }
        EventType::KubeExecStart | EventType::KubeExecEnd => Charge::Budgeted(Budget::Exec),
        EventType::DbProtocolError => Charge::Budgeted(Budget::ProtocolError),
        EventType::KubeRequest | EventType::DbQuery | EventType::DbError => {
            Charge::Budgeted(Budget::Noisy)
        }
        _ => Charge::Invalid,
    }
}

fn needs_update(row_already_marked: bool, pending: Option<u64>) -> bool {
    !row_already_marked && pending.is_some()
}

fn refuse(
    control: &Control,
    node_id: &str,
    refusal: Refusal,
    events: usize,
    sessions: usize,
) -> Response {
    let notices = &control.agent_events.notices;
    if let Some(suppressed) = notices.admit(node_id, refusal.notice(), control.tick()) {
        audit::refused(node_id, refusal.code(), events, sessions, suppressed);
    }
    match refusal {
        Refusal::Malformed => BodyFailure::Malformed.into_response(),
        Refusal::TooLarge => BodyFailure::TooLarge.into_response(),
        Refusal::TooManyEvents | Refusal::TooManyReports | Refusal::SessionIdShape => {
            error_response(StatusCode::BAD_REQUEST, INVALID_BATCH)
        }
        Refusal::UnknownSession
        | Refusal::ForeignSession
        | Refusal::SshSession
        | Refusal::NotAuthorized => {
            error_response(StatusCode::BAD_REQUEST, AGENT_EVENTS_INVALID_SESSION)
        }
    }
}

fn refuse_sessions(
    control: &Control,
    node_id: &str,
    batch: &AgentEventBatch,
    offenders: &[(&str, Refusal)],
) -> Response {
    let Some((_, first)) = offenders.first() else {
        return server_error();
    };
    let notices = &control.agent_events.notices;
    if let Some(suppressed) = notices.admit(node_id, first.notice(), control.tick()) {
        audit::refused(
            node_id,
            first.code(),
            batch.events.len(),
            offenders.len(),
            suppressed,
        );
    }
    json_response(
        StatusCode::BAD_REQUEST,
        &AgentEventsRefusal {
            error: AGENT_EVENTS_INVALID_SESSION.to_owned(),
            sessions: offenders
                .iter()
                .take(AGENT_EVENTS_MAX_REFUSED_SESSIONS)
                .map(|(id, _)| (*id).to_owned())
                .collect(),
        },
    )
}

pub(crate) async fn handle(
    State(control): State<Control>,
    authenticated: Option<Extension<AuthenticatedNode>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(Extension(AuthenticatedNode(node_id))) = authenticated else {
        return empty_response(StatusCode::UNAUTHORIZED);
    };
    if let Decision::Limited { retry_after } = control
        .agent_events
        .requests
        .check(&node_id, control.tick())
    {
        return too_many_requests(retry_after);
    }
    let batch = match json_body::<AgentEventBatch>(&headers, body) {
        Ok(batch) => batch,
        Err(BodyFailure::TooLarge) => return refuse(&control, &node_id, Refusal::TooLarge, 0, 0),
        Err(BodyFailure::Malformed) => return refuse(&control, &node_id, Refusal::Malformed, 0, 0),
    };
    if let Err(refusal) = shape(&batch) {
        let sessions = session_ids(&batch).len();
        return refuse(&control, &node_id, refusal, batch.events.len(), sessions);
    }
    let task = tokio::spawn(async move { record(&control, &node_id, batch).await });
    task.await.unwrap_or_else(|_| {
        tracing::error!(target: "jaunt::control", "recording agent events did not finish");
        server_error()
    })
}

#[derive(Default)]
struct Tally {
    accepted: u64,
    dropped: u64,
    withheld: u64,
    drops: BTreeMap<(String, DropReason), u64>,
}

impl Tally {
    fn drop(&mut self, session_id: &str, reason: DropReason, count: u64) {
        let slot = self
            .drops
            .entry((session_id.to_owned(), reason))
            .or_insert(0);
        *slot = slot.saturating_add(count);
    }

    fn drop_event(&mut self, session_id: &str, reason: DropReason) {
        self.dropped += 1;
        self.drop(session_id, reason, 1);
    }
}

fn verdict_drop(verdict: Verdict) -> Option<DropReason> {
    match verdict {
        Verdict::Repeat | Verdict::Accept => None,
        Verdict::Invalid => Some(DropReason::Invalid),
        Verdict::OverBudget => Some(DropReason::Budget),
        Verdict::Duplicate => Some(DropReason::Duplicate),
        Verdict::NodeCeiling => Some(DropReason::NodeCeiling),
        Verdict::AgentsCeiling => Some(DropReason::AgentsCeiling),
    }
}

async fn record(control: &Control, node_id: &str, batch: AgentEventBatch) -> Response {
    if let Err(refusal) = active_node(control, node_id).await {
        return refusal.into_response();
    }
    let ids: Vec<&str> = session_ids(&batch).into_iter().collect();
    let rows = match control.store.service_sessions().for_audit(&ids).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "reading the sessions of agent events failed");
            return server_error();
        }
    };
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return server_error();
    };
    let sessions: HashMap<&str, &Session> = rows
        .iter()
        .map(|session| (session.id.as_str(), session))
        .collect();
    let mut standings: HashMap<&str, Standing> = HashMap::new();
    let mut offenders: Vec<(&str, Refusal)> = Vec::new();
    for id in &ids {
        match standing(sessions.get(id).copied(), node_id, now.secs) {
            Ok(standing) => {
                standings.insert(*id, standing);
            }
            Err(refusal) => offenders.push((id, refusal)),
        }
    }
    if !offenders.is_empty() {
        return refuse_sessions(control, node_id, &batch, &offenders);
    }
    let state = &control.agent_events;
    let tick = control.tick();
    let node_key = node_id.to_owned();
    let now_ms = now.secs.saturating_mul(1000);
    let mut tally = Tally::default();
    let mut fitting = Fitting::new(MAX_FITTED_PER_REQUEST);
    for event in &batch.events {
        let Some(session) = sessions.get(event.session_id.as_str()).copied() else {
            continue;
        };
        if standings.get(event.session_id.as_str()) == Some(&Standing::Expired) {
            tally.drop_event(&event.session_id, DropReason::Expired);
            continue;
        }
        if state.ledger.is_repeat(&event.session_id, event.seq) {
            tally.accepted += 1;
            continue;
        }
        let checked = catalog::check(event, session, now_ms, &mut fitting);
        let charge = match &checked {
            Err(_) => Charge::Invalid,
            Ok(checked) => charge_of(checked.kind),
        };
        let verdict = state.ledger.decide(
            &event.session_id,
            event.seq,
            charge,
            session.ended_at,
            now.secs,
            |charge| state.admit(&node_key, charge, tick),
        );
        if let Some(reason) = verdict_drop(verdict) {
            tally.drop_event(&event.session_id, reason);
            continue;
        }
        tally.accepted += 1;
        if let (Verdict::Accept, Ok(checked)) = (verdict, checked) {
            tally.withheld += checked.withheld;
            audit::accepted(
                checked.kind,
                &Accepted {
                    session,
                    observed_at: checked.observed_at,
                    fields: &checked.fields,
                },
            );
        }
    }
    for report in &batch.dropped {
        if report.count == 0 {
            continue;
        }
        let reason = match standings.get(report.session_id.as_str()) {
            Some(Standing::Expired) => DropReason::Expired,
            _ => DropReason::AgentQueue,
        };
        tally.drop(&report.session_id, reason, report.count);
    }
    state.fittings.fetch_add(fitting.used(), Ordering::Relaxed);
    for ((session_id, reason), count) in &tally.drops {
        let Some(session) = sessions.get(session_id.as_str()).copied() else {
            continue;
        };
        if let Some(suppressed) = state.notices.admit(node_id, reason.code(), tick) {
            audit::dropped(session, *reason, *count, suppressed);
        }
        state.ledger.note_dropped(
            session_id,
            *count,
            !session.audit_incomplete,
            session.ended_at,
            now.secs,
        );
    }
    let mut failed = false;
    for id in &ids {
        let Some(session) = sessions.get(id).copied() else {
            continue;
        };
        if let Err(err) = settle_mark(control, session).await {
            tracing::error!(target: "jaunt::control", error = %err, session_id = *id, "marking the audit of a session incomplete failed");
            failed = true;
        }
        announce(control, session, now.secs, tick);
    }
    if failed {
        return server_error();
    }
    json_response(
        StatusCode::OK,
        &AgentEventsAccepted {
            accepted: tally.accepted,
            dropped: tally.dropped,
            withheld: tally.withheld,
        },
    )
}

async fn settle_mark(control: &Control, session: &Session) -> Result<(), jaunt_store::StoreError> {
    let state = &control.agent_events;
    let pending = state.ledger.pending_mark(&session.id);
    if !needs_update(session.audit_incomplete, pending) {
        if pending.is_some() {
            state.ledger.marked(&session.id);
        }
        return Ok(());
    }
    state.mark_attempts.fetch_add(1, Ordering::Relaxed);
    let newly = control
        .store
        .service_sessions()
        .mark_audit_incomplete(&session.id, &session.node_id)
        .await?;
    state.ledger.marked(&session.id);
    if newly {
        state.ledger.defer_event(&session.id);
    }
    Ok(())
}

fn announce(control: &Control, session: &Session, now: i64, tick: std::time::Duration) {
    let state = &control.agent_events;
    let Some(dropped_total) = state.ledger.pending_event(&session.id) else {
        return;
    };
    let long_ended = session
        .ended_at
        .is_some_and(|ended| now.saturating_sub(ended) > WINDOW_SECS);
    if long_ended {
        state.ledger.event_settled(&session.id);
        return;
    }
    if state.admit_mark(&session.node_id, tick) == Gate::Open {
        audit::audit_incomplete(session, dropped_total);
        state.ledger.event_settled(&session.id);
    }
}

#[cfg(feature = "test-support")]
pub(crate) async fn settle_stale(control: &Control, session_id: &str) -> Option<()> {
    let mut stale = control.store.sessions().get(session_id).await.ok()??;
    stale.audit_incomplete = false;
    let now = control.now()?;
    control
        .agent_events
        .ledger
        .note_dropped(session_id, 1, true, stale.ended_at, now.secs);
    settle_mark(control, &stale).await.ok()?;
    announce(control, &stale, now.secs, control.tick());
    Some(())
}

pub(crate) async fn sweep(control: &Control) {
    let Some(now) = control.now() else {
        return;
    };
    let state = &control.agent_events;
    let pending = state.ledger.unresolved(now.secs, MAX_AUDIT_LOOKUP);
    if !pending.is_empty() {
        let ids: Vec<&str> = pending.iter().map(String::as_str).collect();
        match control.store.service_sessions().for_audit(&ids).await {
            Ok(rows) => {
                for id in &ids {
                    match rows.iter().find(|row| row.id == *id) {
                        None => state.ledger.forget(id),
                        Some(session) => {
                            state.ledger.resolve(id, session.ended_at);
                            if let Err(err) = settle_mark(control, session).await {
                                tracing::warn!(target: "jaunt::control", error = %err, session_id = *id, "marking the audit of a session incomplete failed; it is retried at the next sweep");
                            }
                            announce(control, session, now.secs, control.tick());
                        }
                    }
                }
            }
            Err(err) => {
                tracing::warn!(target: "jaunt::control", error = %err, "reading the sessions of tracked agent events failed");
            }
        }
    }
    state.ledger.sweep(now.secs);
}

#[cfg(test)]
mod tests {
    use jaunt_audit::EventType;
    use jaunt_proto::{AGENT_EVENT_NAMES, AgentEvent, AgentEventBatch, DroppedEvents};
    use jaunt_store::{Session, SessionKind, SessionOrigin, SessionState};

    use super::{
        Budget, Charge, ENDED_GRACE_SECS, Edge, Refusal, Standing, charge_of, needs_update, shape,
        standing,
    };

    const NOW: i64 = 1_800_000_000;
    const UUID: &str = "0b0f4c6e-1d2a-4b3c-8d4e-5f6a7b8c9d0e";
    const KUBE: &str = "k-0123456789abcdef0123456789abcdef";

    fn session(kind: SessionKind) -> Session {
        Session {
            id: UUID.to_owned(),
            user_id: "u".to_owned(),
            serial: 1,
            node_id: "n".to_owned(),
            state: SessionState::Active,
            created_at: NOW - 10,
            expires_at: NOW + 10,
            authorized_at: Some(NOW - 9),
            ended_at: None,
            login: None,
            exit_status: None,
            bytes_in: None,
            bytes_out: None,
            recording_incomplete: None,
            end_reason: None,
            max_duration_secs: None,
            origin: SessionOrigin::Ssh,
            record_input: None,
            kind,
            service_id: None,
            target: None,
            roles: Vec::new(),
            grant_ids: Vec::new(),
            db_client_serial: None,
            outcome: None,
            decision_hash: None,
            service_name: None,
            audit_incomplete: false,
            parent_session_id: None,
            record: None,
        }
    }

    #[test]
    fn a_live_or_expired_service_session_of_this_node_is_owned_and_nothing_else() {
        let live = session(SessionKind::Db);
        let ended = |at: i64| Session {
            state: SessionState::Ended,
            ended_at: Some(at),
            ..session(SessionKind::Tcp)
        };
        let cases = [
            (None, "n", Err(Refusal::UnknownSession)),
            (Some(live.clone()), "other", Err(Refusal::ForeignSession)),
            (
                Some(session(SessionKind::Ssh)),
                "n",
                Err(Refusal::SshSession),
            ),
            (
                Some(Session {
                    state: SessionState::Routed,
                    authorized_at: None,
                    ..session(SessionKind::Tcp)
                }),
                "n",
                Err(Refusal::NotAuthorized),
            ),
            (Some(ended(NOW - ENDED_GRACE_SECS)), "n", Ok(Standing::Live)),
            (
                Some(ended(NOW - ENDED_GRACE_SECS - 1)),
                "n",
                Ok(Standing::Expired),
            ),
            (
                Some(ended(NOW - ENDED_GRACE_SECS - 1)),
                "other",
                Err(Refusal::ForeignSession),
            ),
            (
                Some(Session {
                    state: SessionState::Ended,
                    ..session(SessionKind::Kube)
                }),
                "n",
                Ok(Standing::Expired),
            ),
            (Some(live), "n", Ok(Standing::Live)),
            (Some(session(SessionKind::Kube)), "n", Ok(Standing::Live)),
        ];
        for (stored, node, expected) in cases {
            assert_eq!(
                standing(stored.as_ref(), node, NOW),
                expected,
                "{stored:?} {node}"
            );
        }
    }

    #[test]
    fn a_session_already_marked_in_its_row_is_never_marked_again() {
        assert!(needs_update(false, Some(3)));
        assert!(!needs_update(true, Some(3)));
        assert!(!needs_update(false, None));
        assert!(!needs_update(true, None));
    }

    #[test]
    fn every_agent_event_is_charged_to_its_own_kind_of_limit_and_nothing_else_is_charged() {
        for known in AGENT_EVENT_NAMES {
            let kind = EventType::from_name(known.name).unwrap();
            let expected = match known.name {
                "kube.session.start" | "db.session.start" | "tcp.session.start" => {
                    Charge::Once(Edge::Start)
                }
                "kube.session.end" | "db.session.end" | "tcp.session.end" => {
                    Charge::Once(Edge::End)
                }
                "kube.exec.start" | "kube.exec.end" => Charge::Budgeted(Budget::Exec),
                "db.protocol_error" => Charge::Budgeted(Budget::ProtocolError),
                _ => Charge::Budgeted(Budget::Noisy),
            };
            assert_eq!(charge_of(kind), expected, "{}", known.name);
            assert_eq!(
                matches!(expected, Charge::Budgeted(Budget::Noisy)),
                !known.lifecycle,
                "{}",
                known.name
            );
        }
        for other in [EventType::SessionStart, EventType::AgentEventsDropped] {
            assert_eq!(charge_of(other), Charge::Invalid);
        }
    }

    fn event(session_id: &str) -> AgentEvent {
        AgentEvent {
            session_id: session_id.to_owned(),
            seq: 1,
            observed_at: 0,
            name: "tcp.session.start".to_owned(),
            fields: Default::default(),
        }
    }

    #[test]
    fn the_batch_shape_bounds_events_reports_and_session_id_forms() {
        let full = AgentEventBatch {
            events: vec![event(UUID); 256],
            dropped: vec![
                DroppedEvents {
                    session_id: KUBE.to_owned(),
                    count: 1,
                };
                256
            ],
        };
        assert_eq!(shape(&full), Ok(()));
        let child = AgentEventBatch {
            events: vec![event("kx-0123456789abcdef0123456789abcdef")],
            dropped: Vec::new(),
        };
        assert_eq!(shape(&child), Ok(()));
        let mut over = full.clone();
        over.events.push(event(UUID));
        assert_eq!(shape(&over), Err(Refusal::TooManyEvents));
        let mut over = full.clone();
        over.dropped.push(over.dropped[0].clone());
        assert_eq!(shape(&over), Err(Refusal::TooManyReports));
        for bad in [
            "",
            "s-1",
            "k-0123",
            "kx-0123",
            &UUID.to_uppercase(),
            "../x",
            &format!("{UUID}\n"),
        ] {
            let batch = AgentEventBatch {
                events: vec![event(bad)],
                dropped: Vec::new(),
            };
            assert_eq!(shape(&batch), Err(Refusal::SessionIdShape), "{bad:?}");
        }
        let mut bad_report = AgentEventBatch::default();
        bad_report.dropped.push(DroppedEvents {
            session_id: "../x".to_owned(),
            count: 1,
        });
        assert_eq!(shape(&bad_report), Err(Refusal::SessionIdShape));
    }
}
