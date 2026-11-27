mod audit;
mod capabilities;
mod notices;

use axum::Extension;
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use jaunt_limits::Rate;
use jaunt_proto::{AccountReport, AgentCapabilities};
use jaunt_store::{Session, SessionState};

use crate::agent::{AuthenticatedNode, refuse_unless_active};
use crate::control::Control;
use crate::http::{empty_response, error_response, json_body, server_error};
use crate::plane::check_fields;

pub(crate) use self::notices::{AccountNotice, AccountNotices};

pub(crate) const REPORT_WINDOW_SECS: i64 = 50;

const FOREIGN_WARNINGS_PER_NODE: Rate = Rate::clamped(1, 1);

pub(crate) struct HostAccounts {
    pub(crate) capabilities: capabilities::Capabilities,
    pub(crate) notices: AccountNotices,
    refusals: audit::NodeThrottle,
    foreign_reports: audit::NodeThrottle,
}

impl Default for HostAccounts {
    fn default() -> Self {
        Self {
            capabilities: capabilities::Capabilities::default(),
            notices: AccountNotices::default(),
            refusals: audit::NodeThrottle::new(audit::REFUSALS_PER_NODE),
            foreign_reports: audit::NodeThrottle::new(FOREIGN_WARNINGS_PER_NODE),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mismatch {
    UnknownSession,
    WrongNode,
    NotActive,
    WrongLogin,
    Late,
    OutOfOrder,
}

impl Mismatch {
    const fn reason(self) -> &'static str {
        match self {
            Mismatch::UnknownSession => "session_unknown",
            Mismatch::WrongNode => "wrong_node",
            Mismatch::NotActive => "session_not_active",
            Mismatch::WrongLogin => "login_mismatch",
            Mismatch::Late => "late",
            Mismatch::OutOfOrder => "out_of_order",
        }
    }
}

fn reported_session<'a>(
    session: Option<&'a Session>,
    node_id: &str,
    login: &str,
    now: i64,
) -> Result<&'a Session, Mismatch> {
    let session = session.ok_or(Mismatch::UnknownSession)?;
    if session.node_id != node_id {
        return Err(Mismatch::WrongNode);
    }
    if session.state != SessionState::Active {
        return Err(Mismatch::NotActive);
    }
    if session.login.as_deref() != Some(login) {
        return Err(Mismatch::WrongLogin);
    }
    match session.authorized_at {
        Some(authorized_at) if now.saturating_sub(authorized_at) <= REPORT_WINDOW_SECS => {
            Ok(session)
        }
        _ => Err(Mismatch::Late),
    }
}

fn refused(control: &Control, node_id: &str, session_id: &str, mismatch: Mismatch) -> Response {
    let warning = (mismatch == Mismatch::WrongNode)
        .then(|| {
            control
                .host_accounts
                .foreign_reports
                .admit(node_id, control.tick())
        })
        .flatten();
    if let Some(suppressed) = warning {
        tracing::warn!(
            target: "jaunt::control",
            node_id,
            session_id,
            reason = mismatch.reason(),
            suppressed,
            "a node reported an account step for a session of another node"
        );
    } else {
        tracing::debug!(
            target: "jaunt::control",
            node_id,
            session_id,
            reason = mismatch.reason(),
            "an account report was refused"
        );
    }
    error_response(StatusCode::CONFLICT, "account_report_refused")
}

pub(crate) async fn capabilities(
    State(control): State<Control>,
    authenticated: Option<Extension<AuthenticatedNode>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(Extension(AuthenticatedNode(node_id))) = authenticated else {
        return empty_response(StatusCode::UNAUTHORIZED);
    };
    let request = match json_body::<AgentCapabilities>(&headers, body) {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    if let Some(refused) = refuse_unless_active(&control, &node_id).await {
        return refused;
    }
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return server_error();
    };
    let connection = control.presence.connected_since(&node_id);
    control.host_accounts.capabilities.announce(
        &node_id,
        request.creates_accounts,
        connection,
        now.system,
    );
    empty_response(StatusCode::NO_CONTENT)
}

pub(crate) async fn session_account(
    State(control): State<Control>,
    authenticated: Option<Extension<AuthenticatedNode>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(Extension(AuthenticatedNode(node_id))) = authenticated else {
        return empty_response(StatusCode::UNAUTHORIZED);
    };
    let report = match json_body::<AccountReport>(&headers, body) {
        Ok(report) => report,
        Err(failure) => return failure.into_response(),
    };
    let Ok(event) = report.event() else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if check_fields(&[&node_id, &report.session_id, &report.login]).is_err() {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    }
    if let Some(refused) = refuse_unless_active(&control, &node_id).await {
        return refused;
    }
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return server_error();
    };
    let stored = match control.store.sessions().get(&report.session_id).await {
        Ok(stored) => stored,
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "loading a session for an account report failed");
            return server_error();
        }
    };
    let session = match reported_session(stored.as_ref(), &node_id, &report.login, now.secs) {
        Ok(session) => session,
        Err(mismatch) => return refused(&control, &node_id, &report.session_id, mismatch),
    };
    let tick = control.tick();
    if control
        .host_accounts
        .notices
        .accept(&session.id, &event, tick)
        .is_err()
    {
        return refused(&control, &node_id, &session.id, Mismatch::OutOfOrder);
    }
    let login = session.login.as_deref().unwrap_or_default();
    audit::record(
        &control.host_accounts.refusals,
        &audit::Subject {
            user_id: &session.user_id,
            node_id: &session.node_id,
            session_id: &session.id,
            login,
        },
        &event,
        tick,
    );
    empty_response(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use jaunt_store::{Session, SessionState};

    use super::{Mismatch, REPORT_WINDOW_SECS, reported_session};

    fn session(state: SessionState, login: Option<&str>, authorized_at: Option<i64>) -> Session {
        Session {
            id: "s-1".to_owned(),
            user_id: "u-1".to_owned(),
            serial: 1,
            node_id: "n-1".to_owned(),
            state,
            created_at: 0,
            expires_at: 0,
            authorized_at,
            ended_at: None,
            login: login.map(str::to_owned),
            exit_status: None,
            bytes_in: None,
            bytes_out: None,
            recording_incomplete: None,
            end_reason: None,
            max_duration_secs: None,
        }
    }

    #[test]
    fn only_the_node_of_an_active_session_may_report_on_its_login_soon_after_authorization() {
        let now = 1_000;
        let active = session(SessionState::Active, Some("alice"), Some(now));
        let late = session(
            SessionState::Active,
            Some("alice"),
            Some(now - REPORT_WINDOW_SECS - 1),
        );
        let edge = session(
            SessionState::Active,
            Some("alice"),
            Some(now - REPORT_WINDOW_SECS),
        );
        let routed = session(SessionState::Routed, None, None);
        let ended = session(SessionState::Ended, Some("alice"), Some(now));
        let unauthorized = session(SessionState::Active, Some("alice"), None);
        for (stored, node, login, expected) in [
            (Some(&active), "n-1", "alice", Ok(())),
            (Some(&edge), "n-1", "alice", Ok(())),
            (None, "n-1", "alice", Err(Mismatch::UnknownSession)),
            (Some(&active), "n-2", "alice", Err(Mismatch::WrongNode)),
            (Some(&routed), "n-1", "alice", Err(Mismatch::NotActive)),
            (Some(&ended), "n-1", "alice", Err(Mismatch::NotActive)),
            (Some(&active), "n-1", "bob", Err(Mismatch::WrongLogin)),
            (Some(&late), "n-1", "alice", Err(Mismatch::Late)),
            (Some(&unauthorized), "n-1", "alice", Err(Mismatch::Late)),
        ] {
            assert_eq!(
                reported_session(stored, node, login, now).map(|_| ()),
                expected,
                "{node} {login}"
            );
        }
    }
}
