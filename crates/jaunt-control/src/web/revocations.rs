use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use jaunt_store::{Revocation, RevocationCursor, RevocationKind};
use serde::{Deserialize, Serialize};

use crate::control::Control;
use crate::http::{empty_response, error_response, json_body, json_response, server_error};
use crate::revocation::{
    ListRevocationsError, RevokeError, RevokeRequest, UnrevokeError, is_identifier,
};

use super::session::{RequireAdmin, RevocationsWrite, SessionsRead};

const DEFAULT_PAGE: u32 = 50;
const WEB_AUTHOR_PREFIX: &str = "web:";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeBody {
    kind: String,
    subject: String,
    reason: String,
}

#[derive(Serialize)]
struct RevocationBody {
    id: String,
    kind: &'static str,
    subject: String,
    reason: String,
    created_at: i64,
    created_by: String,
}

impl From<Revocation> for RevocationBody {
    fn from(revocation: Revocation) -> RevocationBody {
        RevocationBody {
            id: revocation.id,
            kind: revocation.kind.as_str(),
            subject: revocation.subject,
            reason: revocation.reason,
            created_at: revocation.created_at,
            created_by: revocation.created_by,
        }
    }
}

#[derive(Serialize)]
struct RevokedBody {
    revocation: RevocationBody,
    created: bool,
    terminated_sessions: usize,
}

#[derive(Serialize)]
struct ListBody {
    revocations: Vec<RevocationBody>,
    next: Option<String>,
}

fn invalid_request() -> Response {
    error_response(StatusCode::BAD_REQUEST, "invalid_request")
}

fn author_of(admin: &RequireAdmin<impl super::session::Permission>) -> String {
    format!("{WEB_AUTHOR_PREFIX}{}", admin.session.user().id)
}

pub(crate) async fn create(
    State(control): State<Control>,
    admin: RequireAdmin<RevocationsWrite>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: RevokeBody = match json_body(&headers, body) {
        Ok(body) => body,
        Err(failure) => return failure.into_response(),
    };
    let Some(kind) = RevocationKind::parse(&body.kind) else {
        return invalid_request();
    };
    let request = RevokeRequest {
        kind,
        subject: body.subject,
        reason: body.reason,
    };
    let author = author_of(&admin);
    let revocations = control.revocations();
    let finished = tokio::spawn(async move { revocations.revoke(&request, &author).await }).await;
    let outcome = match finished {
        Ok(outcome) => outcome,
        Err(_) => {
            tracing::error!(target: "jaunt::control", "the revocation task did not finish");
            return server_error();
        }
    };
    match outcome {
        Ok(revoked) => {
            let status = if revoked.created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            json_response(
                status,
                &RevokedBody {
                    revocation: revoked.revocation.into(),
                    created: revoked.created,
                    terminated_sessions: revoked.terminated,
                },
            )
        }
        Err(RevokeError::InvalidSubject(_) | RevokeError::InvalidReason) => invalid_request(),
        Err(RevokeError::UnknownSubject(_)) => {
            error_response(StatusCode::NOT_FOUND, "unknown_subject")
        }
        Err(
            err @ (RevokeError::InvalidAuthor
            | RevokeError::Clock
            | RevokeError::Store(_)
            | RevokeError::CloseTimedOut),
        ) => {
            tracing::error!(target: "jaunt::control", error = %err, "storing a revocation failed");
            server_error()
        }
    }
}

pub(crate) async fn list(
    State(control): State<Control>,
    _admin: RequireAdmin<SessionsRead>,
    uri: Uri,
) -> Response {
    let Some((limit, after)) = list_query(uri.query()) else {
        return invalid_request();
    };
    match control.revocations().list(after.as_ref(), limit).await {
        Ok(page) => json_response(
            StatusCode::OK,
            &ListBody {
                next: page.next.as_ref().map(cursor_text),
                revocations: page
                    .revocations
                    .into_iter()
                    .map(RevocationBody::from)
                    .collect(),
            },
        ),
        Err(ListRevocationsError::PageSize) => invalid_request(),
        Err(err @ ListRevocationsError::Store(_)) => {
            tracing::error!(target: "jaunt::control", error = %err, "listing revocations failed");
            server_error()
        }
    }
}

pub(crate) async fn remove(
    State(control): State<Control>,
    admin: RequireAdmin<RevocationsWrite>,
    Path(id): Path<String>,
) -> Response {
    let author = author_of(&admin);
    let revocations = control.revocations();
    let finished = tokio::spawn(async move { revocations.remove(&id, &author).await }).await;
    match finished {
        Ok(Ok(_)) => empty_response(StatusCode::NO_CONTENT),
        Ok(Err(UnrevokeError::NotFound)) => error_response(StatusCode::NOT_FOUND, "not_found"),
        Ok(Err(err @ (UnrevokeError::InvalidAuthor | UnrevokeError::Store(_)))) => {
            tracing::error!(target: "jaunt::control", error = %err, "removing a revocation failed");
            server_error()
        }
        Err(_) => {
            tracing::error!(target: "jaunt::control", "the revocation removal task did not finish");
            server_error()
        }
    }
}

fn list_query(query: Option<&str>) -> Option<(u32, Option<RevocationCursor>)> {
    let mut limit = None;
    let mut after = None;
    for (key, value) in form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match key.as_ref() {
            "limit" if limit.is_none() => limit = Some(value.parse::<u32>().ok()?),
            "after" if after.is_none() => after = Some(parse_cursor(&value)?),
            _ => return None,
        }
    }
    Some((limit.unwrap_or(DEFAULT_PAGE), after))
}

fn parse_cursor(text: &str) -> Option<RevocationCursor> {
    let (created_at, id) = text.split_once('.')?;
    let created_at = created_at.parse::<i64>().ok()?;
    is_identifier(id).then(|| RevocationCursor {
        created_at,
        id: id.to_owned(),
    })
}

fn cursor_text(cursor: &RevocationCursor) -> String {
    format!("{}.{}", cursor.created_at, cursor.id)
}

#[cfg(test)]
mod tests {
    use jaunt_store::RevocationCursor;

    use super::{DEFAULT_PAGE, cursor_text, list_query};

    #[test]
    fn list_queries_accept_a_limit_and_a_cursor_once_and_nothing_else() {
        let cursor = RevocationCursor {
            created_at: 1_700_000_000,
            id: "67e55044-10b1-426f-9247-bb680e5fe0c8".to_owned(),
        };
        let text = cursor_text(&cursor);
        assert_eq!(list_query(None), Some((DEFAULT_PAGE, None)));
        assert_eq!(
            list_query(Some(&format!("limit=5&after={text}"))),
            Some((5, Some(cursor)))
        );
        for bad in [
            "limit=x",
            "limit=-1",
            "limit=1&limit=2",
            "after=nodot",
            "after=1.bad/id",
            "after=x.abc",
            "other=1",
        ] {
            assert_eq!(list_query(Some(bad)), None, "{bad}");
        }
    }
}
