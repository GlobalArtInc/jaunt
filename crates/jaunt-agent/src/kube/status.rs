use http::header::{CONTENT_TYPE, HeaderValue, RETRY_AFTER};
use http::{Response, StatusCode};

use super::KubeLimits;
use super::body::ProxyBody;
use super::policy::{Decision, Refused};

const MISDIRECTED: &str = "this connection serves another Kubernetes cluster than the host the request names; connect to that cluster's own address";
const BAD_PATH: &str = "the request path is not in canonical form: empty or dot segments, encoded slashes, backslashes, NUL, control characters and invalid escapes are refused";
const BAD_FRAMING: &str = "transfer codings other than chunked are not supported";
const METHOD: &str = "this request method is not supported through Jaunt";
const UPGRADES: &str = "exec, attach and port-forward are not available yet through Jaunt";
const DECISION: &str = "the access decision for this session cannot be applied; ask an administrator to check the Kubernetes roles";
const IMPERSONATE_HEADER: &str = "Impersonate-Uid, Impersonate-Extra-* and other impersonation headers cannot be set through Jaunt; only --as and --as-group are honoured";
const LOOKALIKE: &str = "header names with underscores that stand for identity headers are refused";
const SEVERAL_USERS: &str = "only one user can be chosen with --as";
const UNREACHABLE: &str = "the Kubernetes API server cannot be reached through the Jaunt agent";
const TIMEOUT: &str = "the Kubernetes API server did not answer in time";
const ENDING: &str = "the session is ending";
const BUSY: &str =
    "every connection from the Jaunt agent to the Kubernetes API server is busy; try again";
const CLIENT_STALLED: &str = "the client stopped sending the request body for too long";

fn status(code: StatusCode, reason: &str, message: &str) -> Response<ProxyBody> {
    let body = serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "metadata": {},
        "status": "Failure",
        "message": message,
        "reason": reason,
        "code": code.as_u16(),
    })
    .to_string();
    let mut response = Response::new(ProxyBody::fixed(body));
    *response.status_mut() = code;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

pub(crate) fn misdirected() -> Response<ProxyBody> {
    status(StatusCode::MISDIRECTED_REQUEST, "BadRequest", MISDIRECTED)
}

pub(crate) fn bad_path() -> Response<ProxyBody> {
    status(StatusCode::BAD_REQUEST, "BadRequest", BAD_PATH)
}

pub(crate) fn bad_framing() -> Response<ProxyBody> {
    status(StatusCode::BAD_REQUEST, "BadRequest", BAD_FRAMING)
}

pub(crate) fn method_not_allowed() -> Response<ProxyBody> {
    status(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", METHOD)
}

pub(crate) fn upgrades_unavailable() -> Response<ProxyBody> {
    status(StatusCode::FORBIDDEN, "Forbidden", UPGRADES)
}

pub(crate) fn decision_unusable() -> Response<ProxyBody> {
    status(StatusCode::FORBIDDEN, "Forbidden", DECISION)
}

pub(crate) fn refused(refused: Refused, decision: &Decision) -> Response<ProxyBody> {
    let users = || {
        decision
            .users()
            .iter()
            .map(|user| user.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let message = match refused {
        Refused::Header => IMPERSONATE_HEADER.to_owned(),
        Refused::LookalikeHeader => LOOKALIKE.to_owned(),
        Refused::SeveralUsers => SEVERAL_USERS.to_owned(),
        Refused::ChooseUser => format!(
            "this session may act as several Kubernetes users; choose one with --as: {}",
            users()
        ),
        Refused::UserNotAllowed => format!(
            "the user chosen with --as is not allowed for this session; allowed users: {}",
            users()
        ),
        Refused::GroupNotAllowed => {
            let groups = decision
                .groups()
                .iter()
                .map(|group| group.as_str())
                .collect::<Vec<_>>();
            if groups.is_empty() {
                "this session may not choose groups with --as-group".to_owned()
            } else {
                format!(
                    "a group chosen with --as-group is not allowed for this session; allowed groups: {}",
                    groups.join(", ")
                )
            }
        }
    };
    status(StatusCode::FORBIDDEN, "Forbidden", &message)
}

fn retry_soon(mut response: Response<ProxyBody>) -> Response<ProxyBody> {
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

pub(crate) fn too_many(limits: KubeLimits) -> Response<ProxyBody> {
    let message = format!(
        "too many requests are open at once through Jaunt: at most {} per user and {} per connection; finish or close some watches, log streams or downloads",
        limits.slots_per_user, limits.slots_per_connection
    );
    retry_soon(status(
        StatusCode::TOO_MANY_REQUESTS,
        "TooManyRequests",
        &message,
    ))
}

pub(crate) fn busy() -> Response<ProxyBody> {
    retry_soon(status(
        StatusCode::SERVICE_UNAVAILABLE,
        "ServiceUnavailable",
        BUSY,
    ))
}

pub(crate) fn client_stalled() -> Response<ProxyBody> {
    status(StatusCode::REQUEST_TIMEOUT, "Timeout", CLIENT_STALLED)
}

pub(crate) fn unreachable() -> Response<ProxyBody> {
    status(StatusCode::BAD_GATEWAY, "ServiceUnavailable", UNREACHABLE)
}

pub(crate) fn timeout() -> Response<ProxyBody> {
    status(StatusCode::GATEWAY_TIMEOUT, "Timeout", TIMEOUT)
}

pub(crate) fn ending() -> Response<ProxyBody> {
    status(
        StatusCode::SERVICE_UNAVAILABLE,
        "ServiceUnavailable",
        ENDING,
    )
}
