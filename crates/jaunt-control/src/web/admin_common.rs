use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use axum::response::Response;

use crate::http::error_response;
use crate::revocation::is_identifier;

use super::session::WebSession;

pub(crate) const DEFAULT_PAGE: u32 = 50;
pub(crate) const MAX_PAGE: u32 = 200;
const WEB_ACTOR_PREFIX: &str = "web:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    Malformed,
    Invalid(&'static str),
}

impl Refusal {
    pub(crate) fn into_response(self) -> Response {
        match self {
            Refusal::Malformed => invalid_request(),
            Refusal::Invalid(code) => invalid_value(code),
        }
    }
}

pub(crate) fn web_actor(session: &WebSession) -> String {
    format!("{WEB_ACTOR_PREFIX}{}", session.user().id)
}

pub(crate) fn invalid_request() -> Response {
    error_response(StatusCode::BAD_REQUEST, "invalid_request")
}

pub(crate) fn invalid_value(code: &'static str) -> Response {
    error_response(StatusCode::UNPROCESSABLE_ENTITY, code)
}

pub(crate) fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "not_found")
}

pub(crate) fn conflict(code: &'static str) -> Response {
    error_response(StatusCode::CONFLICT, code)
}

pub(crate) fn known_id(id: &str) -> Option<&str> {
    is_identifier(id).then_some(id)
}

pub(crate) fn page_limit(value: &str) -> Result<u32, Refusal> {
    let limit = value.parse::<u32>().map_err(|_| Refusal::Malformed)?;
    if limit == 0 || limit > MAX_PAGE {
        return Err(Refusal::Invalid("invalid_limit"));
    }
    Ok(limit)
}

pub(crate) fn unix_secs(time: SystemTime) -> Option<i64> {
    let secs = time.duration_since(UNIX_EPOCH).ok()?.as_secs();
    i64::try_from(secs).ok()
}

pub(crate) fn once<T>(slot: &mut Option<T>, value: T) -> Result<(), Refusal> {
    if slot.is_some() {
        return Err(Refusal::Malformed);
    }
    *slot = Some(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Refusal, once, page_limit};

    #[test]
    fn page_limits_are_whole_numbers_from_one_to_two_hundred() {
        assert_eq!(page_limit("1"), Ok(1));
        assert_eq!(page_limit("200"), Ok(200));
        assert_eq!(page_limit("0"), Err(Refusal::Invalid("invalid_limit")));
        assert_eq!(page_limit("201"), Err(Refusal::Invalid("invalid_limit")));
        for malformed in ["", "-1", "x", "1.5"] {
            assert_eq!(
                page_limit(malformed),
                Err(Refusal::Malformed),
                "{malformed}"
            );
        }
        let mut slot = None;
        assert_eq!(once(&mut slot, 1), Ok(()));
        assert_eq!(once(&mut slot, 2), Err(Refusal::Malformed));
    }
}
