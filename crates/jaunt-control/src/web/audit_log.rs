use axum::extract::State;
use axum::http::{StatusCode, Uri};
use axum::response::Response;
use jaunt_audit::AuditFilter;

use crate::control::Control;
use crate::http::{error_response, json_response, server_error};

use super::session::{AuditRead, RequireAdmin};

pub(crate) async fn list(
    State(control): State<Control>,
    _admin: RequireAdmin<AuditRead>,
    uri: Uri,
) -> Response {
    let query = uri.query().unwrap_or_default();
    let pairs = form_urlencoded::parse(query.as_bytes());
    let filter = match AuditFilter::from_pairs(pairs) {
        Ok(filter) => filter,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, error.code()),
    };
    match jaunt_audit::query(&control.store, &filter).await {
        Ok(page) => json_response(StatusCode::OK, &page),
        Err(error) => {
            tracing::error!(target: "jaunt::control", error = %error, "reading the audit events failed");
            server_error()
        }
    }
}
