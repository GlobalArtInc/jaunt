use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;

use crate::ca_rotation;
use crate::control::Control;
use crate::http::{json_response, server_error};

use super::session::{AuditRead, RequireAdmin};

pub(crate) async fn show(
    State(control): State<Control>,
    _admin: RequireAdmin<AuditRead>,
) -> Response {
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return server_error();
    };
    let ca_dir = control.ca_dir.clone();
    let listings = match tokio::task::spawn_blocking(move || ca_rotation::read_listings(&ca_dir))
        .await
    {
        Ok(Ok(listings)) => listings,
        Ok(Err(err)) => {
            tracing::error!(target: "jaunt::control", error = %err, "reading the certificate authority keys failed");
            return server_error();
        }
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "reading the certificate authority keys stopped");
            return server_error();
        }
    };
    match ca_rotation::reports(&control.store, listings, now.secs).await {
        Ok(reports) => json_response(StatusCode::OK, &ca_rotation::status_json(&reports)),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "reading the rotation counters failed");
            server_error()
        }
    }
}
