use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use jaunt_proto::{ClientConfig, GateEndpoint};

use crate::control::Control;
use crate::http::{error_response, json_response};

pub(crate) async fn handle(State(control): State<Control>) -> Response {
    let Some(gate) = &control.gate_endpoint else {
        return error_response(StatusCode::NOT_FOUND, "not_configured");
    };
    json_response(
        StatusCode::OK,
        &ClientConfig {
            ssh_suffix: control.ssh_suffix.as_str().to_owned(),
            gate: GateEndpoint {
                host: gate.host().to_owned(),
                port: gate.port(),
            },
            host_ca_keys: control.host_ca_keys.clone(),
        },
    )
}
