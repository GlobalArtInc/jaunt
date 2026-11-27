use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_proto::{
    ClientConfig, ClientConfigV2, GATE_ALPN_SSH, GATE_ALPN_SVC, GateEndpoint, PinnedRoot,
    ServicesClient, SshGateClient,
};

use crate::control::Control;
use crate::http::{error_response, json_response, server_error};
use crate::server_cert::unix_secs;
use crate::whoami::authenticate;

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
            host_ca_keys: control.ca_snapshot().host_ca_keys().to_vec(),
        },
    )
}

pub(crate) async fn handle_v2(State(control): State<Control>, headers: HeaderMap) -> Response {
    if let Err(failure) = authenticate(&control, &headers).await {
        return failure.into_response();
    }
    let Some(gate) = &control.gate_endpoint else {
        return error_response(StatusCode::NOT_FOUND, "not_configured");
    };
    let services = match &control.services_domain {
        Some(domain) => {
            let (Some(not_before), Some(not_after)) = (
                unix_secs(control.internal_ca.root_not_before()),
                unix_secs(control.internal_ca.root_not_after()),
            ) else {
                tracing::error!(target: "jaunt::control", "the internal root has a validity the wire format cannot carry");
                return server_error();
            };
            Some(ServicesClient {
                domain: domain.as_str().to_owned(),
                gate_tls_name: domain.as_str().to_owned(),
                port: control.agent_endpoint.port(),
                alpn: vec![GATE_ALPN_SSH.to_owned(), GATE_ALPN_SVC.to_owned()],
                roots: vec![PinnedRoot {
                    certificate_der: STANDARD.encode(control.internal_ca.root_der()),
                    sha256: control.internal_ca.root_sha256_hex(),
                    not_before,
                    not_after,
                }],
            })
        }
        None => None,
    };
    json_response(
        StatusCode::OK,
        &ClientConfigV2 {
            ssh_suffix: control.ssh_suffix.as_str().to_owned(),
            gate: GateEndpoint {
                host: gate.host().to_owned(),
                port: gate.port(),
            },
            host_ca_keys: control.ca_snapshot().host_ca_keys().to_vec(),
            ssh_gate: SshGateClient {
                client_transport: control.client_transport,
            },
            services,
        },
    )
}
