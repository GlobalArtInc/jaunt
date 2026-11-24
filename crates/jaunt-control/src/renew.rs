use axum::Extension;
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use jaunt_proto::RenewRequest;
use jaunt_store::NodeKeys;

use crate::agent::AuthenticatedNode;
use crate::control::Control;
use crate::enroll::Invalid;
use crate::http::{empty_response, error_response, json_body, json_response, server_error};
use crate::issuance;
use crate::node_audit::{self, Renewed};
use crate::node_keys::{self, SshHostKey, TlsKey};
use crate::poll::certificates_of;

fn node_removed() -> Response {
    error_response(StatusCode::FORBIDDEN, "node_removed")
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
    let request = match json_body::<RenewRequest>(&headers, body) {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return server_error();
    };
    let node = match control.store.nodes().get_active(&node_id).await {
        Ok(Some(node)) => node,
        Ok(None) => return node_removed(),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "loading the node failed");
            return server_error();
        }
    };

    let tls = match request.tls_public_key.as_deref() {
        Some(text) => match node_keys::parse_tls(text) {
            Some(tls) => tls,
            None => return Invalid::TlsPublicKey.into_response(),
        },
        None => match node_keys::parse_tls(&node.tls_public_key) {
            Some(tls) => tls,
            None => return corrupt_keys(),
        },
    };
    let ssh = match request.ssh_host_public_key.as_deref() {
        Some(text) => match node_keys::parse_ssh(text) {
            Some(ssh) => ssh,
            None => return Invalid::SshHostPublicKey.into_response(),
        },
        None => match node_keys::parse_ssh(&node.ssh_host_public_key) {
            Some(ssh) => ssh,
            None => return corrupt_keys(),
        },
    };
    let rotated = tls.canonical != node.tls_public_key || ssh.canonical != node.ssh_host_public_key;

    let bundle = match issuance::issue(&control, &node.id, &node.name, &tls, &ssh, now).await {
        Ok(bundle) => bundle,
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "issuing the renewal failed");
            return server_error();
        }
    };
    match control
        .store
        .nodes()
        .record_renewal(
            &node.id,
            &node_keys_of(&tls, &ssh),
            &bundle.records(now.secs),
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => return node_removed(),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "recording the renewal failed");
            return server_error();
        }
    }
    node_audit::cert_renewed(&Renewed {
        node_id: &node.id,
        name: &node.name,
        x509_serial: &bundle.x509_serial,
        ssh_serial: &bundle.ssh_serial,
        rotated,
    });
    json_response(StatusCode::OK, &certificates_of(&bundle))
}

fn corrupt_keys() -> Response {
    tracing::error!(target: "jaunt::control", "the stored node keys are not valid");
    server_error()
}

fn node_keys_of(tls: &TlsKey, ssh: &SshHostKey) -> NodeKeys {
    NodeKeys {
        tls_public_key: tls.canonical.clone(),
        ssh_host_public_key: ssh.canonical.clone(),
        tls_spki_sha256: tls.sha256.clone(),
        ssh_host_key_fingerprint: ssh.fingerprint.clone(),
    }
}
