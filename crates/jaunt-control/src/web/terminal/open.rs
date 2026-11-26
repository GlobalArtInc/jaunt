use std::collections::BTreeMap;
use std::net::SocketAddr;

use axum::Extension;
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use jaunt_proto::is_portable_login;
use jaunt_store::Node;
use serde::{Deserialize, Serialize};

use crate::control::Control;
use crate::device::net::ClientAddress;
use crate::http::{error_response, json_body, json_response, server_error};
use crate::identity::policy_identity;
use crate::naming::is_dns_label;
use crate::nodes::MAX_NODES;
use crate::plane::node_info;
use crate::serve::SocketWrites;
use crate::web::session::WebSession;

use super::audit::Denial;
use super::live::Limits;
use super::protocol::{self, Offer};
use super::run::{self, Plan};
use super::tickets::{Binding, IssueProblem};
use super::{TERMINAL_MAX_FRAME_BYTES, TERMINAL_SUBPROTOCOL, TERMINAL_TICKET_TTL_SECS};

const WRITE_BUFFER_BYTES: usize = 64 * 1024;
const MAX_WRITE_BUFFER_BYTES: usize = 4 * TERMINAL_MAX_FRAME_BYTES;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TicketRequest {
    node: String,
    login: String,
}

#[derive(Serialize)]
struct TicketBody {
    ticket: String,
    expires_in: i64,
}

#[derive(Serialize)]
struct TargetBody {
    node: String,
    labels: BTreeMap<String, String>,
    connected: bool,
    creates_accounts: bool,
    logins: Vec<String>,
}

fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "not_found")
}

fn denied() -> Response {
    error_response(StatusCode::FORBIDDEN, "denied")
}

fn deny(control: &Control, denial: &Denial<'_>) -> Response {
    control.web.terminals.denials.record(denial, control.tick());
    denied()
}

struct StoreFailed;

async fn reachable_node(
    control: &Control,
    session: &WebSession,
    node: &str,
    login: &str,
) -> Result<Option<Node>, StoreFailed> {
    let found = control
        .store
        .nodes()
        .get_active_by_name(node)
        .await
        .map_err(|err| {
            tracing::error!(target: "jaunt::control", error = %err, "loading a terminal node failed");
            StoreFailed
        })?;
    let Some(found) = found else {
        return Ok(None);
    };
    let policy = control.policy_snapshot();
    let allowed = policy
        .authorize_ssh(&policy_identity(session.user()), &node_info(&found), login)
        .allowed;
    Ok(allowed.then_some(found))
}

pub(crate) async fn ticket(
    State(control): State<Control>,
    session: WebSession,
    client: Option<Extension<ClientAddress>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(installed) = control.web.terminals.installed() else {
        return not_found();
    };
    let request: TicketRequest = match json_body(&headers, body) {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    if !is_dns_label(&request.node) || !is_portable_login(&request.login) {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Some(now) = control.now() else {
        return server_error();
    };
    let user_id = session.user().id.clone();
    let denial = |reason| Denial {
        user_id: &user_id,
        reason,
        reference: None,
        node: &request.node,
        login: &request.login,
        client_addr: client
            .as_ref()
            .map(|Extension(ClientAddress(ip))| SocketAddr::new(*ip, 0)),
    };
    match reachable_node(&control, &session, &request.node, &request.login).await {
        Ok(Some(_)) => {}
        Ok(None) => return deny(&control, &denial("denied")),
        Err(StoreFailed) => return server_error(),
    }
    let binding = Binding {
        web_session: session.0.session.id_hash.clone(),
        user_id: user_id.clone(),
        node: request.node.clone(),
        login: request.login.clone(),
    };
    match installed.tickets.issue(binding, now.secs) {
        Ok(ticket) => json_response(
            StatusCode::OK,
            &TicketBody {
                ticket,
                expires_in: TERMINAL_TICKET_TTL_SECS,
            },
        ),
        Err(IssueProblem::Full) => {
            control
                .web
                .terminals
                .denials
                .record(&denial("tickets_full"), control.tick());
            error_response(StatusCode::TOO_MANY_REQUESTS, "limit")
        }
        Err(IssueProblem::Entropy) => {
            tracing::error!(target: "jaunt::control", "the system entropy source failed");
            server_error()
        }
    }
}

struct TerminalQuery {
    node: String,
    login: String,
    cols: u32,
    rows: u32,
}

impl TerminalQuery {
    fn parse(query: Option<&str>) -> Option<TerminalQuery> {
        let mut node = None;
        let mut login = None;
        let mut cols = None;
        let mut rows = None;
        for (key, value) in form_urlencoded::parse(query?.as_bytes()) {
            let slot = match key.as_ref() {
                "node" => &mut node,
                "login" => &mut login,
                "cols" => &mut cols,
                "rows" => &mut rows,
                _ => return None,
            };
            if slot.replace(value.into_owned()).is_some() {
                return None;
            }
        }
        let node = node.filter(|node| is_dns_label(node))?;
        let login = login.filter(|login| is_portable_login(login))?;
        let cols = cols?.parse().ok()?;
        let rows = rows?.parse().ok()?;
        protocol::dimensions(cols, rows)?;
        Some(TerminalQuery {
            node,
            login,
            cols,
            rows,
        })
    }
}

fn client_address(parts: &Parts) -> Option<SocketAddr> {
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer)| *peer);
    let resolved = parts
        .extensions
        .get::<ClientAddress>()
        .map(|ClientAddress(ip)| *ip);
    match (resolved, peer) {
        (Some(ip), Some(peer)) if ip == peer.ip().to_canonical() => {
            Some(SocketAddr::new(ip, peer.port()))
        }
        (Some(ip), _) => Some(SocketAddr::new(ip, 0)),
        (None, Some(peer)) => Some(SocketAddr::new(peer.ip().to_canonical(), peer.port())),
        (None, None) => None,
    }
}

pub(crate) async fn open(State(control): State<Control>, request: Request) -> Response {
    let Some(installed) = control.web.terminals.installed() else {
        return not_found();
    };
    let (mut parts, _body) = request.into_parts();
    if !protocol::origin_is(&parts.headers, control.public_origin()) {
        return error_response(StatusCode::FORBIDDEN, "forbidden");
    }
    let Some(offer) = protocol::offer(&parts.headers) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let session = match WebSession::from_request_parts(&mut parts, &control).await {
        Ok(session) => session,
        Err(rejection) => return rejection.into_response(),
    };
    let Some(query) = TerminalQuery::parse(parts.uri.query()) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Some(client_addr) = client_address(&parts) else {
        tracing::error!(target: "jaunt::control", "the peer address of a terminal request is unknown");
        return server_error();
    };
    let socket_writes = parts.extensions.get::<SocketWrites>().cloned();
    let user = session.user().clone();
    let denial = |reason| Denial {
        user_id: &user.id,
        reason,
        reference: None,
        node: &query.node,
        login: &query.login,
        client_addr: Some(client_addr),
    };
    let Offer::Ticketed(secret) = offer else {
        return deny(&control, &denial("ticket_missing"));
    };
    let Some(now) = control.now() else {
        return server_error();
    };
    let binding = Binding {
        web_session: session.0.session.id_hash.clone(),
        user_id: user.id.clone(),
        node: query.node.clone(),
        login: query.login.clone(),
    };
    if let Err(problem) = installed.tickets.check(&secret, &binding, now.secs) {
        return deny(&control, &denial(problem.reason()));
    }
    let node = match control.store.nodes().get_active_by_name(&query.node).await {
        Ok(Some(node)) => node,
        Ok(None) => return deny(&control, &denial("node_gone")),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "loading a terminal node failed");
            return server_error();
        }
    };
    let upgrade = match WebSocketUpgrade::from_request_parts(&mut parts, &control).await {
        Ok(upgrade) => upgrade,
        Err(rejection) => return rejection.into_response(),
    };
    if let Err(problem) = installed.tickets.take(&secret, &binding, now.secs) {
        return deny(&control, &denial(problem.reason()));
    }
    let admission = control.web.terminals.live.admit(
        &user.id,
        &binding.web_session,
        &node.id,
        &Limits {
            per_user: installed.settings.max_per_user,
            total: installed.settings.max_total,
        },
    );
    let plan = Plan {
        user,
        web_session: binding.web_session,
        web_expires_at: session.0.session.expires_at,
        node,
        login: query.login,
        size: jaunt_ssh::TerminalDimensions {
            cols: query.cols,
            rows: query.rows,
        },
        client_addr,
        socket_writes,
        installed,
    };
    let running = control.clone();
    upgrade
        .protocols([TERMINAL_SUBPROTOCOL])
        .max_frame_size(TERMINAL_MAX_FRAME_BYTES)
        .max_message_size(TERMINAL_MAX_FRAME_BYTES)
        .write_buffer_size(WRITE_BUFFER_BYTES)
        .max_write_buffer_size(MAX_WRITE_BUFFER_BYTES)
        .on_upgrade(move |socket| run::run(running, socket, plan, admission))
}

pub(crate) async fn targets(State(control): State<Control>, session: WebSession) -> Response {
    if control.web.terminals.installed().is_none() {
        return not_found();
    }
    let nodes = match control.store.nodes().list().await {
        Ok(nodes) => nodes,
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "listing the terminal targets failed");
            return server_error();
        }
    };
    let policy = control.policy_snapshot();
    let identity = policy_identity(session.user());
    let mut listed: Vec<TargetBody> = nodes
        .iter()
        .filter(|node| node.state == jaunt_store::NodeState::Active)
        .filter_map(|node| {
            let info = node_info(node);
            let logins = policy.ssh_logins(&identity, &info);
            (!logins.is_empty()).then(|| {
                let connected_since = control.presence.connected_since(&node.id);
                TargetBody {
                    node: node.name.clone(),
                    labels: info.labels,
                    connected: connected_since.is_some(),
                    creates_accounts: control
                        .host_accounts
                        .capabilities
                        .creates_accounts(&node.id, connected_since),
                    logins,
                }
            })
        })
        .collect();
    listed.sort_by(|left, right| left.node.cmp(&right.node));
    listed.truncate(MAX_NODES);
    json_response(StatusCode::OK, &listed)
}

#[cfg(test)]
mod tests {
    use super::TerminalQuery;

    #[test]
    fn the_query_names_one_node_one_login_and_a_bounded_size_once_each() {
        let parsed =
            TerminalQuery::parse(Some("node=web-01&login=deploy&cols=80&rows=24")).unwrap();
        assert_eq!(
            (
                parsed.node.as_str(),
                parsed.login.as_str(),
                parsed.cols,
                parsed.rows
            ),
            ("web-01", "deploy", 80, 24)
        );
        for refused in [
            None,
            Some(""),
            Some("node=web-01&login=deploy&cols=80"),
            Some("node=web-01&login=deploy&cols=80&rows=24&rows=25"),
            Some("node=web-01&login=deploy&cols=80&rows=24&ticket=x"),
            Some("node=Web-01&login=deploy&cols=80&rows=24"),
            Some("node=web-01.other&login=deploy&cols=80&rows=24"),
            Some("node=web-01&login=-oProxyCommand&cols=80&rows=24"),
            Some("node=web-01&login=deploy&cols=0&rows=24"),
            Some("node=web-01&login=deploy&cols=80&rows=201"),
            Some("node=web-01&login=deploy&cols=eighty&rows=24"),
        ] {
            assert!(TerminalQuery::parse(refused).is_none(), "{refused:?}");
        }
    }
}
