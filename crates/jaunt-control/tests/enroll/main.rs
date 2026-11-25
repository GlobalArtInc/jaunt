mod admin;
mod audit;
mod audit_events;
mod authorize;
mod authorize_checks;
mod ca_rotation;
mod client_api;
mod enroll;
mod flow;
mod recording_support;
mod recordings;
mod renew;
mod revoke;
mod route;
mod serve;
mod session_http;
mod session_support;
mod subject_key;
mod support;
mod sweep;
mod trust;
mod web_enrolments;
mod web_guard;
mod web_nodes;
mod web_sessions;
mod web_support;

#[allow(dead_code)]
#[path = "../login/provider.rs"]
mod provider;

#[path = "../login/sign_hook.rs"]
mod sign_hook;
