use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

use http::StatusCode;
use jaunt_kube::{ApiRequest, Discovery, NonResourceRequest, Verb};
use jaunt_proto::{AgentEventValue, KubernetesAudit, ServiceOutcome};

use super::policy::Decision;
use crate::clock::Clock;
use crate::runtime::events::{SessionEvent, SessionEvents};

pub(crate) const SESSION_START: &str = "kube.session.start";
pub(crate) const SESSION_END: &str = "kube.session.end";
pub(crate) const REQUEST: &str = "kube.request";

const SHORT_BYTES: usize = 32;
const NAME_BYTES: usize = 128;
const HOST_BYTES: usize = 255;
const LIST_BYTES: usize = 512;
const ADDR_BYTES: usize = 64;
const UNKNOWN_VERB: &str = "unknown";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    Read,
    Write,
    Watch,
    Exec,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Fields(BTreeMap<String, AgentEventValue>);

impl Fields {
    fn text(&mut self, name: &str, value: &str, max: usize) {
        self.0.insert(
            name.to_owned(),
            AgentEventValue::Text(cut(value, max).to_owned()),
        );
    }

    fn some_text(&mut self, name: &str, value: Option<&str>, max: usize) {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            self.text(name, value, max);
        }
    }

    fn int(&mut self, name: &str, value: u64) {
        self.0.insert(
            name.to_owned(),
            AgentEventValue::Int(i64::try_from(value).unwrap_or(i64::MAX)),
        );
    }

    #[cfg(test)]
    pub(crate) fn get(&self, name: &str) -> Option<&AgentEventValue> {
        self.0.get(name)
    }
}

pub(crate) fn cut(text: &str, max: usize) -> &str {
    let mut end = max.min(text.len());
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    text.get(..end).unwrap_or_default()
}

fn join_within<'a>(names: impl Iterator<Item = &'a str>, max: usize) -> String {
    let mut joined = String::new();
    for name in names {
        let extra = if joined.is_empty() { 0 } else { 1 };
        if joined.len() + extra + name.len() > max {
            break;
        }
        if extra == 1 {
            joined.push(',');
        }
        joined.push_str(name);
    }
    joined
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Described {
    pub(crate) class: Class,
    pub(crate) audited: bool,
    pub(crate) fields: Fields,
}

pub(crate) fn describe(request: &ApiRequest, mode: KubernetesAudit) -> Described {
    let all = mode == KubernetesAudit::All;
    let mut fields = Fields::default();
    match request {
        ApiRequest::Resource(resource) => {
            let channel = matches!(
                resource.subresource(),
                Some("exec" | "attach" | "portforward" | "proxy")
            );
            let class = match resource.verb() {
                Verb::Exec | Verb::Attach | Verb::PortForward => Class::Exec,
                _ if channel => Class::Exec,
                Verb::Get | Verb::List | Verb::Log => Class::Read,
                Verb::Watch => Class::Watch,
                Verb::Create
                | Verb::Update
                | Verb::Patch
                | Verb::Delete
                | Verb::DeleteCollection => Class::Write,
            };
            fields.text("verb", resource.verb().as_str(), SHORT_BYTES);
            fields.some_text("api_group", Some(resource.group()), NAME_BYTES);
            fields.some_text("api_version", Some(resource.version()), SHORT_BYTES);
            fields.some_text("resource", Some(resource.resource()), NAME_BYTES);
            fields.some_text("subresource", resource.subresource(), NAME_BYTES);
            fields.some_text("namespace", resource.namespace(), NAME_BYTES);
            fields.some_text("name", resource.name(), HOST_BYTES);
            let audited = all
                || matches!(class, Class::Write | Class::Exec)
                || resource.resource() == "secrets";
            Described {
                class,
                audited,
                fields,
            }
        }
        ApiRequest::NonResource(non_resource) => {
            fields.text("verb", Verb::Get.as_str(), SHORT_BYTES);
            if let NonResourceRequest::Discovery(discovery) = non_resource {
                let (group, version) = match discovery {
                    Discovery::CoreVersions | Discovery::Groups => (None, None),
                    Discovery::CoreResources { version } => (None, Some(version.as_str())),
                    Discovery::GroupVersions { group } => (Some(group.as_str()), None),
                    Discovery::GroupResources { group, version } => {
                        (Some(group.as_str()), Some(version.as_str()))
                    }
                };
                fields.some_text("api_group", group, NAME_BYTES);
                fields.some_text("api_version", version, SHORT_BYTES);
            }
            Described {
                class: Class::Read,
                audited: all,
                fields,
            }
        }
        ApiRequest::Unknown => {
            fields.text("verb", UNKNOWN_VERB, SHORT_BYTES);
            Described {
                class: Class::Write,
                audited: true,
                fields,
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Counts {
    read: u64,
    write: u64,
    watch: u64,
    exec: u64,
}

struct Pending {
    fields: Fields,
    started: SystemTime,
}

#[derive(Default)]
struct State {
    counts: Counts,
    pending: HashMap<u64, Pending>,
    next: u64,
    ended: bool,
}

pub(crate) struct SessionAudit {
    events: SessionEvents,
    clock: Arc<dyn Clock>,
    mode: KubernetesAudit,
    state: Mutex<State>,
}

impl SessionAudit {
    pub(crate) fn new(events: SessionEvents, clock: Arc<dyn Clock>, mode: KubernetesAudit) -> Self {
        Self {
            events,
            clock,
            mode,
            state: Mutex::new(State::default()),
        }
    }

    pub(crate) fn mode(&self) -> KubernetesAudit {
        self.mode
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn emit(&self, name: &'static str, fields: Fields) {
        self.events.emit(SessionEvent {
            name,
            fields: fields.0,
        });
    }

    pub(crate) fn start(&self, decision: Option<&Decision>, client_addr: &str) {
        let mut fields = Fields::default();
        if let Some(decision) = decision {
            let user = join_within(
                decision.users().iter().map(|user| user.as_str()),
                HOST_BYTES,
            );
            let groups = join_within(
                decision.groups().iter().map(|group| group.as_str()),
                LIST_BYTES,
            );
            fields.text("user", &user, HOST_BYTES);
            fields.some_text("groups", Some(&groups), LIST_BYTES);
        }
        fields.some_text("client_addr", Some(client_addr), ADDR_BYTES);
        self.emit(SESSION_START, fields);
    }

    pub(crate) fn begin(self: &Arc<Self>, described: Described) -> Option<RequestAudit> {
        let mut state = self.state();
        if state.ended {
            return None;
        }
        let counter = match described.class {
            Class::Read => &mut state.counts.read,
            Class::Write => &mut state.counts.write,
            Class::Watch => &mut state.counts.watch,
            Class::Exec => &mut state.counts.exec,
        };
        *counter = counter.saturating_add(1);
        let id = described.audited.then(|| {
            let id = state.next;
            state.next = state.next.wrapping_add(1);
            state.pending.insert(
                id,
                Pending {
                    fields: described.fields,
                    started: self.clock.now(),
                },
            );
            id
        });
        Some(RequestAudit {
            audit: Arc::clone(self),
            id,
        })
    }

    fn finish(&self, id: u64, status: Option<StatusCode>) {
        let mut state = self.state();
        let Some(pending) = state.pending.remove(&id) else {
            return;
        };
        self.emit_request(pending, status);
    }

    fn emit_request(&self, pending: Pending, status: Option<StatusCode>) {
        let mut fields = pending.fields;
        if let Some(status) = status {
            fields.int("status", u64::from(status.as_u16()));
        }
        let elapsed = self
            .clock
            .now()
            .duration_since(pending.started)
            .unwrap_or_default();
        fields.int(
            "duration_ms",
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        );
        self.emit(REQUEST, fields);
    }

    pub(crate) fn end(&self, outcome: ServiceOutcome, bytes_up: u64, bytes_down: u64) {
        let mut state = self.state();
        if state.ended {
            return;
        }
        state.ended = true;
        let mut unanswered: Vec<(u64, Pending)> = state.pending.drain().collect();
        unanswered.sort_unstable_by_key(|(id, _)| *id);
        for (_, pending) in unanswered {
            self.emit_request(pending, None);
        }
        let counts = state.counts;
        let mut fields = Fields::default();
        fields.int("requests_read", counts.read);
        fields.int("requests_write", counts.write);
        fields.int("requests_watch", counts.watch);
        fields.int("requests_exec", counts.exec);
        fields.int("bytes_up", bytes_up);
        fields.int("bytes_down", bytes_down);
        fields.text("reason", outcome.as_str(), SHORT_BYTES);
        self.emit(SESSION_END, fields);
    }
}

pub(crate) struct RequestAudit {
    audit: Arc<SessionAudit>,
    id: Option<u64>,
}

impl RequestAudit {
    pub(crate) fn answered(mut self, status: StatusCode) {
        if let Some(id) = self.id.take() {
            self.audit.finish(id, Some(status));
        }
    }
}

impl Drop for RequestAudit {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.audit.finish(id, None);
        }
    }
}
