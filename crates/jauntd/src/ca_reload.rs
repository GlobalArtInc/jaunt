use std::error::Error;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use jaunt_ca::{CaKind, FileBackend, Signer, TrustSet, fingerprint_hex};
use jaunt_control::{CaSnapshot, Clock, Control};
use jaunt_gate::SshGate;
use jaunt_ssh::UserCaKeys;
use jaunt_tunnel::{AgentRegistry, TrustBroadcast};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::ca::resolve_identity;

pub const RELOAD_INTERVAL: Duration = Duration::from_secs(10);
pub const FAILURE_QUIET: Duration = Duration::from_secs(60);
const MAX_REASON_CHARS: usize = 200;
const MAX_LOGGED_NODES: usize = 20;
const READ_STOPPED: &str = "reading the certificate authority keys stopped unexpectedly";

pub type IdentityEnv = Arc<dyn Fn(&str) -> Option<OsString> + Send + Sync>;

pub struct CaReloadParts {
    pub ca_dir: PathBuf,
    pub env: IdentityEnv,
    pub control: Control,
    pub gate: Option<Arc<SshGate>>,
    pub registry: Option<AgentRegistry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reload {
    Unchanged,
    Applied { kinds: Vec<CaKind>, notified: usize },
    Failed { reason: String, reported: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateCertificate {
    Absent,
    Current,
    Reissued,
    Failed { reason: String, reported: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tick {
    pub reload: Reload,
    pub gate: GateCertificate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SlotState {
    active: String,
    next: Option<String>,
    trust_id: String,
}

impl SlotState {
    fn of(trust: &TrustSet) -> SlotState {
        SlotState {
            active: fingerprint_hex(trust.active()),
            next: trust.next().map(fingerprint_hex),
            trust_id: trust.set_id(),
        }
    }
}

type Loaded = (TrustSet, FileBackend);

struct Changes {
    user: Option<Loaded>,
    host: Option<Loaded>,
}

#[derive(Default)]
struct FailureLog {
    reported: Vec<(String, SystemTime)>,
}

impl FailureLog {
    fn admit(&mut self, reason: &str, now: SystemTime) -> bool {
        self.reported.retain(|(_, at)| {
            now.duration_since(*at)
                .is_ok_and(|elapsed| elapsed < FAILURE_QUIET)
        });
        if self.reported.iter().any(|(seen, _)| seen == reason) {
            return false;
        }
        self.reported.push((reason.to_owned(), now));
        true
    }

    fn clear(&mut self) {
        self.reported.clear();
    }
}

pub struct CaReloader {
    parts: CaReloadParts,
    reload_failures: FailureLog,
    gate_failures: FailureLog,
}

impl CaReloader {
    pub fn new(parts: CaReloadParts) -> CaReloader {
        CaReloader {
            parts,
            reload_failures: FailureLog::default(),
            gate_failures: FailureLog::default(),
        }
    }

    pub async fn tick(&mut self, now: SystemTime) -> Tick {
        let reload = self.reload(now).await;
        let gate = self.check_gate(now).await;
        Tick { reload, gate }
    }

    async fn reload(&mut self, now: SystemTime) -> Reload {
        let current = self.parts.control.ca_snapshot();
        let user = SlotState::of(current.user_trust());
        let host = SlotState::of(current.host_trust());
        let ca_dir = self.parts.ca_dir.clone();
        let env = Arc::clone(&self.parts.env);
        let read =
            tokio::task::spawn_blocking(move || read_changes(&ca_dir, &env, &user, &host)).await;
        let changes = match read {
            Ok(Ok(Some(changes))) => changes,
            Ok(Ok(None)) => {
                self.reload_failures.clear();
                return Reload::Unchanged;
            }
            Ok(Err(reason)) => return self.reload_failed(reason, now),
            Err(_) => return self.reload_failed(READ_STOPPED.to_owned(), now),
        };
        match self.apply(&current, changes) {
            Ok(reload) => {
                self.reload_failures.clear();
                reload
            }
            Err(reason) => self.reload_failed(reason, now),
        }
    }

    fn apply(&self, current: &CaSnapshot, changes: Changes) -> Result<Reload, String> {
        let (user_signer, user_trust) =
            chosen(changes.user, current.user_signer(), current.user_trust());
        let (host_signer, host_trust) =
            chosen(changes.host, current.host_signer(), current.host_trust());
        let user_changed = SlotState::of(&user_trust) != SlotState::of(current.user_trust());
        let host_changed = SlotState::of(&host_trust) != SlotState::of(current.host_trust());
        let mut kinds = Vec::new();
        if user_changed {
            kinds.push(CaKind::User);
        }
        if host_changed {
            kinds.push(CaKind::Host);
        }
        if kinds.is_empty() {
            return Ok(Reload::Unchanged);
        }
        let gate_trust = match (&self.parts.gate, user_changed) {
            (Some(_), true) => Some(gate_trust(current.user_trust(), &user_trust)?),
            _ => None,
        };
        let snapshot = CaSnapshot::new(user_signer, user_trust, host_signer, host_trust)
            .map_err(|err| format!("the new keys do not form a usable set: {err}"))?;
        if let (Some(gate), Some(trust)) = (&self.parts.gate, &gate_trust) {
            gate.replace_user_cas(trust.during.clone());
        }
        self.parts.control.replace_snapshot(snapshot);
        if let (Some(gate), Some(trust)) = (&self.parts.gate, gate_trust) {
            gate.replace_user_cas(trust.after);
        }
        let applied = self.parts.control.ca_snapshot();
        for kind in &kinds {
            let trust = match kind {
                CaKind::User => applied.user_trust(),
                _ => applied.host_trust(),
            };
            audit_reloaded(*kind, trust);
        }
        let notified = self.notify_agents();
        Ok(Reload::Applied { kinds, notified })
    }

    fn notify_agents(&self) -> usize {
        let Some(registry) = &self.parts.registry else {
            return 0;
        };
        report_broadcast(&registry.broadcast_trust_update())
    }

    fn reload_failed(&mut self, reason: String, now: SystemTime) -> Reload {
        let reason = truncated(&reason);
        let reported = self.reload_failures.admit(&reason, now);
        report_failure(&reason, reported);
        Reload::Failed { reason, reported }
    }

    async fn check_gate(&mut self, now: SystemTime) -> GateCertificate {
        let Some(gate) = &self.parts.gate else {
            return GateCertificate::Absent;
        };
        let active = fingerprint_hex(self.parts.control.ca_snapshot().host_trust().active());
        if gate.host_certificate_signer() == active {
            self.gate_failures.clear();
            return GateCertificate::Current;
        }
        match gate
            .reissue_host_certificate_unless_signed_by(&active)
            .await
        {
            Ok(reissued) => {
                self.gate_failures.clear();
                if !reissued {
                    return GateCertificate::Current;
                }
                tracing::info!(
                    target: "jaunt::gate",
                    signer = active.as_str(),
                    "the gate host certificate was re-issued by the active host key"
                );
                GateCertificate::Reissued
            }
            Err(err) => {
                let reason = truncated(&format!(
                    "the gate host certificate was not re-issued by the active host key: {}",
                    chain(&err)
                ));
                let reported = self.gate_failures.admit(&reason, now);
                report_failure(&reason, reported);
                GateCertificate::Failed { reason, reported }
            }
        }
    }
}

fn report_broadcast(broadcast: &TrustBroadcast) -> usize {
    if !broadcast.failed.is_empty() {
        let nodes: Vec<String> = broadcast
            .failed
            .iter()
            .take(MAX_LOGGED_NODES)
            .map(|(node, error)| format!("{}: {error}", node.as_str()))
            .collect();
        tracing::warn!(
            target: "jaunt::daemon",
            failed = broadcast.failed.len(),
            nodes = nodes.join(", "),
            "some agents were not told about the new trust set; they read it again on their next refresh"
        );
    }
    tracing::info!(
        target: "jaunt::daemon",
        notified = broadcast.sent,
        "told the connected agents to read the new trust set"
    );
    broadcast.sent
}

fn read_changes(
    ca_dir: &Path,
    env: &IdentityEnv,
    user: &SlotState,
    host: &SlotState,
) -> Result<Option<Changes>, String> {
    let user_changed = changed(ca_dir, CaKind::User, user)?;
    let host_changed = changed(ca_dir, CaKind::Host, host)?;
    if !user_changed && !host_changed {
        return Ok(None);
    }
    let identity = resolve_identity(ca_dir, &**env)?;
    let load = |kind: CaKind, wanted: bool| {
        wanted
            .then(|| {
                FileBackend::load_with_next(ca_dir, kind, &identity)
                    .map_err(|err| format!("{kind} keys: {err}"))
            })
            .transpose()
    };
    Ok(Some(Changes {
        user: load(CaKind::User, user_changed)?,
        host: load(CaKind::Host, host_changed)?,
    }))
}

fn changed(ca_dir: &Path, kind: CaKind, current: &SlotState) -> Result<bool, String> {
    let listing =
        FileBackend::read_slot(ca_dir, kind).map_err(|err| format!("{kind} keys: {err}"))?;
    Ok(SlotState::of(&listing.trust) != *current)
}

fn chosen(
    loaded: Option<Loaded>,
    signer: &Arc<dyn Signer>,
    trust: &TrustSet,
) -> (Arc<dyn Signer>, TrustSet) {
    match loaded {
        Some((trust, backend)) => (Arc::new(backend), trust),
        None => (Arc::clone(signer), trust.clone()),
    }
}

struct GateTrust {
    during: UserCaKeys,
    after: UserCaKeys,
}

fn gate_trust(old: &TrustSet, new: &TrustSet) -> Result<GateTrust, String> {
    let lines = |trust: &TrustSet| {
        trust
            .to_authorized_lines()
            .map_err(|err| format!("user keys: {err}"))
    };
    let kept: Vec<String> = new.keys().iter().map(fingerprint_hex).collect();
    let mut during = lines(new)?;
    for (key, line) in old.keys().iter().zip(lines(old)?) {
        if !kept.contains(&fingerprint_hex(key)) {
            during.push(line);
        }
    }
    let keys = |lines: Vec<String>| {
        UserCaKeys::from_openssh_lines(lines)
            .map_err(|err| format!("user keys for the gate: {err}"))
    };
    Ok(GateTrust {
        during: keys(during)?,
        after: keys(lines(new)?)?,
    })
}

fn audit_reloaded(kind: CaKind, trust: &TrustSet) {
    let trust_id = trust.set_id();
    let active_fp = fingerprint_hex(trust.active());
    tracing::info!(
        target: "jaunt::audit",
        event = "ca.reloaded",
        kind = kind.as_str(),
        trust_id = trust_id.as_str(),
        active_fp = active_fp.as_str()
    );
}

fn report_failure(reason: &str, reported: bool) {
    if reported {
        tracing::warn!(target: "jaunt::audit", event = "ca.reload.failed", reason);
    } else {
        tracing::debug!(
            target: "jaunt::daemon",
            reason,
            "the certificate authority keys still cannot be applied"
        );
    }
}

fn chain(err: &dyn Error) -> String {
    let mut text = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

fn truncated(reason: &str) -> String {
    reason.chars().take(MAX_REASON_CHARS).collect()
}

pub struct CaWatcher {
    stop: CancellationToken,
    task: JoinHandle<()>,
    _stop_on_drop: DropGuard,
}

impl CaWatcher {
    pub fn start(mut reloader: CaReloader, interval: Duration, clock: Clock) -> CaWatcher {
        let stop = CancellationToken::new();
        let token = stop.clone();
        let task = tokio::spawn(async move {
            let mut ticks = tokio::time::interval(interval);
            ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    biased;
                    () = token.cancelled() => return,
                    _ = ticks.tick() => {}
                }
                tokio::select! {
                    biased;
                    () = token.cancelled() => return,
                    _ = reloader.tick(clock()) => {}
                }
            }
        });
        CaWatcher {
            _stop_on_drop: stop.clone().drop_guard(),
            stop,
            task,
        }
    }

    pub async fn stop(self, grace: Duration) {
        let CaWatcher { stop, mut task, .. } = self;
        stop.cancel();
        match tokio::time::timeout(grace, &mut task).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                tracing::error!(target: "jaunt::daemon", "the certificate authority watcher panicked");
            }
            Err(_) => {
                task.abort();
                tracing::warn!(
                    target: "jaunt::daemon",
                    "the certificate authority watcher did not stop within the shutdown grace and was aborted"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests;
