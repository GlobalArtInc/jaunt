mod announce;
mod audit;
mod availability;
mod flights;
mod helper;
mod lookup;
#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::Duration;

use jaunt_host_users::{HostUsersConfig, Name, Reason, SessionLabel, check_login, is_reserved};
use jaunt_proto::{AccountEvent, AccountReport, AccountStage};
use jaunt_ssh::{AccountKeeper, AccountStep};
use jaunt_tunnel::BoxFuture;
use tokio::task::JoinHandle;

use crate::clock::Clock;
use crate::run::api::{AgentApi, ApiError};

pub use announce::{ANNOUNCE_EVERY, ControlCapabilities, announce_capabilities};
pub use availability::{Availability, HostUsersPaths};
pub use helper::HELPER_WAIT;
#[cfg(test)]
pub use lookup::LookupError;
pub use lookup::{Getent, PasswdLookup, Presence};

use audit::Visit;
use availability::Unavailable;
use flights::{Attempt, FlightPlan, Flights, Joined, Outcome, Settled, refusal_of};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountTimings {
    pub lookup: Duration,
    pub report: Duration,
    pub helper: Duration,
    pub refusal_memory: Duration,
    pub announce_every: Duration,
}

pub const ACCOUNT_TIMINGS: AccountTimings = AccountTimings {
    lookup: Duration::from_secs(2),
    report: Duration::from_secs(2),
    helper: HELPER_WAIT,
    refusal_memory: Duration::from_secs(60),
    announce_every: ANNOUNCE_EVERY,
};

pub struct AccountParts {
    pub availability: Arc<Availability>,
    pub lookup: Arc<dyn PasswdLookup>,
    pub api: Arc<AgentApi>,
    pub clock: Arc<dyn Clock>,
    pub timings: AccountTimings,
}

pub struct AccountService {
    availability: Arc<Availability>,
    lookup: Arc<dyn PasswdLookup>,
    api: Arc<AgentApi>,
    flights: Arc<Flights>,
    report_timeout: Duration,
}

impl AccountService {
    pub fn new(parts: AccountParts) -> Self {
        let flights = Flights::new(
            parts.availability.socket().to_path_buf(),
            parts.clock,
            parts.timings.helper,
            parts.timings.refusal_memory,
        );
        Self {
            availability: parts.availability,
            lookup: parts.lookup,
            api: parts.api,
            flights: Arc::new(flights),
            report_timeout: parts.timings.report,
        }
    }

    async fn ensure_account(&self, login: &str, session_id: &str) -> AccountStep {
        let visit = Visit { session_id, login };
        let name = match check_login(login) {
            Ok(name) => name,
            Err(reason) => return self.refuse_early(&visit, reason).await,
        };
        match self.lookup.passwd(&name).await {
            Ok(Presence::Present) => return AccountStep::Continue,
            Ok(Presence::Absent) => {}
            Err(error) => {
                tracing::warn!(
                    target: "jaunt::agent",
                    event = "agent.host_user.lookup_failed",
                    session_id,
                    error = %error,
                    "cannot tell whether the account exists; sshd decides"
                );
                return AccountStep::Continue;
            }
        }
        let config = match self.availability.creation() {
            Ok(config) => config,
            Err(unavailable) => return self.missing(&visit, unavailable).await,
        };
        if let Err(reason) = node_rules(config, &name) {
            return self.refuse_early(&visit, reason).await;
        }
        let Ok(session) = SessionLabel::parse(session_id) else {
            return self.fail_early(&visit, "session_label").await;
        };
        let plan = FlightPlan {
            login: &name,
            session: &session,
            config,
        };
        match self.flights.join(&plan) {
            Some(Joined::Remembered(settled)) => self.conclude(&visit, settled, None).await,
            Some(Joined::Flying(flight)) => {
                let creating = self.spawn_report(
                    &visit,
                    AccountEvent::Creating {
                        reference: flight.attempt.control().clone(),
                    },
                );
                let settled = flight.landed().await;
                self.conclude(&visit, settled, Some(creating)).await
            }
            None => self.fail_early(&visit, "reference").await,
        }
    }

    async fn conclude(
        &self,
        visit: &Visit<'_>,
        settled: Settled,
        creating: Option<JoinHandle<()>>,
    ) -> AccountStep {
        let reference = settled.attempt.control().clone();
        let (step, event) = match settled.outcome {
            Outcome::Exists => {
                tracing::debug!(
                    target: "jaunt::agent",
                    session_id = visit.session_id,
                    "ref" = reference.as_str(),
                    "the account helper found the account already present"
                );
                return AccountStep::Continue;
            }
            Outcome::Created { uid, home, groups } => {
                let event = AccountEvent::Created {
                    reference,
                    uid,
                    home,
                    groups,
                };
                (AccountStep::Continue, event)
            }
            Outcome::Refused(reason) => (
                AccountStep::Refused,
                AccountEvent::Refused { reference, reason },
            ),
            Outcome::Failed {
                stage, exit_code, ..
            } => {
                let event = AccountEvent::Failed {
                    reference,
                    stage,
                    exit_code,
                };
                (AccountStep::Failed, event)
            }
            Outcome::Missing => {
                audit::missing(visit, &reference, "helper_disabled");
                (AccountStep::NoAccount, AccountEvent::Missing { reference })
            }
        };
        if let Some(creating) = creating
            && creating.await.is_err()
        {
            tracing::debug!(
                target: "jaunt::agent",
                session_id = visit.session_id,
                "the creating report task ended abnormally"
            );
        }
        self.report(visit, event).await;
        step
    }

    async fn missing(&self, visit: &Visit<'_>, unavailable: Unavailable) -> AccountStep {
        let Some(attempt) = Attempt::random() else {
            return AccountStep::NoAccount;
        };
        let reference = attempt.control().clone();
        audit::missing(visit, &reference, unavailable.as_str());
        self.report(visit, AccountEvent::Missing { reference })
            .await;
        AccountStep::NoAccount
    }

    async fn refuse_early(&self, visit: &Visit<'_>, reason: Reason) -> AccountStep {
        let Some(attempt) = Attempt::random() else {
            return AccountStep::Refused;
        };
        let reference = attempt.control().clone();
        let reason = refusal_of(reason);
        audit::refused(visit, &reference, reason.as_str());
        self.report(visit, AccountEvent::Refused { reference, reason })
            .await;
        AccountStep::Refused
    }

    async fn fail_early(&self, visit: &Visit<'_>, cause: &'static str) -> AccountStep {
        let Some(attempt) = Attempt::random() else {
            tracing::error!(
                target: "jaunt::agent",
                session_id = visit.session_id,
                "cannot make an account reference"
            );
            return AccountStep::Failed;
        };
        let reference = attempt.control().clone();
        let stage = AccountStage::Request;
        audit::failed(visit, &reference, stage, None, cause);
        let event = AccountEvent::Failed {
            reference,
            stage,
            exit_code: None,
        };
        self.report(visit, event).await;
        AccountStep::Failed
    }

    fn spawn_report(&self, visit: &Visit<'_>, event: AccountEvent) -> JoinHandle<()> {
        let report = AccountReport::new(visit.session_id.to_owned(), visit.login.to_owned(), event);
        tokio::spawn(deliver(Arc::clone(&self.api), report, self.report_timeout))
    }

    async fn report(&self, visit: &Visit<'_>, event: AccountEvent) {
        let report = AccountReport::new(visit.session_id.to_owned(), visit.login.to_owned(), event);
        deliver(Arc::clone(&self.api), report, self.report_timeout).await;
    }
}

impl AccountKeeper for AccountService {
    fn ensure<'a>(&'a self, login: &'a str, session_id: &'a str) -> BoxFuture<'a, AccountStep> {
        Box::pin(self.ensure_account(login, session_id))
    }
}

fn node_rules(config: &HostUsersConfig, login: &Name) -> Result<(), Reason> {
    if !config.names().permits(login) {
        return Err(Reason::NameRule);
    }
    if is_reserved(login, config.privileged_groups()) {
        return Err(Reason::ReservedName);
    }
    Ok(())
}

async fn deliver(api: Arc<AgentApi>, report: AccountReport, limit: Duration) {
    let event = report.event.as_str();
    let session_id = report.session_id.as_str();
    match tokio::time::timeout(limit, api.account_report(&report)).await {
        Ok(Ok(())) => {}
        Ok(Err(ApiError::Status { status: 404, .. })) => tracing::debug!(
            target: "jaunt::agent",
            session_id,
            event,
            "the control plane does not take account reports"
        ),
        Ok(Err(ApiError::Status { status: 409, .. })) => tracing::debug!(
            target: "jaunt::agent",
            session_id,
            event,
            "the control plane refused an account report"
        ),
        Ok(Err(error)) => tracing::warn!(
            target: "jaunt::agent",
            event = "agent.host_user.report_failed",
            session_id,
            report = event,
            error = %error,
            "an account report did not reach the control plane"
        ),
        Err(_) => tracing::warn!(
            target: "jaunt::agent",
            event = "agent.host_user.report_failed",
            session_id,
            report = event,
            "an account report timed out"
        ),
    }
}
