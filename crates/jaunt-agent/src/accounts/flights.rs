use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use jaunt_host_users::{
    EnsureRequest, FailedStage, HostUsersConfig, Name, Reason, Reference, Response, SessionLabel,
};
use jaunt_proto::{AccountReference, AccountRefusal, AccountStage};
use tokio::sync::watch;

use crate::accounts::audit::{self, Visit};
use crate::accounts::helper::ask_helper;
use crate::clock::Clock;

const MAX_REMEMBERED_REFUSALS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    helper: Reference,
    control: AccountReference,
}

impl Attempt {
    pub fn random() -> Option<Self> {
        Self::from_bits(rand::random())
    }

    pub fn from_bits(bits: u32) -> Option<Self> {
        let helper = Reference::from_random(bits);
        let control = AccountReference::parse(helper.as_str()).ok()?;
        Some(Self { helper, control })
    }

    pub fn control(&self) -> &AccountReference {
        &self.control
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Exists,
    Created {
        uid: u32,
        home: String,
        groups: Vec<String>,
    },
    Refused(AccountRefusal),
    Failed {
        stage: AccountStage,
        exit_code: Option<i32>,
        cause: &'static str,
    },
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settled {
    pub attempt: Attempt,
    pub outcome: Outcome,
}

#[derive(Clone)]
pub struct Flight {
    pub attempt: Attempt,
    result: watch::Receiver<Option<Settled>>,
}

impl Flight {
    pub async fn landed(mut self) -> Settled {
        let outcome = match self.result.wait_for(Option::is_some).await {
            Ok(settled) => settled.as_ref().map(|settled| settled.outcome.clone()),
            Err(_) => None,
        };
        Settled {
            attempt: self.attempt,
            outcome: outcome.unwrap_or_else(abandoned),
        }
    }
}

fn abandoned() -> Outcome {
    Outcome::Failed {
        stage: AccountStage::Request,
        exit_code: None,
        cause: "abandoned",
    }
}

pub enum Joined {
    Remembered(Settled),
    Flying(Flight),
}

struct Remembered {
    settled: Settled,
    at: SystemTime,
}

#[derive(Default)]
struct Book {
    flying: HashMap<Name, Flight>,
    refusals: HashMap<Name, Remembered>,
}

pub struct Flights {
    book: Mutex<Book>,
    turn: tokio::sync::Mutex<()>,
    socket: PathBuf,
    clock: Arc<dyn Clock>,
    helper_wait: Duration,
    memory: Duration,
}

pub struct FlightPlan<'a> {
    pub login: &'a Name,
    pub session: &'a SessionLabel,
    pub config: &'a HostUsersConfig,
}

impl Flights {
    pub fn new(
        socket: PathBuf,
        clock: Arc<dyn Clock>,
        helper_wait: Duration,
        memory: Duration,
    ) -> Self {
        Self {
            book: Mutex::new(Book::default()),
            turn: tokio::sync::Mutex::new(()),
            socket,
            clock,
            helper_wait,
            memory,
        }
    }

    fn book(&self) -> MutexGuard<'_, Book> {
        self.book.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn join(self: &Arc<Self>, plan: &FlightPlan<'_>) -> Option<Joined> {
        let now = self.clock.now();
        let mut book = self.book();
        let memory = self.memory;
        book.refusals
            .retain(|_, remembered| still_remembered(remembered.at, now, memory));
        if let Some(remembered) = book.refusals.get(plan.login) {
            return Some(Joined::Remembered(remembered.settled.clone()));
        }
        if let Some(flight) = book.flying.get(plan.login) {
            return Some(Joined::Flying(flight.clone()));
        }
        let attempt = Attempt::random()?;
        let (sender, result) = watch::channel(None);
        let flight = Flight {
            attempt: attempt.clone(),
            result,
        };
        book.flying.insert(plan.login.clone(), flight.clone());
        drop(book);
        let request = EnsureRequest {
            login: plan.login.as_str().to_owned(),
            reference: attempt.helper.clone(),
            session: plan.session.clone(),
        };
        let landing = Landing {
            flights: Arc::clone(self),
            login: plan.login.clone(),
            session: plan.session.clone(),
            attempt,
            sender: Some(sender),
        };
        tokio::spawn(fly(landing, request, plan.config.clone()));
        Some(Joined::Flying(flight))
    }

    async fn ask(
        &self,
        request: &EnsureRequest,
        config: &HostUsersConfig,
        login: &Name,
    ) -> Outcome {
        let exchange = async {
            let _turn = self.turn.lock().await;
            ask_helper(&self.socket, request).await
        };
        match tokio::time::timeout(self.helper_wait, exchange).await {
            Ok(Ok(response)) => judge(response, config, login),
            Ok(Err(error)) => {
                tracing::warn!(
                    target: "jaunt::agent",
                    event = "agent.host_user.helper_error",
                    "ref" = request.reference.as_str(),
                    error = %error,
                    "the account helper did not give a usable answer"
                );
                Outcome::Failed {
                    stage: AccountStage::Request,
                    exit_code: None,
                    cause: error.cause(),
                }
            }
            Err(_) => {
                tracing::warn!(
                    target: "jaunt::agent",
                    event = "agent.host_user.helper_error",
                    "ref" = request.reference.as_str(),
                    "the account helper did not answer in time; the account may still appear"
                );
                Outcome::Failed {
                    stage: AccountStage::Request,
                    exit_code: None,
                    cause: "timeout",
                }
            }
        }
    }
}

fn still_remembered(at: SystemTime, now: SystemTime, memory: Duration) -> bool {
    now.duration_since(at).is_ok_and(|elapsed| elapsed < memory)
}

struct Landing {
    flights: Arc<Flights>,
    login: Name,
    session: SessionLabel,
    attempt: Attempt,
    sender: Option<watch::Sender<Option<Settled>>>,
}

impl Landing {
    fn record(&self, outcome: &Outcome) {
        let visit = Visit {
            session_id: self.session.as_str(),
            login: self.login.as_str(),
        };
        let reference = self.attempt.control();
        match outcome {
            Outcome::Created { uid, home, .. } => audit::created(&visit, reference, *uid, home),
            Outcome::Refused(reason) => audit::refused(&visit, reference, reason.as_str()),
            Outcome::Failed {
                stage,
                exit_code,
                cause,
            } => audit::failed(&visit, reference, *stage, *exit_code, cause),
            Outcome::Exists | Outcome::Missing => {}
        }
    }

    fn land(mut self, outcome: Outcome) {
        self.record(&outcome);
        let settled = Settled {
            attempt: self.attempt.clone(),
            outcome,
        };
        let now = self.flights.clock.now();
        let mut book = self.flights.book();
        book.flying.remove(&self.login);
        if matches!(settled.outcome, Outcome::Refused(_))
            && book.refusals.len() < MAX_REMEMBERED_REFUSALS
        {
            book.refusals.insert(
                self.login.clone(),
                Remembered {
                    settled: settled.clone(),
                    at: now,
                },
            );
        }
        if let Some(sender) = self.sender.take() {
            sender.send_replace(Some(settled));
        }
    }
}

impl Drop for Landing {
    fn drop(&mut self) {
        if self.sender.is_none() {
            return;
        }
        self.record(&abandoned());
        let mut book = self.flights.book();
        if book
            .flying
            .get(&self.login)
            .is_some_and(|flight| flight.attempt == self.attempt)
        {
            book.flying.remove(&self.login);
        }
    }
}

async fn fly(landing: Landing, request: EnsureRequest, config: HostUsersConfig) {
    let outcome = landing.flights.ask(&request, &config, &landing.login).await;
    landing.land(outcome);
}

pub fn judge(response: Response, config: &HostUsersConfig, login: &Name) -> Outcome {
    match response {
        Response::Exists => Outcome::Exists,
        Response::Disabled => Outcome::Missing,
        Response::Refused { reason } => Outcome::Refused(refusal_of(reason)),
        Response::Failed { stage, exit_code } => Outcome::Failed {
            stage: stage_of(stage),
            exit_code,
            cause: "helper",
        },
        Response::Created { uid, home, groups } => {
            if uid == 0 || !(config.uid_min()..=config.uid_max()).contains(&uid) {
                return Outcome::Failed {
                    stage: AccountStage::Verify,
                    exit_code: None,
                    cause: "uid",
                };
            }
            if home != config.home_of(login) {
                return Outcome::Failed {
                    stage: AccountStage::Verify,
                    exit_code: None,
                    cause: "home",
                };
            }
            Outcome::Created {
                uid,
                home,
                groups: groups.into_iter().map(String::from).collect(),
            }
        }
    }
}

pub fn refusal_of(reason: Reason) -> AccountRefusal {
    match reason {
        Reason::NameRule => AccountRefusal::NameRule,
        Reason::ReservedName => AccountRefusal::ReservedName,
        Reason::GroupCollision => AccountRefusal::GroupCollision,
        Reason::HomeExists => AccountRefusal::HomeExists,
        Reason::MaxUsers => AccountRefusal::MaxUsers,
        Reason::RateLimit => AccountRefusal::RateLimit,
        Reason::UidRange => AccountRefusal::UidRange,
    }
}

fn stage_of(stage: FailedStage) -> AccountStage {
    match stage {
        FailedStage::Busy => AccountStage::Busy,
        FailedStage::Request => AccountStage::Request,
        FailedStage::State => AccountStage::State,
        FailedStage::Lookup => AccountStage::Lookup,
        FailedStage::Tool => AccountStage::Tool,
        FailedStage::Useradd => AccountStage::Useradd,
        FailedStage::Verify => AccountStage::Verify,
        FailedStage::Partial => AccountStage::Partial,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use jaunt_host_users::{HostUsersConfig, HostUsersSection, Name, Response, Settings};
    use jaunt_proto::AccountStage;
    use tokio::sync::watch;

    use super::{Attempt, Flight, Flights, Landing, Outcome, judge};
    use crate::testkit::{ManualClock, soon};

    fn config() -> HostUsersConfig {
        let section = HostUsersSection {
            enabled: true,
            ..HostUsersSection::default()
        };
        let Ok(Settings::Enabled(config)) = section.settings() else {
            panic!("the default enabled section is valid");
        };
        config
    }

    #[test]
    fn every_random_value_makes_a_reference_both_sides_accept() {
        for bits in [0, 1, 0xDEAD_BEEF, u32::MAX] {
            let attempt = Attempt::from_bits(bits).unwrap();
            assert_eq!(attempt.helper.as_str(), attempt.control.as_str());
            assert_eq!(attempt.control.as_str().len(), 10);
        }
        assert_eq!(
            Attempt::from_bits(0xDEAD_BEEF).unwrap().control.as_str(),
            "H-DEADBEEF"
        );
        assert!(Attempt::random().is_some());
    }

    #[test]
    fn a_created_answer_must_name_a_uid_in_range_and_the_configured_home() {
        let config = config();
        let login = Name::parse("alice").unwrap();
        let home = config.home_of(&login);
        let verify = |cause| Outcome::Failed {
            stage: AccountStage::Verify,
            exit_code: None,
            cause,
        };
        let created = |uid| Outcome::Created {
            uid,
            home: home.clone(),
            groups: vec!["alice".to_owned()],
        };
        let cases = [
            (config.uid_min(), home.clone(), created(config.uid_min())),
            (config.uid_max(), home.clone(), created(config.uid_max())),
            (config.uid_min() - 1, home.clone(), verify("uid")),
            (config.uid_max() + 1, home.clone(), verify("uid")),
            (config.uid_min(), format!("{home}x"), verify("home")),
            (config.uid_min(), "/root".to_owned(), verify("home")),
        ];
        for (uid, answered_home, expected) in cases {
            let response = Response::Created {
                uid,
                home: answered_home.clone(),
                groups: vec![login.clone()],
            };
            assert_eq!(
                judge(response, &config, &login),
                expected,
                "{uid} {answered_home}"
            );
        }
    }

    #[tokio::test]
    async fn a_landing_dropped_without_an_outcome_frees_the_login_and_wakes_waiters() {
        let clock = ManualClock::new(SystemTime::UNIX_EPOCH);
        let flights = Arc::new(Flights::new(
            "/nonexistent.sock".into(),
            clock,
            Duration::from_secs(1),
            Duration::from_secs(60),
        ));
        let login = Name::parse("alice").unwrap();
        let attempt = Attempt::from_bits(7).unwrap();
        let (sender, result) = watch::channel(None);
        let flight = Flight {
            attempt: attempt.clone(),
            result,
        };
        flights.book().flying.insert(login.clone(), flight.clone());
        let landing = Landing {
            flights: Arc::clone(&flights),
            login: login.clone(),
            session: jaunt_host_users::SessionLabel::parse("s-1").unwrap(),
            attempt: attempt.clone(),
            sender: Some(sender),
        };
        drop(landing);
        assert!(flights.book().flying.is_empty());
        let settled = soon("the waiter", flight.landed()).await;
        assert_eq!(settled.attempt, attempt);
        assert_eq!(
            settled.outcome,
            Outcome::Failed {
                stage: AccountStage::Request,
                exit_code: None,
                cause: "abandoned",
            }
        );
    }
}
