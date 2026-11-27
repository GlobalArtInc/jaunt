use std::fmt;
use std::iter;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::{ConfigError, HostUsersConfig, Settings, check_host};
use crate::directory::DirectoryUse;
use crate::journal::Severity;
use crate::names::Name;
use crate::protocol::{FailedStage, Reference, Response, SessionLabel};
use crate::rules::{Candidate, Decision, decide, gather};
use crate::state::{AccountState, Reconciliation, State};
use crate::store::{StateLock, StoreError};
use crate::sys::{Tool, ToolError, USERADD, USERDEL};
use crate::system::{Files, FilesError, Runner, ToolExit, Users};
use crate::useradd::{
    AfterFailure, RollbackPermit, USERADD_TIMEOUT, USERDEL_TIMEOUT, UseraddOutcome, after_failure,
    classify_useradd, useradd_args, userdel_args,
};
use crate::verify::verify_created;

pub const HELPER_DEADLINE: Duration = Duration::from_secs(10);

pub(crate) trait Ledger {
    fn load(&self) -> Result<State, StoreError>;
    fn save(&self, state: &State) -> Result<(), StoreError>;
}

impl Ledger for StateLock<'_> {
    fn load(&self) -> Result<State, StoreError> {
        StateLock::load(self)
    }

    fn save(&self, state: &State) -> Result<(), StoreError> {
        StateLock::save(self, state)
    }
}

pub(crate) trait Node {
    fn settings(&self) -> Result<Settings, ConfigError>;
    fn shells(&self) -> Result<String, FilesError>;
    fn directory(&self) -> Result<DirectoryUse, FilesError>;
    fn tool(&self, tool: &Tool) -> Result<PathBuf, ToolError>;
}

pub(crate) struct System<'a> {
    pub(crate) users: &'a dyn Users,
    pub(crate) files: &'a dyn Files,
    pub(crate) runner: &'a mut dyn Runner,
    pub(crate) node: &'a dyn Node,
    pub(crate) now: u64,
}

pub(crate) struct Ticket<'a> {
    pub(crate) login: &'a Name,
    pub(crate) reference: &'a Reference,
    pub(crate) session: &'a SessionLabel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Removal {
    pub(crate) removed: bool,
    pub(crate) exit_code: Option<i32>,
}

#[derive(Debug, Default)]
pub(crate) struct Notes {
    pub(crate) severity: Severity,
    pub(crate) uid: Option<u32>,
    pub(crate) useradd: Option<ToolExit>,
    pub(crate) removal: Option<Removal>,
    pub(crate) settled: Reconciliation,
    pub(crate) repaired: Vec<Name>,
    pub(crate) details: Vec<String>,
}

impl Notes {
    fn raise(&mut self, severity: Severity) {
        self.severity = self.severity.max(severity);
    }

    fn note(&mut self, cause: &dyn fmt::Display) {
        self.details.push(cause.to_string());
    }

    pub(crate) fn failed(
        &mut self,
        stage: FailedStage,
        severity: Severity,
        cause: &dyn fmt::Display,
    ) -> Response {
        self.raise(severity);
        self.note(cause);
        Response::Failed {
            stage,
            exit_code: None,
        }
    }

    fn disabled_by(&mut self, cause: &dyn fmt::Display) -> Response {
        self.raise(Severity::Warning);
        self.note(cause);
        Response::Disabled
    }

    fn config_problem(&mut self, error: ConfigError) -> Response {
        match error {
            ConfigError::Lookup(error) => {
                self.failed(FailedStage::Lookup, Severity::Warning, &error)
            }
            error => self.disabled_by(&error),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum Anomaly {
    #[error("the account database lists a network user directory")]
    NetworkDirectory,
    #[error("useradd failed and left an account that may not be rolled back")]
    LeftBehind,
    #[error("userdel left the account in place")]
    StillThere,
}

pub(crate) fn handle(
    ticket: &Ticket<'_>,
    ledger: &dyn Ledger,
    system: &mut System<'_>,
    notes: &mut Notes,
) -> Response {
    let mut state = match ledger.load() {
        Ok(state) => state,
        Err(error) => return notes.failed(FailedStage::State, Severity::Warning, &error),
    };
    match state.reconcile(system.users, system.now) {
        Ok(settled) => notes.settled = settled,
        Err(error) => return notes.failed(FailedStage::Lookup, Severity::Warning, &error),
    }
    let settled = &notes.settled;
    let interrupted = [&settled.dropped, &settled.unconfirmed, &settled.not_adopted]
        .iter()
        .any(|logins| !logins.is_empty());
    if interrupted {
        notes.raise(Severity::Warning);
    }
    if notes.settled.changed()
        && let Err(error) = ledger.save(&state)
    {
        return notes.failed(FailedStage::State, Severity::Warning, &error);
    }
    let config = match system.node.settings() {
        Ok(Settings::Enabled(config)) => config,
        Ok(Settings::Disabled) => return Response::Disabled,
        Err(error) => return notes.config_problem(error),
    };
    repair_homes(&config, &state, system.files, notes);
    let shells = match system.node.shells() {
        Ok(shells) => shells,
        Err(error) => return notes.disabled_by(&error),
    };
    if let Err(error) = check_host(&config, &shells, system.users, system.files) {
        return notes.config_problem(error);
    }
    let directory = match system.node.directory() {
        Ok(directory) => directory,
        Err(error) => return notes.disabled_by(&error),
    };
    let facts = match gather(
        &config,
        ticket.login.clone(),
        directory,
        &state,
        (system.users, system.files),
        system.now,
    ) {
        Ok(facts) => facts,
        Err(error) => return notes.failed(FailedStage::Lookup, Severity::Warning, &error),
    };
    match decide(&config, &facts) {
        Decision::Disabled => notes.disabled_by(&Anomaly::NetworkDirectory),
        Decision::Exists => Response::Exists,
        Decision::Refused(reason) => Response::Refused { reason },
        Decision::Create(candidate) => Creation {
            config: &config,
            candidate: &candidate,
            home_existed: facts.home_exists,
            ticket,
            ledger,
            state: &mut state,
            notes,
        }
        .run(system),
    }
}

fn repair_homes(config: &HostUsersConfig, state: &State, files: &dyn Files, notes: &mut Notes) {
    let mode = config.home_mode().bits();
    for login in notes.settled.unconfirmed.clone() {
        let Some(record) = state.record(&login) else {
            continue;
        };
        let Some(uid) = record.uid() else {
            continue;
        };
        if record.state() != AccountState::Unconfirmed {
            continue;
        }
        match files.chmod_directory_nofollow(Path::new(record.home()), uid, mode) {
            Ok(()) => notes.repaired.push(login),
            Err(error) => {
                notes.raise(Severity::Warning);
                notes.note(&error);
            }
        }
    }
}

struct Creation<'a> {
    config: &'a HostUsersConfig,
    candidate: &'a Candidate,
    home_existed: bool,
    ticket: &'a Ticket<'a>,
    ledger: &'a dyn Ledger,
    state: &'a mut State,
    notes: &'a mut Notes,
}

impl Creation<'_> {
    fn run(self, system: &mut System<'_>) -> Response {
        let tools = system
            .node
            .tool(&USERADD)
            .and_then(|useradd| Ok((useradd, system.node.tool(&USERDEL)?)));
        let (useradd, userdel) = match tools {
            Ok(tools) => tools,
            Err(error) => {
                return self
                    .notes
                    .failed(FailedStage::Tool, Severity::Warning, &error);
            }
        };
        let ticket = self.ticket;
        if let Err(error) =
            self.state
                .begin(self.candidate, ticket.reference, ticket.session, system.now)
        {
            return self
                .notes
                .failed(FailedStage::State, Severity::Warning, &error);
        }
        if let Err(error) = self.ledger.save(self.state) {
            return self
                .notes
                .failed(FailedStage::State, Severity::Warning, &error);
        }
        let args = useradd_args(self.config, self.candidate);
        let exit = match system.runner.run(&useradd, &args, USERADD_TIMEOUT) {
            Ok(exit) => exit,
            Err(error) => {
                self.notes.raise(Severity::Warning);
                self.notes.note(&error);
                return match system.users.passwd(self.candidate.login()) {
                    Ok(None) => self.abandon(Response::Failed {
                        stage: FailedStage::Tool,
                        exit_code: None,
                    }),
                    Ok(Some(_)) => {
                        self.keep_unconfirmed(FailedStage::Partial, None, &Anomaly::LeftBehind)
                    }
                    Err(lookup) => self.keep_unconfirmed(FailedStage::Lookup, None, &lookup),
                };
            }
        };
        self.notes.useradd = Some(exit.clone());
        match classify_useradd(&exit) {
            UseraddOutcome::Created => self.finish(system),
            outcome => self.recover(outcome, exit.code, &userdel, system),
        }
    }

    fn finish(self, system: &mut System<'_>) -> Response {
        let login = self.candidate.login();
        let looked = system
            .users
            .passwd(login)
            .and_then(|passwd| Ok((passwd, system.users.group(login)?)));
        let (passwd, group) = match looked {
            Ok(entries) => entries,
            Err(error) => return self.keep_unconfirmed(FailedStage::Lookup, None, &error),
        };
        let home = match system.files.lstat(Path::new(self.candidate.home())) {
            Ok(home) => home,
            Err(error) => return self.keep_unconfirmed(FailedStage::Lookup, None, &error),
        };
        self.notes.uid = passwd.as_ref().map(|entry| entry.uid);
        let verified = match verify_created(
            self.config,
            self.candidate,
            passwd.as_ref(),
            group.as_ref(),
            home.as_ref(),
        ) {
            Ok(verified) => verified,
            Err(problem) => {
                let decision = after_failure(
                    UseraddOutcome::Created,
                    self.config,
                    self.candidate,
                    passwd.as_ref(),
                    self.home_existed,
                    self.state,
                );
                return match decision {
                    AfterFailure::Abandon => {
                        self.notes.raise(Severity::Error);
                        self.notes.note(&problem);
                        self.abandon(Response::Failed {
                            stage: FailedStage::Verify,
                            exit_code: None,
                        })
                    }
                    AfterFailure::RollBack(_) | AfterFailure::KeepUnconfirmed => {
                        self.keep_unconfirmed(FailedStage::Verify, None, &problem)
                    }
                };
            }
        };
        if let Err(error) = self.state.bind(&verified) {
            return self.keep_unconfirmed(FailedStage::State, None, &error);
        }
        if let Err(error) = self.ledger.save(self.state) {
            return self
                .notes
                .failed(FailedStage::State, Severity::Error, &error);
        }
        let mode = self.config.home_mode().bits();
        if let Err(error) =
            system
                .files
                .chmod_directory_nofollow(Path::new(verified.home()), verified.uid(), mode)
        {
            return self
                .notes
                .failed(FailedStage::Partial, Severity::Error, &error);
        }
        if let Err(error) = self.state.activate(login) {
            return self
                .notes
                .failed(FailedStage::State, Severity::Error, &error);
        }
        if let Err(error) = self.ledger.save(self.state) {
            return self
                .notes
                .failed(FailedStage::State, Severity::Error, &error);
        }
        Response::Created {
            uid: verified.uid(),
            home: verified.home().to_owned(),
            groups: iter::once(login.clone())
                .chain(self.config.supplementary_groups().cloned())
                .collect(),
        }
    }

    fn recover(
        self,
        outcome: UseraddOutcome,
        exit_code: Option<i32>,
        userdel: &Path,
        system: &mut System<'_>,
    ) -> Response {
        let entry = match system.users.passwd(self.candidate.login()) {
            Ok(entry) => entry,
            Err(error) => return self.keep_unconfirmed(FailedStage::Lookup, exit_code, &error),
        };
        self.notes.uid = entry.as_ref().map(|entry| entry.uid);
        let decision = after_failure(
            outcome,
            self.config,
            self.candidate,
            entry.as_ref(),
            self.home_existed,
            self.state,
        );
        match decision {
            AfterFailure::Abandon => match outcome.refusal() {
                Some(reason) => self.abandon(Response::Refused { reason }),
                None => {
                    self.notes.raise(Severity::Warning);
                    self.abandon(Response::Failed {
                        stage: FailedStage::Useradd,
                        exit_code,
                    })
                }
            },
            AfterFailure::RollBack(permit) => self.roll_back(&permit, userdel, exit_code, system),
            AfterFailure::KeepUnconfirmed => {
                self.keep_unconfirmed(FailedStage::Partial, exit_code, &Anomaly::LeftBehind)
            }
        }
    }

    fn roll_back(
        self,
        permit: &RollbackPermit,
        userdel: &Path,
        useradd_exit: Option<i32>,
        system: &mut System<'_>,
    ) -> Response {
        let exit_code = match system
            .runner
            .run(userdel, &userdel_args(permit), USERDEL_TIMEOUT)
        {
            Ok(exit) => exit.code,
            Err(error) => {
                self.notes.note(&error);
                None
            }
        };
        let remaining = system.users.passwd(permit.login());
        let removed = matches!(remaining, Ok(None));
        self.notes.removal = Some(Removal { removed, exit_code });
        match remaining {
            Ok(None) => {
                self.notes.raise(Severity::Warning);
                self.abandon(Response::Failed {
                    stage: FailedStage::Useradd,
                    exit_code: useradd_exit,
                })
            }
            Ok(Some(_)) => {
                self.keep_unconfirmed(FailedStage::Partial, useradd_exit, &Anomaly::StillThere)
            }
            Err(error) => self.keep_unconfirmed(FailedStage::Partial, useradd_exit, &error),
        }
    }

    fn keep_unconfirmed(
        self,
        stage: FailedStage,
        exit_code: Option<i32>,
        cause: &dyn fmt::Display,
    ) -> Response {
        self.notes.raise(Severity::Error);
        self.notes.note(cause);
        if let Err(error) = self.state.mark_unconfirmed(self.candidate.login()) {
            return self
                .notes
                .failed(FailedStage::State, Severity::Error, &error);
        }
        if let Err(error) = self.ledger.save(self.state) {
            return self
                .notes
                .failed(FailedStage::State, Severity::Error, &error);
        }
        Response::Failed { stage, exit_code }
    }

    fn abandon(self, response: Response) -> Response {
        if let Err(error) = self.state.abandon(self.candidate.login()) {
            return self
                .notes
                .failed(FailedStage::State, Severity::Error, &error);
        }
        if let Err(error) = self.ledger.save(self.state) {
            return self
                .notes
                .failed(FailedStage::State, Severity::Error, &error);
        }
        response
    }
}

#[cfg(test)]
mod tests;
