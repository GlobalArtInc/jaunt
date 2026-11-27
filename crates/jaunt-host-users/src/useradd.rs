use std::time::Duration;

use crate::config::HostUsersConfig;
use crate::names::Name;
use crate::rules::{Candidate, Reason};
use crate::state::{AccountState, State};
use crate::system::{PasswdEntry, ToolExit};

pub const SKEL_DIR: &str = "/etc/skel";
pub const ACCOUNT_COMMENT: &str = "jaunt";
pub const USERADD_TIMEOUT: Duration = Duration::from_secs(5);
pub const USERDEL_TIMEOUT: Duration = Duration::from_secs(2);

const LOCKED_BUT_NOT_DISABLED_PASSWORD: &str = "*";
const UID_RANGE_EXHAUSTED: i32 = 4;
const NAME_IN_USE: i32 = 9;
const GROUP_UPDATE_FAILED: i32 = 10;
const HOME_CREATION_FAILED: i32 = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseraddOutcome {
    Created,
    UidRangeExhausted,
    NameInUse,
    TimedOut,
    Failed { exit_code: Option<i32> },
}

impl UseraddOutcome {
    pub fn refusal(self) -> Option<Reason> {
        match self {
            Self::UidRangeExhausted => Some(Reason::UidRange),
            Self::Created | Self::NameInUse | Self::TimedOut | Self::Failed { .. } => None,
        }
    }

    fn allows_rollback(self) -> bool {
        matches!(
            self,
            Self::TimedOut
                | Self::Failed {
                    exit_code: Some(GROUP_UPDATE_FAILED | HOME_CREATION_FAILED)
                }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackPermit {
    login: Name,
}

impl RollbackPermit {
    pub fn login(&self) -> &Name {
        &self.login
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AfterFailure {
    Abandon,
    RollBack(RollbackPermit),
    KeepUnconfirmed,
}

pub fn useradd_args(config: &HostUsersConfig, candidate: &Candidate) -> Vec<String> {
    let mut args: Vec<String> = [
        "--create-home",
        "--home-dir",
        candidate.home(),
        "--skel",
        SKEL_DIR,
        "--shell",
        config.shell(),
        "--user-group",
    ]
    .map(str::to_owned)
    .into();
    let groups: Vec<&str> = config.supplementary_groups().map(Name::as_str).collect();
    if !groups.is_empty() {
        args.push("--groups".to_owned());
        args.push(groups.join(","));
    }
    args.extend(
        [
            "--comment",
            ACCOUNT_COMMENT,
            "--password",
            LOCKED_BUT_NOT_DISABLED_PASSWORD,
            "--no-log-init",
        ]
        .map(str::to_owned),
    );
    let (low, high) = (config.uid_min(), config.uid_max());
    for setting in [
        format!("UID_MIN={low}"),
        format!("UID_MAX={high}"),
        format!("GID_MIN={low}"),
        format!("GID_MAX={high}"),
        format!("HOME_MODE={:04o}", config.home_mode().bits()),
    ] {
        args.push("-K".to_owned());
        args.push(setting);
    }
    args.push("--".to_owned());
    args.push(candidate.login().as_str().to_owned());
    args
}

pub fn classify_useradd(exit: &ToolExit) -> UseraddOutcome {
    if exit.timed_out {
        return UseraddOutcome::TimedOut;
    }
    match exit.code {
        Some(0) => UseraddOutcome::Created,
        Some(UID_RANGE_EXHAUSTED) => UseraddOutcome::UidRangeExhausted,
        Some(NAME_IN_USE) => UseraddOutcome::NameInUse,
        exit_code => UseraddOutcome::Failed { exit_code },
    }
}

pub fn after_failure(
    outcome: UseraddOutcome,
    config: &HostUsersConfig,
    candidate: &Candidate,
    entry: Option<&PasswdEntry>,
    home_existed_before: bool,
    state: &State,
) -> AfterFailure {
    let login = candidate.login();
    let Some(entry) = entry else {
        return AfterFailure::Abandon;
    };
    if outcome == UseraddOutcome::NameInUse {
        return AfterFailure::Abandon;
    }
    let in_range = entry.uid != 0 && (config.uid_min()..=config.uid_max()).contains(&entry.uid);
    let marked_ours = state.record(login).is_some_and(|record| {
        record.state() == AccountState::Pending && record.uid().is_none_or(|uid| uid == entry.uid)
    });
    if outcome.allows_rollback()
        && entry.name == *login
        && in_range
        && !home_existed_before
        && marked_ours
    {
        AfterFailure::RollBack(RollbackPermit {
            login: login.clone(),
        })
    } else {
        AfterFailure::KeepUnconfirmed
    }
}

pub fn userdel_args(permit: &RollbackPermit) -> Vec<String> {
    vec![
        "--remove".to_owned(),
        "--".to_owned(),
        permit.login.as_str().to_owned(),
    ]
}

#[cfg(test)]
mod tests;
