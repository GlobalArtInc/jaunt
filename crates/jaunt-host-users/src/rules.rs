use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::HostUsersConfig;
use crate::directory::DirectoryUse;
use crate::names::{Name, is_reserved};
use crate::rate::Attempts;
use crate::state::State;
use crate::system::{Files, FilesError, LookupError, Users};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    NameRule,
    ReservedName,
    GroupCollision,
    HomeExists,
    MaxUsers,
    RateLimit,
    UidRange,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NameRule => "name_rule",
            Self::ReservedName => "reserved_name",
            Self::GroupCollision => "group_collision",
            Self::HomeExists => "home_exists",
            Self::MaxUsers => "max_users",
            Self::RateLimit => "rate_limit",
            Self::UidRange => "uid_range",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    login: Name,
    home: String,
}

impl Candidate {
    pub(crate) fn new(login: Name, home: String) -> Self {
        Self { login, home }
    }

    pub fn login(&self) -> &Name {
        &self.login
    }

    pub fn home(&self) -> &str {
        &self.home
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Disabled,
    Exists,
    Refused(Reason),
    Create(Candidate),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    pub(crate) login: Name,
    pub(crate) home: String,
    pub(crate) directory: DirectoryUse,
    pub(crate) account_exists: bool,
    pub(crate) group_exists: bool,
    pub(crate) home_exists: bool,
    pub(crate) managed_users: u32,
    pub(crate) attempts: Attempts,
    pub(crate) now: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum FactsError {
    #[error(transparent)]
    Lookup(#[from] LookupError),
    #[error(transparent)]
    Files(#[from] FilesError),
}

pub fn check_login(raw: &str) -> Result<Name, Reason> {
    Name::parse(raw).map_err(|_| Reason::NameRule)
}

pub fn gather(
    config: &HostUsersConfig,
    login: Name,
    directory: DirectoryUse,
    state: &State,
    system: (&dyn Users, &dyn Files),
    now: u64,
) -> Result<Facts, FactsError> {
    let (users, files) = system;
    let home = config.home_of(&login);
    let account_exists = users.passwd(&login)?.is_some();
    let group_exists = users.group(&login)?.is_some();
    let home_exists = files.lstat(Path::new(&home))?.is_some();
    let managed_users = state.counted_users(users)?;
    Ok(Facts {
        login,
        home,
        directory,
        account_exists,
        group_exists,
        home_exists,
        managed_users,
        attempts: state.attempts().clone(),
        now,
    })
}

pub fn decide(config: &HostUsersConfig, facts: &Facts) -> Decision {
    if facts.directory == DirectoryUse::Network && !config.allow_with_directory() {
        return Decision::Disabled;
    }
    if facts.account_exists {
        return Decision::Exists;
    }
    let refusal = if !config.names().permits(&facts.login) {
        Some(Reason::NameRule)
    } else if is_reserved(&facts.login, config.privileged_groups()) {
        Some(Reason::ReservedName)
    } else if facts.group_exists {
        Some(Reason::GroupCollision)
    } else if facts.home_exists {
        Some(Reason::HomeExists)
    } else if facts.managed_users >= config.max_users() {
        Some(Reason::MaxUsers)
    } else if !facts.attempts.allows(facts.now) {
        Some(Reason::RateLimit)
    } else {
        None
    };
    match refusal {
        Some(reason) => Decision::Refused(reason),
        None => Decision::Create(Candidate::new(facts.login.clone(), facts.home.clone())),
    }
}

#[cfg(test)]
mod tests;
