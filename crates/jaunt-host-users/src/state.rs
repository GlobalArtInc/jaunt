use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::config::MAX_HOME_BYTES;
use crate::names::Name;
use crate::paths::is_clean_absolute_path;
use crate::protocol::{Reference, SessionLabel};
use crate::rate::Attempts;
use crate::rules::Candidate;
use crate::system::{LookupError, PasswdEntry, Users, lookup_many};
use crate::verify::Verified;

pub const STATE_VERSION: u64 = 1;
pub const MAX_RECORDS: usize = 4096;
pub const MAX_STATE_BYTES: usize = 2 * 1024 * 1024;

const MAX_STORED_ATTEMPTS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountState {
    Pending,
    Active,
    Unconfirmed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRecord {
    login: Name,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gid: Option<u32>,
    home: String,
    created_at: u64,
    #[serde(rename = "ref")]
    reference: Reference,
    session: SessionLabel,
    state: AccountState,
}

impl AccountRecord {
    pub fn login(&self) -> &Name {
        &self.login
    }

    pub fn uid(&self) -> Option<u32> {
        self.uid
    }

    pub fn gid(&self) -> Option<u32> {
        self.gid
    }

    pub fn home(&self) -> &str {
        &self.home
    }

    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    pub fn reference(&self) -> &Reference {
        &self.reference
    }

    pub fn session(&self) -> &SessionLabel {
        &self.session
    }

    pub fn state(&self) -> AccountState {
        self.state
    }

    pub fn is_managed(&self, entry: Option<&PasswdEntry>) -> bool {
        self.state != AccountState::Pending
            && self
                .uid
                .is_some_and(|uid| entry.is_some_and(|entry| entry.uid == uid))
    }

    fn counts_toward_quota(&self, entry: Option<&PasswdEntry>) -> bool {
        entry.is_some_and(|entry| self.uid.is_none_or(|uid| uid == entry.uid))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    accounts: Vec<AccountRecord>,
    attempts: Attempts,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reconciliation {
    pub dropped: Vec<Name>,
    pub unconfirmed: Vec<Name>,
    pub not_adopted: Vec<Name>,
    pub forgotten: Vec<Name>,
    pub attempts_settled: bool,
}

impl Reconciliation {
    pub fn changed(&self) -> bool {
        self.attempts_settled
            || !self.dropped.is_empty()
            || !self.unconfirmed.is_empty()
            || !self.not_adopted.is_empty()
            || !self.forgotten.is_empty()
    }
}

enum Settled {
    Keep,
    Remove,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("the state file is larger than {MAX_STATE_BYTES} bytes")]
    TooLarge,
    #[error("the state file is not valid JSON of the expected shape")]
    Malformed,
    #[error("the state file has an unsupported version")]
    Version,
    #[error("the state file is inconsistent: {0}")]
    Invalid(&'static str),
    #[error("the state file already holds {MAX_RECORDS} records")]
    Full,
    #[error("there is no pending record for {login}")]
    NotPending { login: Name },
    #[error("a pending record for {login} already exists")]
    AlreadyPending { login: Name },
    #[error("the pending record for {login} has no uid yet")]
    Unbound { login: Name },
    #[error("the verified home of {login} differs from its pending record")]
    HomeMismatch { login: Name },
    #[error("the state could not be encoded")]
    Encode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateFile {
    v: u64,
    accounts: Vec<AccountRecord>,
    attempts: Attempts,
}

#[derive(Serialize)]
struct StateFileRef<'a> {
    v: u64,
    accounts: &'a [AccountRecord],
    attempts: &'a Attempts,
}

impl State {
    pub fn from_json(bytes: &[u8]) -> Result<Self, StateError> {
        if bytes.len() > MAX_STATE_BYTES {
            return Err(StateError::TooLarge);
        }
        let file: StateFile = serde_json::from_slice(bytes).map_err(|_| StateError::Malformed)?;
        if file.v != STATE_VERSION {
            return Err(StateError::Version);
        }
        if file.accounts.len() > MAX_RECORDS {
            return Err(StateError::Invalid("too many records"));
        }
        if file.attempts.count() > MAX_STORED_ATTEMPTS {
            return Err(StateError::Invalid("too many attempts"));
        }
        let mut logins = BTreeSet::new();
        for record in &file.accounts {
            if !logins.insert(record.login.as_str()) {
                return Err(StateError::Invalid("a login appears twice"));
            }
            if record.uid.is_some() != record.gid.is_some() {
                return Err(StateError::Invalid("a record has only one of uid and gid"));
            }
            if record.state == AccountState::Active && record.uid.is_none() {
                return Err(StateError::Invalid("an active record has no uid"));
            }
            if !is_clean_absolute_path(&record.home, MAX_HOME_BYTES) {
                return Err(StateError::Invalid("a record has an invalid home"));
            }
        }
        Ok(Self {
            accounts: file.accounts,
            attempts: file.attempts,
        })
    }

    pub fn to_json(&self) -> Result<Vec<u8>, StateError> {
        let file = StateFileRef {
            v: STATE_VERSION,
            accounts: &self.accounts,
            attempts: &self.attempts,
        };
        let mut bytes = serde_json::to_vec(&file).map_err(|_| StateError::Encode)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn accounts(&self) -> &[AccountRecord] {
        &self.accounts
    }

    pub fn attempts(&self) -> &Attempts {
        &self.attempts
    }

    pub fn record(&self, login: &Name) -> Option<&AccountRecord> {
        self.accounts.iter().find(|record| record.login == *login)
    }

    pub fn counted_users(&self, users: &dyn Users) -> Result<u32, LookupError> {
        let entries = lookup_many(users, &self.logins())?;
        let counted = self
            .accounts
            .iter()
            .zip(&entries)
            .filter(|(record, entry)| record.counts_toward_quota(entry.as_ref()))
            .count();
        Ok(u32::try_from(counted).unwrap_or(u32::MAX))
    }

    pub fn reconcile(
        &mut self,
        users: &dyn Users,
        now: u64,
    ) -> Result<Reconciliation, LookupError> {
        let entries = lookup_many(users, &self.logins())?;
        let mut report = Reconciliation::default();
        let mut entries = entries.into_iter();
        self.accounts.retain_mut(|record| {
            let entry = entries.next().flatten();
            match settle_record(record, entry.as_ref(), &mut report) {
                Settled::Keep => true,
                Settled::Remove => false,
            }
        });
        report.attempts_settled = self.attempts.settle(now);
        Ok(report)
    }

    fn logins(&self) -> Vec<Name> {
        self.accounts
            .iter()
            .map(|record| record.login.clone())
            .collect()
    }

    pub fn begin(
        &mut self,
        candidate: &Candidate,
        reference: &Reference,
        session: &SessionLabel,
        now: u64,
    ) -> Result<(), StateError> {
        let login = candidate.login();
        if self
            .record(login)
            .is_some_and(|record| record.state == AccountState::Pending)
        {
            return Err(StateError::AlreadyPending {
                login: login.clone(),
            });
        }
        let replaces = self.record(login).is_some();
        if !replaces && self.accounts.len() >= MAX_RECORDS {
            return Err(StateError::Full);
        }
        self.accounts.retain(|record| record.login != *login);
        self.accounts.push(AccountRecord {
            login: login.clone(),
            uid: None,
            gid: None,
            home: candidate.home().to_owned(),
            created_at: now,
            reference: reference.clone(),
            session: session.clone(),
            state: AccountState::Pending,
        });
        self.attempts.record(now);
        Ok(())
    }

    pub fn bind(&mut self, verified: &Verified) -> Result<(), StateError> {
        let login = verified.login();
        let record = self.pending_mut(login)?;
        if record.home != verified.home() {
            return Err(StateError::HomeMismatch {
                login: login.clone(),
            });
        }
        record.uid = Some(verified.uid());
        record.gid = Some(verified.gid());
        Ok(())
    }

    pub fn activate(&mut self, login: &Name) -> Result<(), StateError> {
        let record = self.pending_mut(login)?;
        if record.uid.is_none() {
            return Err(StateError::Unbound {
                login: login.clone(),
            });
        }
        record.state = AccountState::Active;
        Ok(())
    }

    pub fn mark_unconfirmed(&mut self, login: &Name) -> Result<(), StateError> {
        self.pending_mut(login)?.state = AccountState::Unconfirmed;
        Ok(())
    }

    pub fn abandon(&mut self, login: &Name) -> Result<(), StateError> {
        self.pending_mut(login)?;
        self.accounts.retain(|record| record.login != *login);
        Ok(())
    }

    fn pending_mut(&mut self, login: &Name) -> Result<&mut AccountRecord, StateError> {
        self.accounts
            .iter_mut()
            .find(|record| record.login == *login && record.state == AccountState::Pending)
            .ok_or_else(|| StateError::NotPending {
                login: login.clone(),
            })
    }
}

fn settle_record(
    record: &mut AccountRecord,
    entry: Option<&PasswdEntry>,
    report: &mut Reconciliation,
) -> Settled {
    let login = record.login.clone();
    let same_uid = entry.is_some_and(|entry| record.uid == Some(entry.uid));
    match (record.state, entry, record.uid) {
        (AccountState::Pending, None, _) => {
            report.dropped.push(login);
            Settled::Remove
        }
        (AccountState::Pending, Some(_), _) if same_uid => {
            record.state = AccountState::Unconfirmed;
            report.unconfirmed.push(login);
            Settled::Keep
        }
        (AccountState::Pending, Some(_), None) => {
            record.state = AccountState::Unconfirmed;
            report.not_adopted.push(login);
            Settled::Keep
        }
        (AccountState::Pending, Some(_), Some(_)) => {
            report.not_adopted.push(login);
            Settled::Remove
        }
        (AccountState::Active | AccountState::Unconfirmed, Some(_), None) => Settled::Keep,
        (AccountState::Active | AccountState::Unconfirmed, _, _) if same_uid => Settled::Keep,
        (AccountState::Active | AccountState::Unconfirmed, _, _) => {
            report.forgotten.push(login);
            Settled::Remove
        }
    }
}

#[cfg(test)]
mod tests;
