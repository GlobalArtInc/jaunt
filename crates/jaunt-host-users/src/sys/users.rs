use std::cell::Cell;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::process::{Stdout, run};
use crate::names::Name;
use crate::system::{GroupEntry, LookupError, PasswdEntry, Users};

pub(crate) const LOOKUP_TIMEOUT: Duration = Duration::from_secs(1);
pub(crate) const LOOKUP_BUDGET: Duration = Duration::from_secs(1);

const MAX_LOOKUP_OUTPUT: usize = 4 * 1024 * 1024;
const ALL_FOUND: i32 = 0;
const SOME_MISSING: i32 = 2;
const PASSWD: &str = "passwd";
const GROUP: &str = "group";

enum Answer {
    AllFound(Vec<u8>),
    SomeMissing(Vec<u8>),
}

pub(crate) struct SystemUsers {
    getent: PathBuf,
    timeout: Duration,
    budget: Duration,
    spent: Cell<Duration>,
}

impl SystemUsers {
    pub(crate) fn new(getent: PathBuf) -> Self {
        Self::with_limits(getent, LOOKUP_TIMEOUT, LOOKUP_BUDGET)
    }

    fn with_limits(getent: PathBuf, timeout: Duration, budget: Duration) -> Self {
        Self {
            getent,
            timeout,
            budget,
            spent: Cell::new(Duration::ZERO),
        }
    }

    fn query(&self, database: &'static str, keys: &[&Name]) -> Result<Answer, LookupError> {
        let timed_out = LookupError::Exit {
            database,
            exit_code: None,
        };
        let remaining = self.budget.saturating_sub(self.spent.get());
        if remaining.is_zero() {
            return Err(timed_out);
        }
        let mut args = vec![database.to_owned(), "--".to_owned()];
        args.extend(keys.iter().map(|key| key.as_str().to_owned()));
        let started = Instant::now();
        let finished = run(
            &self.getent,
            &args,
            self.timeout.min(remaining),
            Stdout::Capture {
                limit: MAX_LOOKUP_OUTPUT,
            },
        );
        self.spent
            .set(self.spent.get().saturating_add(started.elapsed()));
        let finished = finished.map_err(|source| LookupError::Run { database, source })?;
        if finished.timed_out {
            return Err(timed_out);
        }
        if finished.stdout.truncated {
            return Err(LookupError::Malformed { database });
        }
        match finished.code {
            Some(ALL_FOUND) => Ok(Answer::AllFound(finished.stdout.bytes)),
            Some(SOME_MISSING) => Ok(Answer::SomeMissing(finished.stdout.bytes)),
            exit_code => Err(LookupError::Exit {
                database,
                exit_code,
            }),
        }
    }

    fn single<T>(
        &self,
        database: &'static str,
        key: &Name,
        parse: fn(&str) -> Option<(Name, T)>,
    ) -> Result<Option<T>, LookupError> {
        let malformed = LookupError::Malformed { database };
        match self.query(database, &[key])? {
            Answer::SomeMissing(output) if output.is_empty() => Ok(None),
            Answer::SomeMissing(_) => Err(malformed),
            Answer::AllFound(output) => match lines(&output, database)?.as_slice() {
                [line] => match parse(line) {
                    Some((name, entry)) if name == *key => Ok(Some(entry)),
                    _ => Err(malformed),
                },
                _ => Err(malformed),
            },
        }
    }
}

fn lines<'a>(output: &'a [u8], database: &'static str) -> Result<Vec<&'a str>, LookupError> {
    let malformed = || LookupError::Malformed { database };
    let text = std::str::from_utf8(output).map_err(|_| malformed())?;
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let body = text.strip_suffix('\n').ok_or_else(malformed)?;
    Ok(body.split('\n').collect())
}

fn parse_id(field: &str) -> Option<u32> {
    if field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    field.parse().ok()
}

fn parse_passwd(line: &str) -> Option<(Name, PasswdEntry)> {
    let fields: Vec<&str> = line.split(':').collect();
    let [name, _, uid, gid, _, home, shell] = fields.as_slice() else {
        return None;
    };
    let name = Name::parse(name).ok()?;
    let entry = PasswdEntry {
        name: name.clone(),
        uid: parse_id(uid)?,
        gid: parse_id(gid)?,
        home: (*home).to_owned(),
        shell: (*shell).to_owned(),
    };
    Some((name, entry))
}

fn parse_group(line: &str) -> Option<(Name, GroupEntry)> {
    let fields: Vec<&str> = line.split(':').collect();
    let [name, _, gid, _] = fields.as_slice() else {
        return None;
    };
    let name = Name::parse(name).ok()?;
    let entry = GroupEntry {
        name: name.clone(),
        gid: parse_id(gid)?,
    };
    Some((name, entry))
}

impl Users for SystemUsers {
    fn passwd(&self, login: &Name) -> Result<Option<PasswdEntry>, LookupError> {
        self.single(PASSWD, login, parse_passwd)
    }

    fn passwd_many(&self, logins: &[Name]) -> Result<Vec<Option<PasswdEntry>>, LookupError> {
        if logins.is_empty() {
            return Ok(Vec::new());
        }
        let malformed = || LookupError::Malformed { database: PASSWD };
        let keys: Vec<&Name> = logins.iter().collect();
        let (output, all_found) = match self.query(PASSWD, &keys)? {
            Answer::AllFound(output) => (output, true),
            Answer::SomeMissing(output) => (output, false),
        };
        let entries = lines(&output, PASSWD)?
            .into_iter()
            .map(|line| parse_passwd(line).map(|(_, entry)| entry))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(malformed)?;
        let mut remaining = entries.into_iter().peekable();
        let aligned: Vec<Option<PasswdEntry>> = logins
            .iter()
            .map(|login| remaining.next_if(|entry| entry.name == *login))
            .collect();
        let found_all = aligned.iter().all(Option::is_some);
        if remaining.next().is_some() || found_all != all_found {
            return Err(malformed());
        }
        Ok(aligned)
    }

    fn group(&self, name: &Name) -> Result<Option<GroupEntry>, LookupError> {
        self.single(GROUP, name, parse_group)
    }
}

#[cfg(test)]
mod tests;
