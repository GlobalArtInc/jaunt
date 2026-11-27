use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use serde::Serialize;

use crate::cli::complain;
use crate::state::{AccountRecord, AccountState, State};
use crate::store::{LOCK_WAIT, STATE_DIR, StateDir, StoreError};
use crate::sys::{GETENT, ROOT_UID, SystemClock, SystemUsers, ToolError, locate};
use crate::system::{LookupError, PasswdEntry, lookup_many};

const LAST_RENDERED_SECOND: u64 = 253_402_300_799;
const SECONDS_PER_DAY: u64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Presence {
    Present,
    Missing,
    OtherUid,
    Unbound,
    Unknown,
}

impl Presence {
    fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Missing => "missing",
            Self::OtherUid => "other_uid",
            Self::Unbound => "unbound",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct Row<'a> {
    login: &'a str,
    state: AccountState,
    #[serde(skip_serializing_if = "Option::is_none")]
    uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gid: Option<u32>,
    home: &'a str,
    created_at: u64,
    #[serde(rename = "ref")]
    reference: &'a str,
    session: &'a str,
    account: Presence,
}

#[derive(Serialize)]
struct Listing<'a> {
    accounts: &'a [Row<'a>],
}

#[derive(Debug, thiserror::Error)]
enum ListError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Tool(#[from] ToolError),
    #[error(transparent)]
    Lookup(#[from] LookupError),
    #[error("the listing could not be encoded")]
    Encode,
}

fn presence(record: &AccountRecord, entry: Option<Option<&PasswdEntry>>) -> Presence {
    match (entry, record.uid()) {
        (None, _) => Presence::Unknown,
        (Some(None), _) => Presence::Missing,
        (Some(Some(_)), None) => Presence::Unbound,
        (Some(Some(entry)), Some(uid)) if entry.uid == uid => Presence::Present,
        (Some(Some(_)), Some(_)) => Presence::OtherUid,
    }
}

pub(crate) fn rows<'a>(
    state: &'a State,
    entries: Option<&'a [Option<PasswdEntry>]>,
) -> Vec<Row<'a>> {
    state
        .accounts()
        .iter()
        .enumerate()
        .map(|(index, record)| Row {
            login: record.login().as_str(),
            state: record.state(),
            uid: record.uid(),
            gid: record.gid(),
            home: record.home(),
            created_at: record.created_at(),
            reference: record.reference().as_str(),
            session: record.session().as_str(),
            account: presence(
                record,
                entries.map(|entries| entries.get(index).and_then(Option::as_ref)),
            ),
        })
        .collect()
}

fn state_name(state: AccountState) -> &'static str {
    match state {
        AccountState::Pending => "pending",
        AccountState::Active => "active",
        AccountState::Unconfirmed => "unconfirmed",
    }
}

pub(crate) fn utc(seconds: u64) -> String {
    if seconds > LAST_RENDERED_SECOND {
        return seconds.to_string();
    }
    let days = i64::try_from(seconds / SECONDS_PER_DAY).unwrap_or_default();
    let rest = seconds % SECONDS_PER_DAY;
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

pub(crate) fn render_table(rows: &[Row<'_>]) -> String {
    let header = [
        "LOGIN",
        "STATE",
        "UID",
        "ACCOUNT",
        "CREATED (UTC)",
        "REF",
        "SESSION",
        "HOME",
    ];
    let cells: Vec<[String; 8]> = rows
        .iter()
        .map(|row| {
            [
                row.login.to_owned(),
                state_name(row.state).to_owned(),
                row.uid
                    .map_or_else(|| "-".to_owned(), |uid| uid.to_string()),
                row.account.as_str().to_owned(),
                utc(row.created_at),
                row.reference.to_owned(),
                row.session.to_owned(),
                row.home.to_owned(),
            ]
        })
        .collect();
    let mut widths = header.map(str::len);
    for line in &cells {
        for (width, cell) in widths.iter_mut().zip(line) {
            *width = (*width).max(cell.len());
        }
    }
    let format_line = |line: &[&str]| {
        let mut text = String::new();
        for (index, (cell, width)) in line.iter().zip(widths).enumerate() {
            if index + 1 == line.len() {
                text.push_str(cell);
            } else {
                text.push_str(&format!("{cell:<width$}  "));
            }
        }
        text.trim_end().to_owned()
    };
    let mut output = format_line(&header);
    output.push('\n');
    for line in &cells {
        let line: Vec<&str> = line.iter().map(String::as_str).collect();
        output.push_str(&format_line(&line));
        output.push('\n');
    }
    output
}

pub(crate) fn render_json(rows: &[Row<'_>]) -> Option<String> {
    let mut text = serde_json::to_string_pretty(&Listing { accounts: rows }).ok()?;
    text.push('\n');
    Some(text)
}

fn load_state() -> Result<State, StoreError> {
    let path = Path::new(STATE_DIR);
    let absent = matches!(
        fs::symlink_metadata(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound
    );
    if absent {
        return Ok(State::default());
    }
    let directory = StateDir::open(path, ROOT_UID)?;
    directory.lock(&SystemClock, LOCK_WAIT)?.load()
}

fn lookup(state: &State) -> Result<Vec<Option<PasswdEntry>>, ListError> {
    let users = SystemUsers::new(locate(&GETENT, ROOT_UID)?);
    let logins: Vec<_> = state
        .accounts()
        .iter()
        .map(|record| record.login().clone())
        .collect();
    Ok(lookup_many(&users, &logins)?)
}

fn listing(json: bool) -> Result<(String, Option<ListError>), ListError> {
    let state = load_state()?;
    let (entries, problem) = match lookup(&state) {
        Ok(entries) => (Some(entries), None),
        Err(error) => (None, Some(error)),
    };
    let rows = rows(&state, entries.as_deref());
    let text = if json {
        render_json(&rows).ok_or(ListError::Encode)?
    } else {
        render_table(&rows)
    };
    Ok((text, problem))
}

pub(crate) fn run(json: bool) -> ExitCode {
    let (text, problem) = match listing(json) {
        Ok(result) => result,
        Err(error) => return complain(&error, ExitCode::FAILURE),
    };
    if let Err(error) = io::stdout().lock().write_all(text.as_bytes()) {
        return complain(&error, ExitCode::FAILURE);
    }
    match problem {
        None => ExitCode::SUCCESS,
        Some(error) => complain(
            &format!("the accounts could not be looked up: {error}"),
            ExitCode::FAILURE,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{Presence, render_json, render_table, rows, utc};
    use crate::system::PasswdEntry;
    use crate::testing::{name, record, state_of};

    #[test]
    fn created_times_render_as_utc_calendar_dates() {
        for (seconds, text) in [
            (0, "1970-01-01 00:00:00"),
            (951_782_400, "2000-02-29 00:00:00"),
            (1_764_000_000, "2025-11-24 16:00:00"),
            (253_402_300_799, "9999-12-31 23:59:59"),
            (253_402_300_800, "253402300800"),
        ] {
            assert_eq!(utc(seconds), text, "{seconds}");
        }
    }

    #[test]
    fn each_record_shows_whether_the_account_still_carries_its_uid() {
        let state = state_of(
            vec![
                record("alice", Some(30_000), "active"),
                record("bob", Some(30_001), "unconfirmed"),
                record("carol", None, "unconfirmed"),
                record("dave", Some(30_003), "active"),
            ],
            &[],
        );
        let entry = |login: &str, uid| PasswdEntry {
            name: name(login),
            uid,
            gid: uid,
            home: format!("/home/{login}"),
            shell: "/bin/bash".to_owned(),
        };
        let entries = vec![
            Some(entry("alice", 30_000)),
            Some(entry("bob", 40_000)),
            Some(entry("carol", 30_002)),
            None,
        ];
        let listed = rows(&state, Some(&entries));
        let presence: Vec<Presence> = listed.iter().map(|row| row.account).collect();
        assert_eq!(
            presence,
            [
                Presence::Present,
                Presence::OtherUid,
                Presence::Unbound,
                Presence::Missing
            ]
        );
        assert!(
            rows(&state, None)
                .iter()
                .all(|row| row.account == Presence::Unknown)
        );

        let table = render_table(&listed);
        let mut lines = table.lines();
        assert_eq!(
            lines.next().unwrap(),
            "LOGIN  STATE        UID    ACCOUNT    CREATED (UTC)        REF         SESSION  HOME"
        );
        assert_eq!(
            lines.next().unwrap(),
            "alice  active       30000  present    2025-11-24 16:00:00  H-0000000A  s-1      /home/alice"
        );
        assert!(
            table.contains("carol  unconfirmed  -      unbound"),
            "{table}"
        );

        let json: serde_json::Value = serde_json::from_str(&render_json(&listed).unwrap()).unwrap();
        assert_eq!(
            json["accounts"][0],
            serde_json::json!({
                "login": "alice", "state": "active", "uid": 30000, "gid": 30000,
                "home": "/home/alice", "created_at": 1_764_000_000_u64, "ref": "H-0000000A",
                "session": "s-1", "account": "present"
            })
        );
        assert!(json["accounts"][2].get("uid").is_none());
    }
}
