use std::fmt;
use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use crate::clock::Clock;
use crate::journal::{Entry, Severity};
use crate::line::{MAX_REQUEST_BYTES, REQUEST_BUDGET, read_line};
use crate::names::Name;
use crate::protocol::{EnsureRequest, FailedStage, Response, encode_response, parse_request};
use crate::rules::check_login;
use crate::serve::{Notes, System, Ticket, handle};
use crate::store::{LOCK_WAIT, STATE_DIR, StateDir, StoreError};
use crate::sys::{
    ByteReader, GETENT, ROOT_UID, SystemClock, SystemFiles, SystemNode, SystemRunner, SystemUsers,
    ToolError, limit_waits, locate, peer_uid, send, unix_seconds,
};
use crate::system::{LookupError, Users};

const REPLY_BUDGET: Duration = Duration::from_secs(3);

#[derive(Debug, thiserror::Error)]
enum Admission {
    #[error("the peer of standard input is unknown: {0}")]
    Peer(#[source] io::Error),
    #[error(transparent)]
    Tool(ToolError),
    #[error(transparent)]
    Lookup(LookupError),
    #[error("the agent user {0} does not exist")]
    AgentMissing(Name),
    #[error("the peer runs as uid {peer} and the agent user as uid {agent}")]
    WrongPeer { peer: u32, agent: u32 },
    #[error("the socket timeouts could not be set: {0}")]
    Socket(#[source] io::Error),
}

pub(crate) fn serve(config: &Path, agent_user: &Name) -> ExitCode {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let (input, output) = (stdin.as_fd(), stdout.as_fd());
    let users = match admit(input, output, agent_user) {
        Ok(users) => users,
        Err(refusal) => {
            let mut entry = Entry::new(Severity::Warning);
            entry.field("connection", "rejected");
            if let Admission::WrongPeer { peer, .. } = &refusal {
                entry.field("peer_uid", peer);
            }
            entry.text("detail", refusal.to_string().as_bytes());
            return finish(&entry, false);
        }
    };
    let clock = SystemClock;
    let mut entry = Entry::new(Severity::Info);
    let response = respond(input, config, &users, &clock, &mut entry);
    let replied = match encode_response(&response) {
        Ok(line) => send(output, &line, &clock, REPLY_BUDGET).map_err(|error| error.to_string()),
        Err(error) => Err(error.to_string()),
    };
    if let Err(problem) = &replied {
        entry.raise(Severity::Warning);
        entry.text("reply", problem.as_bytes());
    }
    finish(&entry, replied.is_ok())
}

fn finish(entry: &Entry, replied: bool) -> ExitCode {
    let logged = writeln!(io::stderr().lock(), "{entry}").is_ok();
    if replied && logged {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn admit(
    input: BorrowedFd<'_>,
    output: BorrowedFd<'_>,
    agent_user: &Name,
) -> Result<SystemUsers, Admission> {
    let peer = peer_uid(input).map_err(Admission::Peer)?;
    let users = SystemUsers::new(locate(&GETENT, ROOT_UID).map_err(Admission::Tool)?);
    let agent = users
        .passwd(agent_user)
        .map_err(Admission::Lookup)?
        .ok_or_else(|| Admission::AgentMissing(agent_user.clone()))?
        .uid;
    if !peer_allowed(peer, agent) {
        return Err(Admission::WrongPeer { peer, agent });
    }
    limit_waits(input, output).map_err(Admission::Socket)?;
    Ok(users)
}

fn peer_allowed(peer: u32, agent: u32) -> bool {
    peer == agent
}

fn respond(
    input: BorrowedFd<'_>,
    config: &Path,
    users: &SystemUsers,
    clock: &SystemClock,
    entry: &mut Entry,
) -> Response {
    let request = read_line(
        &mut ByteReader::new(input),
        clock,
        REQUEST_BUDGET,
        MAX_REQUEST_BYTES,
    )
    .map_err(|error| error.to_string())
    .and_then(|line| parse_request(&line).map_err(|error| error.to_string()));
    let request = match request {
        Ok(request) => request,
        Err(problem) => {
            let response = Response::Failed {
                stage: FailedStage::Request,
                exit_code: None,
            };
            let notes = Notes {
                severity: Severity::Warning,
                details: vec![problem],
                ..Notes::default()
            };
            record_outcome(entry, &response, &notes);
            return response;
        }
    };
    entry.field("ref", &request.reference);
    entry.field("session", &request.session);
    entry.login(&request.login);
    let (response, notes) = match check_login(&request.login) {
        Ok(login) => locked(&login, &request, config, users, clock),
        Err(reason) => (Response::Refused { reason }, Notes::default()),
    };
    record_outcome(entry, &response, &notes);
    response
}

fn locked(
    login: &Name,
    request: &EnsureRequest,
    config: &Path,
    users: &SystemUsers,
    clock: &dyn Clock,
) -> (Response, Notes) {
    let mut notes = Notes::default();
    let directory = match StateDir::open(Path::new(STATE_DIR), ROOT_UID) {
        Ok(directory) => directory,
        Err(error) => {
            let response = notes.failed(FailedStage::State, Severity::Warning, &error);
            return (response, notes);
        }
    };
    let lock = match directory.lock(clock, LOCK_WAIT) {
        Ok(lock) => lock,
        Err(error) => {
            let stage = match error {
                StoreError::Busy => FailedStage::Busy,
                _ => FailedStage::State,
            };
            let response = notes.failed(stage, Severity::Warning, &error);
            return (response, notes);
        }
    };
    let files = SystemFiles;
    let mut runner = SystemRunner;
    let node = SystemNode::new(config);
    let mut system = System {
        users,
        files: &files,
        runner: &mut runner,
        node: &node,
        now: unix_seconds(SystemTime::now()),
    };
    let ticket = Ticket {
        login,
        reference: &request.reference,
        session: &request.session,
    };
    let response = handle(&ticket, &lock, &mut system, &mut notes);
    (response, notes)
}

struct Logins<'a>(&'a [Name]);

impl fmt::Display for Logins<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, login) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(",")?;
            }
            write!(f, "{login}")?;
        }
        Ok(())
    }
}

fn record_outcome(entry: &mut Entry, response: &Response, notes: &Notes) {
    entry.raise(notes.severity);
    match response {
        Response::Exists => entry.field("outcome", "exists"),
        Response::Created { .. } => entry.field("outcome", "created"),
        Response::Disabled => entry.field("outcome", "disabled"),
        Response::Refused { reason } => {
            entry.field("outcome", "refused");
            entry.field("reason", reason.as_str());
        }
        Response::Failed { stage, .. } => {
            entry.field("outcome", "failed");
            entry.field("stage", stage.as_str());
        }
    }
    if let Some(uid) = notes.uid {
        entry.field("uid", uid);
    }
    if let Some(useradd) = &notes.useradd {
        match useradd.code {
            Some(code) => entry.field("exit", code),
            None => entry.field("exit", "signal"),
        }
        if useradd.timed_out {
            entry.field("timed_out", "yes");
        }
        if !useradd.stderr.is_empty() {
            entry.text("stderr", &useradd.stderr);
        }
    }
    if let Some(removal) = notes.removal {
        entry.field("rollback", if removal.removed { "removed" } else { "kept" });
        match removal.exit_code {
            Some(code) => entry.field("userdel_exit", code),
            None => entry.field("userdel_exit", "none"),
        }
    }
    let settled = &notes.settled;
    for (key, logins) in [
        ("dropped", &settled.dropped),
        ("unconfirmed", &settled.unconfirmed),
        ("not_adopted", &settled.not_adopted),
        ("forgotten", &settled.forgotten),
        ("repaired", &notes.repaired),
    ] {
        if !logins.is_empty() {
            entry.field(key, Logins(logins));
        }
    }
    if !notes.details.is_empty() {
        entry.text("detail", notes.details.join("; ").as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::{peer_allowed, record_outcome};
    use crate::journal::{Entry, Severity};
    use crate::protocol::{FailedStage, Response};
    use crate::rules::Reason;
    use crate::serve::{Notes, Removal};
    use crate::system::ToolExit;
    use crate::testing::name;

    #[test]
    fn only_the_agent_uid_is_admitted_and_root_only_when_the_agent_is_root() {
        for (peer, agent, allowed) in [
            (1001, 1000, false),
            (0, 1000, false),
            (1000, 0, false),
            (1000, 1000, true),
            (0, 0, true),
        ] {
            assert_eq!(
                peer_allowed(peer, agent),
                allowed,
                "peer {peer} agent {agent}"
            );
        }
    }

    #[test]
    fn the_outcome_line_carries_the_stage_uid_tool_exit_and_clean_stderr() {
        let mut notes = Notes {
            severity: Severity::Error,
            uid: Some(30_001),
            useradd: Some(ToolExit {
                code: Some(12),
                timed_out: false,
                stderr: b"useradd: cannot create directory\n\x1b[1m".to_vec(),
            }),
            removal: Some(Removal {
                removed: false,
                exit_code: Some(6),
            }),
            ..Notes::default()
        };
        notes.settled.unconfirmed.push(name("bob"));
        notes
            .details
            .push("userdel left the account in place".to_owned());
        let mut entry = Entry::new(Severity::Info);
        entry.field("ref", "H-0000000A");
        record_outcome(
            &mut entry,
            &Response::Failed {
                stage: FailedStage::Partial,
                exit_code: Some(12),
            },
            &notes,
        );
        assert_eq!(
            entry.to_string(),
            concat!(
                "<3>ERROR ref=H-0000000A outcome=failed stage=partial uid=30001 exit=12 ",
                "stderr=\"useradd: cannot create directory  [1m\" rollback=kept userdel_exit=6 ",
                "unconfirmed=bob detail=\"userdel left the account in place\"",
            )
        );

        let mut entry = Entry::new(Severity::Info);
        record_outcome(
            &mut entry,
            &Response::Refused {
                reason: Reason::UidRange,
            },
            &Notes::default(),
        );
        assert_eq!(
            entry.to_string(),
            "<6>INFO outcome=refused reason=uid_range"
        );
    }
}
