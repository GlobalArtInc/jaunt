use std::io::{self, Write};

use crate::agent::{AgentError, SshAgent};
use crate::client::{ApiClient, ApiError};
use crate::display::{format_local, format_span, printable};
use crate::server_url::ServerUrl;
use crate::store::{ProfileMeta, ProfileStore, StoreError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentView {
    NotConfigured,
    Loaded,
    NotLoaded,
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub server: ServerUrl,
    pub meta: ProfileMeta,
}

impl Session {
    pub fn load(store: &ProfileStore) -> Result<Option<Session>, StoreError> {
        let server = store.read_server()?;
        let meta = store.read_meta()?;
        match (server, meta) {
            (Some(server), Some(meta)) => Ok(Some(Session { server, meta })),
            (None, None) => Ok(None),
            _ => Err(StoreError::Corrupt {
                path: store.dir().to_owned(),
            }),
        }
    }

    pub fn is_valid_at(&self, now_secs: i64) -> bool {
        now_secs < self.meta.valid_before
    }
}

pub fn agent_view(store: &ProfileStore, agent: &SshAgent) -> AgentView {
    if !agent.is_configured() {
        return AgentView::NotConfigured;
    }
    let line = match store.read_public_key_line() {
        Ok(Some(line)) => line,
        Ok(None) => return AgentView::Unknown("the public key file is missing".to_owned()),
        Err(err) => return AgentView::Unknown(err.to_string()),
    };
    match agent.holds(&line) {
        Ok(true) => AgentView::Loaded,
        Ok(false) => AgentView::NotLoaded,
        Err(AgentError::NotRunning) => AgentView::NotConfigured,
        Err(err) => AgentView::Unknown(err.to_string()),
    }
}

pub fn render(
    out: &mut dyn Write,
    session: &Session,
    now_secs: i64,
    agent: &AgentView,
) -> io::Result<()> {
    let meta = &session.meta;
    writeln!(
        out,
        "Signed in as {} (user {})",
        printable(&meta.email),
        printable(&meta.user_id)
    )?;
    writeln!(out, "Server: {}", session.server)?;
    writeln!(out, "Certificate serial: {}", meta.serial)?;
    let remaining = meta.valid_before.saturating_sub(now_secs);
    let state = if session.is_valid_at(now_secs) {
        format!("{} left", format_span(remaining.unsigned_abs()))
    } else {
        format!(
            "expired {} ago, run `jaunt login` again",
            format_span(remaining.unsigned_abs())
        )
    };
    writeln!(
        out,
        "Valid until: {} ({state})",
        format_local(meta.valid_before)
    )?;
    match agent {
        AgentView::NotConfigured => Ok(()),
        AgentView::Loaded => writeln!(out, "Key in ssh-agent: yes"),
        AgentView::NotLoaded => writeln!(out, "Key in ssh-agent: no"),
        AgentView::Unknown(reason) => {
            writeln!(out, "Key in ssh-agent: unknown ({})", printable(reason))
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OnlineError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("the API token file is missing; run `jaunt login` again")]
    NoToken,
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error("cannot write to the terminal: {0}")]
    Terminal(io::Error),
}

impl OnlineError {
    pub fn is_rejection(&self) -> bool {
        matches!(self, OnlineError::Api(ApiError::Unauthorized))
    }
}

pub fn check_online(
    out: &mut dyn Write,
    store: &ProfileStore,
    server: &ServerUrl,
) -> Result<(), OnlineError> {
    let token = store.read_token()?.ok_or(OnlineError::NoToken)?;
    let who = ApiClient::new(server)?.whoami(&token)?;
    let groups = if who.groups.is_empty() {
        "none".to_owned()
    } else {
        who.groups
            .iter()
            .map(|group| printable(group))
            .collect::<Vec<_>>()
            .join(", ")
    };
    writeln!(
        out,
        "Server check: signed in as {}; groups: {groups}; certificate serial {}; token valid until {}",
        printable(&who.email),
        who.cert_serial,
        format_local(who.token_expires_at)
    )
    .map_err(OnlineError::Terminal)
}

#[cfg(test)]
mod tests {
    use super::{AgentView, Session, render};
    use crate::server_url::ServerUrl;
    use crate::store::ProfileMeta;

    fn session(valid_before: i64) -> Session {
        Session {
            server: ServerUrl::parse("https://jaunt.example.com").unwrap(),
            meta: ProfileMeta {
                user_id: "u-1".to_owned(),
                email: "a@example.com".to_owned(),
                serial: 7,
                key_id: "jaunt:a@example.com:7".to_owned(),
                valid_after: 0,
                valid_before,
                token_expires_at: valid_before,
                host_ca_keys: Vec::new(),
            },
        }
    }

    fn rendered(session: &Session, now: i64, agent: &AgentView) -> String {
        let mut out = Vec::new();
        render(&mut out, session, now, agent).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn a_session_is_valid_strictly_before_its_expiry() {
        let live = session(1_000);
        assert!(live.is_valid_at(999));
        assert!(!live.is_valid_at(1_000));
        assert!(!live.is_valid_at(1_001));
    }

    #[test]
    fn the_report_shows_time_left_or_expiry_and_the_agent_state() {
        let live = rendered(
            &session(10_000),
            10_000 - 2 * 3_600 - 5 * 60,
            &AgentView::Loaded,
        );
        assert!(live.contains("Signed in as a@example.com (user u-1)"));
        assert!(live.contains("Server: https://jaunt.example.com"));
        assert!(live.contains("Certificate serial: 7"));
        assert!(live.contains("(2h 5m left)"), "{live}");
        assert!(live.contains("Key in ssh-agent: yes"));

        let expired = rendered(&session(10_000), 10_000 + 90, &AgentView::NotLoaded);
        assert!(expired.contains("expired 1m ago"), "{expired}");
        assert!(expired.contains("Key in ssh-agent: no"));

        let silent = rendered(&session(10_000), 0, &AgentView::NotConfigured);
        assert!(!silent.contains("ssh-agent"));
        let unknown = rendered(
            &session(10_000),
            0,
            &AgentView::Unknown("boom\n".to_owned()),
        );
        assert!(unknown.contains("Key in ssh-agent: unknown (boom?)"));
    }
}
