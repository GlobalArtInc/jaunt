use std::io::{self, Write};

use crate::agent::{AgentError, SshAgent};
use crate::client::{ApiClient, ApiError};
use crate::display::{format_local, format_span, printable};
use crate::server_url::ServerUrl;
use crate::ssh_config::{EnsureCommand, ensure_match_line};
use crate::ssh_include::{IncludeTarget, include_present};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshView {
    NotSetUp,
    Ready {
        suffix: String,
        gate: String,
        shadowed_by: Option<String>,
        auto_sign_in: bool,
    },
    IncludeMissing {
        config: String,
    },
    Unknown(String),
}

pub fn ssh_view(
    store: &ProfileStore,
    include: Option<&IncludeTarget>,
    command: Option<&EnsureCommand<'_>>,
) -> SshView {
    let config = match store.read_client_config() {
        Ok(Some(config)) => config,
        Ok(None) => return SshView::NotSetUp,
        Err(err) => return SshView::Unknown(err.to_string()),
    };
    match store.ssh_files_present() {
        Ok(true) => {}
        Ok(false) => return SshView::Unknown("the generated files are missing".to_owned()),
        Err(err) => return SshView::Unknown(err.to_string()),
    }
    if let Some(target) = include {
        match include_present(target) {
            Ok(true) => {}
            Ok(false) => {
                return SshView::IncludeMissing {
                    config: target.config_path.display().to_string(),
                };
            }
            Err(err) => return SshView::Unknown(err.to_string()),
        }
    }
    let generated = match store.read_ssh_config() {
        Ok(text) => text.unwrap_or_default(),
        Err(err) => return SshView::Unknown(err.to_string()),
    };
    let auto_sign_in = command
        .and_then(|command| ensure_match_line(&config.ssh_suffix, command).ok())
        .is_some_and(|expected| generated.lines().any(|line| line == expected));
    let shadowed_by = store
        .shadowing_profiles(&config.ssh_suffix)
        .into_iter()
        .next();
    SshView::Ready {
        suffix: config.ssh_suffix,
        gate: format!("{}:{}", config.gate.host, config.gate.port),
        shadowed_by,
        auto_sign_in,
    }
}

pub fn render(
    out: &mut dyn Write,
    session: &Session,
    now_secs: i64,
    agent: &AgentView,
    ssh: &SshView,
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
        AgentView::NotConfigured => {}
        AgentView::Loaded => writeln!(out, "Key in ssh-agent: yes")?,
        AgentView::NotLoaded => writeln!(out, "Key in ssh-agent: no")?,
        AgentView::Unknown(reason) => {
            writeln!(out, "Key in ssh-agent: unknown ({})", printable(reason))?;
        }
    }
    match ssh {
        SshView::NotSetUp => writeln!(out, "SSH setup: not installed"),
        SshView::Ready {
            suffix,
            gate,
            shadowed_by,
            auto_sign_in,
        } => {
            writeln!(
                out,
                "SSH setup: ready (hosts *.{} through {})",
                printable(suffix),
                printable(gate)
            )?;
            if *auto_sign_in {
                writeln!(
                    out,
                    "Auto sign-in: on (ssh signs you in again when the certificate expires)"
                )?;
            } else {
                writeln!(
                    out,
                    "Auto sign-in: off (run `jaunt login` again to turn it on)"
                )?;
            }
            match shadowed_by {
                Some(other) => writeln!(
                    out,
                    "SSH setup: shadowed by profile {}: ssh reads that profile's settings for *.{} first",
                    printable(other),
                    printable(suffix)
                ),
                None => Ok(()),
            }
        }
        SshView::IncludeMissing { config } => writeln!(
            out,
            "SSH setup: files are in place but {} does not include them; run `jaunt login` again",
            printable(config)
        ),
        SshView::Unknown(reason) => {
            writeln!(out, "SSH setup: unknown ({})", printable(reason))
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
    use super::{AgentView, Session, SshView, render};
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
        rendered_with(session, now, agent, &SshView::NotSetUp)
    }

    fn rendered_with(session: &Session, now: i64, agent: &AgentView, ssh: &SshView) -> String {
        let mut out = Vec::new();
        render(&mut out, session, now, agent, ssh).unwrap();
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

    #[test]
    fn the_report_says_whether_the_ssh_setup_is_in_place() {
        let session = session(10_000);
        let cases = [
            (SshView::NotSetUp, "SSH setup: not installed"),
            (
                SshView::Ready {
                    suffix: "example.test".to_owned(),
                    gate: "gate.example.org:22".to_owned(),
                    shadowed_by: None,
                    auto_sign_in: true,
                },
                "SSH setup: ready (hosts *.example.test through gate.example.org:22)\nAuto sign-in: on",
            ),
            (
                SshView::Ready {
                    suffix: "example.test".to_owned(),
                    gate: "gate.example.org:22".to_owned(),
                    shadowed_by: Some("alpha".to_owned()),
                    auto_sign_in: false,
                },
                "Auto sign-in: off (run `jaunt login` again to turn it on)\nSSH setup: shadowed by profile alpha:",
            ),
            (
                SshView::IncludeMissing {
                    config: "/home/u/.ssh/config".to_owned(),
                },
                "SSH setup: files are in place but /home/u/.ssh/config does not include them",
            ),
            (
                SshView::Unknown("boom\n".to_owned()),
                "SSH setup: unknown (boom?)",
            ),
        ];
        for (view, line) in cases {
            let text = rendered_with(&session, 0, &AgentView::NotConfigured, &view);
            assert!(text.contains(line), "{text}");
        }
    }
}
