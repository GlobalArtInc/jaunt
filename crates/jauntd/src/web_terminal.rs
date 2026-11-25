use std::sync::Arc;
use std::time::Duration;

use jaunt_control::{
    DEFAULT_MAX_TERMINAL_TICKETS, DEFAULT_MAX_TERMINALS, DEFAULT_MAX_TERMINALS_PER_USER,
    DEFAULT_TERMINAL_IDLE_TIMEOUT, GateEvent, GateLink, GateRefusal, GateRequest, TerminalGate,
    WebTerminalSettings,
};
use jaunt_gate::{InProcessClient, InProcessRefusal, SshGate};
use jaunt_ssh::OuterEvent;
use serde::Deserialize;

pub const MAX_TERMINALS_PER_USER_LIMIT: usize = 64;
pub const MAX_TERMINALS_LIMIT: usize = 4096;
pub const MIN_TERMINAL_IDLE_SECS: u64 = 60;
pub const MAX_TERMINAL_IDLE_SECS: u64 = 86_400;
pub const MIN_TERMINAL_TICKETS: usize = 16;
pub const MAX_TERMINAL_TICKETS: usize = 65_536;

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct WebTerminalSection {
    pub enabled: Option<bool>,
    pub max_per_user: Option<usize>,
    pub max_total: Option<usize>,
    pub idle_timeout_secs: Option<u64>,
    pub max_tickets: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WebTerminalConfigError {
    #[error("web_terminal.enabled needs web: true and an ssh_gate section")]
    Unsupported,
    #[error("web_terminal.max_per_user must be between 1 and {MAX_TERMINALS_PER_USER_LIMIT}")]
    PerUser,
    #[error(
        "web_terminal.max_total must be between 1 and {MAX_TERMINALS_LIMIT} and at least max_per_user"
    )]
    Total,
    #[error(
        "web_terminal.idle_timeout_secs must be between {MIN_TERMINAL_IDLE_SECS} and {MAX_TERMINAL_IDLE_SECS}"
    )]
    IdleTimeout,
    #[error(
        "web_terminal.max_tickets must be between {MIN_TERMINAL_TICKETS} and {MAX_TERMINAL_TICKETS}"
    )]
    Tickets,
}

impl WebTerminalSection {
    pub fn into_settings(
        self,
        web: bool,
        gate: bool,
    ) -> Result<Option<WebTerminalSettings>, WebTerminalConfigError> {
        let max_per_user = self.max_per_user.unwrap_or(DEFAULT_MAX_TERMINALS_PER_USER);
        if !(1..=MAX_TERMINALS_PER_USER_LIMIT).contains(&max_per_user) {
            return Err(WebTerminalConfigError::PerUser);
        }
        let max_total = self.max_total.unwrap_or(DEFAULT_MAX_TERMINALS);
        if !(max_per_user..=MAX_TERMINALS_LIMIT).contains(&max_total) {
            return Err(WebTerminalConfigError::Total);
        }
        let idle_secs = self
            .idle_timeout_secs
            .unwrap_or(DEFAULT_TERMINAL_IDLE_TIMEOUT.as_secs());
        if !(MIN_TERMINAL_IDLE_SECS..=MAX_TERMINAL_IDLE_SECS).contains(&idle_secs) {
            return Err(WebTerminalConfigError::IdleTimeout);
        }
        let max_tickets = self.max_tickets.unwrap_or(DEFAULT_MAX_TERMINAL_TICKETS);
        if !(MIN_TERMINAL_TICKETS..=MAX_TERMINAL_TICKETS).contains(&max_tickets) {
            return Err(WebTerminalConfigError::Tickets);
        }
        let supported = web && gate;
        match (self.enabled, supported) {
            (Some(false), _) | (None, false) => Ok(None),
            (Some(true), false) => Err(WebTerminalConfigError::Unsupported),
            (Some(true) | None, true) => Ok(Some(WebTerminalSettings {
                max_per_user,
                max_total,
                idle_timeout: Duration::from_secs(idle_secs),
                max_tickets,
            })),
        }
    }
}

pub struct GateTerminals {
    gate: Arc<SshGate>,
}

impl GateTerminals {
    pub fn new(gate: Arc<SshGate>) -> Self {
        Self { gate }
    }
}

impl TerminalGate for GateTerminals {
    fn host_name(&self) -> String {
        self.gate.host_names().first().cloned().unwrap_or_default()
    }

    fn connect(&self, request: GateRequest) -> Result<GateLink, GateRefusal> {
        let events = request.events;
        let connection = self
            .gate
            .connect_in_process(InProcessClient {
                client_addr: request.client_addr,
                shutdown: request.shutdown,
                events: Arc::new(move |event: &OuterEvent| match event {
                    OuterEvent::ForwardOpened { session_id, .. } => events(GateEvent::Routed {
                        session_id: session_id.clone(),
                    }),
                    OuterEvent::ForwardRefused { refusal, .. } => {
                        events(GateEvent::Refused(*refusal));
                    }
                    _ => {}
                }),
            })
            .map_err(|refusal| match refusal {
                InProcessRefusal::Busy => GateRefusal::Busy,
                InProcessRefusal::Limited => GateRefusal::Limited,
            })?;
        let serve = connection.serve;
        Ok(GateLink {
            stream: Box::new(connection.stream),
            serve: Box::pin(async move {
                let reason = serve.await;
                tracing::debug!(target: "jaunt::gate", reason = reason.reason(), "an in-process ssh connection ended");
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use jaunt_control::WebTerminalSettings;

    use super::{WebTerminalConfigError, WebTerminalSection};

    fn settings(
        text: &str,
        web: bool,
        gate: bool,
    ) -> Result<Option<WebTerminalSettings>, WebTerminalConfigError> {
        serde_saphyr::from_str::<WebTerminalSection>(text)
            .unwrap()
            .into_settings(web, gate)
    }

    #[test]
    fn the_terminal_is_on_by_default_only_with_the_web_console_and_the_gate() {
        assert_eq!(
            settings("{}\n", true, true).unwrap(),
            Some(WebTerminalSettings {
                max_per_user: 4,
                max_total: 64,
                idle_timeout: Duration::from_secs(1800),
                max_tickets: 1024,
            })
        );
        assert_eq!(settings("{}\n", false, true).unwrap(), None);
        assert_eq!(settings("{}\n", true, false).unwrap(), None);
        assert_eq!(settings("enabled: false\n", true, true).unwrap(), None);
        assert_eq!(
            settings("enabled: true\n", true, false),
            Err(WebTerminalConfigError::Unsupported)
        );
        assert_eq!(
            settings("enabled: true\n", false, true),
            Err(WebTerminalConfigError::Unsupported)
        );
    }

    #[test]
    fn every_limit_can_be_tuned_within_its_range() {
        let tuned = settings(
            "max_per_user: 2\nmax_total: 10\nidle_timeout_secs: 60\nmax_tickets: 16\n",
            true,
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            tuned,
            WebTerminalSettings {
                max_per_user: 2,
                max_total: 10,
                idle_timeout: Duration::from_secs(60),
                max_tickets: 16,
            }
        );
        for (text, expected) in [
            ("max_per_user: 0\n", WebTerminalConfigError::PerUser),
            ("max_per_user: 65\n", WebTerminalConfigError::PerUser),
            ("max_total: 0\n", WebTerminalConfigError::Total),
            ("max_total: 3\n", WebTerminalConfigError::Total),
            ("max_total: 4097\n", WebTerminalConfigError::Total),
            (
                "idle_timeout_secs: 59\n",
                WebTerminalConfigError::IdleTimeout,
            ),
            (
                "idle_timeout_secs: 86401\n",
                WebTerminalConfigError::IdleTimeout,
            ),
            ("max_tickets: 15\n", WebTerminalConfigError::Tickets),
            ("max_tickets: 65537\n", WebTerminalConfigError::Tickets),
        ] {
            assert_eq!(settings(text, true, true), Err(expected), "{text:?}");
            assert!(expected.to_string().starts_with("web_terminal."));
        }
    }

    #[test]
    fn unknown_fields_are_refused_while_parsing() {
        for text in ["extra: 1\n", "max_users: 1\n", "idle_timeout: 60\n"] {
            assert!(
                serde_saphyr::from_str::<WebTerminalSection>(text).is_err(),
                "{text:?}"
            );
        }
    }
}
