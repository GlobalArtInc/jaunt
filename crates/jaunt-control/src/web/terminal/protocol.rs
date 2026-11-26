use axum::http::{HeaderMap, header};
use jaunt_ssh::{TerminalDimensions, TerminalExit};
use serde::{Deserialize, Serialize};

use super::live::End;
use super::{TERMINAL_SUBPROTOCOL, TERMINAL_TICKET_PREFIX};

pub(crate) const MAX_COLS: u32 = 500;
pub(crate) const MAX_ROWS: u32 = 200;
const MAX_OFFERED_PROTOCOLS: usize = 2;

pub(crate) const NORMAL: u16 = 1000;
pub(crate) const GOING_AWAY: u16 = 1001;
pub(crate) const POLICY: u16 = 1008;
pub(crate) const TOO_BIG: u16 = 1009;
pub(crate) const INTERNAL: u16 = 1011;
pub(crate) const REVOKED: u16 = 4001;
pub(crate) const IDLE: u16 = 4002;
pub(crate) const STALLED: u16 = 4003;

pub(crate) fn dimensions(cols: u32, rows: u32) -> Option<TerminalDimensions> {
    ((1..=MAX_COLS).contains(&cols) && (1..=MAX_ROWS).contains(&rows))
        .then_some(TerminalDimensions { cols, rows })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Offer {
    Ticketed(String),
    Unticketed,
}

pub(crate) fn offer(headers: &HeaderMap) -> Option<Offer> {
    let mut lines = headers.get_all(header::SEC_WEBSOCKET_PROTOCOL).iter();
    let (Some(line), None) = (lines.next(), lines.next()) else {
        return None;
    };
    let mut offered = Vec::new();
    for entry in line.to_str().ok()?.split(',') {
        offered.push(entry.trim());
        if offered.len() > MAX_OFFERED_PROTOCOLS {
            return None;
        }
    }
    let mut terminal = false;
    let mut ticket = None;
    for entry in offered {
        if entry == TERMINAL_SUBPROTOCOL && !terminal {
            terminal = true;
        } else if let Some(secret) = entry.strip_prefix(TERMINAL_TICKET_PREFIX)
            && ticket.is_none()
        {
            ticket = Some(secret.to_owned());
        } else {
            return None;
        }
    }
    terminal.then(|| ticket.map_or(Offer::Unticketed, Offer::Ticketed))
}

pub(crate) fn origin_is(headers: &HeaderMap, public_origin: &str) -> bool {
    let mut values = headers.get_all(header::ORIGIN).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.as_bytes() == public_origin.as_bytes(),
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    Resize(TerminalDimensions),
    Ping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Malformed;

#[derive(Deserialize)]
#[serde(tag = "t", deny_unknown_fields)]
enum Incoming {
    #[serde(rename = "resize")]
    Resize { cols: u32, rows: u32 },
    #[serde(rename = "ping")]
    Ping {},
}

pub(crate) fn parse_text(text: &str) -> Result<Command, Malformed> {
    match serde_json::from_str::<Incoming>(text).map_err(|_| Malformed)? {
        Incoming::Resize { cols, rows } => {
            dimensions(cols, rows).map(Command::Resize).ok_or(Malformed)
        }
        Incoming::Ping {} => Ok(Command::Ping),
    }
}

#[derive(Serialize)]
#[serde(tag = "t", rename_all = "lowercase")]
enum Outgoing<'a> {
    Ready {
        session_id: &'a str,
    },
    Exit {
        status: Option<u32>,
        signal: Option<&'a str>,
    },
    Error {
        code: &'static str,
    },
    Pong,
}

fn text(message: &Outgoing<'_>) -> String {
    serde_json::to_string(message)
        .unwrap_or_else(|_| String::from("{\"t\":\"error\",\"code\":\"unavailable\"}"))
}

pub(crate) fn ready(session_id: &str) -> String {
    text(&Outgoing::Ready { session_id })
}

pub(crate) fn exit(outcome: Option<&TerminalExit>) -> String {
    let (status, signal) = match outcome {
        Some(TerminalExit::Status(status)) => (Some(*status), None),
        Some(TerminalExit::Signal(signal)) => (None, Some(signal.as_str())),
        None => (None, None),
    };
    text(&Outgoing::Exit { status, signal })
}

pub(crate) fn error(code: &'static str) -> String {
    text(&Outgoing::Error { code })
}

pub(crate) fn pong() -> String {
    text(&Outgoing::Pong)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Closing {
    pub(crate) code: Option<u16>,
    pub(crate) error: Option<&'static str>,
    pub(crate) reason: &'static str,
    pub(crate) audit: &'static str,
}

pub(crate) const fn closing(end: End) -> Closing {
    let (code, error, reason, audit) = match end {
        End::Exited => (Some(NORMAL), None, "exited", "exit"),
        End::ClientClosed => (Some(NORMAL), None, "closed", "client_closed"),
        End::Revoked => (Some(REVOKED), Some("revoked"), "revoked", "revoked"),
        End::IdleTimeout => (Some(IDLE), Some("timeout"), "idle timeout", "idle_timeout"),
        End::MaxDuration => (
            Some(POLICY),
            Some("timeout"),
            "session time limit",
            "max_duration",
        ),
        End::WebSessionEnded => (
            Some(POLICY),
            Some("timeout"),
            "web session ended",
            "web_session_ended",
        ),
        End::Denied => (Some(POLICY), Some("denied"), "denied", "denied"),
        End::Limit => (Some(POLICY), Some("limit"), "limit", "limit"),
        End::Unavailable => (
            Some(INTERNAL),
            Some("unavailable"),
            "unavailable",
            "unavailable",
        ),
        End::Malformed => (Some(POLICY), None, "bad message", "malformed"),
        End::TooBig => (Some(TOO_BIG), None, "message too big", "too_big"),
        End::NodeViolation => (
            Some(INTERNAL),
            Some("unavailable"),
            "unavailable",
            "node_violation",
        ),
        End::DeadPeer => (None, None, "", "dead_peer"),
        End::Wedged => (Some(STALLED), Some("stalled"), "stalled", "wedged"),
        End::Shutdown => (
            Some(GOING_AWAY),
            Some("unavailable"),
            "going away",
            "shutdown",
        ),
    };
    Closing {
        code,
        error,
        reason,
        audit,
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header};
    use jaunt_ssh::{TerminalDimensions, TerminalExit};

    use super::{
        Command, Malformed, Offer, closing, dimensions, error, exit, offer, origin_is, parse_text,
        ready,
    };
    use crate::web::terminal::live::End;

    fn protocols(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(
                header::SEC_WEBSOCKET_PROTOCOL,
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    #[test]
    fn the_offer_is_one_header_line_with_the_terminal_protocol_and_at_most_one_ticket() {
        let ticket = "a".repeat(43);
        let with_ticket = format!("jaunt-terminal.v1, jaunt-ticket.{ticket}");
        let ticket_first = format!("jaunt-ticket.{ticket},jaunt-terminal.v1");
        let split = format!("jaunt-ticket.{ticket}");
        for (values, expected) in [
            (
                vec![with_ticket.as_str()],
                Some(Offer::Ticketed(ticket.clone())),
            ),
            (
                vec![ticket_first.as_str()],
                Some(Offer::Ticketed(ticket.clone())),
            ),
            (vec!["jaunt-terminal.v1", split.as_str()], None),
            (vec!["jaunt-terminal.v1", "jaunt-terminal.v1"], None),
            (vec!["jaunt-terminal.v1"], Some(Offer::Unticketed)),
            (vec![], None),
            (vec![split.as_str()], None),
            (vec!["jaunt-terminal.v2"], None),
            (vec!["jaunt-terminal.v1, chat"], None),
            (vec!["jaunt-terminal.v1, jaunt-terminal.v1"], None),
            (
                vec!["jaunt-terminal.v1, jaunt-ticket.a, jaunt-ticket.b"],
                None,
            ),
            (vec!["JAUNT-TERMINAL.V1"], None),
        ] {
            assert_eq!(offer(&protocols(&values)), expected, "{values:?}");
        }
    }

    #[test]
    fn only_the_exact_public_origin_is_accepted() {
        let with = |values: &[&str]| {
            let mut headers = HeaderMap::new();
            for value in values {
                headers.append(header::ORIGIN, HeaderValue::from_str(value).unwrap());
            }
            origin_is(&headers, "https://jaunt.example")
        };
        assert!(with(&["https://jaunt.example"]));
        for refused in [
            vec![],
            vec!["https://evil.example"],
            vec!["null"],
            vec!["http://jaunt.example"],
            vec!["https://jaunt.example:443"],
            vec!["https://jaunt.example/"],
            vec!["https://jaunt.example", "https://jaunt.example"],
        ] {
            assert!(!with(&refused), "{refused:?}");
        }
    }

    #[test]
    fn control_messages_are_strict_and_bounded() {
        assert_eq!(
            parse_text(r#"{"t":"resize","cols":500,"rows":200}"#),
            Ok(Command::Resize(TerminalDimensions {
                cols: 500,
                rows: 200
            }))
        );
        assert_eq!(parse_text(r#"{"t":"ping"}"#), Ok(Command::Ping));
        for refused in [
            r#"{"t":"resize","cols":0,"rows":24}"#,
            r#"{"t":"resize","cols":501,"rows":24}"#,
            r#"{"t":"resize","cols":80,"rows":201}"#,
            r#"{"t":"resize","cols":80,"rows":0}"#,
            r#"{"t":"resize","cols":-1,"rows":24}"#,
            r#"{"t":"resize","cols":80}"#,
            r#"{"t":"resize","cols":80,"rows":24,"x":1}"#,
            r#"{"t":"ping","extra":true}"#,
            r#"{"t":"exec","command":"id"}"#,
            r#"{"cols":80,"rows":24}"#,
            "not json",
            "",
        ] {
            assert_eq!(parse_text(refused), Err(Malformed), "{refused}");
        }
        assert_eq!(
            dimensions(1, 1),
            Some(TerminalDimensions { cols: 1, rows: 1 })
        );
    }

    #[test]
    fn server_messages_have_the_documented_shape() {
        assert_eq!(ready("s-1"), r#"{"t":"ready","session_id":"s-1"}"#);
        assert_eq!(
            exit(Some(&TerminalExit::Status(3))),
            r#"{"t":"exit","status":3,"signal":null}"#
        );
        assert_eq!(
            exit(Some(&TerminalExit::Signal("TERM".to_owned()))),
            r#"{"t":"exit","status":null,"signal":"TERM"}"#
        );
        assert_eq!(exit(None), r#"{"t":"exit","status":null,"signal":null}"#);
        assert_eq!(error("denied"), r#"{"t":"error","code":"denied"}"#);
    }

    #[test]
    fn every_end_maps_to_its_close_code_generic_error_and_audit_reason() {
        for (end, code, error, audit) in [
            (End::Exited, Some(1000), None, "exit"),
            (End::ClientClosed, Some(1000), None, "client_closed"),
            (End::Revoked, Some(4001), Some("revoked"), "revoked"),
            (
                End::IdleTimeout,
                Some(4002),
                Some("timeout"),
                "idle_timeout",
            ),
            (
                End::MaxDuration,
                Some(1008),
                Some("timeout"),
                "max_duration",
            ),
            (
                End::WebSessionEnded,
                Some(1008),
                Some("timeout"),
                "web_session_ended",
            ),
            (End::Denied, Some(1008), Some("denied"), "denied"),
            (End::Limit, Some(1008), Some("limit"), "limit"),
            (
                End::Unavailable,
                Some(1011),
                Some("unavailable"),
                "unavailable",
            ),
            (
                End::NodeViolation,
                Some(1011),
                Some("unavailable"),
                "node_violation",
            ),
            (End::Malformed, Some(1008), None, "malformed"),
            (End::TooBig, Some(1009), None, "too_big"),
            (End::DeadPeer, None, None, "dead_peer"),
            (End::Wedged, Some(4003), Some("stalled"), "wedged"),
            (End::Shutdown, Some(1001), Some("unavailable"), "shutdown"),
        ] {
            let closing = closing(end);
            assert_eq!(
                (closing.code, closing.error, closing.audit),
                (code, error, audit),
                "{end:?}"
            );
            assert!(closing.reason.len() <= 123);
        }
    }
}
