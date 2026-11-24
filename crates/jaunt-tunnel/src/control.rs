use std::io;

use bytes::{Buf, BytesMut};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proto::{MAX_CONTROL_MESSAGE_BYTES, SessionId};

const READ_CHUNK: usize = 4096;
pub(crate) const MAX_AGENT_VERSION_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ControlError {
    #[error("control message exceeds the size limit")]
    TooLarge,
    #[error("control message is malformed")]
    Malformed,
    #[error("control stream ended inside a message")]
    Truncated,
    #[error("control message could not be encoded")]
    Encode,
    #[error("control stream i/o failed: {0:?}")]
    Io(io::ErrorKind),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ServerMessage {
    Welcome {},
    TerminateSession { session: SessionId },
    TrustUpdate {},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum AgentMessage {
    Hello { version: u32, agent_version: String },
}

pub(crate) fn agent_version_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_AGENT_VERSION_LEN
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

pub(crate) struct ControlChannel<IO> {
    io: IO,
    buffer: BytesMut,
}

impl<IO> ControlChannel<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn new(io: IO) -> Self {
        Self {
            io,
            buffer: BytesMut::new(),
        }
    }

    pub(crate) async fn recv<T: DeserializeOwned>(&mut self) -> Result<Option<T>, ControlError> {
        loop {
            if let Some(newline) = self.buffer.iter().position(|byte| *byte == b'\n') {
                let line = self.buffer.split_to(newline);
                self.buffer.advance(1);
                if line.len() > MAX_CONTROL_MESSAGE_BYTES {
                    return Err(ControlError::TooLarge);
                }
                return serde_json::from_slice(&line)
                    .map(Some)
                    .map_err(|_| ControlError::Malformed);
            }
            if self.buffer.len() > MAX_CONTROL_MESSAGE_BYTES {
                return Err(ControlError::TooLarge);
            }
            let mut chunk = [0_u8; READ_CHUNK];
            let read = self
                .io
                .read(&mut chunk)
                .await
                .map_err(|error| ControlError::Io(error.kind()))?;
            if read == 0 {
                return if self.buffer.is_empty() {
                    Ok(None)
                } else {
                    Err(ControlError::Truncated)
                };
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    pub(crate) async fn send<T: Serialize>(&mut self, message: &T) -> Result<(), ControlError> {
        let mut encoded = serde_json::to_vec(message).map_err(|_| ControlError::Encode)?;
        if encoded.len() > MAX_CONTROL_MESSAGE_BYTES {
            return Err(ControlError::TooLarge);
        }
        encoded.push(b'\n');
        self.io
            .write_all(&encoded)
            .await
            .map_err(|error| ControlError::Io(error.kind()))?;
        self.io
            .flush()
            .await
            .map_err(|error| ControlError::Io(error.kind()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn id(value: &str) -> SessionId {
        SessionId::new(value).unwrap()
    }

    #[test]
    fn wire_format_is_stable() {
        let hello = AgentMessage::Hello {
            version: 1,
            agent_version: "0.1.0".to_owned(),
        };
        assert_eq!(
            serde_json::to_string(&hello).unwrap(),
            r#"{"type":"hello","version":1,"agent_version":"0.1.0"}"#
        );
        let terminate = ServerMessage::TerminateSession { session: id("s-1") };
        assert_eq!(
            serde_json::to_string(&terminate).unwrap(),
            r#"{"type":"terminate_session","session":"s-1"}"#
        );
        assert_eq!(
            serde_json::to_string(&ServerMessage::Welcome {}).unwrap(),
            r#"{"type":"welcome"}"#
        );
        assert_eq!(
            serde_json::to_string(&ServerMessage::TrustUpdate {}).unwrap(),
            r#"{"type":"trust_update"}"#
        );
    }

    #[test]
    fn unknown_fields_and_types_are_rejected() {
        let server_cases = [
            r#"{"type":"welcome","extra":1}"#,
            r#"{"type":"trust_update","extra":true}"#,
            r#"{"type":"terminate_session","session":"s","extra":1}"#,
            r#"{"type":"terminate_session"}"#,
            r#"{"type":"terminate_session","session":"bad id"}"#,
            r#"{"type":"hello","version":1,"agent_version":"x"}"#,
            r#"{"type":"nope"}"#,
            r#"{}"#,
            r#"[]"#,
        ];
        for case in server_cases {
            assert!(
                serde_json::from_str::<ServerMessage>(case).is_err(),
                "{case}"
            );
        }
        let agent_cases = [
            r#"{"type":"hello","version":1,"agent_version":"x","extra":1}"#,
            r#"{"type":"hello","version":"1","agent_version":"x"}"#,
            r#"{"type":"hello","version":1}"#,
            r#"{"type":"welcome"}"#,
        ];
        for case in agent_cases {
            assert!(
                serde_json::from_str::<AgentMessage>(case).is_err(),
                "{case}"
            );
        }
    }

    #[tokio::test]
    async fn channel_round_trips_and_reports_eof() {
        let (left, right) = duplex(64 * 1024);
        let mut sender = ControlChannel::new(left);
        let mut receiver = ControlChannel::new(right);
        sender.send(&ServerMessage::Welcome {}).await.unwrap();
        sender
            .send(&ServerMessage::TerminateSession { session: id("a") })
            .await
            .unwrap();
        drop(sender);
        assert_eq!(
            receiver.recv::<ServerMessage>().await,
            Ok(Some(ServerMessage::Welcome {}))
        );
        assert_eq!(
            receiver.recv::<ServerMessage>().await,
            Ok(Some(ServerMessage::TerminateSession { session: id("a") }))
        );
        assert_eq!(receiver.recv::<ServerMessage>().await, Ok(None));
    }

    #[tokio::test]
    async fn channel_enforces_limits_and_framing() {
        let padding = "x".repeat(MAX_CONTROL_MESSAGE_BYTES + 1);
        let oversized_with_newline = format!("{padding}\n");
        let unterminated = "x".repeat(MAX_CONTROL_MESSAGE_BYTES + READ_CHUNK + 1);
        let cases: [(&str, ControlError); 4] = [
            (oversized_with_newline.as_str(), ControlError::TooLarge),
            (unterminated.as_str(), ControlError::TooLarge),
            ("not json\n", ControlError::Malformed),
            ("{\"type\":\"welcome\"}", ControlError::Truncated),
        ];
        for (input, expected) in cases {
            let (mut raw, right) = duplex(128 * 1024);
            raw.write_all(input.as_bytes()).await.unwrap();
            drop(raw);
            let mut receiver = ControlChannel::new(right);
            assert_eq!(
                receiver.recv::<ServerMessage>().await,
                Err(expected),
                "{}",
                &input[..input.len().min(24)]
            );
        }
    }

    fn hello_with_padding(padding: usize) -> AgentMessage {
        AgentMessage::Hello {
            version: 1,
            agent_version: "v".repeat(padding),
        }
    }

    fn encoded_len(message: &AgentMessage) -> usize {
        serde_json::to_vec(message).unwrap().len()
    }

    #[tokio::test]
    async fn the_size_limit_is_inclusive_on_both_directions() {
        let overhead = encoded_len(&hello_with_padding(0));
        let at_limit = hello_with_padding(MAX_CONTROL_MESSAGE_BYTES - overhead);
        let over_limit = hello_with_padding(MAX_CONTROL_MESSAGE_BYTES - overhead + 1);
        assert_eq!(encoded_len(&at_limit), MAX_CONTROL_MESSAGE_BYTES);
        assert_eq!(encoded_len(&over_limit), MAX_CONTROL_MESSAGE_BYTES + 1);

        let (left, right) = duplex(128 * 1024);
        let mut sender = ControlChannel::new(left);
        let mut receiver = ControlChannel::new(right);
        sender.send(&at_limit).await.unwrap();
        assert_eq!(sender.send(&over_limit).await, Err(ControlError::TooLarge));
        assert_eq!(receiver.recv::<AgentMessage>().await, Ok(Some(at_limit)));

        let (mut raw, right) = duplex(128 * 1024);
        let mut line = serde_json::to_vec(&over_limit).unwrap();
        line.push(b'\n');
        raw.write_all(&line).await.unwrap();
        let mut receiver = ControlChannel::new(right);
        assert_eq!(
            receiver.recv::<AgentMessage>().await,
            Err(ControlError::TooLarge)
        );
    }

    #[tokio::test]
    async fn send_refuses_oversized_messages() {
        let (left, _right) = duplex(1024);
        let mut sender = ControlChannel::new(left);
        let message = AgentMessage::Hello {
            version: 1,
            agent_version: "v".repeat(MAX_CONTROL_MESSAGE_BYTES),
        };
        assert_eq!(sender.send(&message).await, Err(ControlError::TooLarge));
    }

    #[test]
    fn agent_version_rules() {
        assert!(agent_version_is_valid("0.1.0-rc.1+build5"));
        assert!(!agent_version_is_valid(""));
        assert!(!agent_version_is_valid("has space"));
        assert!(!agent_version_is_valid(
            &"v".repeat(MAX_AGENT_VERSION_LEN + 1)
        ));
    }
}
