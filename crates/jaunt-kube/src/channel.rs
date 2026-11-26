use std::fmt;

use thiserror::Error;

pub const STDIN: u8 = 0;
pub const STDOUT: u8 = 1;
pub const STDERR: u8 = 2;
pub const STATUS: u8 = 3;
pub const RESIZE: u8 = 4;
pub const CLOSE_SIGNAL: u8 = 255;

pub const V4_PROTOCOL: &str = "v4.channel.k8s.io";
pub const V5_PROTOCOL: &str = "v5.channel.k8s.io";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelProtocol {
    V4,
    V5,
}

impl ChannelProtocol {
    pub fn from_subprotocol(name: &str) -> Option<Self> {
        match name {
            V4_PROTOCOL => Some(Self::V4),
            V5_PROTOCOL => Some(Self::V5),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::V4 => V4_PROTOCOL,
            Self::V5 => V5_PROTOCOL,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ChannelFrame<'a> {
    Data { channel: u8, payload: &'a [u8] },
    Close { channel: u8 },
}

impl fmt::Debug for ChannelFrame<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data { channel, payload } => f
                .debug_struct("Data")
                .field("channel", channel)
                .field("bytes", &payload.len())
                .finish(),
            Self::Close { channel } => f.debug_struct("Close").field("channel", channel).finish(),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    #[error("channel message is empty")]
    Empty,
    #[error("close signal must name exactly one channel")]
    InvalidCloseSignal,
    #[error("channel 255 carries the close signal in this protocol")]
    ReservedChannel,
    #[error("this protocol has no close signal")]
    CloseUnsupported,
}

pub fn parse_channel_message(
    protocol: ChannelProtocol,
    message: &[u8],
) -> Result<ChannelFrame<'_>, ChannelError> {
    let (&channel, payload) = message.split_first().ok_or(ChannelError::Empty)?;
    match (protocol, channel, payload) {
        (ChannelProtocol::V5, CLOSE_SIGNAL, [closed]) => {
            Ok(ChannelFrame::Close { channel: *closed })
        }
        (ChannelProtocol::V5, CLOSE_SIGNAL, _) => Err(ChannelError::InvalidCloseSignal),
        _ => Ok(ChannelFrame::Data { channel, payload }),
    }
}

pub fn build_channel_message(
    protocol: ChannelProtocol,
    frame: &ChannelFrame<'_>,
) -> Result<Vec<u8>, ChannelError> {
    match (protocol, *frame) {
        (
            ChannelProtocol::V5,
            ChannelFrame::Data {
                channel: CLOSE_SIGNAL,
                ..
            },
        ) => Err(ChannelError::ReservedChannel),
        (_, ChannelFrame::Data { channel, payload }) => {
            let mut message = Vec::with_capacity(payload.len() + 1);
            message.push(channel);
            message.extend_from_slice(payload);
            Ok(message)
        }
        (ChannelProtocol::V5, ChannelFrame::Close { channel }) => Ok(vec![CLOSE_SIGNAL, channel]),
        (ChannelProtocol::V4, ChannelFrame::Close { .. }) => Err(ChannelError::CloseUnsupported),
    }
}
