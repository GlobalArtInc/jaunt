use std::fmt;

use thiserror::Error;

pub const MAX_CONTROL_PAYLOAD_BYTES: usize = 125;

const MAX_HEADER_BYTES: usize = 14;
const FIN_BIT: u8 = 0x80;
const RESERVED_BITS: u8 = 0x70;
const OPCODE_BITS: u8 = 0x0f;
const MASK_BIT: u8 = 0x80;
const LENGTH_BITS: u8 = 0x7f;
const LENGTH_16: u8 = 126;
const LENGTH_64: u8 = 127;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl Opcode {
    fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0x0 => Some(Self::Continuation),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xa => Some(Self::Pong),
            _ => None,
        }
    }

    fn bits(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xa,
        }
    }

    fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum WsMessage {
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Option<u16>),
}

impl fmt::Debug for WsMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Binary(bytes) => f
                .debug_struct("Binary")
                .field("bytes", &bytes.len())
                .finish(),
            Self::Ping(bytes) => f.debug_struct("Ping").field("bytes", &bytes.len()).finish(),
            Self::Pong(bytes) => f.debug_struct("Pong").field("bytes", &bytes.len()).finish(),
            Self::Close(code) => f.debug_tuple("Close").field(code).finish(),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WsError {
    #[error("websocket frame sets reserved bits")]
    ReservedBits,
    #[error("websocket frame uses an unknown opcode")]
    UnknownOpcode,
    #[error("client websocket frame is not masked")]
    Unmasked,
    #[error("server websocket frame is masked")]
    Masked,
    #[error("websocket control frame is fragmented")]
    FragmentedControl,
    #[error("websocket control frame payload exceeds {MAX_CONTROL_PAYLOAD_BYTES} bytes")]
    ControlTooLong,
    #[error("fragmented websocket messages are not supported")]
    FragmentedMessage,
    #[error("websocket text messages are not supported")]
    TextMessage,
    #[error("websocket message exceeds {limit} bytes")]
    TooLarge { limit: usize },
    #[error("websocket frame length is not valid")]
    InvalidLength,
    #[error("websocket close frame payload is not valid")]
    InvalidClose,
    #[error("websocket data after the close frame")]
    AfterClose,
    #[error("websocket stream ended inside a frame")]
    Truncated,
}

#[derive(Debug, Clone, Copy)]
struct Frame {
    opcode: Opcode,
    mask: Option<[u8; 4]>,
    remaining: usize,
    offset: usize,
}

pub struct WsReader {
    direction: Direction,
    max_message_bytes: usize,
    header: [u8; MAX_HEADER_BYTES],
    header_len: usize,
    frame: Option<Frame>,
    payload: Vec<u8>,
    closed: bool,
    failed: Option<WsError>,
}

impl fmt::Debug for WsReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WsReader")
            .field("direction", &self.direction)
            .field("max_message_bytes", &self.max_message_bytes)
            .field("header_bytes", &self.header_len)
            .field("in_frame", &self.frame.is_some())
            .field("payload_bytes", &self.payload.len())
            .field("closed", &self.closed)
            .field("failed", &self.failed)
            .finish()
    }
}

impl WsReader {
    pub fn new(direction: Direction, max_message_bytes: usize) -> Self {
        Self {
            direction,
            max_message_bytes,
            header: [0; MAX_HEADER_BYTES],
            header_len: 0,
            frame: None,
            payload: Vec::new(),
            closed: false,
            failed: None,
        }
    }

    pub fn direction(&self) -> Direction {
        self.direction
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn feed(&mut self, bytes: &[u8], out: &mut Vec<WsMessage>) -> Result<(), WsError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        let result = self.consume(bytes, out);
        if let Err(error) = result {
            self.failed = Some(error);
            self.frame = None;
            self.payload = Vec::new();
        }
        result
    }

    pub fn end_of_stream(&self) -> Result<(), WsError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if self.header_len > 0 || self.frame.is_some() {
            return Err(WsError::Truncated);
        }
        Ok(())
    }

    fn consume(&mut self, mut bytes: &[u8], out: &mut Vec<WsMessage>) -> Result<(), WsError> {
        while !bytes.is_empty() {
            if self.closed {
                return Err(WsError::AfterClose);
            }
            bytes = match self.frame {
                Some(frame) => self.read_payload(frame, bytes, out)?,
                None => self.read_header(bytes, out)?,
            };
        }
        Ok(())
    }

    fn read_header<'a>(
        &mut self,
        bytes: &'a [u8],
        out: &mut Vec<WsMessage>,
    ) -> Result<&'a [u8], WsError> {
        let needed = self.header_needed();
        let take = needed.saturating_sub(self.header_len).min(bytes.len());
        let (head, rest) = bytes.split_at(take);
        let end = self.header_len + take;
        if let Some(slot) = self.header.get_mut(self.header_len..end) {
            slot.copy_from_slice(head);
        }
        self.header_len = end;
        if self.header_len == self.header_needed() {
            let frame = self.parse_header()?;
            self.header_len = 0;
            self.frame = Some(frame);
            if frame.remaining == 0 {
                self.complete(frame, out)?;
            }
        }
        Ok(rest)
    }

    fn header_needed(&self) -> usize {
        if self.header_len < 2 {
            return 2;
        }
        let second = self.header[1];
        let extended = match second & LENGTH_BITS {
            LENGTH_16 => 2,
            LENGTH_64 => 8,
            _ => 0,
        };
        let mask = if second & MASK_BIT != 0 { 4 } else { 0 };
        2 + extended + mask
    }

    fn parse_header(&mut self) -> Result<Frame, WsError> {
        let header = self.header;
        let [first, second, ref tail @ ..] = header;
        let tail: &[u8] = tail;
        if first & RESERVED_BITS != 0 {
            return Err(WsError::ReservedBits);
        }
        let opcode = Opcode::from_bits(first & OPCODE_BITS).ok_or(WsError::UnknownOpcode)?;
        let fin = first & FIN_BIT != 0;
        let masked = second & MASK_BIT != 0;
        match (self.direction, masked) {
            (Direction::ClientToServer, false) => return Err(WsError::Unmasked),
            (Direction::ServerToClient, true) => return Err(WsError::Masked),
            _ => {}
        }
        let (length, tail) = match second & LENGTH_BITS {
            LENGTH_16 => {
                let (raw, rest) = tail
                    .split_first_chunk::<2>()
                    .ok_or(WsError::InvalidLength)?;
                (u64::from(u16::from_be_bytes(*raw)), rest)
            }
            LENGTH_64 => {
                let (raw, rest) = tail
                    .split_first_chunk::<8>()
                    .ok_or(WsError::InvalidLength)?;
                let value = u64::from_be_bytes(*raw);
                if value >> 63 != 0 {
                    return Err(WsError::InvalidLength);
                }
                (value, rest)
            }
            short => (u64::from(short), tail),
        };
        let mask = if masked {
            Some(*tail.first_chunk::<4>().ok_or(WsError::InvalidLength)?)
        } else {
            None
        };
        let limit = WsError::TooLarge {
            limit: self.max_message_bytes,
        };
        let remaining = usize::try_from(length).map_err(|_| limit)?;
        match opcode {
            Opcode::Close | Opcode::Ping | Opcode::Pong => {
                if !fin {
                    return Err(WsError::FragmentedControl);
                }
                if remaining > MAX_CONTROL_PAYLOAD_BYTES {
                    return Err(WsError::ControlTooLong);
                }
            }
            Opcode::Continuation => return Err(WsError::FragmentedMessage),
            Opcode::Text | Opcode::Binary if !fin => return Err(WsError::FragmentedMessage),
            Opcode::Text => return Err(WsError::TextMessage),
            Opcode::Binary => {
                if remaining > self.max_message_bytes {
                    return Err(limit);
                }
            }
        }
        self.payload = Vec::new();
        Ok(Frame {
            opcode,
            mask,
            remaining,
            offset: 0,
        })
    }

    fn read_payload<'a>(
        &mut self,
        mut frame: Frame,
        bytes: &'a [u8],
        out: &mut Vec<WsMessage>,
    ) -> Result<&'a [u8], WsError> {
        let take = frame.remaining.min(bytes.len());
        let (payload, rest) = bytes.split_at(take);
        match frame.mask {
            Some(mask) => {
                self.payload
                    .extend(payload.iter().enumerate().map(|(index, byte)| {
                        byte ^ mask[frame.offset.wrapping_add(index) % mask.len()]
                    }))
            }
            None => self.payload.extend_from_slice(payload),
        }
        frame.offset = frame.offset.wrapping_add(take);
        frame.remaining -= take;
        self.frame = Some(frame);
        if frame.remaining == 0 {
            self.complete(frame, out)?;
        }
        Ok(rest)
    }

    fn complete(&mut self, frame: Frame, out: &mut Vec<WsMessage>) -> Result<(), WsError> {
        self.frame = None;
        let payload = std::mem::take(&mut self.payload);
        let message = match frame.opcode {
            Opcode::Binary => WsMessage::Binary(payload),
            Opcode::Ping => WsMessage::Ping(payload),
            Opcode::Pong => WsMessage::Pong(payload),
            Opcode::Close => {
                let code = match payload.as_slice() {
                    [] => None,
                    [high, low, reason @ ..] => {
                        if std::str::from_utf8(reason).is_err() {
                            return Err(WsError::InvalidClose);
                        }
                        Some(u16::from_be_bytes([*high, *low]))
                    }
                    [_] => return Err(WsError::InvalidClose),
                };
                self.closed = true;
                WsMessage::Close(code)
            }
            Opcode::Text => return Err(WsError::TextMessage),
            Opcode::Continuation => return Err(WsError::FragmentedMessage),
        };
        out.push(message);
        Ok(())
    }
}

pub fn encode_frame(
    opcode: Opcode,
    fin: bool,
    payload: &[u8],
    mask: Option<[u8; 4]>,
) -> Result<Vec<u8>, WsError> {
    if opcode.is_control() {
        if !fin {
            return Err(WsError::FragmentedControl);
        }
        if payload.len() > MAX_CONTROL_PAYLOAD_BYTES {
            return Err(WsError::ControlTooLong);
        }
    }
    let mut frame = Vec::with_capacity(payload.len() + MAX_HEADER_BYTES);
    frame.push(if fin { FIN_BIT } else { 0 } | opcode.bits());
    let mask_bit = if mask.is_some() { MASK_BIT } else { 0 };
    match u16::try_from(payload.len()) {
        Ok(short) if short < u16::from(LENGTH_16) => {
            frame.push(mask_bit | u8::try_from(short).map_err(|_| WsError::InvalidLength)?);
        }
        Ok(medium) => {
            frame.push(mask_bit | LENGTH_16);
            frame.extend_from_slice(&medium.to_be_bytes());
        }
        Err(_) => {
            frame.push(mask_bit | LENGTH_64);
            let long = u64::try_from(payload.len()).map_err(|_| WsError::InvalidLength)?;
            frame.extend_from_slice(&long.to_be_bytes());
        }
    }
    match mask {
        Some(key) => {
            frame.extend_from_slice(&key);
            frame.extend(
                payload
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ key[index % key.len()]),
            );
        }
        None => frame.extend_from_slice(payload),
    }
    Ok(frame)
}
