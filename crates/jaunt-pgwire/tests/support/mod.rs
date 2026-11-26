#![allow(dead_code)]

use jaunt_pgwire::{
    BackendDecoder, BackendMessage, DecodeError, Event, FrontendDecoder, FrontendMessage, Limits,
};

pub trait Decoder {
    type Message;
    fn push(&mut self, input: &[u8]) -> Result<(), DecodeError>;
    fn next_event(&mut self) -> Result<Option<Event<Self::Message>>, DecodeError>;
}

impl Decoder for FrontendDecoder {
    type Message = FrontendMessage;
    fn push(&mut self, input: &[u8]) -> Result<(), DecodeError> {
        FrontendDecoder::push(self, input)
    }
    fn next_event(&mut self) -> Result<Option<Event<FrontendMessage>>, DecodeError> {
        FrontendDecoder::next_event(self)
    }
}

impl Decoder for BackendDecoder {
    type Message = BackendMessage;
    fn push(&mut self, input: &[u8]) -> Result<(), DecodeError> {
        BackendDecoder::push(self, input)
    }
    fn next_event(&mut self) -> Result<Option<Event<BackendMessage>>, DecodeError> {
        BackendDecoder::next_event(self)
    }
}

#[derive(Debug)]
pub struct Outcome<M> {
    pub messages: Vec<(M, Vec<u8>)>,
    pub error: Option<DecodeError>,
}

impl<M: std::fmt::Debug> Outcome<M> {
    pub fn fingerprint(&self) -> (Vec<(String, Vec<u8>)>, Option<DecodeError>) {
        let messages = self
            .messages
            .iter()
            .map(|(message, bytes)| (format!("{message:?}"), bytes.clone()))
            .collect();
        (messages, self.error.clone())
    }

    pub fn only(self) -> Vec<M> {
        assert_eq!(self.error, None);
        self.messages
            .into_iter()
            .map(|(message, _)| message)
            .collect()
    }
}

pub fn run<D: Decoder>(decoder: &mut D, input: &[u8], step: usize) -> Outcome<D::Message> {
    let mut messages: Vec<(D::Message, Vec<u8>)> = Vec::new();
    let mut passed = Vec::new();
    for piece in input.chunks(step.max(1)) {
        if let Err(error) = decoder.push(piece) {
            return Outcome {
                messages,
                error: Some(error),
            };
        }
        loop {
            match decoder.next_event() {
                Ok(Some(Event::Frame(frame))) => {
                    passed.extend_from_slice(frame.raw());
                    let raw = frame.raw().to_vec();
                    messages.push((frame.into_message(), raw));
                }
                Ok(Some(Event::Continuation(chunk))) => {
                    passed.extend_from_slice(chunk.bytes());
                    let last = messages.last_mut().expect("a continuation follows a frame");
                    last.1.extend_from_slice(chunk.bytes());
                }
                Ok(None) => break,
                Err(error) => {
                    assert!(input.starts_with(&passed));
                    return Outcome {
                        messages,
                        error: Some(error),
                    };
                }
            }
        }
    }
    assert!(input.starts_with(&passed));
    Outcome {
        messages,
        error: None,
    }
}

pub fn frontend(input: &[u8]) -> Outcome<FrontendMessage> {
    frontend_with(Limits::default(), input)
}

pub fn frontend_with(limits: Limits, input: &[u8]) -> Outcome<FrontendMessage> {
    let mut whole = FrontendDecoder::new(limits).expect("valid limits");
    let mut bytewise = FrontendDecoder::new(limits).expect("valid limits");
    let outcome = run(&mut whole, input, input.len());
    assert_eq!(
        run(&mut bytewise, input, 1).fingerprint(),
        outcome.fingerprint()
    );
    outcome
}

pub fn backend(input: &[u8]) -> Outcome<BackendMessage> {
    backend_with(Limits::default(), input)
}

pub fn backend_with(limits: Limits, input: &[u8]) -> Outcome<BackendMessage> {
    let mut whole = BackendDecoder::new(limits).expect("valid limits");
    let mut bytewise = BackendDecoder::new(limits).expect("valid limits");
    let outcome = run(&mut whole, input, input.len());
    assert_eq!(
        run(&mut bytewise, input, 1).fingerprint(),
        outcome.fingerprint()
    );
    outcome
}

pub fn cstr(text: &str) -> Vec<u8> {
    let mut out = text.as_bytes().to_vec();
    out.push(0);
    out
}

pub fn message(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&(i32::try_from(body.len() + 4).expect("small")).to_be_bytes());
    out.extend_from_slice(body);
    out
}

pub fn packet(code: u32, body: &[u8]) -> Vec<u8> {
    let mut out = (i32::try_from(body.len() + 8).expect("small"))
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(body);
    out
}

pub const V3_0: u32 = 3 << 16;
pub const V3_2: u32 = (3 << 16) | 2;
pub const SSL_REQUEST: u32 = (1234 << 16) | 5679;
pub const GSSENC_REQUEST: u32 = (1234 << 16) | 5680;
pub const CANCEL_REQUEST: u32 = (1234 << 16) | 5678;

pub fn startup(parameters: &[(&str, &str)]) -> Vec<u8> {
    startup_version(V3_0, parameters)
}

pub fn startup_version(code: u32, parameters: &[(&str, &str)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, value) in parameters {
        body.extend(cstr(name));
        body.extend(cstr(value));
    }
    body.push(0);
    packet(code, &body)
}

pub fn after_startup(rest: &[&[u8]]) -> Vec<u8> {
    let mut input = startup(&[("user", "app")]);
    for part in rest {
        input.extend_from_slice(part);
    }
    input
}

pub fn i16s(values: &[i16]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_be_bytes())
        .collect()
}

pub fn i32s(values: &[i32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_be_bytes())
        .collect()
}
