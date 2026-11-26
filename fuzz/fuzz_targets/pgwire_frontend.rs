#![no_main]

use jaunt_pgwire::{DecodeError, Event, FrontendDecoder, FrontendMessage, Limits, PasswordKind};
use libfuzzer_sys::fuzz_target;

const LIMITS: Limits = Limits {
    max_data_message: 4096,
    max_statement_message: 1024,
    max_startup_message: 512,
    max_startup_parameters: 8,
    max_pending: 1 << 20,
};

type Outcome = (Vec<(FrontendMessage, Vec<u8>)>, Option<DecodeError>);

fn fingerprint(outcome: &Outcome) -> (Vec<(String, &[u8])>, Option<DecodeError>) {
    let messages = outcome
        .0
        .iter()
        .map(|(message, bytes)| (format!("{message:?}"), bytes.as_slice()))
        .collect();
    (messages, outcome.1.clone())
}

fn run(input: &[u8], step: usize) -> Outcome {
    let mut decoder = FrontendDecoder::new(LIMITS).expect("valid limits");
    let mut messages: Vec<(FrontendMessage, Vec<u8>)> = Vec::new();
    let mut passed = Vec::new();
    for piece in input.chunks(step) {
        decoder
            .push(piece)
            .expect("input is below the pending limit");
        loop {
            match decoder.next_event() {
                Ok(Some(Event::Frame(frame))) => {
                    passed.extend_from_slice(frame.raw());
                    messages.push((frame.message().clone(), frame.raw().to_vec()));
                }
                Ok(Some(Event::Continuation(chunk))) => {
                    passed.extend_from_slice(chunk.bytes());
                    let last = messages.last_mut().expect("a continuation follows a frame");
                    last.1.extend_from_slice(chunk.bytes());
                }
                Ok(None) => break,
                Err(error) => {
                    assert!(input.starts_with(&passed));
                    assert!(decoder.is_poisoned());
                    assert_eq!(decoder.next_event().err(), Some(DecodeError::Poisoned));
                    return (messages, Some(error));
                }
            }
        }
    }
    assert!(input.starts_with(&passed));
    (messages, None)
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, input)) = data.split_first() else {
        return;
    };
    let whole = run(input, input.len().max(1));
    let pieces = run(input, usize::from(selector % 32) + 1);
    assert_eq!(fingerprint(&whole), fingerprint(&pieces));
    for (message, bytes) in &whole.0 {
        match message {
            FrontendMessage::Query(statement) => {
                assert!(bytes.len() <= LIMITS.max_statement_message + 1);
                let excerpt = statement.excerpt(64);
                assert!(excerpt.text.len() <= 64);
                assert_eq!(excerpt.truncated, excerpt.dropped_bytes > 0);
                statement.kind();
            }
            FrontendMessage::Password(response) => {
                for kind in [
                    PasswordKind::Password,
                    PasswordKind::SaslInitial,
                    PasswordKind::Sasl,
                    PasswordKind::Gss,
                ] {
                    let _ = response.interpret(kind);
                }
            }
            _ => {}
        }
    }
});
