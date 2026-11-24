use jaunt_record::MAX_EVENT_TEXT_BYTES;

use crate::common::recorder as new_recorder;
use crate::common::{drive, event_lines, finish_cast, joined_data, parse_cast, seeded};

#[test]
fn header_is_exact_and_valid_json() {
    let (recorder, _clock) = new_recorder(false);
    let (cast, _, _) = finish_cast(recorder);
    let header = String::from_utf8(cast).unwrap();
    assert_eq!(
        header,
        "{\"version\":2,\"width\":80,\"height\":24,\"timestamp\":1700000000,\"env\":{\"SHELL\":\"/bin/bash\",\"TERM\":\"xterm-256color\"}}\n"
    );
    assert!(parse_cast(header.as_bytes()).unwrap().events.is_empty());
}

#[test]
fn event_times_are_formatted_with_at_most_six_decimals() {
    let (mut recorder, clock) = new_recorder(false);
    recorder.push_output(b"a").unwrap();
    clock.set_micros(1_500_000);
    recorder.push_output(b"b").unwrap();
    clock.set_micros(1_234_567_891);
    recorder.push_output(b"c").unwrap();
    clock.set_micros(1_234_567_891 + 2_000_000);
    recorder.push_output(b"d").unwrap();
    let (cast, _, _) = finish_cast(recorder);
    assert_eq!(
        event_lines(&cast),
        [
            "[0.0, \"o\", \"a\"]",
            "[1.5, \"o\", \"b\"]",
            "[1234.567891, \"o\", \"c\"]",
            "[1236.567891, \"o\", \"d\"]",
        ]
    );
}

#[test]
fn clock_going_backwards_is_clamped() {
    let (mut recorder, clock) = new_recorder(false);
    clock.set_micros(5_000_000);
    recorder.push_output(b"a").unwrap();
    clock.set_micros(2_000_000);
    recorder.push_output(b"b").unwrap();
    let (cast, _, _) = finish_cast(recorder);
    assert_eq!(
        event_lines(&cast),
        ["[5.0, \"o\", \"a\"]", "[5.0, \"o\", \"b\"]"]
    );
}

#[test]
fn resize_and_marker_events() {
    let (mut recorder, _clock) = new_recorder(false);
    recorder.resize(100, 40).unwrap();
    recorder.marker("deploy \"start\"").unwrap();
    let (cast, _, _) = finish_cast(recorder);
    assert_eq!(
        event_lines(&cast),
        [
            "[0.0, \"r\", \"100x40\"]",
            "[0.0, \"m\", \"deploy \\\"start\\\"\"]"
        ]
    );
}

#[test]
fn input_is_ignored_unless_recording_input() {
    let (mut recorder, _clock) = new_recorder(false);
    assert!(!recorder.push_input(b"secret-password\n").unwrap());
    let (cast, manifest, _) = finish_cast(recorder);
    assert!(event_lines(&cast).is_empty());
    assert!(!String::from_utf8(cast).unwrap().contains("secret"));
    assert_eq!(manifest.bytes_in, 16);
    assert!(!manifest.input_recorded);

    let (mut recorder, _clock) = new_recorder(true);
    assert!(recorder.push_input(b"ls\n").unwrap());
    let (cast, manifest, _) = finish_cast(recorder);
    assert_eq!(event_lines(&cast), ["[0.0, \"i\", \"ls\\n\"]"]);
    assert!(manifest.input_recorded);
    assert_eq!(manifest.bytes_in, 3);
}

fn output_text_of_split_push(bytes: &[u8], at: usize) -> String {
    let (mut recorder, _clock) = new_recorder(false);
    recorder.push_output(&bytes[..at]).unwrap();
    recorder.push_output(&bytes[at..]).unwrap();
    let (cast, _, _) = finish_cast(recorder);
    joined_data(&parse_cast(&cast).unwrap(), "o")
}

#[test]
fn utf8_split_at_every_byte_boundary_matches_unsplit_text() {
    let text = "a\u{e9}\u{20ac}\u{1f600}z\u{65e5}";
    for at in 0..=text.len() {
        assert_eq!(
            output_text_of_split_push(text.as_bytes(), at),
            text,
            "split at {at}"
        );
    }
}

#[test]
fn invalid_bytes_become_replacement_characters() {
    let bytes = b"ab\xff\xe2\x82c\xc0\xf0\x9f\x98";
    let expected = String::from_utf8_lossy(bytes).into_owned();
    assert_eq!(expected, "ab\u{fffd}\u{fffd}c\u{fffd}\u{fffd}");
    for at in 0..=bytes.len() {
        assert_eq!(
            output_text_of_split_push(bytes, at),
            expected,
            "split at {at}"
        );
    }
}

#[test]
fn empty_pushes_emit_nothing() {
    let (mut recorder, _clock) = new_recorder(true);
    recorder.push_output(&[]).unwrap();
    recorder.push_input(&[]).unwrap();
    let (cast, _, _) = finish_cast(recorder);
    assert!(event_lines(&cast).is_empty());
}

#[test]
fn an_incomplete_input_sequence_is_flushed_lossily_at_finish() {
    let (mut recorder, _clock) = new_recorder(true);
    assert!(recorder.push_input(&[0xe2, 0x82]).unwrap());
    let (cast, _, _) = finish_cast(recorder);
    assert_eq!(event_lines(&cast), ["[0.0, \"i\", \"\u{fffd}\"]"]);

    let (mut recorder, _clock) = new_recorder(false);
    recorder.push_output(&[b'a', 0xe2, 0x82]).unwrap();
    let (cast, _, _) = finish_cast(recorder);
    assert_eq!(
        event_lines(&cast),
        ["[0.0, \"o\", \"a\"]", "[0.0, \"o\", \"\u{fffd}\"]"]
    );
}

#[test]
fn a_long_multibyte_push_is_split_into_valid_bounded_events() {
    let (mut recorder, _clock) = new_recorder(false);
    let text = "\u{65e5}\u{1f600}".repeat(20_000);
    recorder.push_output(text.as_bytes()).unwrap();
    let (cast, _, _) = finish_cast(recorder);
    let parsed = parse_cast(&cast).unwrap();
    assert!(parsed.events.len() > 3);
    for event in &parsed.events {
        assert!(event.data.len() <= MAX_EVENT_TEXT_BYTES);
        assert!(!event.data.is_empty());
    }
    assert!(parsed.events[0].data.len() > MAX_EVENT_TEXT_BYTES - 4);
    assert_eq!(joined_data(&parsed, "o"), text);
}

#[test]
fn random_session_is_accepted_by_a_strict_reference_parser() {
    let (mut recorder, clock) = new_recorder(true);
    let mut rng = seeded(7);
    let driven = drive(&mut recorder, &clock, &mut rng, 400_000);
    let (cast, _, _) = finish_cast(recorder);
    let parsed = parse_cast(&cast).unwrap();
    assert_eq!(
        joined_data(&parsed, "o"),
        String::from_utf8_lossy(&driven.output)
    );
}
