#![no_main]

use jaunt_pgwire::{
    Event, FrontendDecoder, FrontendMessage, Limits, MAX_NAME_BYTES, StartupMessage, StartupPolicy,
    StartupRefusal,
};
use libfuzzer_sys::fuzz_target;

fn startup(bytes: &[u8]) -> Option<StartupMessage> {
    let mut decoder = FrontendDecoder::new(Limits::default()).expect("valid limits");
    decoder.push(bytes).ok()?;
    match decoder.next_event() {
        Ok(Some(Event::Frame(frame))) => match frame.into_message() {
            FrontendMessage::Startup(startup) => Some(startup),
            _ => None,
        },
        _ => None,
    }
}

fuzz_target!(|data: &[u8]| {
    let Some(message) = startup(data) else {
        return;
    };
    let policy = StartupPolicy::default();
    let Ok(request) = policy.inspect(&message) else {
        return;
    };
    assert!(!request.user.is_empty() && request.user.len() <= MAX_NAME_BYTES);
    assert!(!request.database.is_empty() && request.database.len() <= MAX_NAME_BYTES);
    let (user, database) = (request.user.to_owned(), request.database.to_owned());
    let rewritten = policy
        .rewrite(&message, &user, &database)
        .expect("inspected names are accepted");
    assert!(
        rewritten
            .parameters()
            .all(|(name, _)| !name.eq_ignore_ascii_case("replication"))
    );
    let again = startup(&rewritten.encode().expect("bounded")).expect("an encoded startup decodes");
    assert_eq!(again, rewritten);
    match policy.rewrite(&again, &user, &database) {
        Ok(same) => assert_eq!(same, rewritten),
        Err(
            StartupRefusal::TooManyParameters { .. } | StartupRefusal::ParametersTooLarge { .. },
        ) => {}
        Err(other) => panic!("a rewritten startup was refused: {other}"),
    }
    assert_eq!(
        policy.rewrite(&message, &format!("{user}x"), &database),
        Err(StartupRefusal::UserMismatch)
    );
});
