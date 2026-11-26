#![no_main]

use http::Method;
use jaunt_kube::{ApiRequest, Verb, classify};
use libfuzzer_sys::fuzz_target;

const METHODS: [&str; 8] = [
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT",
];

fn encode_every_byte(text: &str) -> String {
    text.bytes().map(|byte| format!("%{byte:02X}")).collect()
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let Ok(target) = std::str::from_utf8(rest) else {
        return;
    };
    let method = Method::from_bytes(METHODS[usize::from(selector) % METHODS.len()].as_bytes())
        .expect("a listed method is valid");
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    let request = classify(&method, path, query);
    if !path.contains('%') {
        assert_eq!(classify(&method, &encode_every_byte(path), query), request);
    }
    let ApiRequest::Resource(resource) = &request else {
        return;
    };
    assert_eq!(resource.is_watch(), resource.verb() == Verb::Watch);
    assert!(!resource.resource().is_empty());
    assert!(!resource.version().is_empty());
    for segment in [resource.namespace(), resource.name()]
        .into_iter()
        .flatten()
    {
        assert!(!segment.is_empty());
        assert!(!segment.chars().any(|ch| ch.is_control() || ch == '/'));
    }
    if matches!(
        resource.verb(),
        Verb::Exec | Verb::Attach | Verb::PortForward | Verb::Log
    ) {
        assert_eq!(resource.group(), "");
        assert_eq!(resource.resource(), "pods");
        assert!(resource.namespace().is_some() && resource.name().is_some());
    }
    if matches!(
        resource.verb(),
        Verb::Exec | Verb::Attach | Verb::PortForward
    ) {
        assert!(resource.is_upgrade_candidate());
    }
});
