#![no_main]

use std::sync::OnceLock;

use jaunt_gate::{EntryNames, MAX_CLIENT_HELLO_BYTES, SniClass, parse_client_hello};
use libfuzzer_sys::fuzz_target;

const DOMAIN: &str = "svc.example.com";
const AGENTS: &str = "agents.example.com";

fn names() -> &'static EntryNames {
    static NAMES: OnceLock<EntryNames> = OnceLock::new();
    NAMES.get_or_init(|| {
        EntryNames::new(&[AGENTS.to_owned()], Some(DOMAIN)).expect("the fixed names are valid")
    })
}

fn bare(name: &str) -> String {
    let lowered = name.to_ascii_lowercase();
    lowered.strip_suffix('.').unwrap_or(&lowered).to_owned()
}

fn check(name: Option<&str>) {
    match (names().classify(name), name) {
        (SniClass::Missing, given) => assert!(given.is_none()),
        (SniClass::Gate, Some(given)) => assert_eq!(bare(given), DOMAIN),
        (SniClass::Kube(cluster), Some(given)) => {
            assert!(!cluster.is_empty() && cluster.len() <= 63);
            assert!(!cluster.contains('.'));
            assert_eq!(bare(given), format!("{cluster}.kube.{DOMAIN}"));
        }
        (SniClass::Agents, Some(given)) => {
            assert_eq!(given.trim_end_matches('.').to_ascii_lowercase(), AGENTS);
        }
        (SniClass::Unknown, Some(_)) => {}
        (class, None) => panic!("{class:?} without a server name"),
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(hello) = parse_client_hello(data) {
        assert!(hello.bytes().len() <= MAX_CLIENT_HELLO_BYTES);
        assert!(data.starts_with(hello.bytes()));
        check(hello.info().server_name());
    }
    if let Ok(text) = std::str::from_utf8(data) {
        check(Some(text));
    }
});
