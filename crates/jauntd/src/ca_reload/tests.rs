use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jaunt_ca::TrustSet;
use jaunt_ca::ssh_key::rand_core::OsRng;
use jaunt_ca::ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey};
use jaunt_ssh::UserCaKeys;
use jaunt_tunnel::{NodeId, SendError, TrustBroadcast};
use tracing_subscriber::fmt::MakeWriter;

use super::{
    FAILURE_QUIET, FailureLog, MAX_REASON_CHARS, RELOAD_INTERVAL, gate_trust, report_broadcast,
    truncated,
};
use crate::logging::{build_filter, subscriber};

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000 + secs)
}

#[test]
fn a_failure_is_reported_once_per_reason_and_minute() {
    let mut log = FailureLog::default();
    let quiet = FAILURE_QUIET.as_secs();
    for (now, reason, reported) in [
        (0, "broken", true),
        (10, "broken", false),
        (20, "other", true),
        (quiet - 1, "broken", false),
        (quiet, "broken", true),
        (quiet + 10, "other", false),
        (quiet + 20, "other", true),
        (quiet + 30, "broken", false),
        (5, "broken", true),
    ] {
        assert_eq!(log.admit(reason, at(now)), reported, "{now} {reason}");
    }
}

#[test]
fn recovery_forgets_the_reported_failures() {
    let mut log = FailureLog::default();
    assert!(log.admit("broken", at(0)));
    assert!(!log.admit("broken", at(10)));
    log.clear();
    assert!(log.admit("broken", at(20)));
}

#[test]
fn reasons_are_cut_on_a_character_boundary() {
    let long = "\u{e9}".repeat(MAX_REASON_CHARS + 50);
    assert_eq!(truncated(&long).chars().count(), MAX_REASON_CHARS);
    assert_eq!(truncated("short"), "short");
}

#[test]
fn the_watcher_keeps_the_promise_printed_by_the_ca_commands() {
    assert!(RELOAD_INTERVAL <= Duration::from_secs(10));
    assert!(crate::ca_rotation::LAST_LINE.ends_with("within 10 s"));
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl MakeWriter<'_> for Captured {
    type Writer = Captured;

    fn make_writer(&self) -> Captured {
        self.clone()
    }
}

#[test]
fn agents_that_missed_the_update_are_named_in_a_warning() {
    let captured = Captured::default();
    let _guard = tracing::subscriber::set_default(subscriber(
        build_filter(None).unwrap(),
        captured.clone(),
        None,
    ));

    let sent = report_broadcast(&TrustBroadcast {
        sent: 2,
        failed: vec![
            (NodeId::new("node-busy").unwrap(), SendError::Backlogged),
            (NodeId::new("node-gone").unwrap(), SendError::Closed),
        ],
    });

    assert_eq!(sent, 2);
    let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    let warning = text
        .lines()
        .find(|line| line.contains("\"level\":\"WARN\""))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(warning.contains("\"failed\":2"), "{warning}");
    assert!(
        warning.contains("node-busy: control queue of the agent is full"),
        "{warning}"
    );
    assert!(
        warning.contains("node-gone: connection to the agent is closed"),
        "{warning}"
    );
}

fn trust(keys: &[&PublicKey], active: &PublicKey) -> TrustSet {
    TrustSet::new(
        keys.iter().map(|key| (*key).clone()).collect(),
        active.fingerprint(HashAlg::Sha256),
    )
    .unwrap()
}

fn gate_keys(keys: &[&PublicKey]) -> UserCaKeys {
    UserCaKeys::from_openssh_lines(keys.iter().map(|key| key.to_openssh().unwrap())).unwrap()
}

#[test]
fn the_gate_trusts_old_and_new_keys_while_the_signer_is_swapped_and_only_new_ones_after() {
    let [a, b] = [(), ()].map(|()| {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone()
    });
    let narrowed = gate_trust(&trust(&[&a, &b], &a), &trust(&[&b], &b)).unwrap();
    assert_eq!(narrowed.during, gate_keys(&[&b, &a]));
    assert_eq!(narrowed.after, gate_keys(&[&b]));

    let widened = gate_trust(&trust(&[&a], &a), &trust(&[&a, &b], &a)).unwrap();
    let both = trust(&[&a, &b], &a);
    let ordered: Vec<&PublicKey> = both.keys().iter().collect();
    assert_eq!(widened.during, gate_keys(&ordered));
    assert_eq!(widened.after, gate_keys(&ordered));
}
