use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use jaunt::agent::SshAgent;
use jaunt::login::{KeyPlacement, LoginError};
use jaunt::loopback::LoopbackError;
use jaunt::status::Session;
use jaunt::store::ProfileStore;
use ssh_key::{Certificate, PrivateKey};

use crate::support::{
    API_TOKEN, Behavior, Browser, COMPLETION_CODE, EMAIL, FakeServer, SERIAL, Script, USER_ID,
    run_login,
};

const LONG: Duration = Duration::from_secs(30);
const SHORT: Duration = Duration::from_millis(400);

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn profile_store(home: &Path) -> ProfileStore {
    ProfileStore::new(home, &jaunt::profile::ProfileName::default_name())
}

fn assert_nothing_on_disk(home: &Path) {
    let leftovers: Vec<_> = match fs::read_dir(home) {
        Ok(entries) => entries
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name != ".default.lock")
            .collect(),
        Err(_) => Vec::new(),
    };
    let lock = home.join(".default.lock");
    assert!(!lock.exists() || fs::read(&lock).unwrap().is_empty());
    assert!(leftovers.is_empty(), "left on disk: {leftovers:?}");
}

#[test]
fn a_full_login_without_an_agent_stores_the_profile_and_puts_the_key_on_disk() {
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let browser = Browser::new(&server, Script::Approve);
    let outcome = run_login(&server, &home, &browser, &SshAgent::new(None), false, LONG);
    let report = outcome.result.unwrap();

    assert_eq!(report.email, EMAIL);
    assert_eq!(report.serial, 7);
    let KeyPlacement::Disk { path, reason } = &report.placement else {
        panic!("expected the key on disk, got {:?}", report.placement);
    };
    assert!(reason.contains("no ssh-agent is running"), "{reason}");
    let warnings = report.warnings();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        !warnings[0].contains('\n') && warnings[0].contains("0600"),
        "{}",
        warnings[0]
    );
    assert!(
        report
            .summary()
            .starts_with("Signed in as alice@example.com; certificate valid until ")
    );
    assert!(report.summary().ends_with("(serial 7)."));
    assert!(outcome.notices.is_empty(), "{}", outcome.notices);
    assert_eq!(browser.opened_urls().len(), 1);

    let store = profile_store(&home);
    assert_eq!(path, &store.private_key_path());
    assert_eq!(mode(&home), 0o700);
    assert_eq!(mode(store.dir()), 0o700);
    for name in [
        "server",
        "id_ed25519.pub",
        "id_ed25519-cert.pub",
        "token",
        "meta.json",
        "id_ed25519",
    ] {
        assert_eq!(mode(&store.dir().join(name)), 0o600, "{name}");
    }

    let public_line = server.seen(|seen| seen.public_key.clone()).unwrap();
    assert_eq!(store.read_public_key_line().unwrap().unwrap(), public_line);
    let private = PrivateKey::from_openssh(fs::read(store.private_key_path()).unwrap()).unwrap();
    assert_eq!(
        private.public_key().key_data(),
        ssh_key::PublicKey::from_openssh(&public_line)
            .unwrap()
            .key_data()
    );
    let certificate =
        Certificate::from_openssh(fs::read_to_string(store.certificate_path()).unwrap().trim())
            .unwrap();
    assert_eq!(certificate.serial(), SERIAL);
    assert_eq!(certificate.valid_principals(), [USER_ID.to_owned()]);
    assert_eq!(certificate.public_key(), private.public_key().key_data());

    let session = Session::load(&store).unwrap().unwrap();
    assert_eq!(session.server, server.server_url());
    assert_eq!(session.meta.email, EMAIL);
    assert_eq!(session.meta.host_ca_keys.len(), 1);
    assert_eq!(store.read_token().unwrap().unwrap().expose(), API_TOKEN);

    let verifier = server.seen(|seen| seen.verifier.clone()).unwrap();
    let mut stored_text = String::new();
    for entry in fs::read_dir(store.dir()).unwrap() {
        stored_text.push_str(&fs::read_to_string(entry.unwrap().path()).unwrap());
    }
    assert!(!stored_text.contains(COMPLETION_CODE));
    assert!(!stored_text.contains(&verifier));
    assert_eq!(
        server.seen(|seen| seen.challenge_method.clone()).as_deref(),
        Some("S256")
    );
    let label = server.seen(|seen| seen.label.clone()).unwrap();
    assert!(label.len() <= 64 && label.contains("(jaunt "), "{label}");
    assert!(server.redirect_port() >= 1024);
}

#[test]
fn a_callback_with_the_wrong_login_id_is_ignored_and_the_right_one_completes_the_login() {
    let server = FakeServer::start(Behavior::default());
    let home = tempfile::tempdir().unwrap();
    let browser = Browser::new(&server, Script::WrongThenApprove);
    let outcome = run_login(
        &server,
        home.path(),
        &browser,
        &SshAgent::new(None),
        false,
        LONG,
    );
    outcome.result.unwrap();
    let responses = browser.responses();
    assert_eq!(responses.len(), 2);
    assert!(
        responses[0].starts_with("HTTP/1.1 400 "),
        "{}",
        responses[0]
    );
    assert!(
        responses[1].starts_with("HTTP/1.1 200 OK"),
        "{}",
        responses[1]
    );
    assert_eq!(server.seen(|seen| seen.finish_calls), 1);
}

#[test]
fn an_error_callback_without_the_login_id_cannot_abort_the_login() {
    let server = FakeServer::start(Behavior::default());
    let home = tempfile::tempdir().unwrap();
    let browser = Browser::new(&server, Script::ErrorWithoutIdThenApprove);
    let outcome = run_login(
        &server,
        home.path(),
        &browser,
        &SshAgent::new(None),
        false,
        LONG,
    );
    outcome.result.unwrap();
    let responses = browser.responses();
    assert_eq!(responses.len(), 2);
    assert!(
        responses[0].starts_with("HTTP/1.1 400 "),
        "{}",
        responses[0]
    );
    assert!(
        responses[1].starts_with("HTTP/1.1 200 OK"),
        "{}",
        responses[1]
    );
}

#[test]
fn refusals_report_a_fixed_message_and_leave_nothing_on_disk() {
    let cases: Vec<(&str, Behavior, Script, &str)> = vec![
        (
            "access denied at the provider",
            Behavior::default(),
            Script::Deny("access_denied"),
            "sign-in was denied",
        ),
        (
            "any other provider error",
            Behavior::default(),
            Script::Deny("server_error"),
            "sign-in failed",
        ),
        (
            "invalid_grant on finish",
            Behavior {
                finish_error: Some("invalid_grant"),
                ..Behavior::default()
            },
            Script::Approve,
            "the sign-in request is no longer valid, run `jaunt login` again",
        ),
        (
            "busy on finish",
            Behavior {
                finish_error: Some("busy"),
                ..Behavior::default()
            },
            Script::Approve,
            "the server is busy, try again",
        ),
        (
            "certificate for the wrong principal",
            Behavior {
                principals: Some(vec!["someone-else".to_owned()]),
                ..Behavior::default()
            },
            Script::Approve,
            "the server returned a certificate with unexpected principals",
        ),
        (
            "certificate for a foreign key",
            Behavior {
                foreign_key: true,
                ..Behavior::default()
            },
            Script::Approve,
            "the server returned a certificate for a different key",
        ),
        (
            "unsafe sign-in address",
            Behavior {
                authorize_url: Some("javascript:alert(1)".to_owned()),
                ..Behavior::default()
            },
            Script::Silent,
            "the server sent a sign-in address that cannot be used safely",
        ),
        (
            "nobody completes the sign-in",
            Behavior::default(),
            Script::Silent,
            "timed out waiting for the browser sign-in",
        ),
    ];
    for (name, behavior, script, message) in cases {
        let server = FakeServer::start(behavior);
        let home = tempfile::tempdir().unwrap();
        let browser = Browser::new(&server, script);
        let outcome = run_login(
            &server,
            home.path(),
            &browser,
            &SshAgent::new(None),
            false,
            SHORT,
        );
        let err = outcome.result.unwrap_err();
        assert_eq!(err.to_string(), message, "{name}");
        assert_nothing_on_disk(home.path());
        if matches!(err, LoginError::BadAuthorizeUrl) {
            assert!(browser.opened_urls().is_empty(), "{name}");
        }
    }
}

#[test]
fn without_a_browser_or_when_it_cannot_open_the_address_is_printed_and_the_wait_continues() {
    let server = FakeServer::start(Behavior::default());
    let home = tempfile::tempdir().unwrap();
    let browser = Browser::new(&server, Script::Silent);
    let outcome = run_login(
        &server,
        home.path(),
        &browser,
        &SshAgent::new(None),
        true,
        SHORT,
    );
    assert!(matches!(
        outcome.result,
        Err(LoginError::Loopback(LoopbackError::TimedOut))
    ));
    assert!(browser.opened_urls().is_empty());
    assert!(
        outcome.notices.contains("http://127.0.0.1:"),
        "{}",
        outcome.notices
    );
    assert_nothing_on_disk(home.path());

    let server = FakeServer::start(Behavior::default());
    let home = tempfile::tempdir().unwrap();
    let browser = Browser::new(&server, Script::Approve).failing_to_open();
    let outcome = run_login(
        &server,
        home.path(),
        &browser,
        &SshAgent::new(None),
        false,
        LONG,
    );
    outcome.result.unwrap();
    assert!(
        outcome.notices.contains("cannot open a browser"),
        "{}",
        outcome.notices
    );
    assert!(
        outcome.notices.contains("http://127.0.0.1:"),
        "{}",
        outcome.notices
    );
}

#[test]
fn the_next_login_wipes_stale_staging_and_retired_directories_and_spares_fresh_ones() {
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    fs::create_dir_all(&home).unwrap();
    let session = |name: &str| {
        let dir = home.join(name);
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("token"), "jt_leftover").unwrap();
        fs::write(dir.join("id_ed25519"), "LEFTOVER-KEY\n").unwrap();
        dir
    };
    let stale_new = session(".default.new.1.1");
    let stale_old = session(".default.old.1.2");
    let running_login = session(".default.new.2.1");
    let other_profile = session(".other.new.1.1");
    let alias = root.path().join("alias");
    fs::hard_link(stale_new.join("id_ed25519"), &alias).unwrap();
    for dir in [&stale_new, &stale_old, &other_profile] {
        fs::File::open(dir)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(20 * 60))
            .unwrap();
    }

    let browser = Browser::new(&server, Script::Approve);
    let report = run_login(&server, &home, &browser, &SshAgent::new(None), false, LONG)
        .result
        .unwrap();
    assert!(report.notes.is_empty(), "{:?}", report.notes);
    assert!(!stale_new.exists() && !stale_old.exists());
    let wiped = fs::read(&alias).unwrap();
    assert_eq!(wiped.len(), "LEFTOVER-KEY\n".len());
    assert!(wiped.iter().all(|byte| *byte == 0));
    assert!(running_login.join("id_ed25519").exists());
    assert!(other_profile.join("id_ed25519").exists());
    assert!(home.join("default").join("server").exists());
}
