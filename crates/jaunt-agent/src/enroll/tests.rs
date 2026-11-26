use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ssh_key::{HashAlg, PublicKey};

use super::client::CallError;
use super::{EnrollEnv, EnrollError, EnrollOptions, enroll, jittered, poll_interval, system_env};
use crate::clock::{format_utc, unix_secs};
use crate::keys::sha256_hex;
use crate::state::StateError;
use crate::state::{EnrollmentRecord, LOCK_FILE, StateDir, previous_dirs};
use crate::testkit::{
    Approval, CODE, ControlScript, EXPIRES_AT, FakeControl, HANDLE, ManualClock, NODE_ID,
    NODE_NAME, PollStep, TestPki,
};
use crate::verify::{VerifyError, node_identity};

const FILES: [&str; 6] = [
    "tls.key",
    "ssh_host_ed25519",
    "x509.der",
    "ssh_host_ed25519-cert.pub",
    "ca-root.der",
    "state.json",
];

struct Outcome {
    result: Result<(), EnrollError>,
    out: String,
    err: String,
    slept: Vec<Duration>,
}

fn options(control: &FakeControl, dir: &Path) -> EnrollOptions {
    EnrollOptions {
        server: control.url.parse().unwrap(),
        name: NODE_NAME.to_owned(),
        labels: BTreeMap::from([("env".to_owned(), "prod".to_owned())]),
        replace: false,
        ca_pin: None,
        state_dir: dir.to_path_buf(),
        hostname: "web-01.example.com".to_owned(),
        timeout: Duration::from_secs(900),
        join_token: None,
    }
}

async fn run_enroll(options: &EnrollOptions) -> Outcome {
    let clock = ManualClock::auto(SystemTime::now());
    let mut jitter = || 0.5;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let result = enroll(
        options,
        &mut EnrollEnv {
            privileged: false,
            clock: &*clock,
            jitter: &mut jitter,
            out: &mut out,
            err: &mut err,
        },
    )
    .await;
    Outcome {
        result,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
        slept: clock.slept(),
    }
}

async fn control(script: ControlScript) -> (Arc<TestPki>, FakeControl) {
    let pki = Arc::new(TestPki::new());
    let control = FakeControl::start(pki.clone(), script).await;
    (pki, control)
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name != LOCK_FILE)
        .collect();
    names.sort();
    names
}

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    FILES
        .iter()
        .map(|name| ((*name).to_owned(), fs::read(dir.join(name)).unwrap()))
        .collect()
}

#[tokio::test]
async fn an_approved_enrollment_stores_private_files_and_prints_only_the_code_and_fingerprints() {
    let (pki, control) = control(ControlScript::new(&[
        PollStep::Pending,
        PollStep::Pending,
        PollStep::Approve(Approval::Valid),
    ]))
    .await;
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let options = options(&control, &state_dir);

    let outcome = run_enroll(&options).await;
    outcome.result.unwrap();

    let request = control.enrolls().pop().unwrap();
    assert_eq!(request.name, NODE_NAME);
    assert_eq!(request.labels["env"], "prod");
    assert_eq!(request.hostname, "web-01.example.com");
    assert!(!request.replace);
    assert_eq!(request.agent_version, crate::AGENT_VERSION);
    assert_eq!(control.polls(), [HANDLE, HANDLE, HANDLE]);
    assert_eq!(outcome.slept, [Duration::from_secs(3); 3]);

    let spki = STANDARD.decode(&request.tls_public_key).unwrap();
    let ssh_fingerprint = PublicKey::from_openssh(&request.ssh_host_public_key)
        .unwrap()
        .fingerprint(HashAlg::Sha256)
        .to_string();
    let expected = format!(
        "code:         {CODE}\n\
         tls key:      sha256:{}\n\
         ssh host key: {ssh_fingerprint}\n\
         expires at:   {}\n\
         An administrator must run `jauntd node approve {CODE}` on the server and check that both fingerprints match.\n",
        sha256_hex(&spki),
        format_utc(EXPIRES_AT),
    );
    assert_eq!(outcome.out, expected);

    assert_eq!(mode_of(&state_dir), 0o700);
    assert_eq!(entries(&state_dir), {
        let mut sorted = FILES.map(str::to_owned).to_vec();
        sorted.sort();
        sorted
    });
    for name in FILES {
        assert_eq!(mode_of(&state_dir.join(name)), 0o600, "{name}");
    }
    assert_eq!(
        fs::read(state_dir.join("ca-root.der")).unwrap(),
        pki.root_der()
    );

    let record: EnrollmentRecord =
        serde_json::from_slice(&fs::read(state_dir.join("state.json")).unwrap()).unwrap();
    let x509 = fs::read(state_dir.join("x509.der")).unwrap();
    let validity = node_identity(&x509, NODE_ID, &spki).unwrap();
    assert_eq!(record.node_id, NODE_ID);
    assert_eq!(record.name, NODE_NAME);
    assert_eq!(record.server_url, control.url);
    assert_eq!(record.agent_endpoint, "agents.jaunt.test:443");
    assert_eq!(record.x509_not_after, validity.not_after);
    assert!(record.ssh_not_after > record.enrolled_at);
    assert!((record.enrolled_at - unix_secs(SystemTime::now())).abs() < 60);
    let loaded = StateDir::open(&state_dir, false).unwrap().load().unwrap();
    assert_eq!(loaded.tls_key.spki_der(), spki.as_slice());

    let tls_key = fs::read(state_dir.join("tls.key")).unwrap();
    let host_key = fs::read_to_string(state_dir.join("ssh_host_ed25519")).unwrap();
    let host_body: String = host_key
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    for text in [&outcome.out, &outcome.err] {
        assert!(!text.contains(HANDLE));
        assert!(!text.contains(&STANDARD.encode(&tls_key)));
        assert!(!text.contains(&host_body[..32]));
        assert!(!text.contains("PRIVATE KEY"));
    }
    assert!(!outcome.err.contains(CODE));
    assert!(outcome.err.contains(NODE_ID));
}

#[tokio::test]
async fn terminal_answers_and_the_local_timeout_store_nothing() {
    let cases: [(&[PollStep], &str); 5] = [
        (&[PollStep::Rejected], "rejected"),
        (&[PollStep::Expired], "expired"),
        (&[PollStep::AlreadyDelivered], "--replace"),
        (&[PollStep::NotFound], "no longer knows"),
        (&[], "within 10 seconds"),
    ];
    for (steps, phrase) in cases {
        let (_pki, control) = control(ControlScript::new(steps)).await;
        let dir = tempfile::tempdir().unwrap();
        let mut options = options(&control, dir.path());
        options.timeout = Duration::from_secs(10);
        let outcome = run_enroll(&options).await;
        let error = outcome.result.unwrap_err();
        let shown = error.to_string();
        assert!(shown.contains(phrase), "{phrase}: {shown}");
        assert!(!shown.contains(HANDLE) && !shown.contains(CODE), "{shown}");
        assert!(entries(dir.path()).is_empty(), "{phrase}");
        if steps.is_empty() {
            assert!(matches!(error, EnrollError::TimedOut { secs: 10 }));
            assert_eq!(control.polls().len(), 3);
        }
    }
}

#[tokio::test]
async fn a_rate_limited_poll_waits_ten_seconds_and_continues() {
    let (_pki, control) = control(ControlScript::new(&[
        PollStep::TooMany,
        PollStep::Approve(Approval::Valid),
    ]))
    .await;
    let dir = tempfile::tempdir().unwrap();
    let outcome = run_enroll(&options(&control, dir.path())).await;
    outcome.result.unwrap();
    assert_eq!(
        outcome.slept,
        [Duration::from_secs(3), Duration::from_secs(10)]
    );
}

#[tokio::test]
async fn enrollment_request_refusals_are_explained() {
    for (status, code, expected) in [
        (StatusCode::CONFLICT, "name_taken", "--replace"),
        (
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_requests",
            "rate limiting",
        ),
        (StatusCode::BAD_REQUEST, "invalid_labels", "invalid_labels"),
    ] {
        let mut script = ControlScript::new(&[]);
        script.enroll_status = status;
        script.enroll_error = code;
        let (_pki, control) = control(script).await;
        let dir = tempfile::tempdir().unwrap();
        let outcome = run_enroll(&options(&control, dir.path())).await;
        let shown = outcome.result.unwrap_err().to_string();
        assert!(shown.contains(expected), "{shown}");
        assert!(outcome.out.is_empty());
        assert!(entries(dir.path()).is_empty());
    }
}

#[tokio::test]
async fn the_ca_pin_must_match_the_delivered_root_before_anything_is_stored() {
    for matching in [true, false] {
        let (pki, control) =
            control(ControlScript::new(&[PollStep::Approve(Approval::Valid)])).await;
        let dir = tempfile::tempdir().unwrap();
        let mut options = options(&control, dir.path());
        let pinned = if matching {
            sha256_hex(pki.root_der())
        } else {
            sha256_hex(b"another root")
        };
        options.ca_pin = Some(format!("sha256:{pinned}").parse().unwrap());
        let outcome = run_enroll(&options).await;
        if matching {
            outcome.result.unwrap();
            assert_eq!(entries(dir.path()).len(), FILES.len());
        } else {
            assert!(matches!(outcome.result, Err(EnrollError::PinMismatch)));
            assert!(entries(dir.path()).is_empty());
        }
    }
}

#[tokio::test]
async fn invalid_certificates_are_refused_and_nothing_is_stored() {
    for (approval, expected) in [
        (Approval::OtherKey, VerifyError::CertificateKey),
        (Approval::WrongNode, VerifyError::CertificateNode),
        (Approval::Expired, VerifyError::CertificateTime),
        (Approval::BadHostCertificate, VerifyError::HostCertificate),
    ] {
        let (_pki, control) = control(ControlScript::new(&[PollStep::Approve(approval)])).await;
        let dir = tempfile::tempdir().unwrap();
        let outcome = run_enroll(&options(&control, dir.path())).await;
        match outcome.result {
            Err(EnrollError::Verify(actual)) => assert_eq!(actual, expected, "{approval:?}"),
            other => panic!("{approval:?}: {other:?}"),
        }
        assert!(entries(dir.path()).is_empty(), "{approval:?}");
    }
}

#[tokio::test]
async fn an_existing_enrollment_is_replaced_only_with_replace_and_only_after_success() {
    let (_pki, control) = control(ControlScript::new(&[PollStep::Approve(Approval::Valid)])).await;
    let dir = tempfile::tempdir().unwrap();
    let mut options = options(&control, dir.path());
    run_enroll(&options).await.result.unwrap();
    let first = snapshot(dir.path());

    let refused = run_enroll(&options).await;
    assert!(matches!(
        refused.result,
        Err(EnrollError::AlreadyEnrolled { .. })
    ));
    assert_eq!(control.enrolls().len(), 1);
    assert_eq!(snapshot(dir.path()), first);

    options.replace = true;
    let (_pki, rejecting) = control_with_steps(&[PollStep::Rejected]).await;
    options.server = rejecting.url.parse().unwrap();
    assert!(matches!(
        run_enroll(&options).await.result,
        Err(EnrollError::Rejected)
    ));
    assert_eq!(snapshot(dir.path()), first);
    assert_eq!(entries(dir.path()).len(), FILES.len());

    let (_pki, approving) = control_with_steps(&[PollStep::Approve(Approval::Valid)]).await;
    options.server = approving.url.parse().unwrap();
    let replaced = run_enroll(&options).await;
    replaced.result.unwrap();
    assert!(approving.enrolls()[0].replace);
    let previous: Vec<String> = entries(dir.path())
        .into_iter()
        .filter(|name| name.starts_with("previous-"))
        .collect();
    assert_eq!(previous.len(), 1);
    let moved = dir.path().join(&previous[0]);
    assert_eq!(mode_of(&moved), 0o700);
    assert_eq!(snapshot(&moved), first);
    assert_ne!(snapshot(dir.path()), first);
    assert!(replaced.err.contains(&previous[0]));
}

async fn control_with_steps(steps: &[PollStep]) -> (Arc<TestPki>, FakeControl) {
    control(ControlScript::new(steps)).await
}

#[tokio::test]
async fn a_failing_write_leaves_no_state_json() {
    let (_pki, control) = control(ControlScript::new(&[PollStep::Approve(Approval::Valid)])).await;
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir
        .path()
        .join(format!(".ca-root.der.{}.tmp", std::process::id()));
    fs::create_dir(&blocker).unwrap();
    fs::write(blocker.join("keep"), b"x").unwrap();

    let outcome = run_enroll(&options(&control, dir.path())).await;
    let error = outcome.result.unwrap_err();
    assert!(matches!(error, EnrollError::Store(_)), "{error}");
    assert!(error.to_string().contains("--replace"));
    assert!(dir.path().join("x509.der").exists());
    assert!(!dir.path().join("ca-root.der").exists());
    assert!(!dir.path().join("state.json").exists());
}

#[tokio::test]
async fn a_failing_write_under_replace_says_where_the_old_files_went() {
    let (_pki, control) = control(ControlScript::new(&[PollStep::Approve(Approval::Valid)])).await;
    let dir = tempfile::tempdir().unwrap();
    let mut options = options(&control, dir.path());
    run_enroll(&options).await.result.unwrap();
    let (_pki, again) = control_with_steps(&[PollStep::Approve(Approval::Valid)]).await;
    options.server = again.url.parse().unwrap();
    options.replace = true;
    let blocker = dir
        .path()
        .join(format!(".ca-root.der.{}.tmp", std::process::id()));
    fs::create_dir(&blocker).unwrap();
    fs::write(blocker.join("keep"), b"x").unwrap();

    let error = run_enroll(&options).await.result.unwrap_err();
    let previous = previous_dirs(dir.path());
    assert_eq!(previous.len(), 1);
    assert!(matches!(error, EnrollError::Store(_)), "{error}");
    assert!(error.to_string().contains(&previous[0]), "{error}");
    assert!(dir.path().join(&previous[0]).join("state.json").exists());
}

#[tokio::test]
async fn an_enrollment_that_appears_while_polling_is_not_moved_without_replace() {
    let dir = tempfile::tempdir().unwrap();
    let mut script = ControlScript::new(&[PollStep::Pending, PollStep::Approve(Approval::Valid)]);
    script.create_on_first_poll = Some(dir.path().join("state.json"));
    let (_pki, control) = control(script).await;

    let outcome = run_enroll(&options(&control, dir.path())).await;
    let error = outcome.result.unwrap_err();
    assert!(
        matches!(error, EnrollError::EnrolledMeanwhile { .. }),
        "{error}"
    );
    assert!(error.to_string().contains("--replace"));
    assert_eq!(entries(dir.path()), ["state.json"]);
    assert_eq!(fs::read(dir.path().join("state.json")).unwrap(), b"{}");
}

#[tokio::test]
async fn a_symlinked_state_directory_is_refused_before_any_request() {
    let (_pki, control) = control(ControlScript::new(&[PollStep::Approve(Approval::Valid)])).await;
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::write(real.join("state.json"), b"{}").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let with_slash = std::path::PathBuf::from(format!("{}/", link.display()));
    for path in [&link, &with_slash] {
        let mut options = options(&control, path);
        options.replace = true;
        let error = run_enroll(&options).await.result.unwrap_err();
        assert!(error.to_string().contains("symbolic link"), "{error}");
        let error = run_enroll(&self::options(&control, path))
            .await
            .result
            .unwrap_err();
        assert!(error.to_string().contains("symbolic link"), "{error}");
    }
    assert!(control.enrolls().is_empty());
    assert_eq!(entries(&real), ["state.json"]);
}

#[tokio::test]
async fn a_foreign_state_directory_is_refused_before_any_request() {
    let (_pki, control) = control(ControlScript::new(&[PollStep::Approve(Approval::Valid)])).await;
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("tls.key.bak"), b"someone else's").unwrap();
    let outcome = run_enroll(&options(&control, dir.path())).await;
    let error = outcome.result.unwrap_err();
    assert!(error.to_string().contains("did not write"), "{error}");
    assert!(control.enrolls().is_empty());
    assert!(outcome.out.is_empty());
    assert_eq!(entries(dir.path()), ["tls.key.bak"]);
    assert!(!dir.path().join(LOCK_FILE).exists());
}

#[tokio::test]
async fn an_agent_endpoint_that_is_not_host_and_port_is_refused() {
    let mut script = ControlScript::new(&[PollStep::Approve(Approval::Valid)]);
    script.agent_endpoint = "Bad Host:443".to_owned();
    let (_pki, control) = control(script).await;
    let dir = tempfile::tempdir().unwrap();
    let outcome = run_enroll(&options(&control, dir.path())).await;
    assert!(matches!(outcome.result, Err(EnrollError::Endpoint)));
    assert!(entries(dir.path()).is_empty());
}

#[tokio::test]
async fn an_oversized_poll_reply_is_refused_and_nothing_is_stored() {
    let (_pki, control) = control(ControlScript::new(&[PollStep::Oversized])).await;
    let dir = tempfile::tempdir().unwrap();
    let outcome = run_enroll(&options(&control, dir.path())).await;
    assert!(
        matches!(
            outcome.result,
            Err(EnrollError::Poll(CallError::BodyTooLarge))
        ),
        "{:?}",
        outcome.result
    );
    assert!(entries(dir.path()).is_empty());
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let (_pki, target) = control(ControlScript::new(&[])).await;
    let mut script = ControlScript::new(&[]);
    script.redirect_to = Some(format!("{}/v1/agent/enroll", target.url));
    let (_pki, redirecting) = control(script).await;
    let dir = tempfile::tempdir().unwrap();
    let outcome = run_enroll(&options(&redirecting, dir.path())).await;
    assert!(
        matches!(
            outcome.result,
            Err(EnrollError::Request(CallError::Status { status: 302, .. }))
        ),
        "{:?}",
        outcome.result
    );
    assert!(target.enrolls().is_empty());
    assert_eq!(redirecting.enrolls().len(), 1);
}

#[tokio::test]
async fn a_temporary_server_error_while_polling_is_retried() {
    let (_pki, control) = control(ControlScript::new(&[
        PollStep::Unavailable,
        PollStep::Approve(Approval::Valid),
    ]))
    .await;
    let dir = tempfile::tempdir().unwrap();
    let outcome = run_enroll(&options(&control, dir.path())).await;
    outcome.result.unwrap();
    assert_eq!(control.polls().len(), 2);
    assert!(outcome.err.contains("HTTP 503"), "{}", outcome.err);
}

#[tokio::test]
async fn codes_that_cannot_be_shown_safely_print_nothing() {
    for code in ["ABCD\u{1b}[2J-2345".to_owned(), "A".repeat(33)] {
        let mut script = ControlScript::new(&[PollStep::Approve(Approval::Valid)]);
        script.code = Some(code.clone());
        let (_pki, control) = control(script).await;
        let dir = tempfile::tempdir().unwrap();
        let outcome = run_enroll(&options(&control, dir.path())).await;
        assert!(
            matches!(outcome.result, Err(EnrollError::BadCode)),
            "{code:?}"
        );
        assert!(outcome.out.is_empty(), "{code:?}");
        assert!(control.polls().is_empty());
    }
}

struct ClosedStream;

impl Write for ClosedStream {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

#[tokio::test]
async fn a_closed_stderr_does_not_turn_a_stored_enrollment_into_a_failure() {
    let (_pki, control) = control(ControlScript::new(&[
        PollStep::Unavailable,
        PollStep::Approve(Approval::Valid),
    ]))
    .await;
    let dir = tempfile::tempdir().unwrap();
    let mut options = options(&control, dir.path());
    options.replace = true;
    fs::write(dir.path().join("tls.key"), b"leftover").unwrap();
    let clock = ManualClock::auto(SystemTime::now());
    let mut jitter = || 0.5;
    let mut out = Vec::new();
    enroll(
        &options,
        &mut EnrollEnv {
            privileged: false,
            clock: &*clock,
            jitter: &mut jitter,
            out: &mut out,
            err: &mut ClosedStream,
        },
    )
    .await
    .unwrap();
    assert!(dir.path().join("state.json").exists());
}

#[test]
fn poll_intervals_are_clamped_and_jitter_stays_within_twenty_percent() {
    assert_eq!(poll_interval(0), Duration::from_secs(2));
    assert_eq!(poll_interval(3), Duration::from_secs(3));
    assert_eq!(poll_interval(u32::MAX), Duration::from_secs(60));
    let interval = Duration::from_secs(10);
    for (sample, expected) in [
        (0.0, 8_000),
        (0.5, 10_000),
        (1.0, 12_000),
        (-4.0, 8_000),
        (9.0, 12_000),
        (f64::NAN, 12_000),
    ] {
        assert_eq!(
            jittered(interval, sample),
            Duration::from_millis(expected),
            "{sample}"
        );
    }
}

#[test]
fn the_system_hostname_is_used_only_when_it_is_presentable() {
    use clap::Parser;

    #[derive(Parser)]
    struct Wrapper {
        #[command(flatten)]
        args: super::EnrollArgs,
    }

    let parsed = Wrapper::try_parse_from([
        "enroll",
        "--server",
        "https://jaunt.example.com",
        "--name",
        "web-01",
    ])
    .unwrap();
    let from_system =
        EnrollOptions::from_args(&parsed.args, || Ok("node-7.example.com".into())).unwrap();
    assert_eq!(from_system.hostname, "node-7.example.com");
    assert_eq!(from_system.timeout, Duration::from_secs(900));
    assert_eq!(
        from_system.state_dir,
        std::path::PathBuf::from("/var/lib/jaunt")
    );
    for bad in ["", "has space"] {
        assert!(matches!(
            EnrollOptions::from_args(&parsed.args, || Ok(bad.into())),
            Err(EnrollError::Hostname { .. })
        ));
    }
    assert!(matches!(
        EnrollOptions::from_args(&parsed.args, || Err(std::io::Error::other("boom"))),
        Err(EnrollError::Hostname { .. })
    ));
}

#[tokio::test]
async fn a_second_enrollment_while_the_first_waits_for_approval_is_refused() {
    let (_pki, control) = control(ControlScript::new(&[])).await;
    let dir = tempfile::tempdir().unwrap();
    let options = options(&control, dir.path());
    let waiting_clock = ManualClock::new(SystemTime::now());
    let mut jitter = || 0.5;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut env = EnrollEnv {
        privileged: false,
        clock: &*waiting_clock,
        jitter: &mut jitter,
        out: &mut out,
        err: &mut err,
    };
    let first = enroll(&options, &mut env);
    tokio::pin!(first);
    let second = async {
        crate::testkit::eventually("the first request", || control.enrolls().len() == 1).await;
        run_enroll(&options).await
    };
    let outcome = tokio::select! {
        finished = &mut first => panic!("the first enrollment ended: {finished:?}"),
        outcome = second => outcome,
    };
    assert!(
        matches!(
            outcome.result,
            Err(EnrollError::Prepare(StateError::Busy { .. }))
        ),
        "{:?}",
        outcome.result
    );
    assert!(outcome.out.is_empty());
    assert_eq!(control.enrolls().len(), 1);
}

#[test]
fn the_production_environment_is_privileged_exactly_when_running_as_root() {
    let mut jitter = || 0.5;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let env = system_env(&mut jitter, &mut out, &mut err);
    assert_eq!(env.privileged, rustix::process::geteuid().is_root());
}

const JOIN_TOKEN: &str = "jt1.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG";

fn token_file(dir: &Path, mode: u32) -> std::path::PathBuf {
    let path = dir.join("join-token");
    fs::write(&path, format!("{JOIN_TOKEN}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn with_token(control: &FakeControl, state_dir: &Path, token_dir: &Path) -> EnrollOptions {
    let mut options = options(control, state_dir);
    let path = token_file(token_dir, 0o600);
    options.join_token =
        Some(super::token::read_token_file(&path, crate::fsio::effective_uid()).unwrap());
    options
}

#[tokio::test]
async fn a_join_token_enrols_without_a_code_and_never_appears_in_the_output() {
    let mut script = ControlScript::new(&[PollStep::Approve(Approval::Valid)]);
    script.join_token = Some(JOIN_TOKEN.to_owned());
    let (_pki, control) = control(script).await;
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");

    let outcome = run_enroll(&with_token(&control, &state_dir, dir.path())).await;

    outcome.result.unwrap();
    let request = control.enrolls().pop().unwrap();
    assert_eq!(request.join_token.as_deref(), Some(JOIN_TOKEN));
    assert!(!format!("{request:?}").contains(JOIN_TOKEN));
    assert_eq!(control.polls(), [HANDLE]);
    let spki = STANDARD.decode(&request.tls_public_key).unwrap();
    let ssh_fingerprint = PublicKey::from_openssh(&request.ssh_host_public_key)
        .unwrap()
        .fingerprint(HashAlg::Sha256)
        .to_string();
    assert_eq!(
        outcome.out,
        format!(
            "tls key:      sha256:{}\nssh host key: {ssh_fingerprint}\nexpires at:   {}\n",
            sha256_hex(&spki),
            format_utc(EXPIRES_AT)
        )
    );
    for text in [&outcome.out, &outcome.err] {
        assert!(!text.contains(JOIN_TOKEN), "{text}");
        assert!(!text.contains(HANDLE));
    }
    assert!(
        outcome.err.contains("join token was accepted"),
        "{}",
        outcome.err
    );
    assert_eq!(entries(&state_dir), {
        let mut sorted = FILES.map(str::to_owned).to_vec();
        sorted.sort();
        sorted
    });
}

#[tokio::test]
async fn a_refused_join_token_is_explained_without_showing_it_and_nothing_is_stored() {
    let mut script = ControlScript::new(&[PollStep::Approve(Approval::Valid)]);
    script.join_token = Some("jt1.another".to_owned());
    let (_pki, control) = control(script).await;
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");

    let outcome = run_enroll(&with_token(&control, &state_dir, dir.path())).await;

    let error = outcome.result.unwrap_err();
    assert!(matches!(error, EnrollError::TokenRefused), "{error}");
    assert!(!error.to_string().contains(JOIN_TOKEN));
    assert!(outcome.out.is_empty());
    assert!(!outcome.err.contains(JOIN_TOKEN));
    assert!(control.polls().is_empty());
    assert!(entries(&state_dir).is_empty());
}

#[tokio::test]
async fn a_server_that_answers_a_codeless_enrolment_without_a_token_is_not_trusted() {
    let mut script = ControlScript::new(&[PollStep::Approve(Approval::Valid)]);
    script.code = None;
    let (_pki, control) = control(script).await;
    let dir = tempfile::tempdir().unwrap();

    let outcome = run_enroll(&options(&control, dir.path())).await;

    assert!(matches!(outcome.result, Err(EnrollError::BadCode)));
    assert!(outcome.out.is_empty());
    assert!(control.polls().is_empty());
}

#[test]
fn the_join_token_comes_only_from_a_private_file_named_on_the_command_line() {
    use clap::{CommandFactory, Parser};

    #[derive(Parser)]
    struct Wrapper {
        #[command(flatten)]
        args: super::EnrollArgs,
    }

    let dir = tempfile::tempdir().unwrap();
    let private = token_file(dir.path(), 0o600);
    let parse = |path: &Path| {
        Wrapper::try_parse_from([
            "enroll".as_ref(),
            "--server".as_ref(),
            "https://jaunt.example.com".as_ref(),
            "--name".as_ref(),
            "web-01".as_ref(),
            "--token-file".as_ref(),
            path.as_os_str(),
        ])
        .unwrap()
    };
    let parsed = parse(&private);
    let options = EnrollOptions::from_args(&parsed.args, || Ok("web-01".into())).unwrap();
    assert_eq!(
        options.join_token.as_ref().map(|token| token.expose()),
        Some(JOIN_TOKEN)
    );

    let shared = dir.path().join("shared");
    fs::write(&shared, JOIN_TOKEN).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o644)).unwrap();
    let refused = EnrollOptions::from_args(&parse(&shared).args, || Ok("web-01".into()));
    let Err(error) = refused else {
        panic!("a readable token file was accepted");
    };
    assert!(matches!(error, EnrollError::TokenFile(_)), "{error}");
    assert!(!error.to_string().contains(JOIN_TOKEN));

    for flag in ["--token", "--join-token"] {
        assert!(
            Wrapper::try_parse_from([
                "enroll",
                "--server",
                "https://jaunt.example.com",
                "--name",
                "web-01",
                flag,
                JOIN_TOKEN,
            ])
            .is_err(),
            "{flag}"
        );
    }
    assert!(
        Wrapper::command()
            .get_arguments()
            .all(|arg| arg.get_env().is_none())
    );
}
