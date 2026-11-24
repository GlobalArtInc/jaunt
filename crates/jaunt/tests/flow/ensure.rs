use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use jaunt::agent::SshAgent;
use jaunt::commands::{EnsureArgs, Environment, run_ensure_with};
use jaunt::ensure::{EnsureError, EnsureIo, Freshness, RenewOptions, Renewed, check, renew};
use jaunt::lock::{LockError, ProfileLock};
use jaunt::login::{LoginError, LoginPorts, SshSetup, login, login_with_lock};
use jaunt::profile::ProfileName;
use jaunt::ssh_config::{EnsureCommand, HEADER, SshConfigError, render_ssh_config, validate};
use jaunt::ssh_include::{IncludeTarget, include_line};
use jaunt::store::ProfileStore;
use jaunt_proto::{ClientConfig, GateEndpoint};
use serde_json::json;

use crate::cli::{base_command, jaunt, stderr, stdout, write_profile};
use crate::support::{
    Behavior, Browser, COMPLETION_CODE, CertSpec, ClientConfigReply, FakeServer, GATE_HOST,
    GATE_PORT, LOGIN_ID, LoginSetup, SUFFIX, Script, ScriptedPrompt, ca_key, new_key_data,
    now_secs, run_login, run_login_setup, serial_section, sign, visit, write_script,
};

const LONG: Duration = Duration::from_secs(30);
const WAITING: &str = "is in progress; waiting for it to finish";

#[derive(Clone, Default)]
struct SharedNotices(Arc<Mutex<Vec<u8>>>);

impl SharedNotices {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl Write for SharedNotices {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        thread::sleep(Duration::from_millis(20));
    }
}

fn now() -> i64 {
    i64::try_from(now_secs()).unwrap()
}

fn certificate_line(valid_before: i64) -> String {
    let mut spec = CertSpec::user(new_key_data(), 0);
    spec.valid_before = u64::try_from(valid_before).unwrap();
    spec.valid_after = spec.valid_before - 8 * 3600;
    sign(&ca_key(), &spec).to_openssh().unwrap()
}

fn write_certificate(dir: &Path, valid_before: i64) {
    fs::write(
        dir.join("id_ed25519-cert.pub"),
        format!("{}\n", certificate_line(valid_before)),
    )
    .unwrap();
}

fn write_session(home: &Path, server_url: &str, valid_before: Option<i64>) -> PathBuf {
    write_profile(home, server_url, now() - 3600);
    let dir = home.join("default");
    if let Some(valid_before) = valid_before {
        write_certificate(&dir, valid_before);
    }
    dir
}

fn store(home: &Path) -> ProfileStore {
    ProfileStore::new(home, &ProfileName::default_name())
}

fn options(home: &Path, deadline: Duration, ssh: Option<SshSetup>) -> RenewOptions {
    RenewOptions {
        home: home.to_owned(),
        custom_home: true,
        profile: ProfileName::default_name(),
        deadline,
        ssh,
    }
}

fn renew_with(
    home: &Path,
    browser: &Browser,
    notices: &mut dyn Write,
    deadline: Duration,
    ssh: Option<SshSetup>,
    prompt: &ScriptedPrompt,
) -> Result<Renewed, EnsureError> {
    let agent = SshAgent::new(None);
    let mut ports = LoginPorts {
        browser,
        agent: &agent,
        clock: &SystemTime::now,
        notices,
        consent: prompt,
    };
    renew(&options(home, deadline, ssh), &mut ports)
}

struct Ran {
    code: u8,
    stdout: Vec<u8>,
    stderr: String,
}

fn ensure_to(
    args: &EnsureArgs,
    environment: &Environment,
    browser: &Browser,
    clock: &dyn Fn() -> SystemTime,
    stderr: &mut dyn Write,
    terminal: bool,
) -> (u8, Vec<u8>) {
    let agent = SshAgent::new(None);
    let prompt = ScriptedPrompt::new(false, false);
    let mut out = Vec::new();
    let code = run_ensure_with(
        args,
        environment,
        EnsureIo {
            stdout: &mut out,
            stderr,
            terminal,
            browser,
            agent: &agent,
            consent: &prompt,
            clock,
        },
    );
    (code, out)
}

fn ensure_in_process(
    args: &EnsureArgs,
    environment: &Environment,
    browser: &Browser,
    terminal: bool,
    at: SystemTime,
) -> Ran {
    let mut err = Vec::new();
    let (code, stdout) = ensure_to(args, environment, browser, &move || at, &mut err, terminal);
    Ran {
        code,
        stdout,
        stderr: String::from_utf8(err).unwrap(),
    }
}

fn args(home: Option<&Path>, quiet: bool) -> EnsureArgs {
    EnsureArgs {
        profile: ProfileName::default_name(),
        home: home.map(Path::to_owned),
        quiet,
    }
}

fn environment(jaunt_home: &Path, user_home: &Path) -> Environment {
    Environment {
        jaunt_home: Some(jaunt_home.as_os_str().to_owned()),
        user_home: Some(user_home.to_owned()),
        ssh_auth_sock: None,
    }
}

#[test]
fn freshness_needs_sixty_seconds_left_and_is_decided_quickly_from_disk() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let valid_before = now() + 3600;
    write_session(&home, "https://jaunt.example.com", Some(valid_before));
    let store = store(&home);

    assert_eq!(check(&store, valid_before - 61).unwrap(), Freshness::Fresh);
    assert_eq!(check(&store, valid_before - 60).unwrap(), Freshness::Fresh);
    assert_eq!(check(&store, valid_before - 59).unwrap(), Freshness::Stale);
    assert_eq!(check(&store, valid_before).unwrap(), Freshness::Stale);
    let fastest = (0..5)
        .map(|_| {
            let started = Instant::now();
            check(&store, now()).unwrap();
            started.elapsed()
        })
        .min()
        .unwrap();
    assert!(fastest < Duration::from_millis(20), "{fastest:?}");
    assert!(!store.lock_path().exists());
}

#[test]
fn the_hot_path_answers_from_disk_with_an_empty_stdout_and_the_documented_exit_codes() {
    let _serial = serial_section();
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    type Arrange = Box<dyn Fn(&Path)>;
    let url = server.url();
    let session = |valid_before: Option<i64>| -> Arrange {
        let url = url.clone();
        Box::new(move |home| {
            write_session(home, &url, valid_before.map(|offset| now() + offset));
        })
    };
    let cases: Vec<(&str, Arrange, i32, &str)> = vec![
        ("valid for an hour", session(Some(3600)), 0, ""),
        ("59 seconds left", session(Some(59)), 1, "run `JAUNT_HOME='"),
        (
            "expired",
            session(Some(-10)),
            1,
            "jaunt login --profile default`",
        ),
        (
            "certificate missing",
            session(None),
            1,
            "jaunt login --profile default`",
        ),
        (
            "certificate corrupt",
            Box::new({
                let url = url.clone();
                move |home| {
                    let dir = write_session(home, &url, None);
                    fs::write(
                        dir.join("id_ed25519-cert.pub"),
                        "ssh-ed25519-cert-v01@openssh.com AAAAnot-a-certificate\n",
                    )
                    .unwrap();
                }
            }),
            1,
            "jaunt login --profile default`",
        ),
        (
            "never signed in",
            Box::new(|_| {}),
            1,
            "jaunt login --profile default --server URL`",
        ),
        (
            "profile directory is a symbolic link",
            Box::new({
                let url = url.clone();
                move |home| {
                    let elsewhere = home.with_file_name("elsewhere");
                    write_session(&elsewhere, &url, Some(now() + 3600));
                    fs::create_dir_all(home).unwrap();
                    symlink(elsewhere.join("default"), home.join("default")).unwrap();
                }
            }),
            2,
            "is not a plain directory",
        ),
    ];
    for (index, (name, arrange, code, message)) in cases.into_iter().enumerate() {
        let home = root.path().join(format!("case{index}")).join("state");
        arrange(&home);

        let output = jaunt(&home, &["ensure", "--profile", "default", "--quiet"]);

        assert_eq!(
            output.status.code(),
            Some(code),
            "{name}: {}",
            stderr(&output)
        );
        assert!(output.stdout.is_empty(), "{name}: {}", stdout(&output));
        if message.is_empty() {
            assert!(output.stderr.is_empty(), "{name}: {}", stderr(&output));
        } else {
            assert!(
                stderr(&output).contains(message),
                "{name}: {}",
                stderr(&output)
            );
            assert_eq!(
                stderr(&output).lines().count(),
                1,
                "{name}: {}",
                stderr(&output)
            );
        }
        assert!(!store(&home).lock_path().exists(), "{name}");
        assert!(!store(&home).failure_marker_path().exists(), "{name}");
    }
    assert_eq!(server.seen(|seen| seen.requests), 0);
}

#[test]
fn the_hot_path_does_not_wait_for_a_held_lock() {
    let _serial = serial_section();
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    write_session(&home, "https://jaunt.example.com", Some(now() + 3600));
    let lock_path = store(&home).lock_path();
    let held = ProfileLock::acquire(&home, &lock_path, Instant::now(), &mut || {}).unwrap();

    let started = Instant::now();
    let output = jaunt(&home, &["ensure"]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    let second = ProfileLock::acquire(&home, &lock_path, Instant::now(), &mut || {});
    assert!(matches!(second, Err(LockError::TimedOut)), "{second:?}");
    drop(held);
}

#[test]
fn logout_waits_for_a_running_sign_in_and_then_signs_out() {
    let _serial = serial_section();
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    write_session(&home, "https://jaunt.example.com", Some(now() + 3600));
    let marker = store(&home).failure_marker_path();
    fs::write(&marker, format!("{}\n", now())).unwrap();
    let lock_path = store(&home).lock_path();
    let held = ProfileLock::acquire(&home, &lock_path, Instant::now(), &mut || {}).unwrap();
    let mut child = base_command(&home)
        .arg("logout")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut errors = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    errors.read_line(&mut line).unwrap();
    assert!(line.contains(WAITING), "{line}");
    assert!(home.join("default/server").exists());

    drop(held);
    let output = child.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "Signed out.\n");
    assert!(!home.join("default").exists());
    assert!(!marker.exists());
}

#[test]
fn a_sign_in_approved_just_before_the_deadline_still_completes() {
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let approve_late = |started: Instant| {
        wait_until("the sign-in started", || {
            server.seen(|seen| seen.redirect_port.is_some())
        });
        thread::sleep(
            (started + Duration::from_millis(1800)).saturating_duration_since(Instant::now()),
        );
        visit(
            server.redirect_port(),
            &format!("/callback?login_id={LOGIN_ID}&code={COMPLETION_CODE}"),
        );
    };

    let plain_home = root.path().join("plain");
    let started = Instant::now();
    let plain = thread::scope(|scope| {
        scope.spawn(|| approve_late(started));
        let browser = Browser::new(&server, Script::Silent);
        run_login(
            &server,
            &plain_home,
            &browser,
            &SshAgent::new(None),
            true,
            Duration::from_secs(2),
        )
        .result
    });
    assert!(plain.is_ok(), "{plain:?}");

    let renewed_home = root.path().join("renewed");
    write_session(&renewed_home, &server.url(), Some(now() - 10));
    let started = Instant::now();
    let renewed = thread::scope(|scope| {
        scope.spawn(|| approve_late(started));
        let browser = Browser::new(&server, Script::Silent);
        renew_with(
            &renewed_home,
            &browser,
            &mut Vec::new(),
            Duration::from_secs(2),
            None,
            &ScriptedPrompt::new(false, false),
        )
    });
    assert!(matches!(renewed, Ok(Renewed::SignedIn(_))), "{renewed:?}");
    assert_eq!(server.seen(|seen| seen.finish_calls), 2);
}

#[test]
fn a_renewal_waiting_behind_a_failed_one_exits_without_a_request() {
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let user = root.path().join("userhome");
    write_session(&home, &server.url(), Some(now() - 10));
    let environment = environment(&home, &user);
    let first_errors = SharedNotices::default();
    let second_errors = SharedNotices::default();
    let silent = Browser::new(&server, Script::Silent);
    let unused = Browser::new(&server, Script::Approve);

    let (first, second) = thread::scope(|scope| {
        let first = scope.spawn(|| {
            let mut sink = first_errors.clone();
            ensure_to(
                &args(None, true),
                &environment,
                &silent,
                &SystemTime::now,
                &mut sink,
                true,
            )
        });
        wait_until("the first renewal opened the browser", || {
            !silent.opened_urls().is_empty()
        });
        let second = scope.spawn(|| {
            let mut sink = second_errors.clone();
            ensure_to(
                &args(None, true),
                &environment,
                &unused,
                &SystemTime::now,
                &mut sink,
                true,
            )
        });
        wait_until("the second renewal waits", || {
            second_errors.text().contains(WAITING)
        });
        visit(
            server.redirect_port(),
            &format!("/callback?login_id={LOGIN_ID}&error=access_denied"),
        );
        (first.join().unwrap(), second.join().unwrap())
    });

    assert_eq!(first.0, 1, "{}", first_errors.text());
    assert!(first_errors.text().contains("sign-in was denied"));
    assert_eq!(second.0, 1, "{}", second_errors.text());
    assert!(
        second_errors
            .text()
            .contains("sign-in did not complete a moment ago"),
        "{}",
        second_errors.text()
    );
    assert!(first.1.is_empty() && second.1.is_empty());
    assert!(unused.opened_urls().is_empty());
    assert_eq!(server.seen(|seen| seen.requests), 1);
}

#[test]
fn a_lock_held_for_another_profile_is_refused_before_any_request() {
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let other = ProfileStore::new(&home, &ProfileName::parse("work").unwrap());
    let held = ProfileLock::acquire(&home, &other.lock_path(), Instant::now(), &mut || {}).unwrap();
    let browser = Browser::new(&server, Script::Approve);
    let agent = SshAgent::new(None);
    let prompt = ScriptedPrompt::new(false, false);
    let mut notices = Vec::new();
    let mut ports = LoginPorts {
        browser: &browser,
        agent: &agent,
        clock: &SystemTime::now,
        notices: &mut notices,
        consent: &prompt,
    };
    let options = jaunt::login::LoginOptions {
        server: server.server_url(),
        profile: ProfileName::default_name(),
        home: home.clone(),
        no_browser: false,
        timeout: LONG,
        ssh: None,
        accept_ssh_config: false,
    };

    let outcome = login_with_lock(&options, &mut ports, &held);

    assert!(
        matches!(outcome, Err(LoginError::ForeignLock)),
        "{outcome:?}"
    );
    assert_eq!(server.seen(|seen| seen.requests), 0);
}

#[test]
fn a_marker_that_is_not_a_regular_file_is_ignored_and_never_a_local_error() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let user = root.path().join("userhome");
    let server = FakeServer::start(Behavior::default());
    write_session(&home, &server.url(), Some(now() - 10));
    fs::create_dir(store(&home).failure_marker_path()).unwrap();
    let browser = Browser::new(&server, Script::Approve);

    let ran = ensure_in_process(
        &args(None, true),
        &environment(&home, &user),
        &browser,
        false,
        SystemTime::now(),
    );

    assert_eq!(ran.code, 1, "{}", ran.stderr);
    assert!(
        ran.stderr.contains("sign-in needed for profile"),
        "{}",
        ran.stderr
    );

    let renewed = ensure_in_process(
        &args(None, true),
        &environment(&home, &user),
        &browser,
        true,
        SystemTime::now(),
    );
    assert_eq!(renewed.code, 0, "{}", renewed.stderr);
    assert!(
        renewed
            .stderr
            .contains("warning: the record of an earlier failed sign-in was not removed"),
        "{}",
        renewed.stderr
    );
}

#[test]
fn a_waiting_renewal_finds_the_certificate_of_the_running_sign_in_and_does_not_sign_in_again() {
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    write_session(&home, &server.url(), Some(now() - 10));
    let notices = SharedNotices::default();
    let second_browser = Browser::new(&server, Script::Approve);

    thread::scope(|scope| {
        let first = scope.spawn(|| {
            let browser = Browser::new(&server, Script::Silent);
            run_login(&server, &home, &browser, &SshAgent::new(None), true, LONG).result
        });
        wait_until("the first sign-in holds the lock", || {
            server.seen(|seen| seen.redirect_port.is_some())
        });
        let second = scope.spawn(|| {
            let mut sink = notices.clone();
            renew_with(
                &home,
                &second_browser,
                &mut sink,
                LONG,
                None,
                &ScriptedPrompt::new(false, false),
            )
        });
        wait_until("the renewal waits", || notices.text().contains(WAITING));
        let page = visit(
            server.redirect_port(),
            &format!("/callback?login_id={LOGIN_ID}&code={COMPLETION_CODE}"),
        );
        assert!(page.starts_with("HTTP/1.1 200 OK"), "{page}");

        first.join().unwrap().unwrap();
        let renewed = second.join().unwrap();
        assert!(matches!(renewed, Ok(Renewed::AlreadyFresh)), "{renewed:?}");
        assert!(second_browser.opened_urls().is_empty());
    });
    assert_eq!(server.seen(|seen| seen.finish_calls), 1);
    assert_eq!(notices.text().lines().count(), 1, "{}", notices.text());
    assert_eq!(check(&store(&home), now()).unwrap(), Freshness::Fresh);
}

#[test]
fn two_logins_in_one_profile_run_one_after_the_other() {
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let notices = SharedNotices::default();

    thread::scope(|scope| {
        let first = scope.spawn(|| {
            let browser = Browser::new(&server, Script::Silent);
            run_login(&server, &home, &browser, &SshAgent::new(None), true, LONG).result
        });
        wait_until("the first login holds the lock", || {
            server.seen(|seen| seen.redirect_port.is_some())
        });
        let second = scope.spawn(|| {
            let browser = Browser::new(&server, Script::Approve);
            let agent = SshAgent::new(None);
            let prompt = ScriptedPrompt::new(false, false);
            let mut sink = notices.clone();
            let mut ports = LoginPorts {
                browser: &browser,
                agent: &agent,
                clock: &SystemTime::now,
                notices: &mut sink,
                consent: &prompt,
            };
            let options = jaunt::login::LoginOptions {
                server: server.server_url(),
                profile: ProfileName::default_name(),
                home: home.clone(),
                no_browser: false,
                timeout: LONG,
                ssh: None,
                accept_ssh_config: false,
            };
            login(&options, &mut ports)
        });
        wait_until("the second login waits", || {
            notices.text().contains(WAITING)
        });
        assert_eq!(server.seen(|seen| seen.finish_calls), 0);
        visit(
            server.redirect_port(),
            &format!("/callback?login_id={LOGIN_ID}&code={COMPLETION_CODE}"),
        );

        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();
    });
    assert_eq!(server.seen(|seen| seen.finish_calls), 2);
}

#[test]
fn a_lock_left_by_a_killed_sign_in_does_not_block_the_next_one() {
    let _serial = serial_section();
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    write_session(&home, &server.url(), Some(now() - 10));
    let mut child = base_command(&home)
        .args([
            "login",
            "--no-browser",
            "--no-ssh-config",
            "--timeout",
            "60",
            "--server",
            &server.url(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut errors = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    while !line.starts_with("http://127.0.0.1:") {
        line.clear();
        assert!(
            errors.read_line(&mut line).unwrap() > 0,
            "the login ended early"
        );
    }
    assert!(store(&home).lock_path().is_file());
    child.kill().unwrap();
    child.wait().unwrap();

    let mut notices = Vec::new();
    let browser = Browser::new(&server, Script::Approve);
    let renewed = renew_with(
        &home,
        &browser,
        &mut notices,
        LONG,
        None,
        &ScriptedPrompt::new(false, false),
    );

    assert!(matches!(renewed, Ok(Renewed::SignedIn(_))), "{renewed:?}");
    let notices = String::from_utf8(notices).unwrap();
    assert!(!notices.contains(WAITING), "{notices}");
    assert!(
        notices.contains("needs renewal; signing in to http://127.0.0.1:"),
        "{notices}"
    );
    assert_eq!(check(&store(&home), now()).unwrap(), Freshness::Fresh);
}

#[test]
fn a_symbolic_link_in_place_of_the_lock_is_a_local_error() {
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    write_session(&home, &server.url(), Some(now() - 10));
    let target = root.path().join("planted");
    symlink(&target, store(&home).lock_path()).unwrap();
    let browser = Browser::new(&server, Script::Approve);

    let renewed = renew_with(
        &home,
        &browser,
        &mut Vec::new(),
        LONG,
        None,
        &ScriptedPrompt::new(false, false),
    );

    let Err(err) = renewed else {
        panic!("expected a refusal, got {renewed:?}");
    };
    assert!(
        matches!(err, EnsureError::Lock(LockError::Unsafe { .. })),
        "{err:?}"
    );
    assert_eq!(err.exit_code(), 2);
    assert!(!target.exists());
    assert_eq!(server.seen(|seen| seen.requests), 0);
}

#[test]
fn an_unsafe_program_path_is_refused_before_any_request() {
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let dir = write_session(&home, &server.url(), Some(now() - 10));
    fs::write(dir.join("ssh_config"), "").unwrap();
    let user = root.path().join("userhome");
    let setup = SshSetup {
        include: IncludeTarget {
            config_path: user.join(".ssh/config"),
            line: include_line(&home, &user).unwrap(),
        },
        program: PathBuf::from("/opt/ja'unt/jaunt"),
        ensure_home: None,
    };
    let browser = Browser::new(&server, Script::Approve);

    let renewed = renew_with(
        &home,
        &browser,
        &mut Vec::new(),
        LONG,
        Some(setup),
        &ScriptedPrompt::new(false, false),
    );

    let Err(err) = renewed else {
        panic!("expected a refusal, got {renewed:?}");
    };
    assert!(
        matches!(
            err,
            EnsureError::Login(LoginError::UnsafeCommand(
                SshConfigError::UnsafeProgram { .. }
            ))
        ),
        "{err:?}"
    );
    assert_eq!(err.exit_code(), 2);
    assert!(!err.to_string().contains("server"), "{err}");
    assert_eq!(server.seen(|seen| seen.requests), 0);
    assert!(browser.opened_urls().is_empty());
}

#[test]
fn a_sign_in_that_never_finishes_stops_at_the_deadline_with_exit_one() {
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    write_session(&home, &server.url(), Some(now() - 10));
    let browser = Browser::new(&server, Script::Silent);

    let started = Instant::now();
    let renewed = renew_with(
        &home,
        &browser,
        &mut Vec::new(),
        Duration::from_secs(1),
        None,
        &ScriptedPrompt::new(false, false),
    );

    assert!(started.elapsed() < Duration::from_secs(10));
    let Err(err) = renewed else {
        panic!("expected a timeout, got {renewed:?}");
    };
    assert!(matches!(err, EnsureError::TimedOut { .. }), "{err:?}");
    assert_eq!(err.exit_code(), 1);
    let message = err.to_string();
    assert!(
        message.contains("did not finish in time")
            && message.contains("jaunt login --profile default`")
            && !message.contains('\n'),
        "{message}"
    );
    assert_eq!(browser.opened_urls().len(), 1);
}

#[test]
fn the_browser_wait_gets_only_what_is_left_after_waiting_for_the_lock() {
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    write_session(&home, &server.url(), Some(now() - 10));
    let lock_path = store(&home).lock_path();
    let held = ProfileLock::acquire(&home, &lock_path, Instant::now(), &mut || {}).unwrap();
    let browser = Browser::new(&server, Script::Silent);
    let deadline = Duration::from_secs(3);

    let started = Instant::now();
    let renewed = thread::scope(|scope| {
        scope.spawn(move || {
            thread::sleep(Duration::from_millis(1500));
            drop(held);
        });
        renew_with(
            &home,
            &browser,
            &mut Vec::new(),
            deadline,
            None,
            &ScriptedPrompt::new(false, false),
        )
    });

    let elapsed = started.elapsed();
    assert!(
        matches!(renewed, Err(EnsureError::TimedOut { .. })),
        "{renewed:?}"
    );
    assert!(elapsed >= Duration::from_millis(1500), "{elapsed:?}");
    assert!(
        elapsed <= deadline + Duration::from_millis(750),
        "{elapsed:?}"
    );
    assert_eq!(browser.opened_urls().len(), 1);
}

#[test]
fn the_slow_path_signs_in_with_an_empty_stdout_and_quiet_keeps_only_warnings() {
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let user = root.path().join("userhome");
    write_session(&home, &server.url(), Some(now() - 10));
    let browser = Browser::new(&server, Script::Approve);

    let quiet = ensure_in_process(
        &args(None, true),
        &environment(&home, &user),
        &browser,
        true,
        SystemTime::now(),
    );

    assert_eq!(quiet.code, 0, "{}", quiet.stderr);
    assert!(quiet.stdout.is_empty());
    assert!(
        quiet.stderr.contains("needs renewal; signing in to"),
        "{}",
        quiet.stderr
    );
    assert!(
        quiet
            .stderr
            .contains("warning: the private key is stored on disk"),
        "{}",
        quiet.stderr
    );
    assert!(!quiet.stderr.contains("Signed in as"), "{}", quiet.stderr);

    write_certificate(&home.join("default"), now() - 10);
    let loud = ensure_in_process(
        &args(None, false),
        &environment(&home, &user),
        &browser,
        true,
        SystemTime::now(),
    );
    assert_eq!(loud.code, 0, "{}", loud.stderr);
    assert!(loud.stdout.is_empty());
    assert!(
        loud.stderr.contains("Signed in as alice@example.com"),
        "{}",
        loud.stderr
    );
}

#[test]
fn a_changed_gate_without_a_terminal_prompt_is_reported_even_under_quiet() {
    let gate_key = FakeServer::start(Behavior::default()).host_ca_line();
    let server = FakeServer::start(Behavior {
        client_config: ClientConfigReply::Custom(json!({
            "ssh_suffix": SUFFIX,
            "gate": {"host": GATE_HOST, "port": 2200},
            "host_ca_keys": [gate_key],
        })),
        ..Behavior::default()
    });
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let user = root.path().join("userhome");
    fs::create_dir(&user).unwrap();
    let prompt = ScriptedPrompt::new(false, false);
    let browser = Browser::new(&server, Script::Approve);
    run_login_setup(
        &server,
        &home,
        &browser,
        &SshAgent::new(None),
        false,
        LONG,
        LoginSetup {
            profile: "default",
            ssh: Some(IncludeTarget {
                config_path: user.join(".ssh/config"),
                line: include_line(&home, &user).unwrap(),
            }),
            accept: true,
            prompt: &prompt,
        },
    )
    .result
    .unwrap();
    let dir = home.join("default");
    let client = fs::read_to_string(dir.join("client.json")).unwrap();
    fs::write(
        dir.join("client.json"),
        client.replace("\"port\": 2200", "\"port\": 2222"),
    )
    .unwrap();
    write_certificate(&dir, now() - 10);

    let ran = ensure_in_process(
        &args(None, true),
        &environment(&home, &user),
        &browser,
        true,
        SystemTime::now(),
    );

    assert_eq!(ran.code, 0, "{}", ran.stderr);
    assert!(ran.stdout.is_empty());
    assert!(
        ran.stderr
            .contains("warning: the server wants to manage ssh for *.example.test through gate.other.test:2200; the SSH setup was skipped"),
        "{}",
        ran.stderr
    );
    assert!(
        ran.stderr
            .contains("warning: the previous SSH setup of this profile was removed"),
        "{}",
        ran.stderr
    );
    assert!(!dir.join("ssh_config").exists());
}

#[test]
fn a_failed_sign_in_pauses_the_next_attempts_for_ninety_seconds() {
    let denying = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let user = root.path().join("userhome");
    write_session(&home, &denying.url(), Some(now() - 10));
    let deny = Browser::new(&denying, Script::Deny("access_denied"));
    let environment = environment(&home, &user);
    let base = SystemTime::now();
    let marker = store(&home).failure_marker_path();

    let first = ensure_in_process(&args(None, true), &environment, &deny, true, base);
    assert_eq!(first.code, 1, "{}", first.stderr);
    assert!(
        first.stderr.contains("sign-in was denied"),
        "{}",
        first.stderr
    );
    assert!(marker.is_file());
    let requests = denying.seen(|seen| seen.requests);

    let started = Instant::now();
    let second = ensure_in_process(
        &args(None, true),
        &environment,
        &deny,
        true,
        base + Duration::from_secs(10),
    );
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(second.code, 1);
    assert!(second.stdout.is_empty());
    assert_eq!(
        second.stderr.trim_end(),
        format!(
            "jaunt: sign-in did not complete a moment ago: run `JAUNT_HOME='{}' jaunt login --profile default`",
            home.display()
        )
    );
    assert_eq!(denying.seen(|seen| seen.requests), requests);
    assert_eq!(deny.opened_urls().len(), 1);

    let third = ensure_in_process(
        &args(None, true),
        &environment,
        &deny,
        true,
        base + Duration::from_secs(91),
    );
    assert_eq!(third.code, 1);
    assert!(denying.seen(|seen| seen.requests) > requests);
    assert_eq!(deny.opened_urls().len(), 2);

    let approve = Browser::new(&denying, Script::Approve);
    let fourth = ensure_in_process(
        &args(None, true),
        &environment,
        &approve,
        true,
        base + Duration::from_secs(200),
    );
    assert_eq!(fourth.code, 0, "{}", fourth.stderr);
    assert!(!marker.exists());
}

#[test]
fn the_home_flag_wins_and_only_the_saved_server_of_that_profile_is_contacted() {
    let saved = FakeServer::start(Behavior::default());
    let other = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let flagged = root.path().join("flagged");
    let from_environment = root.path().join("environment");
    let user = root.path().join("userhome");
    write_session(&flagged, &saved.url(), Some(now() - 10));
    write_session(&from_environment, &other.url(), Some(now() - 10));
    let browser = Browser::new(&saved, Script::Approve);

    let ran = ensure_in_process(
        &args(Some(&flagged), true),
        &environment(&from_environment, &user),
        &browser,
        true,
        SystemTime::now(),
    );

    assert_eq!(ran.code, 0, "{}", ran.stderr);
    assert_eq!(saved.seen(|seen| seen.finish_calls), 1);
    assert_eq!(other.seen(|seen| seen.requests), 0);
    assert_eq!(check(&store(&flagged), now()).unwrap(), Freshness::Fresh);

    let empty = root.path().join("empty");
    let missing = ensure_in_process(
        &args(Some(&empty), true),
        &environment(&from_environment, &user),
        &browser,
        true,
        SystemTime::now(),
    );
    assert_eq!(missing.code, 1);
    assert_eq!(
        missing.stderr.trim_end(),
        format!(
            "jaunt: no sign-in for profile `default` was found in {}: run `JAUNT_HOME='{}' jaunt login --profile default --server URL`",
            empty.join("default").display(),
            empty.display()
        )
    );
    assert!(!empty.exists());
    assert_eq!(other.seen(|seen| seen.requests), 0);
}

#[test]
fn renewal_upgrades_an_older_generated_ssh_config_through_the_known_settings_without_asking() {
    let server = FakeServer::start(Behavior {
        client_config: ClientConfigReply::Valid,
        ..Behavior::default()
    });
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let user = root.path().join("userhome");
    fs::create_dir(&user).unwrap();
    let include = IncludeTarget {
        config_path: user.join(".ssh/config"),
        line: include_line(&home, &user).unwrap(),
    };
    let prompt = ScriptedPrompt::new(false, false);
    let browser = Browser::new(&server, Script::Approve);
    run_login_setup(
        &server,
        &home,
        &browser,
        &SshAgent::new(None),
        false,
        LONG,
        LoginSetup {
            profile: "default",
            ssh: Some(include.clone()),
            accept: true,
            prompt: &prompt,
        },
    )
    .result
    .unwrap();
    let dir = home.join("default");
    let current = fs::read_to_string(dir.join("ssh_config")).unwrap();
    let match_line = current
        .lines()
        .find(|line| line.starts_with("Match "))
        .unwrap();
    let older = current.replacen(&format!("{match_line}\n\n"), "", 1);
    assert!(older.starts_with(&format!("{HEADER}\nHost {GATE_HOST}\n")));
    fs::write(dir.join("ssh_config"), &older).unwrap();
    write_certificate(&dir, now() - 10);

    let refused = renew_with(&home, &browser, &mut Vec::new(), LONG, None, &prompt);
    let Err(err) = refused else {
        panic!("expected a refusal, got {refused:?}");
    };
    assert!(matches!(err, EnsureError::NoSshSetup { .. }), "{err:?}");
    assert_eq!(err.exit_code(), 2);
    assert_eq!(fs::read_to_string(dir.join("ssh_config")).unwrap(), older);
    let marker = store(&home).failure_marker_path();
    assert!(marker.is_file());
    fs::remove_file(&marker).unwrap();

    let setup = SshSetup {
        include,
        program: PathBuf::from("/opt/jaunt/bin/jaunt"),
        ensure_home: Some(home.clone()),
    };
    let renewed = renew_with(&home, &browser, &mut Vec::new(), LONG, Some(setup), &prompt);

    assert!(matches!(renewed, Ok(Renewed::SignedIn(_))), "{renewed:?}");
    assert!(prompt.asked().is_empty());
    let upgraded = fs::read_to_string(dir.join("ssh_config")).unwrap();
    assert!(
        upgraded.starts_with(&format!(
            "{HEADER}\nMatch host *.{SUFFIX} exec \"'/opt/jaunt/bin/jaunt' ensure --home '{}' --profile default --quiet\"\n\nHost {GATE_HOST}\n",
            home.display()
        )),
        "{upgraded}"
    );
}

#[test]
fn status_reports_auto_sign_in_for_a_binary_login_with_the_ssh_setup() {
    let _serial = serial_section();
    let server = FakeServer::start(Behavior {
        client_config: ClientConfigReply::Valid,
        ..Behavior::default()
    });
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");

    let finished = crate::cli::login_through_the_binary(&server, &home, |command| {
        command.arg("--accept-ssh-config");
    });
    assert!(finished.status.success(), "{}", finished.stderr);
    let generated = fs::read_to_string(home.join("default/ssh_config")).unwrap();
    assert!(
        generated.contains(&format!(
            "exec \"'{}' ensure --home '{}' --profile default --quiet\"",
            env!("CARGO_BIN_EXE_jaunt"),
            home.display()
        )),
        "{generated}"
    );

    let status = jaunt(&home, &["status"]);
    assert!(
        stdout(&status).contains("Auto sign-in: on"),
        "{}",
        stdout(&status)
    );
    fs::write(
        home.join("default/ssh_config"),
        generated.replace("Match ", "# Match "),
    )
    .unwrap();
    let status = jaunt(&home, &["status"]);
    assert!(
        stdout(&status).contains("Auto sign-in: off"),
        "{}",
        stdout(&status)
    );
}

fn ssh_available() -> bool {
    Command::new("ssh")
        .arg("-V")
        .output()
        .is_ok_and(|output| output.status.success() || !output.stderr.is_empty())
}

#[test]
fn the_system_ssh_runs_the_generated_command_once_and_keeps_its_stdout_off_the_data_channel() {
    if !ssh_available() {
        eprintln!("skipped: no ssh client found");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let calls = root.path().join("calls.txt");
    let program = write_script(
        root.path(),
        "jaunt",
        &format!(
            "printf '%s\\n' \"$*\" >> \"{}\"\necho fake-stdout-line\necho fake-stderr-line >&2\nexit 0\n",
            calls.display()
        ),
    );
    let host_key = FakeServer::start(Behavior::default()).host_ca_line();
    let config = validate(ClientConfig {
        ssh_suffix: SUFFIX.to_owned(),
        gate: GateEndpoint {
            host: GATE_HOST.to_owned(),
            port: GATE_PORT,
        },
        host_ca_keys: vec![host_key],
    })
    .unwrap();
    let profile = ProfileName::default_name();
    let home = root.path().join("state");
    let text = render_ssh_config(
        &config,
        &home.join("default"),
        &EnsureCommand {
            program: &program,
            home: Some(&home),
            profile: &profile,
        },
    )
    .unwrap();
    let config_path = root.path().join("ssh_config");
    fs::write(&config_path, text).unwrap();
    let resolve = |target: &str| {
        Command::new("ssh")
            .arg("-G")
            .arg("-F")
            .arg(&config_path)
            .arg(target)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };

    let node = resolve(&format!("web-01.{SUFFIX}"));

    eprintln!("ran the system ssh");
    assert!(node.status.success(), "{}", stderr(&node));
    assert_eq!(
        fs::read_to_string(&calls).unwrap(),
        format!(
            "ensure --home {} --profile default --quiet\n",
            home.display()
        )
    );
    assert!(
        stderr(&node).contains("fake-stderr-line"),
        "{}",
        stderr(&node)
    );
    assert!(!stdout(&node).contains("fake-stdout-line"));
    assert!(stdout(&node).contains(&format!("proxyjump jaunt@{GATE_HOST}:{GATE_PORT}")));

    let gate = resolve(GATE_HOST);
    assert!(gate.status.success(), "{}", stderr(&gate));
    assert_eq!(fs::read_to_string(&calls).unwrap().lines().count(), 1);
}
