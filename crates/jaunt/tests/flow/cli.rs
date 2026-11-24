use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};

use crate::support::{
    API_TOKEN, Behavior, COMPLETION_CODE, EMAIL, FakeServer, LOGIN_ID, USER_ID, now_secs,
    serial_section, visit, write_script,
};

pub(crate) fn user_home(home: &Path) -> PathBuf {
    home.parent().unwrap().join("userhome")
}

pub(crate) fn base_command(home: &Path) -> Command {
    fs::create_dir_all(user_home(home)).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_jaunt"));
    command
        .env("JAUNT_HOME", home)
        .env("HOME", user_home(home))
        .stdin(Stdio::null())
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("JAUNT_PROFILE")
        .env_remove("JAUNT_SERVER");
    command
}

pub(crate) fn jaunt(home: &Path, args: &[&str]) -> Output {
    base_command(home).args(args).output().unwrap()
}

pub(crate) fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub(crate) fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub(crate) struct Finished {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

pub(crate) fn login_through_the_binary(
    server: &FakeServer,
    home: &Path,
    tweak: impl FnOnce(&mut Command),
) -> Finished {
    let mut command = base_command(home);
    command
        .args([
            "login",
            "--no-browser",
            "--timeout",
            "60",
            "--server",
            &server.url(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    tweak(&mut command);
    let mut child = command.spawn().unwrap();
    let mut errors = BufReader::new(child.stderr.take().unwrap());
    let mut announced = String::new();
    loop {
        let mut line = String::new();
        let read = errors.read_line(&mut line).unwrap();
        assert!(
            read > 0,
            "the process ended before printing the sign-in address: {announced}"
        );
        announced.push_str(&line);
        if line.starts_with("http://127.0.0.1:") {
            break;
        }
    }
    let page = visit(
        server.redirect_port(),
        &format!("/callback?login_id={LOGIN_ID}&code={COMPLETION_CODE}"),
    );
    assert!(page.starts_with("HTTP/1.1 200 OK"), "{page}");
    let mut rest = String::new();
    errors.read_to_string(&mut rest).unwrap();
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    Finished {
        status: child.wait().unwrap(),
        stdout: out,
        stderr: format!("{announced}{rest}"),
    }
}

pub(crate) fn write_profile(home: &Path, server_url: &str, valid_before: i64) {
    let dir = home.join("default");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("server"), format!("{server_url}\n")).unwrap();
    fs::write(dir.join("token"), API_TOKEN).unwrap();
    let meta = serde_json::json!({
        "user_id": USER_ID,
        "email": EMAIL,
        "serial": 7,
        "key_id": format!("jaunt:{EMAIL}:7"),
        "valid_after": valid_before - 28_800,
        "valid_before": valid_before,
        "token_expires_at": valid_before,
        "host_ca_keys": [],
    });
    fs::write(dir.join("meta.json"), meta.to_string()).unwrap();
}

#[test]
fn usage_errors_exit_two_and_logged_out_commands_behave() {
    let _serial = serial_section();
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let usage: Vec<(&[&str], &str)> = vec![
        (&["login"], "no server given"),
        (
            &["login", "--device", "--server", "https://jaunt.example.com"],
            "not implemented",
        ),
        (&["login", "--server", "http://jaunt.example.com"], "https"),
        (
            &[
                "login",
                "--server",
                "https://jaunt.example.com",
                "--profile",
                "Bad Name",
            ],
            "profile names",
        ),
        (
            &[
                "login",
                "--server",
                "https://jaunt.example.com",
                "--timeout",
                "901",
            ],
            "901",
        ),
        (&["status", "--profile", "../x"], "profile names"),
    ];
    for (args, expected) in usage {
        let output = jaunt(&home, args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains(expected),
            "{args:?}: {}",
            stderr(&output)
        );
    }
    let relative = Command::new(env!("CARGO_BIN_EXE_jaunt"))
        .args(["status"])
        .env("JAUNT_HOME", "relative/dir")
        .output()
        .unwrap();
    assert_eq!(relative.status.code(), Some(2));

    let status = jaunt(&home, &["status"]);
    assert_eq!(status.status.code(), Some(1));
    assert!(
        stdout(&status).contains("Not signed in"),
        "{}",
        stdout(&status)
    );
    let logout = jaunt(&home, &["logout"]);
    assert_eq!(logout.status.code(), Some(0));
    assert!(stdout(&logout).contains("Already signed out."));
    assert!(!home.exists());
}

#[test]
fn an_expired_certificate_makes_status_exit_one_and_an_unreachable_server_does_not() {
    let _serial = serial_section();
    let root = tempfile::tempdir().unwrap();
    let now = i64::try_from(now_secs()).unwrap();

    let expired_home = root.path().join("expired");
    write_profile(&expired_home, "http://127.0.0.1:1", now - 3600);
    let expired = jaunt(&expired_home, &["status"]);
    assert_eq!(expired.status.code(), Some(1), "{}", stderr(&expired));
    assert!(
        stdout(&expired).contains("Signed in as alice@example.com"),
        "{}",
        stdout(&expired)
    );
    assert!(stdout(&expired).contains("expired"), "{}", stdout(&expired));

    let valid_home = root.path().join("valid");
    write_profile(&valid_home, "http://127.0.0.1:1", now + 3600);
    let unconfirmed = jaunt(&valid_home, &["status", "--online"]);
    assert_eq!(
        unconfirmed.status.code(),
        Some(0),
        "{}",
        stderr(&unconfirmed)
    );
    assert!(stdout(&unconfirmed).contains(" left)"));
    assert!(
        stderr(&unconfirmed).contains("warning: the server could not confirm this sign-in"),
        "{}",
        stderr(&unconfirmed)
    );
}

#[test]
fn a_failed_key_placement_through_the_binary_leaves_no_signed_in_profile() {
    let _serial = serial_section();
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let tools = tempfile::tempdir().unwrap();
    write_script(
        tools.path(),
        "ssh-add",
        "for d in \"$JAUNT_HOME\"/.default.new.*; do mkdir \"$d/id_ed25519\"; done\nexit 1\n",
    );
    let path = format!(
        "{}:{}",
        tools.path().display(),
        std::env::var("PATH").unwrap()
    );

    let finished = login_through_the_binary(&server, &home, |command| {
        command
            .env("SSH_AUTH_SOCK", "/run/example/agent.sock")
            .env("PATH", &path);
    });
    assert_eq!(finished.status.code(), Some(1), "{}", finished.stderr);
    assert!(finished.stdout.is_empty(), "{}", finished.stdout);
    assert!(
        finished.stderr.contains("cannot write"),
        "{}",
        finished.stderr
    );
    assert!(!home.join("default").exists());
    let status = jaunt(&home, &["status"]);
    assert_eq!(status.status.code(), Some(1));
    assert!(stdout(&status).contains("Not signed in"));
}

#[test]
fn login_status_and_logout_work_end_to_end_through_the_binary() {
    let _serial = serial_section();
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");

    let finished = login_through_the_binary(&server, &home, |_| {});
    assert!(finished.status.success(), "{}", finished.stderr);
    assert!(
        finished
            .stdout
            .starts_with("Signed in as alice@example.com; certificate valid until ")
            && finished.stdout.trim_end().ends_with("(serial 7)."),
        "{}",
        finished.stdout
    );
    assert_eq!(finished.stdout.lines().count(), 1);
    assert!(
        finished
            .stderr
            .contains("warning: the private key is stored on disk"),
        "{}",
        finished.stderr
    );

    let status = jaunt(&home, &["status"]);
    assert_eq!(status.status.code(), Some(0), "{}", stderr(&status));
    let shown = stdout(&status);
    assert!(
        shown.contains("Signed in as alice@example.com (user "),
        "{shown}"
    );
    assert!(shown.contains("Certificate serial: 7"), "{shown}");
    assert!(shown.contains(" left)"), "{shown}");

    let online = jaunt(&home, &["status", "--online"]);
    assert_eq!(online.status.code(), Some(0), "{}", stderr(&online));
    assert!(
        stdout(&online).contains("Server check: signed in as alice@example.com; groups: ops, dev;"),
        "{}",
        stdout(&online)
    );

    let other_server = jaunt(&home, &["login", "--server", "http://127.0.0.1:1"]);
    assert_eq!(other_server.status.code(), Some(2));
    assert!(
        stderr(&other_server).contains("already signed in to"),
        "{}",
        stderr(&other_server)
    );

    server.revoke();
    let revoked = jaunt(&home, &["status", "--online"]);
    assert_eq!(revoked.status.code(), Some(1));
    assert!(
        stderr(&revoked).contains("does not accept this sign-in"),
        "{}",
        stderr(&revoked)
    );

    let logout = jaunt(&home, &["logout"]);
    assert_eq!(logout.status.code(), Some(0), "{}", stderr(&logout));
    assert!(stdout(&logout).contains("Signed out."));
    assert!(!home.join("default").exists());
    assert_eq!(jaunt(&home, &["status"]).status.code(), Some(1));
    assert_eq!(jaunt(&home, &["logout"]).status.code(), Some(0));
}

#[test]
fn status_names_a_stranded_previous_session_and_logout_removes_it() {
    let _serial = serial_section();
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let stranded = home.join(".default.old.1.1");
    fs::create_dir_all(&stranded).unwrap();
    fs::write(stranded.join("token"), API_TOKEN).unwrap();

    let status = jaunt(&home, &["status"]);
    assert_eq!(status.status.code(), Some(1));
    let shown = stdout(&status);
    assert!(shown.contains("Not signed in"), "{shown}");
    assert!(shown.contains(&stranded.display().to_string()), "{shown}");
    assert!(
        shown.contains(&format!(
            "move it back to {}",
            home.join("default").display()
        )),
        "{shown}"
    );
    assert!(shown.contains("`jaunt logout`"), "{shown}");

    let logout = jaunt(&home, &["logout"]);
    assert_eq!(logout.status.code(), Some(0), "{}", stderr(&logout));
    assert!(
        stdout(&logout).contains("Signed out."),
        "{}",
        stdout(&logout)
    );
    assert!(!stranded.exists());
    assert!(!stdout(&jaunt(&home, &["status"])).contains("previous session"));
}
