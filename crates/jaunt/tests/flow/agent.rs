use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use jaunt::agent::{AgentError, SshAgent};
use jaunt::key::SessionKey;
use jaunt::login::KeyPlacement;
use jaunt::logout::logout;
use jaunt::profile::ProfileName;
use jaunt::status::{AgentView, agent_view};
use jaunt::store::ProfileStore;
use ssh_key::PrivateKey;
use tempfile::TempDir;

use crate::support::{
    Behavior, Browser, FakeServer, Script, USER_ID, names, now_secs, run_login, serial_section,
    write_script,
};

const LONG: Duration = Duration::from_secs(30);

struct RealAgent {
    child: Child,
    socket: PathBuf,
    _dir: TempDir,
}

fn tool_present(tool: &str) -> bool {
    match Command::new(tool)
        .arg("-h")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(_) => true,
        Err(err) => err.kind() != std::io::ErrorKind::NotFound,
    }
}

impl RealAgent {
    fn start() -> Option<RealAgent> {
        for tool in ["ssh-agent", "ssh-add", "ssh-keygen"] {
            if !tool_present(tool) {
                eprintln!("skipped: {tool} is not installed");
                return None;
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let child = Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let agent = RealAgent {
            child,
            socket,
            _dir: dir,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !agent.socket.exists() {
            assert!(
                Instant::now() < deadline,
                "ssh-agent did not create its socket"
            );
            thread::sleep(Duration::from_millis(20));
        }
        Some(agent)
    }

    fn client(&self) -> SshAgent {
        SshAgent::new(Some(self.socket.clone().into_os_string()))
    }

    fn signal(&self, name: &str) {
        let status = Command::new("kill")
            .arg(name)
            .arg(self.child.id().to_string())
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn ssh_add(&self, args: &[&str]) -> Output {
        Command::new("ssh-add")
            .args(args)
            .env("SSH_AUTH_SOCK", &self.socket)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
}

impl Drop for RealAgent {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

fn text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn keygen(flag: &str, file: &Path) -> Output {
    Command::new("ssh-keygen")
        .arg(flag)
        .arg("-f")
        .arg(file)
        .output()
        .unwrap()
}

pub fn login_with(server: &FakeServer, home: &Path, agent: &SshAgent) -> jaunt::login::LoginReport {
    let browser = Browser::new(server, Script::Approve);
    run_login(server, home, &browser, agent, false, LONG)
        .result
        .unwrap()
}

#[test]
fn login_loads_the_key_into_a_real_agent_and_logout_removes_it() {
    let _serial = serial_section();
    let Some(agent) = RealAgent::start() else {
        return;
    };
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let report = login_with(&server, &home, &agent.client());
    assert_eq!(report.placement, KeyPlacement::Agent);
    assert!(report.warnings().is_empty());

    let store = ProfileStore::new(&home, &ProfileName::default_name());
    assert!(!store.private_key_path().exists());
    let fingerprint_line = text(&keygen("-l", &store.public_key_path()));
    let fingerprint = fingerprint_line
        .split_whitespace()
        .find(|field| field.starts_with("SHA256:"))
        .unwrap()
        .to_owned();
    let listing = agent.ssh_add(&["-l"]);
    assert!(listing.status.success());
    assert!(text(&listing).contains(&fingerprint), "{}", text(&listing));
    assert_eq!(agent_view(&store, &agent.client()), AgentView::Loaded);

    let described = keygen("-L", &store.certificate_path());
    assert!(described.status.success());
    let described = text(&described);
    assert!(described.contains("user certificate"), "{described}");
    assert!(
        described.contains("jaunt:alice@example.com:7"),
        "{described}"
    );
    assert!(described.contains(USER_ID), "{described}");
    assert!(described.contains("Serial: 7"), "{described}");

    let public_line = store.read_public_key_line().unwrap().unwrap();
    assert!(agent.client().holds(&public_line).unwrap());
    let other = SessionKey::generate(&ProfileName::default_name()).unwrap();
    assert!(!agent.client().holds(other.public_line()).unwrap());

    let report = logout(&store, &agent.client()).unwrap();
    assert!(report.was_signed_in);
    assert!(report.agent_warning.is_none(), "{:?}", report.agent_warning);
    let listing = agent.ssh_add(&["-l"]);
    assert!(!text(&listing).contains(&fingerprint));
    assert!(!store.dir().exists());
    assert!(!agent.client().holds(&public_line).unwrap());

    let again = logout(&store, &agent.client()).unwrap();
    assert!(!again.was_signed_in);
    assert!(again.agent_warning.is_none());
}

#[test]
fn a_later_login_with_an_agent_removes_the_private_key_file_left_by_an_earlier_one() {
    let _serial = serial_section();
    let Some(agent) = RealAgent::start() else {
        return;
    };
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let first = login_with(&server, &home, &SshAgent::new(None));
    assert!(matches!(first.placement, KeyPlacement::Disk { .. }));
    let store = ProfileStore::new(&home, &ProfileName::default_name());
    assert!(store.private_key_path().exists());

    let second = login_with(&server, &home, &agent.client());
    assert_eq!(second.placement, KeyPlacement::Agent);
    assert!(!store.private_key_path().exists());
}

pub fn recording_ssh_add(dir: &Path, exit_code: i32, stderr_text: &str) -> PathBuf {
    write_script(
        dir,
        "fake-ssh-add",
        &format!(
            "d=$(dirname \"$0\")\nprintf '%s\\n' \"$@\" > \"$d/args.txt\"\ncat > \"$d/stdin.txt\"\nprintf '%s' \"$SSH_AUTH_SOCK\" > \"$d/sock.txt\"\necho '{stderr_text}' >&2\nexit {exit_code}\n"
        ),
    )
}

#[test]
fn the_key_reaches_ssh_add_on_stdin_with_a_lifetime_and_never_touches_disk() {
    let _serial = serial_section();
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let tools = tempfile::tempdir().unwrap();
    let script = recording_ssh_add(tools.path(), 0, "");
    let agent = SshAgent::new(Some("/run/example/agent.sock".into())).with_program(&script);
    let before = now_secs();
    let report = login_with(&server, &home, &agent);
    assert_eq!(report.placement, KeyPlacement::Agent);

    let args = fs::read_to_string(tools.path().join("args.txt")).unwrap();
    let args: Vec<&str> = args.lines().collect();
    assert_eq!(args.len(), 3, "{args:?}");
    assert_eq!((args[0], args[2]), ("-t", "-"));
    let lifetime: u64 = args[1].parse().unwrap();
    let expected = u64::try_from(report.valid_before).unwrap() - before;
    assert!(
        lifetime <= expected && lifetime + 30 >= expected,
        "{lifetime} vs {expected}"
    );
    assert_eq!(
        fs::read_to_string(tools.path().join("sock.txt")).unwrap(),
        "/run/example/agent.sock"
    );

    let piped = fs::read_to_string(tools.path().join("stdin.txt")).unwrap();
    assert!(
        piped.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"),
        "{piped}"
    );
    let store = ProfileStore::new(&home, &ProfileName::default_name());
    let key = PrivateKey::from_openssh(piped).unwrap();
    assert_eq!(
        ssh_key::PublicKey::from(key.public_key().key_data().clone())
            .to_openssh()
            .unwrap(),
        store.read_public_key_line().unwrap().unwrap()
    );
    assert!(!store.private_key_path().exists());
}

#[test]
fn when_ssh_add_fails_or_is_missing_the_key_goes_to_disk_with_a_one_line_reason() {
    let _serial = serial_section();
    let tools = tempfile::tempdir().unwrap();
    let failing = recording_ssh_add(tools.path(), 1, "Could not add identity");
    let missing = PathBuf::from("/nonexistent/ssh-add");
    for (program, expected) in [
        (failing, "ssh-add failed: Could not add identity"),
        (missing, "ssh-add cannot be started"),
    ] {
        let server = FakeServer::start(Behavior::default());
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("state");
        let agent = SshAgent::new(Some("/run/example/agent.sock".into())).with_program(program);
        let report = login_with(&server, &home, &agent);
        let KeyPlacement::Disk { path, reason } = &report.placement else {
            panic!("expected the key on disk, got {:?}", report.placement);
        };
        assert!(reason.contains(expected), "{reason}");
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let warnings = report.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            !warnings[0].contains('\n') && warnings[0].contains(expected),
            "{}",
            warnings[0]
        );
    }
}

#[test]
fn the_agent_view_follows_which_keys_are_loaded() {
    let _serial = serial_section();
    let Some(agent) = RealAgent::start() else {
        return;
    };
    let first = SessionKey::generate(&ProfileName::default_name()).unwrap();
    let second = SessionKey::generate(&ProfileName::default_name()).unwrap();
    let client = agent.client();
    assert!(!client.holds(first.public_line()).unwrap());

    client.add(&second.private_openssh().unwrap(), 60).unwrap();
    assert!(client.holds(second.public_line()).unwrap());
    assert!(!client.holds(first.public_line()).unwrap());
}

#[test]
fn a_second_login_removes_the_previous_key_from_the_agent() {
    let _serial = serial_section();
    let Some(agent) = RealAgent::start() else {
        return;
    };
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let store = ProfileStore::new(&home, &ProfileName::default_name());

    let first = login_with(&server, &home, &agent.client());
    assert!(first.notes.is_empty(), "{:?}", first.notes);
    let first_line = store.read_public_key_line().unwrap().unwrap();
    assert!(agent.client().holds(&first_line).unwrap());

    let second = login_with(&server, &home, &agent.client());
    assert!(second.notes.is_empty(), "{:?}", second.notes);
    let second_line = store.read_public_key_line().unwrap().unwrap();
    assert_ne!(first_line, second_line);
    assert!(agent.client().holds(&second_line).unwrap());
    assert!(!agent.client().holds(&first_line).unwrap());
    assert_eq!(names(&home), [".default.lock", "default"]);
}

#[test]
fn a_stopped_agent_makes_ssh_add_time_out_instead_of_hanging() {
    let _serial = serial_section();
    let Some(agent) = RealAgent::start() else {
        return;
    };
    let key = SessionKey::generate(&ProfileName::default_name()).unwrap();
    let client = agent.client().with_timeout(Duration::from_millis(700));
    client.add(&key.private_openssh().unwrap(), 60).unwrap();

    agent.signal("-STOP");
    let started = Instant::now();
    let outcome = client.holds(key.public_line());
    agent.signal("-CONT");
    assert!(matches!(outcome, Err(AgentError::TimedOut)), "{outcome:?}");
    assert!(started.elapsed() < Duration::from_secs(8));

    assert!(client.holds(key.public_line()).unwrap());
}
