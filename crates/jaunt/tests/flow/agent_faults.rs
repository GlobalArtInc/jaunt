use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use jaunt::agent::{AgentError, RemoveOutcome, SshAgent};
use jaunt::login::{KeyPlacement, LoginError};
use jaunt::logout::logout;
use jaunt::profile::ProfileName;
use jaunt::secret::Secret;
use jaunt::status::{AgentView, agent_view};
use jaunt::store::{ProfileStore, StoreError};

use crate::agent::{login_with, recording_ssh_add};
use crate::support::{
    Behavior, Browser, FakeServer, Script, names, run_login, serial_section, snapshot, write_script,
};

const SHORT: Duration = Duration::from_millis(800);
const LONG: Duration = Duration::from_secs(30);

fn sleeping_ssh_add(dir: &Path) -> PathBuf {
    write_script(
        dir,
        "sleeping-ssh-add",
        "echo $$ > \"$(dirname \"$0\")/pid.txt\"\nexec sleep 60\n",
    )
}

fn agent_with(program: &Path) -> SshAgent {
    SshAgent::new(Some("/run/example/agent.sock".into())).with_program(program)
}

fn process_alive(pid: &str) -> bool {
    Command::new("kill")
        .arg("-0")
        .arg(pid)
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
}

#[test]
fn a_ssh_add_that_never_answers_is_killed_reaped_and_reported_as_a_timeout() {
    let _serial = serial_section();
    let tools = tempfile::tempdir().unwrap();
    let agent = agent_with(&sleeping_ssh_add(tools.path())).with_timeout(SHORT);
    let started = Instant::now();
    assert!(matches!(
        agent.add(&Secret::new("key".to_owned()), 60),
        Err(AgentError::TimedOut)
    ));
    assert!(matches!(
        agent.remove(Path::new("/tmp/example.pub")),
        Err(AgentError::TimedOut)
    ));
    assert!(matches!(
        agent.holds("ssh-ed25519 AAAA"),
        Err(AgentError::TimedOut)
    ));
    assert!(started.elapsed() < Duration::from_secs(20));

    let pid = fs::read_to_string(tools.path().join("pid.txt")).unwrap();
    assert!(
        !process_alive(pid.trim()),
        "ssh-add {} survived",
        pid.trim()
    );
}

#[test]
fn a_hanging_ssh_add_sends_login_to_the_key_file_and_status_to_an_unknown_agent_view() {
    let _serial = serial_section();
    let tools = tempfile::tempdir().unwrap();
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let agent = agent_with(&sleeping_ssh_add(tools.path())).with_timeout(SHORT);

    let report = login_with(&server, &home, &agent);
    let KeyPlacement::Disk { path, reason } = &report.placement else {
        panic!("expected the key on disk, got {:?}", report.placement);
    };
    assert!(reason.contains("timed out"), "{reason}");
    assert!(path.exists());

    let store = ProfileStore::new(&home, &ProfileName::default_name());
    match agent_view(&store, &agent) {
        AgentView::Unknown(note) => assert!(note.contains("timed out"), "{note}"),
        other => panic!("unexpected agent view: {other:?}"),
    }
}

#[test]
fn logout_with_a_hanging_ssh_add_still_deletes_everything_and_warns() {
    let _serial = serial_section();
    let tools = tempfile::tempdir().unwrap();
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    login_with(&server, &home, &SshAgent::new(None));
    let store = ProfileStore::new(&home, &ProfileName::default_name());
    assert!(store.private_key_path().exists());

    let agent = agent_with(&sleeping_ssh_add(tools.path())).with_timeout(SHORT);
    let report = logout(&store, &agent).unwrap();
    assert!(report.was_signed_in);
    assert!(matches!(report.agent_warning, Some(AgentError::TimedOut)));
    assert!(!store.dir().exists());
}

#[test]
fn ssh_add_exit_codes_map_to_unreachable_not_loaded_and_removed() {
    let _serial = serial_section();
    let key = Secret::new("key".to_owned());
    let pub_file = Path::new("/tmp/example.pub");

    let unreachable_dir = tempfile::tempdir().unwrap();
    let unreachable = agent_with(&recording_ssh_add(
        unreachable_dir.path(),
        2,
        "Error connecting to agent: No such file or directory",
    ));
    assert!(matches!(
        unreachable.add(&key, 60),
        Err(AgentError::Unreachable)
    ));
    assert!(matches!(
        unreachable.remove(pub_file),
        Err(AgentError::Unreachable)
    ));
    assert!(matches!(
        unreachable.holds("ssh-ed25519 AAAA"),
        Err(AgentError::Unreachable)
    ));

    let absent_dir = tempfile::tempdir().unwrap();
    let absent = agent_with(&recording_ssh_add(absent_dir.path(), 1, ""));
    assert_eq!(absent.remove(pub_file).unwrap(), RemoveOutcome::NotLoaded);
    assert!(!absent.holds("ssh-ed25519 AAAA").unwrap());
    assert!(matches!(absent.add(&key, 60), Err(AgentError::Failed(_))));

    let present_dir = tempfile::tempdir().unwrap();
    let present = agent_with(&recording_ssh_add(present_dir.path(), 0, ""));
    assert_eq!(present.remove(pub_file).unwrap(), RemoveOutcome::Removed);
}

#[test]
fn a_failed_key_placement_leaves_no_profile_and_keeps_a_previous_session_byte_for_byte() {
    let _serial = serial_section();
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let tools = tempfile::tempdir().unwrap();
    let calls = tools.path().join("calls.txt");
    let sabotage = write_script(
        tools.path(),
        "sabotage-ssh-add",
        &format!(
            "echo \"$@\" >> \"{}\"\nfor d in \"{}\"/.default.new.*; do mkdir \"$d/id_ed25519\"; done\nexit 1\n",
            calls.display(),
            home.display()
        ),
    );
    let agent = agent_with(&sabotage);
    let store = ProfileStore::new(&home, &ProfileName::default_name());
    let attempt = || {
        let browser = Browser::new(&server, Script::Approve);
        run_login(&server, &home, &browser, &agent, false, LONG).result
    };

    let first = attempt();
    assert!(
        matches!(
            first,
            Err(LoginError::Store(StoreError::Io {
                action: "write",
                ..
            }))
        ),
        "{first:?}"
    );
    assert!(!store.dir().exists());
    assert!(names(&home).is_empty(), "{:?}", names(&home));

    login_with(&server, &home, &SshAgent::new(None));
    let before = snapshot(store.dir());
    assert!(before.iter().any(|(name, _, _)| name == "id_ed25519"));

    let second = attempt();
    assert!(
        matches!(
            second,
            Err(LoginError::Store(StoreError::Io {
                action: "write",
                ..
            }))
        ),
        "{second:?}"
    );
    assert_eq!(snapshot(store.dir()), before);
    assert_eq!(names(&home), ["default"]);

    let recorded = fs::read_to_string(&calls).unwrap();
    let lines: Vec<&str> = recorded.lines().collect();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines.iter().all(|line| line.starts_with("-t ")),
        "{lines:?}"
    );
}

#[test]
fn a_failing_removal_of_the_previous_key_is_only_a_warning() {
    let _serial = serial_section();
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let tools = tempfile::tempdir().unwrap();
    let script = write_script(
        tools.path(),
        "removal-fails-ssh-add",
        "if [ \"$1\" = \"-d\" ]; then exit 2; fi\ncat > /dev/null\nexit 0\n",
    );
    let agent = agent_with(&script);
    let store = ProfileStore::new(&home, &ProfileName::default_name());

    let first = login_with(&server, &home, &agent);
    assert!(first.notes.is_empty(), "{:?}", first.notes);
    let first_line = store.read_public_key_line().unwrap().unwrap();

    let second = login_with(&server, &home, &agent);
    assert_eq!(second.placement, KeyPlacement::Agent);
    assert_eq!(second.notes.len(), 1, "{:?}", second.notes);
    assert!(
        second.notes[0].contains("previous key may still be loaded"),
        "{}",
        second.notes[0]
    );
    assert_ne!(store.read_public_key_line().unwrap().unwrap(), first_line);
    assert_eq!(names(&home), ["default"]);
}

#[test]
fn a_grandchild_holding_the_pipes_cannot_stretch_ssh_add_past_its_deadline() {
    let _serial = serial_section();
    let tools = tempfile::tempdir().unwrap();
    let script = write_script(tools.path(), "forking-ssh-add", "sleep 4 &\nexit 0\n");
    let agent = agent_with(&script).with_timeout(Duration::from_millis(500));
    let started = Instant::now();
    let outcome = agent.holds("ssh-ed25519 AAAA");
    assert!(matches!(outcome, Err(AgentError::TimedOut)), "{outcome:?}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn a_commit_failure_after_the_key_was_sent_removes_the_agent_key_and_the_staged_file() {
    let _serial = serial_section();
    for hang_on_add in [false, true] {
        let server = FakeServer::start(Behavior::default());
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("state");
        let tools = tempfile::tempdir().unwrap();
        let calls = tools.path().join("calls.txt");
        let on_add = if hang_on_add {
            "exec sleep 30"
        } else {
            "cat > /dev/null"
        };
        let script = write_script(
            tools.path(),
            "commit-breaker-ssh-add",
            &format!(
                "echo \"$@\" >> \"{}\"\nif [ \"$1\" = \"-t\" ]; then\nprintf x > \"{}/default\"\n{on_add}\nfi\nexit 0\n",
                calls.display(),
                home.display()
            ),
        );
        let agent = agent_with(&script).with_timeout(SHORT);
        let browser = Browser::new(&server, Script::Approve);
        let outcome = run_login(&server, &home, &browser, &agent, false, LONG).result;
        assert!(
            matches!(
                outcome,
                Err(LoginError::Store(StoreError::NotADirectory { .. }))
            ),
            "hang={hang_on_add}: {outcome:?}"
        );

        let recorded = fs::read_to_string(&calls).unwrap();
        let lines: Vec<&str> = recorded.lines().collect();
        assert_eq!(lines.len(), 2, "hang={hang_on_add}: {lines:?}");
        assert!(lines[0].starts_with("-t "), "{lines:?}");
        assert!(
            lines[1].starts_with("-d ")
                && lines[1].contains("/.default.new.")
                && lines[1].ends_with("/id_ed25519.pub"),
            "hang={hang_on_add}: {lines:?}"
        );
        assert_eq!(names(&home), ["default"]);
        assert!(home.join("default").is_file());
    }
}
