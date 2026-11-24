use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use jaunt::agent::SshAgent;
use jaunt::client::ApiError;
use jaunt::login::LoginError;
use jaunt::profile::ProfileName;
use jaunt::ssh_config::SshConfigError;
use jaunt::ssh_include::{IncludeTarget, include_line};
use jaunt::status::{SshView, ssh_view};
use jaunt::store::ProfileStore;
use serde_json::{Value, json};
use tempfile::TempDir;

use crate::support::{
    Behavior, Browser, ClientConfigReply, FakeServer, GATE_HOST, GATE_PORT, LoginSetup, Outcome,
    SUFFIX, Script, ScriptedPrompt, names, run_login_setup, snapshot,
};

const LONG: Duration = Duration::from_secs(30);

struct World {
    server: FakeServer,
    root: TempDir,
    home: PathBuf,
    user_home: PathBuf,
}

fn world_with(behavior: Behavior, home_name: &str) -> World {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join(home_name);
    let user_home = root.path().join("userhome");
    fs::create_dir(&user_home).unwrap();
    World {
        server: FakeServer::start(behavior),
        root,
        home,
        user_home,
    }
}

fn configured() -> Behavior {
    Behavior {
        client_config: ClientConfigReply::Valid,
        ..Behavior::default()
    }
}

fn world() -> World {
    world_with(configured(), "state")
}

impl World {
    fn target(&self) -> IncludeTarget {
        IncludeTarget {
            config_path: self.user_home.join(".ssh/config"),
            line: include_line(&self.home, &self.user_home)
                .unwrap_or_else(|_| "Include ~/.jaunt/*/ssh_config".to_owned()),
        }
    }

    fn ssh_dir(&self) -> PathBuf {
        self.user_home.join(".ssh")
    }

    fn login_on(&self, server: &FakeServer, profile: &str, with_ssh: bool) -> Outcome {
        self.login_asking(
            server,
            profile,
            with_ssh,
            true,
            &ScriptedPrompt::new(false, false),
        )
    }

    fn login_asking(
        &self,
        server: &FakeServer,
        profile: &str,
        with_ssh: bool,
        accept: bool,
        prompt: &ScriptedPrompt,
    ) -> Outcome {
        let browser = Browser::new(server, Script::Approve);
        run_login_setup(
            server,
            &self.home,
            &browser,
            &SshAgent::new(None),
            false,
            LONG,
            LoginSetup {
                profile,
                ssh: with_ssh.then(|| self.target()),
                accept,
                prompt,
            },
        )
    }

    fn login(&self, profile: &str, with_ssh: bool) -> Outcome {
        self.login_on(&self.server, profile, with_ssh)
    }

    fn profile_dir(&self, profile: &str) -> PathBuf {
        self.home.join(profile)
    }

    fn store(&self, profile: &str) -> ProfileStore {
        ProfileStore::new(&self.home, &ProfileName::parse(profile).unwrap())
    }
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn notes_of(outcome: &Outcome) -> String {
    outcome.result.as_ref().unwrap().notes.join("\n")
}

#[test]
fn login_writes_the_profile_files_and_includes_them_from_a_new_ssh_config() {
    let world = world();

    let outcome = world.login("default", true);

    let notes = notes_of(&outcome);
    assert!(
        notes.contains(
            "SSH setup is ready for *.example.test through gate.other.test:2222: created"
        ),
        "{notes}"
    );
    let profile = world.profile_dir("default");
    for name in ["client.json", "ssh_config", "known_hosts"] {
        assert_eq!(mode(&profile.join(name)), 0o600, "{name}");
    }
    let ssh_config = fs::read_to_string(profile.join("ssh_config")).unwrap();
    let profile_text = profile.display().to_string();
    assert!(
        ssh_config.contains(&format!("Host *.{SUFFIX}\n")),
        "{ssh_config}"
    );
    assert!(
        ssh_config.contains(&format!("    ProxyJump jaunt@{GATE_HOST}:{GATE_PORT}\n")),
        "{ssh_config}"
    );
    assert!(
        ssh_config.contains(&format!("    IdentityFile {profile_text}/id_ed25519\n")),
        "{ssh_config}"
    );
    let key = world.server.host_ca_line();
    assert_eq!(
        fs::read_to_string(profile.join("known_hosts")).unwrap(),
        format!(
            "@cert-authority *.{SUFFIX} {key}\n@cert-authority {GATE_HOST} {key}\n@cert-authority [{GATE_HOST}]:{GATE_PORT} {key}\n"
        )
    );
    let config = world.ssh_dir().join("config");
    assert_eq!(
        fs::read_to_string(&config).unwrap(),
        format!("{}\n", world.target().line)
    );
    assert_eq!(mode(&config), 0o600);
    assert_eq!(mode(&world.ssh_dir()), 0o700);
    let stored = world
        .store("default")
        .read_client_config()
        .unwrap()
        .unwrap();
    assert_eq!(stored.ssh_suffix, SUFFIX);
    assert_eq!(stored.gate.port, GATE_PORT);
    assert_eq!(world.server.seen(|seen| seen.client_config_calls), 1);
}

fn ssh_available() -> bool {
    Command::new("ssh")
        .arg("-V")
        .output()
        .is_ok_and(|output| output.status.success() || !output.stderr.is_empty())
}

fn ssh_g(world: &World, target: &str) -> BTreeMap<String, Vec<String>> {
    let output = Command::new("ssh")
        .arg("-G")
        .arg("-F")
        .arg(world.ssh_dir().join("config"))
        .arg(target)
        .env("HOME", &world.user_home)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut parsed: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in String::from_utf8(output.stdout).unwrap().lines() {
        let (key, value) = line.split_once(' ').unwrap_or((line, ""));
        parsed
            .entry(key.to_owned())
            .or_default()
            .push(value.to_owned());
    }
    parsed
}

#[test]
fn the_system_openssh_resolves_the_generated_configuration() {
    if !ssh_available() {
        eprintln!("skipped: no ssh client found");
        return;
    }
    let world = world();
    world.login("default", true).result.unwrap();
    let profile = world.profile_dir("default").display().to_string();

    let node = ssh_g(&world, "deploy@web-01.example.test");

    assert_eq!(
        node["proxyjump"],
        [format!("jaunt@{GATE_HOST}:{GATE_PORT}")]
    );
    assert_eq!(node["user"], ["deploy"]);
    assert_eq!(node["identitiesonly"], ["yes"]);
    assert_eq!(node["stricthostkeychecking"], ["true"]);
    assert_eq!(
        node["userknownhostsfile"],
        [format!("{profile}/known_hosts")]
    );
    assert_eq!(
        node["certificatefile"],
        [format!("{profile}/id_ed25519-cert.pub")]
    );
    assert_eq!(node["identityfile"][0], format!("{profile}/id_ed25519"));

    let gate = ssh_g(&world, GATE_HOST);
    assert_eq!(gate["user"], ["jaunt"]);
    assert_eq!(gate["port"], [GATE_PORT.to_string()]);
    assert_eq!(gate["identitiesonly"], ["yes"]);
    assert_eq!(
        gate["userknownhostsfile"],
        [format!("{profile}/known_hosts")]
    );
    assert!(
        gate.get("proxyjump")
            .is_none_or(|values| values.iter().all(|value| value == "none")),
        "{:?}",
        gate.get("proxyjump")
    );

    let unrelated = ssh_g(&world, "other.test");
    assert!(!unrelated.contains_key("proxyjump"));
    assert_ne!(
        unrelated.get("stricthostkeychecking"),
        Some(&vec!["true".to_owned()])
    );
}

#[test]
fn logging_in_twice_never_duplicates_the_include_and_never_overwrites_the_backup() {
    let world = world();
    fs::create_dir(world.ssh_dir()).unwrap();
    let config = world.ssh_dir().join("config");
    let original = "Host keep\n  User k\n";
    fs::write(&config, original).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o644)).unwrap();

    let first = world.login("default", true);
    let first_notes = notes_of(&first);
    let after_first = fs::read(&config).unwrap();
    let second = world.login("default", true);

    assert!(first_notes.contains("added `Include "), "{first_notes}");
    let line = world.target().line;
    assert_eq!(
        String::from_utf8(after_first.clone()).unwrap(),
        format!("{line}\n\n{original}")
    );
    assert_eq!(fs::read(&config).unwrap(), after_first);
    assert_eq!(mode(&config), 0o644);
    assert_eq!(
        fs::read_to_string(world.ssh_dir().join("config.jaunt-backup")).unwrap(),
        original
    );
    assert_eq!(names(&world.ssh_dir()), ["config", "config.jaunt-backup"]);
    assert!(
        notes_of(&second).contains("already includes"),
        "{}",
        notes_of(&second)
    );
}

#[test]
fn two_profiles_get_independent_files_and_share_one_include_line() {
    let world = world();

    world.login("default", true).result.unwrap();
    world.login("work", true).result.unwrap();

    for profile in ["default", "work"] {
        let dir = world.profile_dir(profile);
        let ssh_config = fs::read_to_string(dir.join("ssh_config")).unwrap();
        assert!(
            ssh_config.contains(&format!("{}/id_ed25519", dir.display())),
            "{ssh_config}"
        );
        let other = if profile == "work" { "default" } else { "work" };
        assert!(
            !ssh_config.contains(&world.profile_dir(other).display().to_string()),
            "{ssh_config}"
        );
        assert!(dir.join("known_hosts").exists());
    }
    let config = fs::read_to_string(world.ssh_dir().join("config")).unwrap();
    assert_eq!(config, format!("{}\n", world.target().line));
    assert_eq!(names(&world.ssh_dir()), ["config"]);

    let first = ssh_view(&world.store("default"), None, None);
    let second = ssh_view(&world.store("work"), None, None);
    let SshView::Ready { shadowed_by, .. } = first else {
        panic!("expected a ready setup, got {first:?}");
    };
    assert_eq!(shadowed_by, None);
    let SshView::Ready { shadowed_by, .. } = second else {
        panic!("expected a ready setup, got {second:?}");
    };
    assert_eq!(shadowed_by.as_deref(), Some("default"));
}

#[test]
fn a_server_without_a_gate_skips_the_ssh_setup_but_the_login_succeeds() {
    let world = world_with(Behavior::default(), "state");

    let outcome = world.login("default", true);

    let notes = notes_of(&outcome);
    assert!(notes.contains("no SSH gateway configured"), "{notes}");
    assert_eq!(
        names(&world.profile_dir("default")),
        [
            "id_ed25519",
            "id_ed25519-cert.pub",
            "id_ed25519.pub",
            "meta.json",
            "server",
            "token"
        ]
    );
    assert!(!world.ssh_dir().exists());
    assert_eq!(world.server.seen(|seen| seen.client_config_calls), 1);
}

#[test]
fn signing_in_without_the_ssh_setup_asks_for_nothing_and_removes_an_older_setup() {
    let world = world();
    world.login("default", true).result.unwrap();
    let config_before = fs::read(world.ssh_dir().join("config")).unwrap();
    assert_eq!(world.server.seen(|seen| seen.client_config_calls), 1);

    let outcome = world.login("default", false);

    let notes = notes_of(&outcome);
    assert!(
        notes.contains("previous SSH setup of this profile was removed"),
        "{notes}"
    );
    for name in ["client.json", "ssh_config", "known_hosts"] {
        assert!(!world.profile_dir("default").join(name).exists(), "{name}");
    }
    assert_eq!(world.server.seen(|seen| seen.client_config_calls), 1);
    assert_eq!(
        fs::read(world.ssh_dir().join("config")).unwrap(),
        config_before
    );

    let fresh = world_with(configured(), "state");
    let plain = fresh.login("default", false);
    assert!(plain.result.unwrap().notes.is_empty());
    assert!(!fresh.ssh_dir().exists());
    assert_eq!(fresh.server.seen(|seen| seen.client_config_calls), 0);
}

#[test]
fn a_failing_client_config_fetch_leaves_the_previous_profile_and_ssh_config_intact() {
    let world = world();
    world.login("default", true).result.unwrap();
    let profile_before = snapshot(&world.profile_dir("default"));
    let config_before = snapshot(&world.ssh_dir());
    let broken = FakeServer::start(Behavior {
        client_config: ClientConfigReply::Failing,
        ..Behavior::default()
    });

    let outcome = world.login_on(&broken, "default", true);

    assert!(matches!(
        outcome.result,
        Err(LoginError::ClientConfig {
            source: ApiError::Rejected { status: 500 }
        })
    ));
    let message = outcome.result.unwrap_err().to_string();
    assert!(message.contains("--no-ssh-config"), "{message}");
    assert_eq!(snapshot(&world.profile_dir("default")), profile_before);
    assert_eq!(snapshot(&world.ssh_dir()), config_before);
    assert_eq!(names(&world.home), [".default.lock", "default"]);
}

#[test]
fn a_profile_path_that_cannot_be_written_safely_fails_before_anything_changes() {
    let world = world_with(configured(), "50%");
    world.login("default", false).result.unwrap();
    let before = snapshot(&world.profile_dir("default"));
    let untouched = FakeServer::start(configured());

    let outcome = world.login_on(&untouched, "default", true);

    assert!(matches!(
        outcome.result,
        Err(LoginError::SshSettings(SshConfigError::UnsafePath { .. }))
    ));
    assert_eq!(snapshot(&world.profile_dir("default")), before);
    assert_eq!(names(&world.home), [".default.lock", "default"]);
    assert!(!world.ssh_dir().exists());
    assert!(untouched.seen(|seen| seen.redirect_port.is_none() && seen.client_config_calls == 0));
}

#[test]
fn hostile_client_configs_are_refused_and_nothing_is_written() {
    let key = FakeServer::start(configured()).host_ca_line();
    let valid = |suffix: &str, host: &str, port: Value, keys: Value| {
        json!({
            "ssh_suffix": suffix,
            "gate": {"host": host, "port": port},
            "host_ca_keys": keys,
        })
    };
    let good_keys = json!([key]);
    let long_suffix = "a".repeat(300);
    let injected = format!("{key}\nProxyCommand touch /tmp/pwned");
    let cases: Vec<(Value, &str)> = vec![
        (
            valid(
                "example.test\nProxyCommand touch /tmp/pwned",
                "g.test",
                json!(22),
                good_keys.clone(),
            ),
            "BadSuffix",
        ),
        (
            valid("ex ample.test", "g.test", json!(22), good_keys.clone()),
            "BadSuffix",
        ),
        (
            valid("example.test%h", "g.test", json!(22), good_keys.clone()),
            "BadSuffix",
        ),
        (
            valid("example.test;id", "g.test", json!(22), good_keys.clone()),
            "BadSuffix",
        ),
        (
            valid("exämple.test", "g.test", json!(22), good_keys.clone()),
            "BadSuffix",
        ),
        (
            valid(&long_suffix, "g.test", json!(22), good_keys.clone()),
            "BadSuffix",
        ),
        (
            valid(
                "example.test",
                "g.test\nProxyCommand x",
                json!(22),
                good_keys.clone(),
            ),
            "BadGateHost",
        ),
        (
            valid(
                "example.test",
                "g.test -oProxyCommand=x",
                json!(22),
                good_keys.clone(),
            ),
            "BadGateHost",
        ),
        (
            valid("example.test", "g%h.test", json!(22), good_keys.clone()),
            "BadGateHost",
        ),
        (
            valid("example.test", "g.test", json!(0), good_keys.clone()),
            "BadGatePort",
        ),
        (
            valid("example.test", "g.test", json!(22), json!([])),
            "BadHostKeys",
        ),
        (
            valid("example.test", "g.test", json!(22), json!([injected])),
            "BadHostKeys",
        ),
        (
            valid(
                "example.test",
                "g.test",
                json!(22),
                json!(["ssh-ed25519 not-base64"]),
            ),
            "BadHostKeys",
        ),
        (
            valid("example.test", "g.test", json!("22"), good_keys.clone()),
            "BadResponse",
        ),
        (
            json!({
                "ssh_suffix": "example.test",
                "gate": {"host": "g.test", "port": 22},
                "host_ca_keys": good_keys,
                "proxy_command": "touch /tmp/pwned",
            }),
            "BadResponse",
        ),
    ];
    for (reply, expected) in cases {
        let world = world_with(
            Behavior {
                client_config: ClientConfigReply::Custom(reply.clone()),
                ..Behavior::default()
            },
            "state",
        );

        let outcome = world.login("default", true);

        let error = outcome.result.unwrap_err();
        let refused = format!("{error:?}");
        assert!(refused.contains(expected), "{reply}: {refused}");
        assert!(error.to_string().contains("--no-ssh-config"), "{error}");
        assert!(!error.to_string().contains("ProxyCommand"), "{error}");
        assert_eq!(names(&world.home), [".default.lock"], "{reply}");
        assert!(!world.ssh_dir().exists(), "{reply}");
        assert!(
            fs::read_dir(world.root.path()).unwrap().count() == 2,
            "{reply}"
        );
    }
}

#[test]
fn a_read_only_ssh_config_is_reported_as_a_warning_with_the_profile_files_in_place() {
    let world = world();
    fs::create_dir(world.ssh_dir()).unwrap();
    let config = world.ssh_dir().join("config");
    fs::write(&config, "Host keep\n").unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o444)).unwrap();

    let outcome = world.login("default", true);

    let notes = notes_of(&outcome);
    assert!(
        notes.contains("warning: the SSH files are in place but"),
        "{notes}"
    );
    assert!(
        notes.contains("add this line at its top yourself: Include "),
        "{notes}"
    );
    assert_eq!(fs::read_to_string(&config).unwrap(), "Host keep\n");
    assert_eq!(names(&world.ssh_dir()), ["config"]);
    assert!(world.profile_dir("default").join("ssh_config").exists());
}

const QUESTION: &str = "This server will manage ssh for *.example.test through gate.other.test:2222. Configure ssh? [y/N]";

fn moved_gate(world: &World, port: u16) -> FakeServer {
    FakeServer::start(Behavior {
        client_config: ClientConfigReply::Custom(json!({
            "ssh_suffix": SUFFIX,
            "gate": {"host": GATE_HOST, "port": port},
            "host_ca_keys": [world.server.host_ca_line()],
        })),
        ..Behavior::default()
    })
}

fn has_ssh_files(world: &World) -> bool {
    world.profile_dir("default").join("ssh_config").exists()
}

#[test]
fn a_terminal_user_is_asked_once_and_an_accepted_triple_is_remembered() {
    let world = world();
    let yes = ScriptedPrompt::new(true, true);

    let first = world.login_asking(&world.server, "default", true, false, &yes);
    let second = world.login_asking(&world.server, "default", true, false, &yes);

    assert_eq!(yes.asked(), [QUESTION]);
    let notes = notes_of(&first);
    assert!(
        notes.contains(&format!(
            "SSH setup is ready for *.{SUFFIX} through {GATE_HOST}:{GATE_PORT}"
        )),
        "{notes}"
    );
    assert!(has_ssh_files(&world));
    assert!(
        notes_of(&second).contains("already includes"),
        "{}",
        notes_of(&second)
    );
}

#[test]
fn a_refusal_on_a_terminal_skips_the_ssh_setup_and_the_login_still_succeeds() {
    let world = world();
    let no = ScriptedPrompt::new(true, false);

    let outcome = world.login_asking(&world.server, "default", true, false, &no);

    assert_eq!(no.asked(), [QUESTION]);
    let notes = notes_of(&outcome);
    assert!(notes.contains("was declined"), "{notes}");
    assert!(notes.contains("--accept-ssh-config"), "{notes}");
    assert!(!has_ssh_files(&world));
    assert!(!world.ssh_dir().exists());
}

#[test]
fn without_a_terminal_the_flag_decides_and_nothing_is_asked() {
    let world = world();
    let silent = ScriptedPrompt::new(false, true);

    let skipped = world.login_asking(&world.server, "default", true, false, &silent);

    let notes = notes_of(&skipped);
    assert!(
        notes.contains(&format!("*.{SUFFIX} through {GATE_HOST}:{GATE_PORT}")),
        "{notes}"
    );
    assert!(
        notes.contains("run `jaunt login --accept-ssh-config` to enable it"),
        "{notes}"
    );
    assert!(!has_ssh_files(&world) && !world.ssh_dir().exists());

    let accepted = world.login_asking(&world.server, "default", true, true, &silent);

    assert!(
        notes_of(&accepted).contains("SSH setup is ready"),
        "{}",
        notes_of(&accepted)
    );
    assert!(has_ssh_files(&world));
    assert!(silent.asked().is_empty());
}

#[test]
fn a_changed_triple_asks_again_and_a_refusal_removes_the_old_setup() {
    let world = world();
    let yes = ScriptedPrompt::new(true, true);
    world
        .login_asking(&world.server, "default", true, false, &yes)
        .result
        .unwrap();
    assert_eq!(yes.asked().len(), 1);

    let moved = moved_gate(&world, 2200);
    let accepted = world.login_asking(&moved, "default", true, false, &yes);
    accepted.result.unwrap();

    assert_eq!(
        yes.asked().last().unwrap(),
        "This server will manage ssh for *.example.test through gate.other.test:2200. Configure ssh? [y/N]"
    );
    assert_eq!(yes.asked().len(), 2);
    assert_eq!(
        world
            .store("default")
            .read_client_config()
            .unwrap()
            .unwrap()
            .gate
            .port,
        2200
    );

    let no = ScriptedPrompt::new(true, false);
    let back = world.login_asking(&world.server, "default", true, false, &no);

    assert_eq!(no.asked(), [QUESTION]);
    assert!(notes_of(&back).contains("previous SSH setup of this profile was removed"));
    assert!(!has_ssh_files(&world));
}

#[test]
fn an_explicit_flag_never_asks_even_for_a_new_triple() {
    let world = world();
    let yes = ScriptedPrompt::new(true, true);

    world
        .login_asking(&world.server, "default", true, true, &yes)
        .result
        .unwrap();

    assert!(yes.asked().is_empty());
    assert!(has_ssh_files(&world));
}
