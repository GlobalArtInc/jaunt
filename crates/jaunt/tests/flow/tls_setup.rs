use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use axum::http::StatusCode;
use std::time::SystemTime;

use jaunt::agent::SshAgent;
use jaunt::client::ApiError;
use jaunt::ensure::{EnsureError, RenewOptions, Renewed, renew};
use jaunt::gate_config::GateServices;
use jaunt::login::{LoginError, LoginPorts};
use jaunt::profile::ProfileName;
use jaunt::ssh_config::SshConfigError;
use jaunt::ssh_include::{IncludeTarget, include_line};
use jaunt::store::ProfileStore;
use serde_json::{Value, json};
use tempfile::TempDir;

use crate::gate::{TestCa, services_json};
use crate::support::{
    Behavior, Browser, ClientConfigReply, FakeServer, GATE_HOST, GATE_PORT, HARMLESS_PROGRAM,
    LoginSetup, Outcome, SUFFIX, Script, ScriptedPrompt, V2Reply, run_login_setup,
};

const PROXY_LINE: &str = "    ProxyCommand '/usr/bin/true' proxy ssh --profile default\n";

struct World {
    server: FakeServer,
    _root: TempDir,
    home: PathBuf,
    user_home: PathBuf,
}

impl World {
    fn new() -> World {
        World::with(Behavior::default())
    }

    fn with(behavior: Behavior) -> World {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("state");
        let user_home = root.path().join("userhome");
        fs::create_dir(&user_home).unwrap();
        World {
            server: FakeServer::start(Behavior {
                client_config: ClientConfigReply::Valid,
                ..behavior
            }),
            _root: root,
            home,
            user_home,
        }
    }

    fn login(&self) -> Outcome {
        self.login_on(&self.server, true)
    }

    fn login_without_ssh(&self) -> Outcome {
        self.login_on(&self.server, false)
    }

    fn login_on(&self, server: &FakeServer, with_ssh: bool) -> Outcome {
        let browser = Browser::new(server, Script::Approve);
        let prompt = ScriptedPrompt::new(false, false);
        run_login_setup(
            server,
            &self.home,
            &browser,
            &SshAgent::new(None),
            false,
            Duration::from_secs(30),
            LoginSetup {
                profile: "default",
                ssh: with_ssh.then(|| IncludeTarget {
                    config_path: self.user_home.join(".ssh/config"),
                    line: include_line(&self.home, &self.user_home).unwrap(),
                }),
                accept: true,
                prompt: &prompt,
            },
        )
    }

    fn renew(&self) -> Result<Renewed, EnsureError> {
        let browser = Browser::new(&self.server, Script::Approve);
        let prompt = ScriptedPrompt::new(false, false);
        let agent = SshAgent::new(None);
        let mut notices = Vec::new();
        let mut ports = LoginPorts {
            browser: &browser,
            agent: &agent,
            clock: &SystemTime::now,
            notices: &mut notices,
            consent: &prompt,
        };
        renew(
            &RenewOptions {
                home: self.home.clone(),
                custom_home: true,
                profile: ProfileName::default_name(),
                deadline: Duration::from_secs(30),
                ssh: None,
            },
            &mut ports,
        )
    }

    fn store(&self) -> ProfileStore {
        ProfileStore::new(&self.home, &ProfileName::default_name())
    }

    fn ssh_config(&self) -> String {
        fs::read_to_string(self.home.join("default/ssh_config")).unwrap()
    }

    fn services_file(&self) -> PathBuf {
        self.home.join("default/services.json")
    }

    fn v2(&self, transport: &str, services: Option<Value>) -> V2Reply {
        V2Reply::Json(json!({
            "ssh_suffix": SUFFIX,
            "gate": {"host": GATE_HOST, "port": GATE_PORT},
            "host_ca_keys": [self.server.host_ca_line()],
            "ssh_gate": {"client_transport": transport},
            "services": services,
        }))
    }
}

fn mode(path: &std::path::Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
}

fn services_with(roots: &[&TestCa]) -> Value {
    let pinned: Vec<Value> = roots.iter().map(|root| root.pinned()).collect();
    services_json(443, &pinned)["services"].clone()
}

fn pinned_roots(stored: &GateServices) -> Vec<String> {
    stored
        .services
        .roots
        .iter()
        .map(|root| root.sha256.clone())
        .collect()
}

#[test]
fn a_tls_server_gets_a_proxy_command_for_the_gate_and_pins_its_roots() {
    let world = World::new();
    let root = TestCa::new("pinned root");
    world
        .server
        .set_client_config_v2(world.v2("tls", Some(services_with(&[&root]))));

    world.login().result.unwrap();

    let text = world.ssh_config();
    let gate_block = text.split("\n\n").nth(1).unwrap();
    let node_block = text.split("\n\n").nth(2).unwrap();
    assert!(
        gate_block.starts_with(&format!("Host {GATE_HOST}\n")),
        "{text}"
    );
    assert!(gate_block.contains(PROXY_LINE), "{text}");
    assert!(!gate_block.contains("ProxyJump"), "{text}");
    assert!(
        node_block.contains(&format!("    ProxyJump jaunt@{GATE_HOST}:{GATE_PORT}\n")),
        "{text}"
    );
    let stored = world.store().read_gate_services().unwrap().unwrap();
    assert_eq!(
        pinned_roots(&stored),
        [root.pinned()["sha256"].as_str().unwrap()]
    );
    assert_eq!(mode(&world.services_file()), 0o600);
    assert_eq!(world.server.seen(|seen| seen.client_config_v2_calls), 1);
    assert_eq!(world.server.seen(|seen| seen.client_config_calls), 0);
}

#[test]
fn roots_are_replaced_by_the_next_login_and_removed_when_the_server_stops_offering_them() {
    let world = World::new();
    world.login().result.unwrap();
    let from_an_old_server = world.ssh_config();
    assert!(!world.services_file().exists());
    let (first, second, third) = (
        TestCa::new("first"),
        TestCa::new("second"),
        TestCa::new("third"),
    );

    world
        .server
        .set_client_config_v2(world.v2("tls", Some(services_with(&[&first, &second]))));
    world.login().result.unwrap();
    world
        .server
        .set_client_config_v2(world.v2("tls", Some(services_with(&[&third]))));
    world.login().result.unwrap();
    let replaced = world.store().read_gate_services().unwrap().unwrap();
    world.server.set_client_config_v2(world.v2("tcp", None));
    world.login().result.unwrap();

    assert_eq!(
        pinned_roots(&replaced),
        [third.pinned()["sha256"].as_str().unwrap()]
    );
    assert!(!world.services_file().exists());
    assert_eq!(world.ssh_config(), from_an_old_server);
}

#[test]
fn only_a_missing_route_falls_back_to_the_first_configuration() {
    let cases = [
        (StatusCode::NOT_FOUND, None, 1),
        (StatusCode::METHOD_NOT_ALLOWED, None, 1),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Some(ApiError::Rejected { status: 500 }),
            0,
        ),
        (
            StatusCode::BAD_GATEWAY,
            Some(ApiError::Rejected { status: 502 }),
            0,
        ),
    ];
    for (status, failure, first_calls) in cases {
        let world = World::new();
        world.server.set_client_config_v2(V2Reply::Status(status));

        let outcome = world.login().result;

        match failure {
            None => {
                outcome.unwrap();
                assert!(world.ssh_config().contains("    ProxyJump none\n"));
            }
            Some(expected) => match outcome {
                Err(LoginError::ClientConfig { source }) => assert_eq!(source, expected),
                other => panic!("{status}: {other:?}"),
            },
        }
        assert_eq!(world.server.seen(|seen| seen.client_config_v2_calls), 1);
        assert_eq!(
            world.server.seen(|seen| seen.client_config_calls),
            first_calls,
            "{status}"
        );
    }
}

#[test]
fn defects_in_the_tls_settings_never_stop_the_sign_in() {
    let (valid, expired) = (TestCa::new("valid"), TestCa::expired("expired"));
    let mut wrong_digest = services_with(&[&valid]);
    wrong_digest["roots"][0]["sha256"] = json!("00".repeat(32));
    let mut bad_domain = services_with(&[&valid]);
    bad_domain["domain"] = json!("Svc.Example");
    let cases = [
        (
            "tls",
            Some(services_with(&[&valid, &expired])),
            Some(1),
            vec![
                "warning: pinned root 2 of the gate was dropped: the pinned root of the gate is not valid at this time",
            ],
        ),
        (
            "tls",
            Some(wrong_digest),
            None,
            vec![
                "warning: pinned root 1 of the gate was dropped: the server sent a pinned root whose SHA-256",
                "warning: TLS roots unusable, using port 2222 for ssh",
            ],
        ),
        (
            "tls",
            None,
            None,
            vec![
                "warning: the server asks for SSH over TLS but sends no TLS settings for the gate; using port 2222 for ssh",
            ],
        ),
        (
            "tcp",
            Some(bad_domain),
            None,
            vec![
                "warning: the TLS settings of the gate were dropped: the server sent a services domain",
            ],
        ),
    ];
    for (transport, services, kept, expected_notes) in cases {
        let world = World::new();
        world
            .server
            .set_client_config_v2(world.v2(transport, services));

        let report = world.login().result.unwrap();

        let stored = world.store().read_gate_services().unwrap();
        assert_eq!(
            stored.as_ref().map(|stored| stored.services.roots.len()),
            kept,
            "{transport} {expected_notes:?}"
        );
        let text = world.ssh_config();
        assert_eq!(text.contains(PROXY_LINE), kept.is_some(), "{text}");
        assert_eq!(
            text.contains("    ProxyJump none\n"),
            kept.is_none(),
            "{text}"
        );
        let unusable = report
            .notes
            .iter()
            .any(|note| note.starts_with("warning: TLS roots unusable"));
        assert_eq!(
            unusable,
            expected_notes
                .iter()
                .any(|note| note.starts_with("warning: TLS roots unusable")),
            "{:?}",
            report.notes
        );
        for expected in expected_notes {
            assert!(
                report.notes.iter().any(|note| note.starts_with(expected)),
                "{expected}: {:?}",
                report.notes
            );
        }
    }
}

#[test]
fn a_failed_fetch_without_ssh_setup_keeps_the_previous_roots_byte_for_byte() {
    let world = World::new();
    let root = TestCa::new("pinned root");
    world
        .server
        .set_client_config_v2(world.v2("tls", Some(services_with(&[&root]))));
    world.login_without_ssh().result.unwrap();
    let before = fs::read(world.services_file()).unwrap();
    world
        .server
        .set_client_config_v2(V2Reply::Status(StatusCode::INTERNAL_SERVER_ERROR));

    let report = world.login_without_ssh().result.unwrap();

    assert_eq!(fs::read(world.services_file()).unwrap(), before);
    assert_eq!(mode(&world.services_file()), 0o600);
    assert_eq!(
        report.notes,
        [
            "warning: cannot fetch the TLS settings of the gate: the server rejected the request (HTTP 500); the previous TLS settings were kept"
        ]
    );
    world
        .server
        .set_client_config_v2(V2Reply::Status(StatusCode::NOT_FOUND));
    let report = world.login_without_ssh().result.unwrap();
    assert!(!world.services_file().exists());
    assert!(report.notes.is_empty(), "{:?}", report.notes);
    world.server.set_client_config_v2(world.v2("tls", None));
    let report = world.login_without_ssh().result.unwrap();
    assert!(report.notes.is_empty(), "{:?}", report.notes);
}

#[test]
fn bad_host_keys_refuse_only_the_ssh_setup_and_the_roots_are_kept_without_it() {
    let world = World::new();
    let root = TestCa::new("pinned root");
    let mut config = world.v2("tls", Some(services_with(&[&root])));
    if let V2Reply::Json(value) = &mut config {
        value["host_ca_keys"] = json!([]);
    }
    world.server.set_client_config_v2(config);

    let with_ssh = world.login().result;
    assert!(!world.home.join("default").exists());
    let message = with_ssh
        .as_ref()
        .err()
        .map(ToString::to_string)
        .unwrap_or_default();
    assert!(
        message.contains("use `--no-ssh-config` to store only the TLS settings"),
        "{message}"
    );
    world.login_without_ssh().result.unwrap();

    assert!(
        matches!(
            with_ssh,
            Err(LoginError::SshSettings(SshConfigError::BadHostKeys))
        ),
        "{with_ssh:?}"
    );
    let stored = world.store().read_gate_services().unwrap().unwrap();
    assert_eq!(
        pinned_roots(&stored),
        [root.pinned()["sha256"].as_str().unwrap()]
    );
    assert!(!world.home.join("default/ssh_config").exists());
}

#[test]
fn a_profile_without_ssh_setup_keeps_its_roots_renews_and_loses_them_with_the_server() {
    let world = World::with(Behavior {
        validity_secs: Some(30),
        ..Behavior::default()
    });
    let root = TestCa::new("pinned root");
    world
        .server
        .set_client_config_v2(world.v2("tls", Some(services_with(&[&root]))));

    world.login_without_ssh().result.unwrap();
    assert_eq!(mode(&world.services_file()), 0o600);
    assert!(!world.home.join("default/ssh_config").exists());
    let renewed = world.renew();
    assert!(matches!(renewed, Ok(Renewed::SignedIn(_))), "{renewed:?}");
    assert!(world.services_file().exists());
    world.server.set_client_config_v2(world.v2("tcp", None));
    let renewed = world.renew();

    assert!(matches!(renewed, Ok(Renewed::SignedIn(_))), "{renewed:?}");
    assert!(!world.services_file().exists());
    assert_eq!(world.server.seen(|seen| seen.client_config_calls), 0);
    assert_eq!(world.server.seen(|seen| seen.client_config_v2_calls), 3);
}

#[test]
fn a_new_server_or_user_drops_the_x509_certificate_and_keeps_the_key() {
    let world = World::new();
    let other = FakeServer::start(Behavior::default());
    let x509 = world.home.join("default/x509");
    let plant = || {
        fs::write(x509.join("cert.pem"), "CERT").unwrap();
    };
    world.login_without_ssh().result.unwrap();
    fs::create_dir(&x509).unwrap();
    fs::write(x509.join("key.pem"), "KEY").unwrap();
    plant();

    world.login_without_ssh().result.unwrap();
    assert!(x509.join("cert.pem").exists());
    world.login_on(&other, false).result.unwrap();
    assert!(!x509.join("cert.pem").exists());
    plant();
    let meta_path = world.home.join("default/meta.json");
    let mut meta: Value = serde_json::from_slice(&fs::read(&meta_path).unwrap()).unwrap();
    meta["user_id"] = json!("00000000-0000-0000-0000-000000000001");
    fs::write(&meta_path, meta.to_string()).unwrap();
    world.login_on(&other, false).result.unwrap();

    assert!(!x509.join("cert.pem").exists());
    assert_eq!(fs::read_to_string(x509.join("key.pem")).unwrap(), "KEY");
}

fn ssh_g(world: &World, target: &str) -> BTreeMap<String, Vec<String>> {
    let output = Command::new("ssh")
        .arg("-G")
        .arg("-F")
        .arg(world.user_home.join(".ssh/config"))
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

pub(crate) fn ssh_available() -> bool {
    Command::new("ssh")
        .arg("-V")
        .output()
        .is_ok_and(|output| output.status.success() || !output.stderr.is_empty())
}

#[test]
fn the_system_openssh_takes_the_proxy_command_for_the_gate_and_the_jump_for_nodes() {
    if !ssh_available() {
        eprintln!("skipped: no ssh client found");
        return;
    }
    let world = World::new();
    let root = TestCa::new("pinned root");
    world
        .server
        .set_client_config_v2(world.v2("tls", Some(services_with(&[&root]))));
    world.login().result.unwrap();

    let gate = ssh_g(&world, GATE_HOST);
    let node = ssh_g(&world, &format!("web-01.{SUFFIX}"));

    assert_eq!(
        gate["proxycommand"],
        [format!("'{HARMLESS_PROGRAM}' proxy ssh --profile default")]
    );
    assert!(
        !gate.contains_key("proxyjump"),
        "{:?}",
        gate.get("proxyjump")
    );
    assert_eq!(gate["user"], ["jaunt"]);
    assert_eq!(
        node["proxyjump"],
        [format!("jaunt@{GATE_HOST}:{GATE_PORT}")]
    );
    assert!(!node.contains_key("proxycommand"));
}
