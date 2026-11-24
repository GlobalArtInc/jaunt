use std::fs;

use jaunt_proto::{NodeList, NodeSummary};

use crate::cli::{base_command, jaunt, login_through_the_binary, stderr, stdout, user_home};
use crate::support::{
    Behavior, ClientConfigReply, FakeServer, GATE_HOST, GATE_PORT, SUFFIX, serial_section,
};

fn node(name: &str, labels: &[(&str, &str)]) -> NodeSummary {
    NodeSummary {
        name: name.to_owned(),
        labels: labels
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect(),
        hostname: format!("{name}.internal"),
        connected: false,
    }
}

fn server(client_config: ClientConfigReply) -> FakeServer {
    FakeServer::start(Behavior {
        client_config,
        nodes: vec![node("web-01", &[("env", "prod")]), node("db-1", &[])],
        ..Behavior::default()
    })
}

#[test]
fn login_status_ls_and_logout_cover_the_ssh_setup_end_to_end() {
    let _serial = serial_section();
    let server = server(ClientConfigReply::Valid);
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let ssh_config = user_home(&home).join(".ssh/config");

    let finished = login_through_the_binary(&server, &home, |command| {
        command.arg("--accept-ssh-config");
    });

    assert!(finished.status.success(), "{}", finished.stderr);
    assert_eq!(finished.stdout.lines().count(), 1, "{}", finished.stdout);
    assert!(
        finished.stderr.contains(
            "SSH setup is ready for *.example.test through gate.other.test:2222: created"
        ),
        "{}",
        finished.stderr
    );
    let include = fs::read_to_string(&ssh_config).unwrap();
    assert_eq!(
        include,
        format!("Include {}/*/ssh_config\n", home.display())
    );

    let status = jaunt(&home, &["status"]);
    assert_eq!(status.status.code(), Some(0), "{}", stderr(&status));
    assert!(
        stdout(&status).contains(&format!(
            "SSH setup: ready (hosts *.{SUFFIX} through {GATE_HOST}:{GATE_PORT})"
        )),
        "{}",
        stdout(&status)
    );

    let listed = jaunt(&home, &["ls"]);
    assert_eq!(listed.status.code(), Some(0), "{}", stderr(&listed));
    let expected = format!(
        "NAME                 LABELS\nweb-01.{SUFFIX}  env=prod\ndb-1.{SUFFIX}    -\nssh <login>@web-01.{SUFFIX}\n"
    );
    assert_eq!(stdout(&listed), expected);

    let json = jaunt(&home, &["ls", "--format", "json"]);
    assert_eq!(json.status.code(), Some(0), "{}", stderr(&json));
    let parsed: NodeList = serde_json::from_str(&stdout(&json)).unwrap();
    assert_eq!(parsed.nodes.len(), 2);
    assert!(!parsed.truncated);
    assert_eq!(parsed.nodes[0].name, "web-01");

    fs::write(&ssh_config, "Host other\n").unwrap();
    let detached = jaunt(&home, &["status"]);
    assert!(
        stdout(&detached).contains("does not include them"),
        "{}",
        stdout(&detached)
    );

    let logout = jaunt(&home, &["logout"]);
    assert_eq!(logout.status.code(), Some(0), "{}", stderr(&logout));
    assert!(!home.join("default").exists());
    assert_eq!(fs::read_to_string(&ssh_config).unwrap(), "Host other\n");
}

#[test]
fn without_a_terminal_or_the_flag_the_binary_skips_the_ssh_setup_and_says_how_to_enable_it() {
    let _serial = serial_section();
    let server = server(ClientConfigReply::Valid);
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");

    let finished = login_through_the_binary(&server, &home, |_| {});

    assert!(finished.status.success(), "{}", finished.stderr);
    assert!(
        finished
            .stderr
            .contains("run `jaunt login --accept-ssh-config` to enable it"),
        "{}",
        finished.stderr
    );
    assert!(!user_home(&home).join(".ssh").exists());
    assert!(!home.join("default/ssh_config").exists());
}

#[test]
fn a_relative_home_is_a_usage_error_for_the_ssh_setup_but_not_with_no_ssh_config() {
    let _serial = serial_section();
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let attempt = |extra: &[&str]| {
        base_command(&home)
            .env("HOME", "relative/home")
            .args(["login", "--server", "https://127.0.0.1:1", "--timeout", "1"])
            .args(extra)
            .output()
            .unwrap()
    };

    let refused = attempt(&[]);

    assert_eq!(refused.status.code(), Some(2), "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("home directory"),
        "{}",
        stderr(&refused)
    );
    assert!(
        stderr(&refused).contains("--no-ssh-config"),
        "{}",
        stderr(&refused)
    );
    let skipped = attempt(&["--no-ssh-config"]);
    assert_ne!(skipped.status.code(), Some(2), "{}", stderr(&skipped));
}

#[test]
fn no_ssh_config_leaves_the_users_ssh_directory_alone_and_ls_still_works() {
    let _serial = serial_section();
    let server = server(ClientConfigReply::Valid);
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");

    let finished = login_through_the_binary(&server, &home, |command| {
        command.arg("--no-ssh-config");
    });

    assert!(finished.status.success(), "{}", finished.stderr);
    assert!(!user_home(&home).join(".ssh").exists());
    assert_eq!(server.seen(|seen| seen.client_config_calls), 0);
    let status = jaunt(&home, &["status"]);
    assert!(
        stdout(&status).contains("SSH setup: not installed"),
        "{}",
        stdout(&status)
    );
    let listed = jaunt(&home, &["ls"]);
    assert_eq!(listed.status.code(), Some(0), "{}", stderr(&listed));
    assert!(
        stdout(&listed).contains(&format!("web-01.{SUFFIX}")),
        "{}",
        stdout(&listed)
    );
}

#[test]
fn ls_falls_back_to_bare_names_when_the_server_has_no_gate() {
    let _serial = serial_section();
    let server = server(ClientConfigReply::NotConfigured);
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let finished = login_through_the_binary(&server, &home, |_| {});
    assert!(finished.status.success(), "{}", finished.stderr);
    assert!(
        finished.stderr.contains("no SSH gateway configured"),
        "{}",
        finished.stderr
    );
    assert!(!user_home(&home).join(".ssh").exists());

    let listed = jaunt(&home, &["ls"]);

    assert_eq!(listed.status.code(), Some(0), "{}", stderr(&listed));
    assert_eq!(
        stdout(&listed),
        "NAME    LABELS\nweb-01  env=prod\ndb-1    -\n"
    );
    assert!(
        stderr(&listed).contains("without the SSH domain"),
        "{}",
        stderr(&listed)
    );
}

#[test]
fn ls_reports_a_rejected_session_and_a_missing_one_with_exit_one() {
    let _serial = serial_section();
    let server = server(ClientConfigReply::Valid);
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");

    let signed_out = jaunt(&home, &["ls"]);
    assert_eq!(signed_out.status.code(), Some(1));
    assert!(
        stderr(&signed_out).contains("run `jaunt login`"),
        "{}",
        stderr(&signed_out)
    );

    let finished = login_through_the_binary(&server, &home, |_| {});
    assert!(finished.status.success(), "{}", finished.stderr);
    server.revoke();
    let rejected = jaunt(&home, &["ls"]);

    assert_eq!(rejected.status.code(), Some(1));
    assert_eq!(
        stderr(&rejected).trim_end(),
        "jaunt: your session expired: run `jaunt login`"
    );
    assert!(stdout(&rejected).is_empty());
}
