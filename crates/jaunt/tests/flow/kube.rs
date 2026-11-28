use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Output, Stdio};
use std::time::{Duration, Instant, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, SecondsFormat, Utc};
use jaunt::agent::SshAgent;
use jaunt::ensure::{Freshness, check};
use jaunt::kube_credentials::{CredentialsIo, CredentialsRequest, run_credentials};
use jaunt::lock::ProfileLock;
use jaunt::profile::ProfileName;
use jaunt::store::ProfileStore;
use jaunt_proto::{ServiceKind, ServiceSummary};
use serde_json::{Value, json};
use ssh_key::private::Ed25519Keypair;
use tempfile::TempDir;
use x509_parser::pem::parse_x509_pem;

use crate::cli::{base_command, stderr, stdout, user_home, write_profile};
use crate::gate::{TestCa, services_json};
use crate::support::{
    Behavior, Browser, CertSpec, FakeServer, GATE_HOST, GATE_PORT, SUFFIX, Script, ScriptedPrompt,
    USER_ID, V2Reply, X509Reply, ca_key, new_key_data, now_secs, serial_section, sign,
};

const PKCS8_PREFIX_LEN: usize = 16;

fn now() -> i64 {
    i64::try_from(now_secs()).unwrap()
}

struct Profile {
    _root: TempDir,
    home: PathBuf,
    ca: TestCa,
}

impl Profile {
    fn new(server_url: &str, ssh_valid_before: i64, with_services: bool) -> Profile {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("state");
        write_profile(&home, server_url, ssh_valid_before);
        let mut spec = CertSpec::user(new_key_data(), 0);
        spec.valid_before = u64::try_from(ssh_valid_before).unwrap();
        spec.valid_after = spec.valid_before - 8 * 3600;
        let line = sign(&ca_key(), &spec).to_openssh().unwrap();
        fs::write(
            home.join("default/id_ed25519-cert.pub"),
            format!("{line}\n"),
        )
        .unwrap();
        let ca = TestCa::new("kube root");
        if with_services {
            fs::write(
                home.join("default/services.json"),
                services_json(443, &[ca.pinned()]).to_string(),
            )
            .unwrap();
        }
        Profile {
            _root: root,
            home,
            ca,
        }
    }

    fn side(&self, name: &str) -> PathBuf {
        self.home.parent().unwrap().join(name)
    }

    fn run(&self, args: &[&str]) -> Output {
        base_command(&self.home)
            .env_remove("KUBECONFIG")
            .args(args)
            .output()
            .unwrap()
    }

    fn run_with_variable(&self, variable: &str, args: &[&str]) -> Output {
        base_command(&self.home)
            .env("KUBECONFIG", variable)
            .args(args)
            .output()
            .unwrap()
    }

    fn key_body(&self) -> Option<String> {
        let key = fs::read_to_string(self.home.join("default/x509/key.pem")).ok()?;
        key.lines().nth(1).map(str::to_owned)
    }
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn assert_no_key_material(text: &str, key_body: Option<&str>, case: &str) {
    assert!(!text.contains("PRIVATE KEY"), "{case}: {text}");
    assert!(!text.contains("-----BEGIN"), "{case}: {text}");
    if let Some(body) = key_body {
        assert!(!text.contains(body), "{case}: {text}");
    }
}

fn entry<'a>(config: &'a Value, list: &str, name: &str) -> &'a Value {
    let found: Vec<&Value> = config[list]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["name"] == name)
        .collect();
    assert_eq!(found.len(), 1, "{list} {name}: {config}");
    found[0]
}

fn names(config: &Value, list: &str) -> Vec<String> {
    config[list]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| item["name"].as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn read_config(path: &Path) -> Value {
    serde_saphyr::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn assert_kubectl_can_use(config: &Value, context: &str, cluster: &str, profile: &Profile) {
    assert_eq!(config["apiVersion"], "v1");
    assert_eq!(config["kind"], "Config");
    let joined = &entry(config, "contexts", context)["context"];
    let cluster_entry = &entry(config, "clusters", joined["cluster"].as_str().unwrap())["cluster"];
    let user = &entry(config, "users", joined["user"].as_str().unwrap())["user"];
    let server = url::Url::parse(cluster_entry["server"].as_str().unwrap()).unwrap();
    assert_eq!(server.scheme(), "https");
    assert_eq!(
        server.host_str(),
        Some(format!("{cluster}.kube.localhost").as_str())
    );
    assert_eq!(server.port(), None);
    let bundle = STANDARD
        .decode(
            cluster_entry["certificate-authority-data"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    let (rest, pem) = parse_x509_pem(&bundle).unwrap();
    assert!(rest.is_empty());
    assert_eq!(pem.label, "CERTIFICATE");
    assert_eq!(pem.contents, profile.ca.der());
    assert!(pem.parse_x509().unwrap().is_ca());
    let exec = &user["exec"];
    assert_eq!(exec["apiVersion"], "client.authentication.k8s.io/v1");
    assert_eq!(exec["interactiveMode"], "IfAvailable");
    assert_eq!(exec["provideClusterInfo"], false);
    let command = Path::new(exec["command"].as_str().unwrap());
    assert!(command.is_absolute());
    assert_eq!(
        fs::canonicalize(command).unwrap(),
        fs::canonicalize(env!("CARGO_BIN_EXE_jaunt")).unwrap()
    );
    let home = profile.home.display().to_string();
    assert_eq!(
        exec["args"],
        json!([
            "kube",
            "credentials",
            "--profile",
            "default",
            "--home",
            home
        ])
    );
    let user_keys: Vec<&String> = user.as_object().unwrap().keys().collect();
    assert_eq!(user_keys, ["exec", "extensions"]);
}

fn assert_exec_credential(text: &str, profile: &Profile, x509_end: i64) {
    assert_eq!(text.lines().count(), 1, "{text}");
    assert!(text.ends_with("}\n"), "{text}");
    let parsed: Value = serde_json::from_str(text).unwrap();
    assert_eq!(parsed["apiVersion"], "client.authentication.k8s.io/v1");
    assert_eq!(parsed["kind"], "ExecCredential");
    let status = parsed["status"].as_object().unwrap();
    let mut keys: Vec<&String> = status.keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "clientCertificateData",
            "clientKeyData",
            "expirationTimestamp"
        ]
    );
    let (rest, pem) =
        parse_x509_pem(status["clientCertificateData"].as_str().unwrap().as_bytes()).unwrap();
    assert!(rest.is_empty(), "only the leaf is sent");
    let leaf = pem.parse_x509().unwrap();
    assert_eq!(leaf.validity().not_after.timestamp(), x509_end);
    assert!(!leaf.is_ca());
    let names = leaf.subject_alternative_name().unwrap().unwrap();
    assert_eq!(
        format!("{:?}", names.value.general_names),
        format!("[URI(\"urn:jaunt:user:{USER_ID}\")]")
    );
    let key = status["clientKeyData"].as_str().unwrap();
    assert_eq!(
        key,
        fs::read_to_string(profile.home.join("default/x509/key.pem")).unwrap()
    );
    let (_, key_pem) = parse_x509_pem(key.as_bytes()).unwrap();
    assert_eq!(key_pem.label, "PRIVATE KEY");
    let seed: [u8; 32] = key_pem.contents[PKCS8_PREFIX_LEN..].try_into().unwrap();
    let public = Ed25519Keypair::from_seed(&seed).public;
    assert!(leaf.public_key().raw.ends_with(&public.0));
    let expected = DateTime::<Utc>::from_timestamp(x509_end - 30, 0)
        .unwrap()
        .to_rfc3339_opts(SecondsFormat::Secs, true);
    assert_eq!(status["expirationTimestamp"], expected.as_str());
    assert!(expected.ends_with('Z'));
}

#[test]
fn credentials_print_exactly_one_exec_credential_and_nothing_else() {
    let _serial = serial_section();
    let x509_end = now() + 1800;
    let server = FakeServer::start(Behavior {
        x509: X509Reply::Issue {
            valid_before: x509_end,
        },
        ..Behavior::default()
    });
    let profile = Profile::new(&server.url(), now() + 3600, true);

    let first = profile.run(&["kube", "credentials", "--cluster", "prod"]);
    let second = profile.run(&["kube", "credentials"]);

    for output in [&first, &second] {
        assert_eq!(output.status.code(), Some(0), "{}", stderr(output));
        assert_eq!(stderr(output), "");
        assert_exec_credential(&stdout(output), &profile, x509_end);
    }
    assert_eq!(server.seen(|seen| seen.x509_requests.len()), 1);
    assert_eq!(mode(&profile.home.join("default/x509/key.pem")), 0o600);
}

#[test]
fn every_failure_prints_nothing_on_stdout_and_never_the_key_on_stderr() {
    let _serial = serial_section();
    let issuing = FakeServer::start(Behavior {
        x509: X509Reply::Issue {
            valid_before: now() + 1800,
        },
        ..Behavior::default()
    });
    let refusing = FakeServer::start(Behavior::default());
    let expired = Profile::new(&issuing.url(), now() - 10, true);
    let never = Profile::new(&issuing.url(), now() + 3600, true);
    fs::remove_dir_all(never.home.join("default")).unwrap();
    let old_server = Profile::new(&issuing.url(), now() + 3600, false);
    let not_issuing = Profile::new(&refusing.url(), now() + 3600, true);
    let long_domain = Profile::new(&issuing.url(), now() + 3600, true);
    let services_path = long_domain.home.join("default/services.json");
    let mut services: Value = serde_json::from_slice(&fs::read(&services_path).unwrap()).unwrap();
    services["services"]["domain"] = json!(format!(
        "{}.{}.{}",
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(60)
    ));
    fs::write(&services_path, services.to_string()).unwrap();
    let longest_label = "a".repeat(63);
    let credentials = ["kube", "credentials", "--cluster", "prod"];
    let cases: [(&str, &Profile, Vec<&str>, i32, &str); 7] = [
        (
            "cluster name too long for the stored domain",
            &long_domain,
            vec!["kube", "credentials", "--cluster", longest_label.as_str()],
            1,
            "is too long for a DNS name",
        ),
        (
            "expired sign-in without a terminal",
            &expired,
            credentials.to_vec(),
            1,
            "has expired: run `JAUNT_HOME='",
        ),
        (
            "never signed in",
            &never,
            credentials.to_vec(),
            1,
            "not signed in",
        ),
        (
            "server without services",
            &old_server,
            credentials.to_vec(),
            1,
            "does not offer Kubernetes access",
        ),
        (
            "server without X.509",
            &not_issuing,
            credentials.to_vec(),
            1,
            "this server does not issue X.509 certificates",
        ),
        (
            "cluster name that is not a DNS label",
            &old_server,
            vec!["kube", "credentials", "--cluster", "Prod_1"],
            2,
            "cluster names are DNS labels",
        ),
        (
            "relative home",
            &old_server,
            vec!["kube", "credentials", "--cluster", "prod", "--home", "rel"],
            2,
            "--home must be an absolute path",
        ),
    ];
    for (case, profile, args, code, message) in cases {
        let output = profile.run(&args);

        assert_eq!(
            output.status.code(),
            Some(code),
            "{case}: {}",
            stderr(&output)
        );
        assert!(output.stdout.is_empty(), "{case}: {}", stdout(&output));
        let errors = stderr(&output);
        assert!(errors.contains(message), "{case}: {errors}");
        if code == 1 {
            assert_eq!(errors.lines().count(), 1, "{case}: {errors}");
        }
        assert_no_key_material(&errors, profile.key_body().as_deref(), case);
    }
    assert!(
        stderr(&expired.run(&credentials)).contains("and retry"),
        "the hint names the retry"
    );
    assert_eq!(issuing.seen(|seen| seen.requests), 0);
    assert!(issuing.seen(|seen| seen.x509_requests.is_empty()));
    assert!(not_issuing.key_body().is_some());
}

struct LockProbe {
    home: PathBuf,
    lock_path: PathBuf,
    bytes: Vec<u8>,
    lock_was_free: Option<bool>,
}

impl Write for LockProbe {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.lock_was_free.is_none() {
            let probe =
                ProfileLock::acquire(&self.home, &self.lock_path, Instant::now(), &mut || {});
            self.lock_was_free = Some(probe.is_ok());
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn an_expired_sign_in_on_a_terminal_signs_in_through_the_browser_and_prints_without_the_lock() {
    let x509_end = now() + 1800;
    let server = FakeServer::start(Behavior {
        x509: X509Reply::Issue {
            valid_before: x509_end,
        },
        ..Behavior::default()
    });
    let profile = Profile::new(&server.url(), now() - 10, true);
    server.set_client_config_v2(V2Reply::Json(json!({
        "ssh_suffix": SUFFIX,
        "gate": {"host": GATE_HOST, "port": GATE_PORT},
        "host_ca_keys": [server.host_ca_line()],
        "ssh_gate": {"client_transport": "tcp"},
        "services": services_json(443, &[profile.ca.pinned()])["services"],
    })));
    let store = ProfileStore::new(&profile.home, &ProfileName::default_name());
    let request = CredentialsRequest {
        home: profile.home.clone(),
        custom_home: true,
        profile: ProfileName::default_name(),
        cluster: Some("prod".parse().unwrap()),
        ssh: None,
        deadline: Duration::from_secs(60),
    };
    let browser = Browser::new(&server, Script::Approve);
    let mut out = LockProbe {
        home: profile.home.clone(),
        lock_path: store.lock_path(),
        bytes: Vec::new(),
        lock_was_free: None,
    };
    let mut errors = Vec::new();

    let code = run_credentials(
        &request,
        CredentialsIo {
            stdout: &mut out,
            stdout_terminal: false,
            stderr: &mut errors,
            terminal: true,
            browser: &browser,
            agent: &SshAgent::new(None),
            consent: &ScriptedPrompt::new(false, false),
            clock: &SystemTime::now,
        },
    );

    let errors = String::from_utf8(errors).unwrap();
    assert_eq!(code, 0, "{errors}");
    assert!(errors.contains("needs renewal; signing in to"), "{errors}");
    assert!(
        errors.contains("Signed in as alice@example.com"),
        "{errors}"
    );
    assert_no_key_material(&errors, profile.key_body().as_deref(), "interactive");
    assert_eq!(out.lock_was_free, Some(true));
    assert_exec_credential(&String::from_utf8(out.bytes).unwrap(), &profile, x509_end);
    assert_eq!(browser.opened_urls().len(), 1);
    assert_eq!(server.seen(|seen| seen.finish_calls), 1);
    assert_eq!(check(&store, now()).unwrap(), Freshness::Fresh);

    let mut silent = Vec::new();
    let mut quiet_errors = Vec::new();
    let expired = Profile::new(&server.url(), now() - 10, true);
    let unused = Browser::new(&server, Script::Approve);
    let code = run_credentials(
        &CredentialsRequest {
            home: expired.home.clone(),
            ..request
        },
        CredentialsIo {
            stdout: &mut silent,
            stdout_terminal: false,
            stderr: &mut quiet_errors,
            terminal: false,
            browser: &unused,
            agent: &SshAgent::new(None),
            consent: &ScriptedPrompt::new(false, false),
            clock: &SystemTime::now,
        },
    );
    assert_eq!(code, 1);
    assert!(silent.is_empty());
    assert!(unused.opened_urls().is_empty());
    assert_eq!(server.seen(|seen| seen.finish_calls), 1);
}

struct BrokenPipe;

impl Write for BrokenPipe {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
}

#[test]
fn a_terminal_or_failing_stdout_never_gets_the_key_and_stderr_never_does() {
    let server = FakeServer::start(Behavior {
        x509: X509Reply::Issue {
            valid_before: now() + 1800,
        },
        ..Behavior::default()
    });
    let profile = Profile::new(&server.url(), now() + 3600, true);
    let request = CredentialsRequest {
        home: profile.home.clone(),
        custom_home: true,
        profile: ProfileName::default_name(),
        cluster: None,
        ssh: None,
        deadline: Duration::from_secs(60),
    };
    let browser = Browser::new(&server, Script::Silent);
    let run = |stdout: &mut dyn Write, stdout_terminal: bool| {
        let mut errors = Vec::new();
        let code = run_credentials(
            &request,
            CredentialsIo {
                stdout,
                stdout_terminal,
                stderr: &mut errors,
                terminal: false,
                browser: &browser,
                agent: &SshAgent::new(None),
                consent: &ScriptedPrompt::new(false, false),
                clock: &SystemTime::now,
            },
        );
        (code, String::from_utf8(errors).unwrap())
    };

    let mut shown = Vec::new();
    let (code, errors) = run(&mut shown, true);

    assert_eq!(code, 2, "{errors}");
    assert!(
        errors.contains("this command is run by kubectl; it prints a private key"),
        "{errors}"
    );
    assert!(shown.is_empty());
    assert!(server.seen(|seen| seen.x509_requests.is_empty()));
    assert!(profile.key_body().is_none());

    let (code, errors) = run(&mut BrokenPipe, false);

    assert_eq!(code, 1, "{errors}");
    assert!(errors.contains("cannot write to the terminal"), "{errors}");
    assert_eq!(errors.lines().count(), 1, "{errors}");
    assert_no_key_material(&errors, profile.key_body().as_deref(), "failing stdout");
    assert!(!errors.contains("clientKeyData"), "{errors}");
    assert!(!errors.contains("ExecCredential"), "{errors}");
}

#[test]
fn kube_login_merges_into_the_first_kubeconfig_path_and_logout_takes_back_only_its_entries() {
    let _serial = serial_section();
    let profile = Profile::new("https://jaunt.example.com", now() + 3600, true);
    let first = profile.side("first/config");
    let second = profile.side("second/config");
    fs::create_dir_all(second.parent().unwrap()).unwrap();
    let theirs = "apiVersion: v1\nkind: Config\ncurrent-context: theirs\nclusters:\n- name: theirs\n  cluster: {server: 'https://k8s.example.test'}\n";
    fs::write(&second, theirs).unwrap();
    let variable = format!("{}:{}", first.display(), second.display());

    let login = profile.run_with_variable(&variable, &["kube", "login", "prod"]);

    assert_eq!(login.status.code(), Some(0), "{}", stderr(&login));
    let shown = stdout(&login);
    assert!(
        shown.starts_with(&format!(
            "Created {} with the Kubernetes cluster `prod` as context `jaunt-default-prod`.",
            first.display()
        )),
        "{shown}"
    );
    assert!(
        shown.contains(&format!(
            "The current context was not set: {} (also in KUBECONFIG) names `theirs`, and kubectl uses that one",
            second.display()
        )),
        "{shown}"
    );
    assert_eq!(fs::read_to_string(&second).unwrap(), theirs);
    assert_eq!(mode(&first), 0o600);
    assert_eq!(mode(first.parent().unwrap()), 0o700);
    let config = read_config(&first);
    assert_kubectl_can_use(&config, "jaunt-default-prod", "prod", &profile);
    assert_eq!(config["current-context"], "");
    let written = fs::read(&first).unwrap();

    let again = profile.run_with_variable(&variable, &["kube", "login", "prod"]);
    assert_eq!(again.status.code(), Some(0), "{}", stderr(&again));
    assert!(
        stdout(&again).contains("nothing changed"),
        "{}",
        stdout(&again)
    );
    assert_eq!(fs::read(&first).unwrap(), written);
    assert_eq!(fs::read_dir(first.parent().unwrap()).unwrap().count(), 1);

    let flag = profile.run_with_variable(
        "/nonexistent/ignored",
        &[
            "kube",
            "login",
            "stage",
            "--context",
            "stage-ctx",
            "--kubeconfig",
            first.to_str().unwrap(),
        ],
    );
    assert_eq!(flag.status.code(), Some(0), "{}", stderr(&flag));
    assert!(stdout(&flag).starts_with("Updated "), "{}", stdout(&flag));
    assert!(stdout(&flag).contains("The previous file is saved as "));
    assert!(
        stdout(&flag).contains("The file had no current context, so it is now `stage-ctx`."),
        "{}",
        stdout(&flag)
    );
    let config = read_config(&first);
    assert_kubectl_can_use(&config, "stage-ctx", "stage", &profile);
    assert_eq!(config["current-context"], "stage-ctx");
    assert_eq!(names(&config, "users"), ["jaunt-default"]);

    let one = profile.run_with_variable(&variable, &["kube", "logout", "prod"]);
    assert_eq!(one.status.code(), Some(0), "{}", stderr(&one));
    assert!(
        stdout(&one).starts_with(&format!(
            "Removed from {}: contexts `jaunt-default-prod`; cluster entries `jaunt-default-prod`.",
            first.display()
        )),
        "{}",
        stdout(&one)
    );
    assert!(
        stdout(&one).contains(
            "Kept the user entry `jaunt-default`: the context `stage-ctx` still uses it."
        ),
        "{}",
        stdout(&one)
    );
    assert_eq!(stderr(&one), "");
    let all = profile.run_with_variable(&variable, &["kube", "logout"]);
    assert_eq!(all.status.code(), Some(0), "{}", stderr(&all));
    assert!(
        stdout(&all).contains(
            "The current context `stage-ctx` was removed, so kubectl has no usable current context now: choose one with `kubectl config use-context NAME`."
        ),
        "{}",
        stdout(&all)
    );
    assert!(
        stderr(&all).contains("warning: the current context `stage-ctx` was removed"),
        "{}",
        stderr(&all)
    );
    let config = read_config(&first);
    for list in ["clusters", "contexts", "users"] {
        assert!(names(&config, list).is_empty(), "{list}: {config}");
    }
    let nothing = profile.run_with_variable(&variable, &["kube", "logout"]);
    assert_eq!(nothing.status.code(), Some(0));
    assert!(
        stdout(&nothing).starts_with("Nothing that jaunt added for profile `default` was found"),
        "{}",
        stdout(&nothing)
    );
    assert_eq!(fs::read_to_string(&second).unwrap(), theirs);
}

#[test]
fn kube_login_uses_the_home_kubeconfig_and_refuses_files_it_cannot_read_untouched() {
    let _serial = serial_section();
    let profile = Profile::new("https://jaunt.example.com", now() + 3600, true);

    let login = profile.run(&["kube", "login", "prod"]);

    assert_eq!(login.status.code(), Some(0), "{}", stderr(&login));
    let default = user_home(&profile.home).join(".kube/config");
    let config = read_config(&default);
    assert_kubectl_can_use(&config, "jaunt-default-prod", "prod", &profile);
    assert_eq!(config["current-context"], "jaunt-default-prod");
    assert!(
        stdout(&login)
            .contains("The file had no current context, so it is now `jaunt-default-prod`."),
        "{}",
        stdout(&login)
    );
    assert_eq!(mode(default.parent().unwrap()), 0o700);

    let refused = [
        ("clusters: [\n", "is not valid YAML"),
        ("apiVersion: v1\nkind: Pod\n", "its `kind` is not `Config`"),
        (
            "apiVersion: v2\nkind: Config\n",
            "its `apiVersion` is not `v1`",
        ),
        (
            "apiVersion: v1\nkind: Config\ncontexts:\n- name: jaunt-default-prod\n  context: {cluster: mine, user: me}\n",
            "choose another name with --context NAME",
        ),
    ];
    for (content, message) in refused {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        fs::write(&path, content).unwrap();

        let output = profile.run(&[
            "kube",
            "login",
            "prod",
            "--kubeconfig",
            path.to_str().unwrap(),
        ]);

        assert_eq!(output.status.code(), Some(1), "{content}");
        assert!(output.stdout.is_empty(), "{content}");
        assert!(
            stderr(&output).contains("was left unchanged"),
            "{}",
            stderr(&output)
        );
        assert!(stderr(&output).contains(message), "{}", stderr(&output));
        assert_eq!(fs::read_to_string(&path).unwrap(), content);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1, "{content}");
    }

    let old_server = Profile::new("https://jaunt.example.com", now() + 3600, false);
    let target = old_server.side("config");
    let old = old_server.run(&[
        "kube",
        "login",
        "prod",
        "--kubeconfig",
        target.to_str().unwrap(),
    ]);
    assert_eq!(old.status.code(), Some(1));
    assert!(
        stderr(&old).contains("does not offer Kubernetes access"),
        "{}",
        stderr(&old)
    );
    assert!(!target.exists());
    let bad_name = old_server.run(&["kube", "login", "Prod"]);
    assert_eq!(bad_name.status.code(), Some(2));
    assert!(stderr(&bad_name).contains("cluster names are DNS labels"));
}

#[test]
fn kube_logins_from_several_processes_at_once_keep_every_entry() {
    let _serial = serial_section();
    let profile = Profile::new("https://jaunt.example.com", now() + 3600, true);
    let path = profile.side("shared-config");
    let clusters = ["alpha", "beta", "gamma", "delta"];

    let children: Vec<Child> = clusters
        .iter()
        .map(|cluster| {
            base_command(&profile.home)
                .env_remove("KUBECONFIG")
                .args([
                    "kube",
                    "login",
                    cluster,
                    "--kubeconfig",
                    path.to_str().unwrap(),
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    }

    let config = read_config(&path);
    let mut contexts = names(&config, "contexts");
    contexts.sort();
    let mut expected: Vec<String> = clusters
        .iter()
        .map(|cluster| format!("jaunt-default-{cluster}"))
        .collect();
    expected.sort();
    assert_eq!(contexts, expected);
    assert_eq!(names(&config, "clusters").len(), clusters.len());
    assert_eq!(names(&config, "users"), ["jaunt-default"]);
    for cluster in clusters {
        assert_kubectl_can_use(
            &config,
            &format!("jaunt-default-{cluster}"),
            cluster,
            &profile,
        );
    }
}

#[test]
fn kube_ls_is_the_kube_listing() {
    let _serial = serial_section();
    let server = FakeServer::start(Behavior {
        services: Some(vec![
            ServiceSummary {
                kind: ServiceKind::Kubernetes,
                name: "prod-eu".to_owned(),
                labels: [("env".to_owned(), "prod".to_owned())].into(),
                connected: true,
            },
            ServiceSummary {
                kind: ServiceKind::Postgres,
                name: "orders".to_owned(),
                labels: Default::default(),
                connected: true,
            },
        ]),
        ..Behavior::default()
    });
    let profile = Profile::new(&server.url(), now() + 3600, true);

    for format in ["text", "json"] {
        let short = profile.run(&["kube", "ls", "--format", format]);
        let long = profile.run(&["ls", "--kind", "kube", "--format", format]);

        assert_eq!(short.status.code(), Some(0), "{}", stderr(&short));
        assert_eq!(stdout(&short), stdout(&long), "{format}");
        assert!(stdout(&short).contains("prod-eu"));
        assert!(!stdout(&short).contains("orders"));
    }
}
