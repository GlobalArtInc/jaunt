use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::args::InstallOptions;
use super::env::Env;
use super::layout::{Layout, SSHD_CONFIG};
use super::report::Report;
use super::runner::{Output, Runner, RunnerError, command_line};

pub const STOCK_SSHD_CONFIG: &str = "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n";

pub struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    pub fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "jaunt-agent-test-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn path_of(&self, virtual_path: &str) -> PathBuf {
        self.path.join(virtual_path.trim_start_matches('/'))
    }

    pub fn write(&self, virtual_path: &str, content: &str) {
        let path = self.path_of(virtual_path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    pub fn read(&self, virtual_path: &str) -> Option<String> {
        fs::read_to_string(self.path_of(virtual_path)).ok()
    }

    pub fn snapshot(&self) -> BTreeMap<String, String> {
        let mut entries = BTreeMap::new();
        collect(&self.path, &self.path, &mut entries);
        entries
    }
}

fn collect(base: &Path, dir: &Path, entries: &mut BTreeMap<String, String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let relative = path
            .strip_prefix(base)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let meta = fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        if meta.is_dir() {
            entries.insert(relative, format!("dir {mode:o}"));
            collect(base, &path, entries);
        } else {
            entries.insert(
                relative,
                format!("file {mode:o} {}", fs::read_to_string(&path).unwrap()),
            );
        }
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone)]
pub struct FakeConfig {
    pub uid: String,
    pub listen: Vec<String>,
    pub sshd_t_rejects_trust_line: bool,
    pub sshd_t_always_fails: bool,
    pub leak_trust_outside_loopback: bool,
    pub foreign_global_ca: Option<String>,
    pub foreign_ca_for_client: Option<(String, String)>,
    pub existing_group: bool,
    pub group_members: String,
    pub existing_user_shell: Option<String>,
    pub existing_user_home: String,
    pub deploy_user_ca: Option<String>,
    pub userdel_keeps_group: bool,
    pub userdel_exit: i32,
    pub systemctl_missing: bool,
    pub useradd_missing: bool,
    pub groupadd_missing: bool,
    pub reload_ssh_ok: bool,
    pub reload_sshd_ok: bool,
    pub daemon_reload_ok: bool,
    pub systemctl_stop_ok: bool,
    pub pubkeyauthentication: String,
    pub authenticationmethods: String,
    pub selinux: Option<String>,
}

impl Default for FakeConfig {
    fn default() -> Self {
        Self {
            uid: "0".to_string(),
            listen: vec!["0.0.0.0:22".to_string(), "[::]:22".to_string()],
            sshd_t_rejects_trust_line: false,
            sshd_t_always_fails: false,
            leak_trust_outside_loopback: false,
            foreign_global_ca: None,
            foreign_ca_for_client: None,
            existing_group: false,
            group_members: String::new(),
            existing_user_shell: None,
            existing_user_home: "/var/lib/jaunt".to_string(),
            deploy_user_ca: None,
            userdel_keeps_group: false,
            userdel_exit: 0,
            systemctl_missing: false,
            useradd_missing: false,
            groupadd_missing: false,
            reload_ssh_ok: true,
            reload_sshd_ok: true,
            daemon_reload_ok: true,
            systemctl_stop_ok: true,
            pubkeyauthentication: "yes".to_string(),
            authenticationmethods: "any".to_string(),
            selinux: None,
        }
    }
}

pub struct FakeRunner {
    root: PathBuf,
    pub config: FakeConfig,
    pub calls: Vec<String>,
    group_present: bool,
    user: Option<(String, String)>,
}

fn reply(code: i32, stdout: &str, stderr: &str) -> Result<Output, RunnerError> {
    Ok(Output {
        code: Some(code),
        stdout: stdout.to_string(),
        stderr: stderr.to_string(),
    })
}

impl FakeRunner {
    fn dropin(&self) -> Option<String> {
        fs::read_to_string(self.root.join("etc/ssh/sshd_config.d/50-jaunt.conf")).ok()
    }

    fn sshd(&self, args: &[&str]) -> Output {
        let mut rest = args;
        if let ["-f", _, tail @ ..] = rest {
            rest = tail;
        }
        let dropin = self.dropin();
        match rest {
            ["-t"] => {
                let rejects = self.config.sshd_t_always_fails
                    || (self.config.sshd_t_rejects_trust_line
                        && dropin
                            .as_deref()
                            .is_some_and(|text| text.contains("TrustedUserCAKeys")));
                if rejects {
                    Output {
                        code: Some(255),
                        stdout: String::new(),
                        stderr: "/etc/ssh/sshd_config.d/50-jaunt.conf line 3: Bad configuration option\n"
                            .to_string(),
                    }
                } else {
                    Output::success_empty()
                }
            }
            ["-T"] => Output {
                code: Some(0),
                stdout: self.dump(None, None),
                stderr: String::new(),
            },
            ["-T", "-C", spec] => Output {
                code: Some(0),
                stdout: self.dump(Some(spec), dropin.as_deref()),
                stderr: String::new(),
            },
            _ => Output {
                code: Some(1),
                stdout: String::new(),
                stderr: "unsupported fake sshd invocation\n".to_string(),
            },
        }
    }

    fn dump(&self, spec: Option<&str>, dropin: Option<&str>) -> String {
        let mut out = String::from("port 22\n");
        for address in &self.config.listen {
            out.push_str(&format!("listenaddress {address}\n"));
        }
        out.push_str(&format!(
            "pubkeyauthentication {}\nauthenticationmethods {}\n",
            self.config.pubkeyauthentication, self.config.authenticationmethods
        ));
        let Some(spec) = spec else {
            let global = self.config.foreign_global_ca.as_deref().unwrap_or("none");
            out.push_str(&format!("trustedusercakeys {global}\n"));
            return out;
        };
        let client = spec
            .split(',')
            .find_map(|part| part.strip_prefix("addr="))
            .unwrap_or("");
        let user = spec
            .split(',')
            .find_map(|part| part.strip_prefix("user="))
            .unwrap_or("");
        let from_dropin = dropin.and_then(|text| {
            let addresses = text
                .lines()
                .find_map(|line| line.trim().strip_prefix("Match Address "))?;
            let path = text
                .lines()
                .find_map(|line| line.trim().strip_prefix("TrustedUserCAKeys "))?;
            let matches = addresses.split(',').any(|address| address == client);
            Some((matches, path.to_string()))
        });
        let per_user = if user == "deploy" {
            self.config.deploy_user_ca.clone()
        } else {
            None
        };
        let for_client = self
            .config
            .foreign_ca_for_client
            .as_ref()
            .filter(|(address, _)| address == client)
            .map(|(_, path)| path.clone());
        let trusted = match (
            &from_dropin,
            for_client,
            per_user,
            &self.config.foreign_global_ca,
        ) {
            (Some((true, path)), _, _, _) => path.clone(),
            (Some((false, path)), _, _, _) if self.config.leak_trust_outside_loopback => {
                path.clone()
            }
            (_, Some(for_client), _, _) => for_client,
            (_, _, Some(per_user), _) => per_user,
            (_, _, _, Some(foreign)) => foreign.clone(),
            _ => "none".to_string(),
        };
        out.push_str(&format!("trustedusercakeys {trusted}\n"));
        out
    }
}

impl Runner for FakeRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<Output, RunnerError> {
        self.calls.push(command_line(program, args));
        if program.ends_with("/sshd") {
            return Ok(self.sshd(args));
        }
        let not_found = || {
            Err(RunnerError::NotFound {
                program: program.to_string(),
            })
        };
        match (program, args) {
            ("systemctl", _) if self.config.systemctl_missing => not_found(),
            ("id", ["-u"]) => reply(0, &format!("{}\n", self.config.uid), ""),
            ("getent", ["group", name]) => {
                if self.group_present {
                    reply(
                        0,
                        &format!("{name}:x:995:{}\n", self.config.group_members),
                        "",
                    )
                } else {
                    reply(2, "", "")
                }
            }
            ("getent", ["passwd", name]) => match &self.user {
                Some((shell, home)) => reply(0, &format!("{name}:x:995:995::{home}:{shell}\n"), ""),
                None => reply(2, "", ""),
            },
            ("groupadd", _) if self.config.groupadd_missing => not_found(),
            ("useradd", _) if self.config.useradd_missing => not_found(),
            ("groupadd" | "addgroup", _) => {
                self.group_present = true;
                reply(0, "", "")
            }
            ("useradd" | "adduser", _) => {
                let home = args
                    .iter()
                    .position(|arg| *arg == "--home-dir" || *arg == "--home")
                    .and_then(|index| args.get(index + 1))
                    .copied()
                    .unwrap_or("");
                self.user = Some(("/usr/sbin/nologin".to_string(), home.to_string()));
                reply(0, "", "")
            }
            ("userdel", _) if self.config.userdel_exit != 0 => reply(
                self.config.userdel_exit,
                "",
                "userdel: cannot lock /etc/passwd\n",
            ),
            ("userdel", _) => {
                self.user = None;
                if !self.config.userdel_keeps_group && self.config.group_members.is_empty() {
                    self.group_present = false;
                }
                reply(0, "", "")
            }
            ("groupdel", _) => {
                self.group_present = false;
                reply(0, "", "")
            }
            ("systemctl", ["daemon-reload"]) if !self.config.daemon_reload_ok => {
                reply(1, "", "Failed to connect to bus\n")
            }
            ("systemctl", ["stop", _]) if !self.config.systemctl_stop_ok => {
                reply(5, "", "Unit jaunt-agent.service not loaded.\n")
            }
            ("systemctl", ["reload", "ssh"]) if !self.config.reload_ssh_ok => {
                reply(5, "", "Unit ssh.service not found.\n")
            }
            ("systemctl", ["reload", "sshd"]) if !self.config.reload_sshd_ok => {
                reply(5, "", "Unit sshd.service not found.\n")
            }
            ("getenforce", []) => match &self.config.selinux {
                Some(mode) => reply(0, mode, ""),
                None => not_found(),
            },
            _ => reply(0, "", ""),
        }
    }
}

pub struct Harness {
    pub root: TempRoot,
    pub layout: Layout,
    pub runner: FakeRunner,
    pub report: Report,
    pub live: bool,
    pub dry_run: bool,
}

impl Harness {
    pub fn new(config: FakeConfig) -> Self {
        let root = TempRoot::new();
        root.write(SSHD_CONFIG, STOCK_SSHD_CONFIG);
        root.write("/usr/sbin/sshd", "");
        let layout = Layout::new(root.path()).unwrap();
        let runner = FakeRunner {
            root: root.path().to_path_buf(),
            group_present: config.existing_group,
            user: config
                .existing_user_shell
                .clone()
                .map(|shell| (shell, config.existing_user_home.clone())),
            config,
            calls: Vec::new(),
        };
        Self {
            root,
            layout,
            runner,
            report: Report::new(),
            live: false,
            dry_run: false,
        }
    }

    pub fn env(&mut self) -> Env<'_> {
        Env {
            layout: &self.layout,
            runner: &mut self.runner,
            report: &mut self.report,
            dry_run: self.dry_run,
            live: self.live,
            path_env: String::new(),
        }
    }

    pub fn calls(&self) -> Vec<String> {
        let prefix = self.root.path().to_string_lossy().into_owned();
        self.runner
            .calls
            .iter()
            .map(|call| call.replace(&prefix, ""))
            .collect()
    }
}

pub fn options() -> InstallOptions {
    InstallOptions {
        user: "jaunt".to_string(),
        binary: "/usr/local/bin/jaunt-agent".to_string(),
        config: "/etc/jaunt/agent.yaml".to_string(),
        state_dir: "/var/lib/jaunt".to_string(),
        no_service: true,
    }
}
