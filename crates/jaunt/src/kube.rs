use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use clap::{Args, Subcommand};

use crate::agent::SshAgent;
use crate::browser::SystemBrowser;
use crate::commands::{
    Environment, LsArgs, OutputFormat, custom_home, ensure_ssh_setup, explicit_home, run_ls,
};
use crate::consent::TerminalPrompt;
use crate::display::printable;
use crate::ensure::SIGN_IN_DEADLINE;
use crate::gate_config::{GateServices, check_root};
use crate::kube_credentials::{CredentialsIo, CredentialsRequest, run_credentials};
use crate::kubeconfig::{
    ConflictError, CurrentContextRule, Kubeconfig, KubeconfigError, LoginChanges, LoginEntries,
    Removal, Yaml, parse_yaml,
};
use crate::kubeconfig_file::{Edited, FileError, FilePorts, LOCK_WAIT, Planned, edit, peek};
use crate::ls::ListKind;
use crate::profile::{ProfileName, resolve_home};
use crate::ssh_config::{is_dns_label, is_dns_name};
use crate::status::Session;
use crate::store::{ProfileStore, StoreError};
use crate::user_x509::pem_encode;

const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 2;
const ENTRY_PREFIX: &str = "jaunt";
const KUBE_LABEL: &str = "kube";
const KUBE_DIR: &str = ".kube";
const KUBE_FILE: &str = "config";
const MAX_CONTEXT_LEN: usize = 253;
const CERTIFICATE_LABEL: &str = "CERTIFICATE";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterName(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "cluster names are DNS labels: 1 to 63 characters a-z, 0-9 and '-', starting and ending with a letter or digit"
)]
pub struct ClusterNameError;

impl ClusterName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ClusterName {
    type Err = ClusterNameError;

    fn from_str(text: &str) -> Result<ClusterName, ClusterNameError> {
        if is_dns_label(text) {
            Ok(ClusterName(text.to_owned()))
        } else {
            Err(ClusterNameError)
        }
    }
}

impl fmt::Display for ClusterName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextName(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "context names are 1 to 253 printable characters without spaces at either end or control characters"
)]
pub struct ContextNameError;

impl FromStr for ContextName {
    type Err = ContextNameError;

    fn from_str(text: &str) -> Result<ContextName, ContextNameError> {
        let usable = !text.is_empty()
            && text.len() <= MAX_CONTEXT_LEN
            && text.trim() == text
            && printable(text) == text;
        if usable {
            Ok(ContextName(text.to_owned()))
        } else {
            Err(ContextNameError)
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum KubeCommand {
    #[command(
        about = "List the Kubernetes clusters you may reach (same as `jaunt ls --kind kube`)"
    )]
    Ls(KubeLsArgs),
    #[command(about = "Add a cluster to your kubeconfig so that kubectl reaches it through jaunt")]
    Login(KubeLoginArgs),
    #[command(
        about = "Print a client certificate for kubectl as an ExecCredential (kubectl runs this through the kubeconfig)"
    )]
    Credentials(KubeCredentialsArgs),
    #[command(about = "Remove the entries this profile added to your kubeconfig")]
    Logout(KubeLogoutArgs),
}

#[derive(Debug, Args)]
pub struct KubeLsArgs {
    #[arg(
        long,
        value_name = "NAME",
        env = "JAUNT_PROFILE",
        default_value = "default"
    )]
    pub profile: ProfileName,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
}

#[derive(Debug, Args)]
pub struct KubeLoginArgs {
    #[arg(value_name = "CLUSTER")]
    pub cluster: ClusterName,
    #[arg(
        long,
        value_name = "NAME",
        env = "JAUNT_PROFILE",
        default_value = "default"
    )]
    pub profile: ProfileName,
    #[arg(
        long,
        value_name = "PATH",
        help = "The kubeconfig to change (default: the first path of KUBECONFIG, else ~/.kube/config)"
    )]
    pub kubeconfig: Option<PathBuf>,
    #[arg(
        long,
        value_name = "NAME",
        help = "Name of the context (default: jaunt-<profile>-<cluster>)"
    )]
    pub context: Option<ContextName>,
}

#[derive(Debug, Args)]
pub struct KubeCredentialsArgs {
    #[arg(
        long,
        value_name = "CLUSTER",
        help = "Accepted from older kubeconfig entries and checked to be a DNS label; the certificate is the same for every cluster"
    )]
    pub cluster: Option<ClusterName>,
    #[arg(
        long,
        value_name = "NAME",
        env = "JAUNT_PROFILE",
        default_value = "default"
    )]
    pub profile: ProfileName,
    #[arg(long, hide = true, value_name = "PATH")]
    pub home: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct KubeLogoutArgs {
    #[arg(value_name = "CLUSTER")]
    pub cluster: Option<ClusterName>,
    #[arg(
        long,
        value_name = "NAME",
        env = "JAUNT_PROFILE",
        default_value = "default"
    )]
    pub profile: ProfileName,
    #[arg(
        long,
        value_name = "PATH",
        help = "The kubeconfig to change (default: the first path of KUBECONFIG, else ~/.kube/config)"
    )]
    pub kubeconfig: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum KubeError {
    #[error("not signed in (profile `{profile}`): run `jaunt login`")]
    NotSignedIn { profile: ProfileName },
    #[error(
        "the server of profile `{profile}` sent no TLS settings for services, so it does not offer Kubernetes access; if the server was updated, run `jaunt login` again"
    )]
    NoServices { profile: ProfileName },
    #[error("the stored services domain cannot be used: run `jaunt login` again")]
    BadDomain,
    #[error("`{name}` is too long for a DNS name")]
    NameTooLong { name: String },
    #[error(
        "no pinned root of the gate is valid now (check the system clock); run `jaunt login` again"
    )]
    NoUsableRoot,
    #[error("the path of the running jaunt program cannot be used in a kubeconfig: {path}")]
    ProgramPath { path: PathBuf },
    #[error("the jaunt home {path} cannot be used in a kubeconfig")]
    HomePath { path: PathBuf },
    #[error("cannot find the kubeconfig: pass --kubeconfig PATH or set KUBECONFIG")]
    NoKubeconfig,
    #[error("{path} was left unchanged: {source}")]
    Unreadable {
        path: PathBuf,
        source: KubeconfigError,
    },
    #[error("{path} was left unchanged: {source}")]
    Conflict {
        path: PathBuf,
        source: ConflictError,
    },
    #[error(transparent)]
    File(#[from] FileError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubeconfigChoice {
    pub path: PathBuf,
    pub others: Vec<PathBuf>,
}

pub fn choose_kubeconfig(
    explicit: Option<&Path>,
    variable: Option<&OsStr>,
    user_home: Option<&Path>,
) -> Result<KubeconfigChoice, KubeError> {
    if let Some(path) = explicit.filter(|path| !path.as_os_str().is_empty()) {
        return Ok(KubeconfigChoice {
            path: path.to_owned(),
            others: Vec::new(),
        });
    }
    let listed: Vec<PathBuf> = variable
        .map(|value| {
            env::split_paths(value)
                .filter(|path| !path.as_os_str().is_empty())
                .collect()
        })
        .unwrap_or_default();
    if let Some((first, others)) = listed.split_first() {
        return Ok(KubeconfigChoice {
            path: first.clone(),
            others: others.to_vec(),
        });
    }
    user_home
        .filter(|home| home.is_absolute())
        .map(|home| KubeconfigChoice {
            path: home.join(KUBE_DIR).join(KUBE_FILE),
            others: Vec::new(),
        })
        .ok_or(KubeError::NoKubeconfig)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextElsewhere {
    Named { path: PathBuf, name: String },
    Unreadable { path: PathBuf },
}

pub fn current_context_elsewhere(target: &Path, others: &[PathBuf]) -> Option<ContextElsewhere> {
    let target = std::path::absolute(target).ok();
    for other in others {
        if std::path::absolute(other).ok() == target {
            continue;
        }
        let bytes = match peek(other) {
            Ok(None) => continue,
            Ok(Some(bytes)) => bytes,
            Err(_) => {
                return Some(ContextElsewhere::Unreadable {
                    path: other.clone(),
                });
            }
        };
        let parsed = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| parse_yaml(text).ok());
        let Some(value) = parsed else {
            return Some(ContextElsewhere::Unreadable {
                path: other.clone(),
            });
        };
        if let Some(name) = value
            .get("current-context")
            .and_then(Yaml::as_str)
            .filter(|name| !name.is_empty())
        {
            return Some(ContextElsewhere::Named {
                path: other.clone(),
                name: name.to_owned(),
            });
        }
    }
    None
}

pub fn cluster_entry_name(profile: &ProfileName, cluster: &ClusterName) -> String {
    format!("{ENTRY_PREFIX}-{profile}-{cluster}")
}

pub fn user_entry_name(profile: &ProfileName) -> String {
    format!("{ENTRY_PREFIX}-{profile}")
}

pub fn check_domain(services: &GateServices) -> Result<(), KubeError> {
    if is_dns_name(&services.services.domain) {
        Ok(())
    } else {
        Err(KubeError::BadDomain)
    }
}

pub fn cluster_host(services: &GateServices, cluster: &ClusterName) -> Result<String, KubeError> {
    check_domain(services)?;
    let domain = &services.services.domain;
    let host = format!("{cluster}.{KUBE_LABEL}.{domain}");
    if is_dns_name(&host) {
        Ok(host)
    } else {
        Err(KubeError::NameTooLong { name: host })
    }
}

pub fn stored_services(
    store: &ProfileStore,
    profile: &ProfileName,
) -> Result<GateServices, KubeError> {
    if let Some(services) = store.read_gate_services()? {
        return Ok(services);
    }
    match Session::load(store)? {
        Some(_) => Err(KubeError::NoServices {
            profile: profile.clone(),
        }),
        None => Err(KubeError::NotSignedIn {
            profile: profile.clone(),
        }),
    }
}

pub struct LoginRequest<'a> {
    pub store: &'a ProfileStore,
    pub profile: &'a ProfileName,
    pub cluster: &'a ClusterName,
    pub context: Option<&'a ContextName>,
    pub program: &'a Path,
    pub pinned_home: Option<&'a Path>,
    pub now: i64,
}

pub fn login_entries(request: &LoginRequest<'_>) -> Result<LoginEntries, KubeError> {
    let services = stored_services(request.store, request.profile)?;
    let host = cluster_host(&services, request.cluster)?;
    let mut bundle = String::new();
    for root in &services.services.roots {
        if let Ok(der) = check_root(root, request.now) {
            bundle.push_str(&pem_encode(CERTIFICATE_LABEL, &der));
        }
    }
    if bundle.is_empty() {
        return Err(KubeError::NoUsableRoot);
    }
    let command = request
        .program
        .to_str()
        .filter(|_| request.program.is_absolute())
        .ok_or_else(|| KubeError::ProgramPath {
            path: request.program.to_owned(),
        })?;
    let mut args = vec![
        "kube".to_owned(),
        "credentials".to_owned(),
        "--profile".to_owned(),
        request.profile.to_string(),
    ];
    if let Some(home) = request.pinned_home {
        let text = home.to_str().ok_or_else(|| KubeError::HomePath {
            path: home.to_owned(),
        })?;
        args.extend(["--home".to_owned(), text.to_owned()]);
    }
    let cluster_entry = cluster_entry_name(request.profile, request.cluster);
    Ok(LoginEntries {
        profile: request.profile.to_string(),
        context: request
            .context
            .map_or_else(|| cluster_entry.clone(), |context| context.0.clone()),
        user_entry: user_entry_name(request.profile),
        cluster_entry,
        server: format!("https://{host}"),
        certificate_authority_data: STANDARD.encode(bundle),
        command: command.to_owned(),
        args,
    })
}

pub fn apply_login(
    path: &Path,
    entries: &LoginEntries,
    rule: CurrentContextRule,
    ports: &mut FilePorts<'_>,
) -> Result<Edited<LoginChanges>, KubeError> {
    edit(path, ports, &mut |current| {
        let mut config = Kubeconfig::parse(current).map_err(|source| KubeError::Unreadable {
            path: path.to_owned(),
            source,
        })?;
        let before = config.clone();
        let changes = config
            .merge_login(entries, rule)
            .map_err(|source| KubeError::Conflict {
                path: path.to_owned(),
                source,
            })?;
        let contents = if current.is_some() && config == before {
            None
        } else {
            Some(config.render().map_err(|source| KubeError::Unreadable {
                path: path.to_owned(),
                source,
            })?)
        };
        Ok(Planned {
            contents,
            report: changes,
        })
    })
}

pub fn apply_logout(
    path: &Path,
    profile: &ProfileName,
    cluster: Option<&ClusterName>,
    ports: &mut FilePorts<'_>,
) -> Result<Edited<Removal>, KubeError> {
    let cluster_entry = cluster.map(|cluster| cluster_entry_name(profile, cluster));
    edit(path, ports, &mut |current| {
        let Some(bytes) = current else {
            return Ok(Planned {
                contents: None,
                report: Removal::default(),
            });
        };
        let mut config =
            Kubeconfig::parse(Some(bytes)).map_err(|source| KubeError::Unreadable {
                path: path.to_owned(),
                source,
            })?;
        let removal = config.remove_profile(profile.as_str(), cluster_entry.as_deref());
        let contents = if removal.is_empty() {
            None
        } else {
            Some(config.render().map_err(|source| KubeError::Unreadable {
                path: path.to_owned(),
                source,
            })?)
        };
        Ok(Planned {
            contents,
            report: removal,
        })
    })
}

fn rename(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}

fn now_secs() -> Option<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
}

fn say(line: impl fmt::Display) {
    eprintln!("jaunt: {line}");
}

fn failure(line: impl fmt::Display) -> ExitCode {
    say(line);
    ExitCode::from(EXIT_FAILED)
}

fn usage_error(line: impl fmt::Display) -> ExitCode {
    say(line);
    ExitCode::from(EXIT_USAGE)
}

fn print_lines(lines: &[String]) -> ExitCode {
    let mut stdout = io::stdout().lock();
    for line in lines {
        if let Err(err) = writeln!(stdout, "{line}") {
            return failure(format!("cannot write to the terminal: {err}"));
        }
    }
    ExitCode::SUCCESS
}

fn names(list: &[String]) -> String {
    list.iter()
        .map(|name| format!("`{}`", printable(name)))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn login_lines(
    edited: &Edited<LoginChanges>,
    cluster: &ClusterName,
    entries: &LoginEntries,
    elsewhere: Option<&ContextElsewhere>,
) -> Vec<String> {
    let path = edited.located.requested.display();
    let context = printable(&entries.context);
    let mut lines = vec![if !edited.written {
        format!(
            "{path} already has the Kubernetes cluster `{cluster}` as context `{context}`; nothing changed."
        )
    } else if edited.created {
        format!("Created {path} with the Kubernetes cluster `{cluster}` as context `{context}`.")
    } else {
        format!("Updated {path}: the Kubernetes cluster `{cluster}` is context `{context}`.")
    }];
    if edited.written && edited.located.via_link {
        lines.push(format!(
            "{path} is a link: wrote through to {}.",
            edited.located.real.display()
        ));
    }
    if let Some(backup) = &edited.backup {
        lines.push(format!(
            "The previous file is saved as {}.",
            backup.display()
        ));
    }
    let missing = edited.report.current_context_missing;
    if edited.report.current_context_set {
        lines.push(format!(
            "The file had no current context, so it is now `{context}`."
        ));
    } else if let (true, Some(ContextElsewhere::Named { path: other, name })) = (missing, elsewhere)
    {
        lines.push(format!(
            "The current context was not set: {} (also in KUBECONFIG) names `{}`, and kubectl uses that one; switch with `kubectl config use-context {context}`.",
            other.display(),
            printable(name)
        ));
    } else if let (true, Some(ContextElsewhere::Unreadable { path: other })) = (missing, elsewhere)
    {
        lines.push(format!(
            "The current context was not set: {} (also in KUBECONFIG) could not be read to see whether it names one; switch with `kubectl config use-context {context}`.",
            other.display()
        ));
    } else {
        lines.push(format!(
            "Use it with `kubectl --context {context} get namespaces` or `kubectl config use-context {context}`."
        ));
    }
    lines
}

pub fn logout_lines(edited: &Edited<Removal>, profile: &ProfileName) -> (Vec<String>, Vec<String>) {
    let path = edited.located.requested.display();
    let removal = &edited.report;
    let mut lines = Vec::new();
    let mut warnings = Vec::new();
    if removal.is_empty() {
        lines.push(format!(
            "Nothing that jaunt added for profile `{profile}` was found in {path}."
        ));
    } else {
        let mut parts = Vec::new();
        for (label, list) in [
            ("contexts", &removal.contexts),
            ("cluster entries", &removal.clusters),
            ("user entries", &removal.users),
        ] {
            if !list.is_empty() {
                parts.push(format!("{label} {}", names(list)));
            }
        }
        lines.push(format!("Removed from {path}: {}.", parts.join("; ")));
        if edited.located.via_link {
            lines.push(format!(
                "{path} is a link: wrote through to {}.",
                edited.located.real.display()
            ));
        }
        if let Some(backup) = &edited.backup {
            lines.push(format!(
                "The previous file is saved as {}.",
                backup.display()
            ));
        }
    }
    for kept in &removal.kept {
        lines.push(format!(
            "Kept the {} entry `{}`: the context `{}` still uses it.",
            kept.kind,
            printable(&kept.name),
            printable(&kept.used_by)
        ));
    }
    if let Some(current) = &removal.current_context_removed {
        lines.push(format!(
            "The current context `{}` was removed, so kubectl has no usable current context now: choose one with `kubectl config use-context NAME`.",
            printable(current)
        ));
        warnings.push(format!(
            "warning: the current context `{}` was removed; choose another with `kubectl config use-context NAME`",
            printable(current)
        ));
    }
    (lines, warnings)
}

fn home_for(environment: &Environment) -> Result<PathBuf, ExitCode> {
    resolve_home(
        environment.jaunt_home.clone(),
        environment.user_home.clone(),
    )
    .map_err(usage_error)
}

fn on_wait_notice(path: &Path) {
    say(format!(
        "another jaunt command is editing {}; waiting for it to finish",
        path.display()
    ));
}

pub fn run_kube(command: &KubeCommand, environment: &Environment) -> ExitCode {
    let variable = env::var_os("KUBECONFIG");
    match command {
        KubeCommand::Ls(args) => run_ls(
            &LsArgs {
                profile: args.profile.clone(),
                format: args.format,
                kind: ListKind::Kube,
            },
            environment,
        ),
        KubeCommand::Login(args) => run_kube_login(args, environment, variable.as_deref()),
        KubeCommand::Credentials(args) => run_kube_credentials(args, environment),
        KubeCommand::Logout(args) => run_kube_logout(args, environment, variable.as_deref()),
    }
}

fn run_kube_login(
    args: &KubeLoginArgs,
    environment: &Environment,
    variable: Option<&OsStr>,
) -> ExitCode {
    let home = match home_for(environment) {
        Ok(home) => home,
        Err(code) => return code,
    };
    let choice = match choose_kubeconfig(
        args.kubeconfig.as_deref(),
        variable,
        environment.user_home.as_deref(),
    ) {
        Ok(choice) => choice,
        Err(err) => return usage_error(err),
    };
    let program = match env::current_exe() {
        Ok(program) => program,
        Err(err) => {
            return failure(format!(
                "cannot find the path of the running jaunt program: {err}"
            ));
        }
    };
    let Some(now) = now_secs() else {
        return failure("the system clock is set before 1970");
    };
    let store = ProfileStore::new(&home, &args.profile);
    let pinned = custom_home(environment, &home);
    let entries = match login_entries(&LoginRequest {
        store: &store,
        profile: &args.profile,
        cluster: &args.cluster,
        context: args.context.as_ref(),
        program: &program,
        pinned_home: pinned.as_deref(),
        now,
    }) {
        Ok(entries) => entries,
        Err(err) => return failure(err),
    };
    let mut on_wait = on_wait_notice;
    let mut ports = FilePorts {
        clock: &SystemTime::now,
        rename: &rename,
        lock_wait: LOCK_WAIT,
        on_wait: &mut on_wait,
    };
    let elsewhere = current_context_elsewhere(&choice.path, &choice.others);
    let rule = if elsewhere.is_some() {
        CurrentContextRule::Keep
    } else {
        CurrentContextRule::SetWhenMissing
    };
    match apply_login(&choice.path, &entries, rule, &mut ports) {
        Ok(edited) => {
            for warning in &edited.warnings {
                say(warning);
            }
            print_lines(&login_lines(
                &edited,
                &args.cluster,
                &entries,
                elsewhere.as_ref(),
            ))
        }
        Err(err) => failure(err),
    }
}

fn run_kube_logout(
    args: &KubeLogoutArgs,
    environment: &Environment,
    variable: Option<&OsStr>,
) -> ExitCode {
    let path = match choose_kubeconfig(
        args.kubeconfig.as_deref(),
        variable,
        environment.user_home.as_deref(),
    ) {
        Ok(choice) => choice.path,
        Err(err) => return usage_error(err),
    };
    let mut on_wait = on_wait_notice;
    let mut ports = FilePorts {
        clock: &SystemTime::now,
        rename: &rename,
        lock_wait: LOCK_WAIT,
        on_wait: &mut on_wait,
    };
    match apply_logout(&path, &args.profile, args.cluster.as_ref(), &mut ports) {
        Ok(edited) => {
            let (lines, warnings) = logout_lines(&edited, &args.profile);
            for warning in edited.warnings.iter().chain(&warnings) {
                say(warning);
            }
            print_lines(&lines)
        }
        Err(err) => failure(err),
    }
}

pub fn credentials_request(
    args: &KubeCredentialsArgs,
    environment: &Environment,
) -> Result<CredentialsRequest, String> {
    let home = explicit_home(args.home.as_ref(), environment)?;
    Ok(CredentialsRequest {
        ssh: ensure_ssh_setup(environment, &home),
        custom_home: custom_home(environment, &home).is_some(),
        home,
        profile: args.profile.clone(),
        cluster: args.cluster.clone(),
        deadline: SIGN_IN_DEADLINE,
    })
}

fn run_kube_credentials(args: &KubeCredentialsArgs, environment: &Environment) -> ExitCode {
    let request = match credentials_request(args, environment) {
        Ok(request) => request,
        Err(message) => return usage_error(message),
    };
    let agent = SshAgent::new(environment.ssh_auth_sock.clone());
    let terminal = io::stdin().is_terminal() || io::stderr().is_terminal();
    let stdout_terminal = io::stdout().is_terminal();
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr();
    ExitCode::from(run_credentials(
        &request,
        CredentialsIo {
            stdout: &mut stdout,
            stdout_terminal,
            stderr: &mut stderr,
            terminal,
            browser: &SystemBrowser,
            agent: &agent,
            consent: &TerminalPrompt,
            clock: &SystemTime::now,
        },
    ))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use jaunt_proto::{ClientTransport, GATE_ALPN_SSH, PinnedRoot, ServicesClient};
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

    use super::{
        ClusterName, ContextElsewhere, ContextName, KubeError, LoginRequest, apply_login,
        apply_logout, choose_kubeconfig, current_context_elsewhere, login_entries,
    };
    use crate::gate_config::{GateServices, sha256_hex};
    use crate::kubeconfig::{CurrentContextRule, LoginEntries};
    use crate::kubeconfig_file::FilePorts;
    use crate::profile::ProfileName;
    use crate::store::ProfileStore;

    const NOW: i64 = 1_800_000_000;

    #[test]
    fn the_kubeconfig_is_the_flag_else_the_first_kubeconfig_path_else_the_home_default() {
        let home = Path::new("/home/u");
        type Case<'a> = (
            Option<&'a str>,
            Option<&'a str>,
            Option<&'a Path>,
            Option<(&'a str, &'a [&'a str])>,
        );
        let cases: [Case<'_>; 7] = [
            (
                Some("/x/flag"),
                Some("/a:/b"),
                Some(home),
                Some(("/x/flag", &[])),
            ),
            (None, Some("/a:/b"), Some(home), Some(("/a", &["/b"]))),
            (None, Some("::/b:/c"), Some(home), Some(("/b", &["/c"]))),
            (
                None,
                Some("relative/k"),
                Some(home),
                Some(("relative/k", &[])),
            ),
            (
                None,
                Some(""),
                Some(home),
                Some(("/home/u/.kube/config", &[])),
            ),
            (None, None, Some(home), Some(("/home/u/.kube/config", &[]))),
            (None, None, Some(Path::new("relative")), None),
        ];
        for (flag, variable, user_home, expected) in cases {
            let found = choose_kubeconfig(flag.map(Path::new), variable.map(OsStr::new), user_home);
            let shown = found
                .as_ref()
                .ok()
                .map(|choice| (choice.path.clone(), choice.others.clone()));
            let wanted = expected.map(|(path, others)| {
                (
                    PathBuf::from(path),
                    others.iter().map(PathBuf::from).collect::<Vec<_>>(),
                )
            });
            assert_eq!(shown, wanted, "{flag:?} {variable:?}");
            if expected.is_none() {
                assert!(matches!(found, Err(KubeError::NoKubeconfig)));
            }
        }
    }

    #[test]
    fn cluster_names_are_dns_labels_and_context_names_are_printable() {
        let long_label = "a".repeat(63);
        let too_long = "a".repeat(64);
        for (name, accepted) in [
            ("prod", true),
            ("prod-eu-1", true),
            ("0", true),
            (long_label.as_str(), true),
            ("", false),
            ("Prod", false),
            ("-prod", false),
            ("prod-", false),
            ("prod.eu", false),
            ("prod_eu", false),
            ("prod\n", false),
            (too_long.as_str(), false),
        ] {
            assert_eq!(name.parse::<ClusterName>().is_ok(), accepted, "{name:?}");
        }
        for (name, accepted) in [
            ("work", true),
            ("arn:aws:eks:eu-west-1:1:cluster/prod", true),
            ("with space", true),
            ("", false),
            (" lead", false),
            ("trail ", false),
            ("a\nb", false),
            ("a\u{1b}[31m", false),
            ("a\u{202e}b", false),
        ] {
            assert_eq!(name.parse::<ContextName>().is_ok(), accepted, "{name:?}");
        }
    }

    fn root(not_after_offset: i64) -> PinnedRoot {
        let epoch = rcgen::date_time_ymd(1970, 1, 1);
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, "root");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.not_before = epoch + Duration::from_secs(u64::try_from(NOW - 100).unwrap());
        params.not_after =
            epoch + Duration::from_secs(u64::try_from(NOW + not_after_offset).unwrap());
        let der = params
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap()
            .der()
            .to_vec();
        PinnedRoot {
            certificate_der: STANDARD.encode(&der),
            sha256: sha256_hex(&der),
            not_before: 0,
            not_after: 0,
        }
    }

    fn store_with(
        roots: Option<Vec<PinnedRoot>>,
        signed_in: bool,
    ) -> (tempfile::TempDir, ProfileStore) {
        let root_dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(root_dir.path(), &ProfileName::default_name());
        fs::create_dir_all(store.dir()).unwrap();
        if signed_in {
            fs::write(store.dir().join("server"), "https://jaunt.example.com\n").unwrap();
            fs::write(
                store.dir().join("meta.json"),
                serde_json::json!({
                    "user_id": "3f2b1c9e-7a44-4d0e-9c58-0a6b8f1d2e77",
                    "email": "alice@example.com",
                    "serial": 7,
                    "key_id": "jaunt:alice@example.com:7",
                    "valid_after": NOW - 100,
                    "valid_before": NOW + 3600,
                    "token_expires_at": NOW + 3600,
                    "host_ca_keys": [],
                })
                .to_string(),
            )
            .unwrap();
        }
        if let Some(roots) = roots {
            let services = GateServices {
                client_transport: ClientTransport::Tls,
                services: ServicesClient {
                    domain: "svc.example.test".to_owned(),
                    gate_tls_name: "svc.example.test".to_owned(),
                    port: 443,
                    alpn: vec![GATE_ALPN_SSH.to_owned()],
                    roots,
                },
            };
            fs::write(
                store.dir().join("services.json"),
                serde_json::to_vec(&services).unwrap(),
            )
            .unwrap();
        }
        (root_dir, store)
    }

    fn request<'a>(
        store: &'a ProfileStore,
        profile: &'a ProfileName,
        cluster: &'a ClusterName,
        context: Option<&'a ContextName>,
        pinned_home: Option<&'a Path>,
    ) -> LoginRequest<'a> {
        LoginRequest {
            store,
            profile,
            cluster,
            context,
            program: Path::new("/usr/local/bin/jaunt"),
            pinned_home,
            now: NOW,
        }
    }

    #[test]
    fn the_entries_name_the_cluster_host_every_valid_root_and_the_plugin_command() {
        let (valid, other, expired) = (root(3600), root(3600), root(-1));
        let (_dir, store) = store_with(Some(vec![valid.clone(), expired, other.clone()]), true);
        let profile = ProfileName::default_name();
        let cluster: ClusterName = "prod".parse().unwrap();
        let home = PathBuf::from("/srv/jaunt home");

        let entries =
            login_entries(&request(&store, &profile, &cluster, None, Some(&home))).unwrap();

        assert_eq!(entries.server, "https://prod.kube.svc.example.test");
        assert_eq!(entries.cluster_entry, "jaunt-default-prod");
        assert_eq!(entries.user_entry, "jaunt-default");
        assert_eq!(entries.context, "jaunt-default-prod");
        assert_eq!(entries.command, "/usr/local/bin/jaunt");
        assert_eq!(
            entries.args,
            [
                "kube",
                "credentials",
                "--profile",
                "default",
                "--home",
                "/srv/jaunt home"
            ]
        );
        let bundle = String::from_utf8(
            STANDARD
                .decode(&entries.certificate_authority_data)
                .unwrap(),
        )
        .unwrap();
        let blocks: Vec<&str> = bundle
            .split_inclusive("-----END CERTIFICATE-----\n")
            .collect();
        assert_eq!(blocks.len(), 2, "{bundle}");
        for (block, pinned) in blocks.iter().zip([&valid, &other]) {
            let (_, pem) = x509_parser::pem::parse_x509_pem(block.as_bytes()).unwrap();
            assert_eq!(STANDARD.encode(&pem.contents), pinned.certificate_der);
        }

        let named: ContextName = "work-prod".parse().unwrap();
        let custom =
            login_entries(&request(&store, &profile, &cluster, Some(&named), None)).unwrap();
        assert_eq!(custom.context, "work-prod");
        assert_eq!(custom.cluster_entry, "jaunt-default-prod");
        assert!(!custom.args.contains(&"--home".to_owned()));
    }

    #[test]
    fn an_old_server_a_missing_sign_in_or_no_valid_root_stop_before_any_change() {
        let profile = ProfileName::default_name();
        let cluster: ClusterName = "prod".parse().unwrap();
        let (_old, old_server) = store_with(None, true);
        let (_none, never) = store_with(None, false);
        let (_stale, stale_roots) = store_with(Some(vec![root(-1)]), true);

        let old = login_entries(&request(&old_server, &profile, &cluster, None, None));
        let missing = login_entries(&request(&never, &profile, &cluster, None, None));
        let unusable = login_entries(&request(&stale_roots, &profile, &cluster, None, None));

        assert!(matches!(old, Err(KubeError::NoServices { .. })), "{old:?}");
        assert!(
            old.unwrap_err()
                .to_string()
                .contains("run `jaunt login` again"),
        );
        assert!(
            matches!(missing, Err(KubeError::NotSignedIn { .. })),
            "{missing:?}"
        );
        assert!(
            matches!(unusable, Err(KubeError::NoUsableRoot)),
            "{unusable:?}"
        );
        let long: ClusterName = "a".repeat(63).parse().unwrap();
        let (_long, long_store) = store_with(Some(vec![root(3600)]), true);
        let mut services: GateServices =
            serde_json::from_slice(&fs::read(long_store.dir().join("services.json")).unwrap())
                .unwrap();
        services.services.domain =
            format!("{}.{}.{}", "b".repeat(63), "c".repeat(63), "d".repeat(60));
        fs::write(
            long_store.dir().join("services.json"),
            serde_json::to_vec(&services).unwrap(),
        )
        .unwrap();
        let too_long = login_entries(&request(&long_store, &profile, &long, None, None));
        assert!(
            matches!(too_long, Err(KubeError::NameTooLong { .. })),
            "{too_long:?}"
        );
    }

    #[test]
    fn another_kubeconfig_path_that_names_a_current_context_is_found_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        let named = dir.path().join("named");
        let empty = dir.path().join("empty");
        let broken = dir.path().join("broken");
        let missing = dir.path().join("missing");
        fs::write(
            &named,
            "apiVersion: v1\nkind: Config\ncurrent-context: theirs\n",
        )
        .unwrap();
        fs::write(&empty, "current-context: ''\n").unwrap();
        fs::write(&broken, "current-context: [\n").unwrap();
        let before = fs::read(&named).unwrap();

        let cases = [
            (vec![missing.clone(), empty.clone()], None),
            (
                vec![missing.clone(), named.clone(), broken.clone()],
                Some(ContextElsewhere::Named {
                    path: named.clone(),
                    name: "theirs".to_owned(),
                }),
            ),
            (
                vec![broken.clone(), named.clone()],
                Some(ContextElsewhere::Unreadable {
                    path: broken.clone(),
                }),
            ),
            (vec![first.clone()], None),
        ];
        for (others, expected) in cases {
            assert_eq!(
                current_context_elsewhere(&first, &others),
                expected,
                "{others:?}"
            );
        }
        assert_eq!(fs::read(&named).unwrap(), before);
        assert!(!first.exists());
    }

    #[test]
    fn an_unchanged_login_and_an_empty_logout_succeed_in_a_read_only_directory() {
        let dir = tempfile::tempdir().unwrap();
        let kube = dir.path().join("kube");
        fs::create_dir(&kube).unwrap();
        let path = kube.join("config");
        let entries = LoginEntries {
            profile: "default".to_owned(),
            cluster_entry: "jaunt-default-prod".to_owned(),
            user_entry: "jaunt-default".to_owned(),
            context: "jaunt-default-prod".to_owned(),
            server: "https://prod.kube.example.test".to_owned(),
            certificate_authority_data: "Uk9PVFM=".to_owned(),
            command: "/usr/local/bin/jaunt".to_owned(),
            args: vec!["kube".to_owned(), "credentials".to_owned()],
        };
        let rename = |from: &Path, to: &Path| fs::rename(from, to);
        let mut on_wait = |_: &Path| {};
        let mut ports = FilePorts {
            clock: &SystemTime::now,
            rename: &rename,
            lock_wait: Duration::from_secs(5),
            on_wait: &mut on_wait,
        };
        apply_login(
            &path,
            &entries,
            CurrentContextRule::SetWhenMissing,
            &mut ports,
        )
        .unwrap();
        fs::set_permissions(&kube, fs::Permissions::from_mode(0o500)).unwrap();

        let again = apply_login(
            &path,
            &entries,
            CurrentContextRule::SetWhenMissing,
            &mut ports,
        );
        let other = ProfileName::parse("other").unwrap();
        let nothing = apply_logout(&path, &other, None, &mut ports);

        fs::set_permissions(&kube, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!again.unwrap().written);
        let nothing = nothing.unwrap();
        assert!(!nothing.written && nothing.report.is_empty());
        let names: Vec<_> = fs::read_dir(&kube)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["config"]);
    }
}
