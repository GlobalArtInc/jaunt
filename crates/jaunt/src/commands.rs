use std::env;
use std::ffi::OsString;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand, ValueEnum};
use jaunt_policy::AdminPermission;
use jaunt_proto::{ADMIN_TOKEN_ENV, NodeList, ServiceList};

use crate::admin::{
    AGENT_TIMEOUT, AdminContext, NewToken, TokenSource, create_token, list_tokens, parse_scope,
    parse_token_source, parse_ttl, read_admin_token, render_created, render_identity,
    render_token_identity, render_token_list, revoke_token, token_whoami, whoami,
};
use crate::agent::SshAgent;
use crate::browser::SystemBrowser;
use crate::client::{ApiClient, ApiError, is_missing_route};
use crate::consent::TerminalPrompt;
use crate::ensure::{EnsureIo, EnsureRequest, RenewOptions, SIGN_IN_DEADLINE};
use crate::login::{LoginOptions, LoginPorts, SshSetup, lock_profile, login};
use crate::logout::logout;
use crate::ls::{
    ListKind, Listing, render_everything_json, render_json, render_kinds_text,
    render_services_json, render_text, select_services,
};
use crate::profile::{ProfileName, resolve_home};
use crate::proxy::proxy_ssh;
use crate::secret::Secret;
use crate::server_url::ServerUrl;
use crate::ssh_config::{EnsureCommand, validate};
use crate::ssh_include::{IncludeTarget, include_line};
use crate::status::{Session, agent_view, check_online, render, ssh_view};
use crate::store::ProfileStore;

const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 2;
const MAX_TIMEOUT_SECS: u64 = 900;
const DEFAULT_TIMEOUT_SECS: u64 = 300;

#[derive(Debug, Clone, Default)]
pub struct Environment {
    pub jaunt_home: Option<OsString>,
    pub user_home: Option<PathBuf>,
    pub ssh_auth_sock: Option<OsString>,
}

impl Environment {
    pub fn from_process() -> Environment {
        Environment {
            jaunt_home: env::var_os("JAUNT_HOME"),
            user_home: env::home_dir(),
            ssh_auth_sock: env::var_os("SSH_AUTH_SOCK"),
        }
    }
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    #[arg(long, value_name = "URL", env = "JAUNT_SERVER")]
    pub server: Option<ServerUrl>,
    #[arg(
        long,
        value_name = "NAME",
        env = "JAUNT_PROFILE",
        default_value = "default"
    )]
    pub profile: ProfileName,
    #[arg(long, help = "Print the sign-in address instead of opening a browser")]
    pub no_browser: bool,
    #[arg(
        long,
        value_name = "SECS",
        default_value_t = DEFAULT_TIMEOUT_SECS,
        value_parser = clap::value_parser!(u64).range(1..=900),
        help = "How long to wait for the browser sign-in (at most 900)"
    )]
    pub timeout: u64,
    #[arg(
        long,
        help = "Sign in without a browser on this machine (not implemented yet)"
    )]
    pub device: bool,
    #[arg(
        long,
        help = "Do not write the ssh_config and known_hosts files or touch ~/.ssh/config"
    )]
    pub no_ssh_config: bool,
    #[arg(
        long,
        conflicts_with = "no_ssh_config",
        help = "Set up ssh for the domain and gateway the server names without asking"
    )]
    pub accept_ssh_config: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Args)]
pub struct LsArgs {
    #[arg(
        long,
        value_name = "NAME",
        env = "JAUNT_PROFILE",
        default_value = "default"
    )]
    pub profile: ProfileName,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
    #[arg(
        long,
        value_enum,
        default_value_t = ListKind::Ssh,
        help = "What to list: hosts (ssh), Kubernetes clusters (kube), databases (db), TCP services (tcp) or everything (all)"
    )]
    pub kind: ListKind,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    #[arg(
        long,
        value_name = "NAME",
        env = "JAUNT_PROFILE",
        default_value = "default"
    )]
    pub profile: ProfileName,
    #[arg(
        long,
        help = "Also ask the server whether the sign-in is still accepted"
    )]
    pub online: bool,
}

#[derive(Debug, Args)]
pub struct EnsureArgs {
    #[arg(
        long,
        value_name = "NAME",
        env = "JAUNT_PROFILE",
        default_value = "default"
    )]
    pub profile: ProfileName,
    #[arg(long, hide = true, value_name = "PATH")]
    pub home: Option<PathBuf>,
    #[arg(long, help = "Print only warnings and errors")]
    pub quiet: bool,
}

#[derive(Debug, Subcommand)]
pub enum ProxyCommand {
    #[command(
        about = "Connect standard input and output to the SSH gateway over TLS (ssh runs this through the generated ssh_config)"
    )]
    Ssh(ProxySshArgs),
}

#[derive(Debug, Args)]
pub struct ProxySshArgs {
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
pub struct AdminArgs {
    #[arg(
        long,
        value_name = "FILE|env",
        value_parser = parse_token_source,
        help = "Use an automation token instead of the session key, read from FILE or from the JAUNT_ADMIN_TOKEN variable when the value is `env` (only `whoami`)"
    )]
    pub token: Option<TokenSource>,
    #[arg(
        long,
        value_name = "URL",
        env = "JAUNT_SERVER",
        help = "With --token, the server to ask (by default the server of the profile)"
    )]
    pub server: Option<ServerUrl>,
    #[command(subcommand)]
    pub command: AdminCommand,
}

#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    #[command(about = "Show the identity the server sees in a signed administrator request")]
    Whoami(AdminWhoamiArgs),
    #[command(about = "Manage automation tokens for the administrator API")]
    Tokens {
        #[command(subcommand)]
        command: TokensCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum TokensCommand {
    #[command(about = "Create a token and print its secret once")]
    Create(TokenCreateArgs),
    #[command(about = "List the tokens")]
    Ls(TokenListArgs),
    #[command(about = "Revoke a token at once")]
    Revoke(TokenRevokeArgs),
}

#[derive(Debug, Args)]
pub struct TokenCreateArgs {
    #[arg(
        long,
        value_name = "NAME",
        env = "JAUNT_PROFILE",
        default_value = "default"
    )]
    pub profile: ProfileName,
    #[arg(
        long,
        value_name = "NAME",
        help = "A name unique among your live tokens"
    )]
    pub name: String,
    #[arg(
        long,
        required = true,
        value_name = "RIGHT",
        value_delimiter = ',',
        value_parser = parse_scope,
        help = "Administrator rights the token carries, for example audit.read"
    )]
    pub scope: Vec<AdminPermission>,
    #[arg(
        long,
        value_name = "DURATION",
        value_parser = parse_ttl,
        help = "Lifetime such as 3600, 12h or 30d (at most 90d, default 30d)"
    )]
    pub ttl: Option<i64>,
    #[arg(
        long,
        value_name = "NETWORK",
        help = "Accept the token only from this network, for example 203.0.113.0/24 (repeatable)"
    )]
    pub cidr: Vec<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
}

#[derive(Debug, Args)]
pub struct TokenListArgs {
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
pub struct TokenRevokeArgs {
    #[arg(
        long,
        value_name = "NAME",
        env = "JAUNT_PROFILE",
        default_value = "default"
    )]
    pub profile: ProfileName,
    #[arg(value_name = "ID", allow_hyphen_values = true)]
    pub id: String,
}

#[derive(Debug, Args)]
pub struct AdminWhoamiArgs {
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
pub struct LogoutArgs {
    #[arg(
        long,
        value_name = "NAME",
        env = "JAUNT_PROFILE",
        default_value = "default"
    )]
    pub profile: ProfileName,
}

fn usage_error(message: impl std::fmt::Display) -> ExitCode {
    eprintln!("jaunt: {message}");
    ExitCode::from(EXIT_USAGE)
}

fn failure(message: impl std::fmt::Display) -> ExitCode {
    eprintln!("jaunt: {message}");
    ExitCode::from(EXIT_FAILED)
}

fn home_for(environment: &Environment) -> Result<PathBuf, ExitCode> {
    resolve_home(
        environment.jaunt_home.clone(),
        environment.user_home.clone(),
    )
    .map_err(usage_error)
}

fn include_target(
    environment: &Environment,
    home: &std::path::Path,
) -> Result<IncludeTarget, ExitCode> {
    let user_home = environment
        .user_home
        .as_deref()
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            usage_error(
                "cannot determine the home directory that holds ~/.ssh/config; use --no-ssh-config",
            )
        })?;
    let line = include_line(home, user_home).map_err(usage_error)?;
    Ok(IncludeTarget {
        config_path: user_home.join(".ssh").join("config"),
        line,
    })
}

fn custom_home(environment: &Environment, home: &Path) -> Option<PathBuf> {
    let default_home = resolve_home(None, environment.user_home.clone()).ok();
    if default_home.as_deref() == Some(home) {
        None
    } else {
        Some(home.to_owned())
    }
}

fn now_secs() -> Result<i64, ExitCode> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .ok_or_else(|| failure("the system clock is set before 1970"))
}

pub fn run_login(args: &LoginArgs, environment: &Environment) -> ExitCode {
    if args.device {
        return usage_error("not implemented: login --device");
    }
    let home = match home_for(environment) {
        Ok(home) => home,
        Err(code) => return code,
    };
    let store = ProfileStore::new(&home, &args.profile);
    let stored = match store.read_server() {
        Ok(stored) => stored,
        Err(err) => return failure(err),
    };
    let server = match (stored, args.server.clone()) {
        (Some(stored), None) => stored,
        (Some(stored), Some(requested)) if stored == requested => stored,
        (Some(stored), Some(_)) => {
            return usage_error(format!(
                "profile `{}` is already signed in to {stored}; run `jaunt logout --profile {}` first or choose another profile",
                args.profile, args.profile
            ));
        }
        (None, Some(requested)) => requested,
        (None, None) => {
            return usage_error("no server given: pass --server URL or set JAUNT_SERVER");
        }
    };
    let ssh = if args.no_ssh_config {
        None
    } else {
        let include = match include_target(environment, &home) {
            Ok(target) => target,
            Err(code) => return code,
        };
        let program = match env::current_exe() {
            Ok(program) => program,
            Err(err) => {
                return usage_error(format!(
                    "cannot find the path of the running jaunt program: {err}; use --no-ssh-config"
                ));
            }
        };
        Some(SshSetup {
            include,
            program,
            ensure_home: custom_home(environment, &home),
        })
    };
    let options = LoginOptions {
        server,
        profile: args.profile.clone(),
        home,
        no_browser: args.no_browser,
        timeout: Duration::from_secs(args.timeout.min(MAX_TIMEOUT_SECS)),
        ssh,
        accept_ssh_config: args.accept_ssh_config,
    };
    let agent = SshAgent::new(environment.ssh_auth_sock.clone());
    let mut stderr = io::stderr();
    let mut ports = LoginPorts {
        browser: &SystemBrowser,
        agent: &agent,
        clock: &SystemTime::now,
        notices: &mut stderr,
        consent: &TerminalPrompt,
    };
    match login(&options, &mut ports) {
        Ok(report) => {
            for warning in report.warnings() {
                eprintln!("jaunt: {warning}");
            }
            match writeln!(io::stdout().lock(), "{}", report.summary()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => failure(format!("cannot write to the terminal: {err}")),
            }
        }
        Err(err) => failure(err),
    }
}

pub fn run_status(args: &StatusArgs, environment: &Environment) -> ExitCode {
    let home = match home_for(environment) {
        Ok(home) => home,
        Err(code) => return code,
    };
    let store = ProfileStore::new(&home, &args.profile);
    let now = match now_secs() {
        Ok(now) => now,
        Err(code) => return code,
    };
    let session = match Session::load(&store) {
        Ok(Some(session)) => session,
        Ok(None) => {
            let mut text = format!(
                "Not signed in (profile `{}`). Run `jaunt login`.",
                args.profile
            );
            match store.stranded_dirs() {
                Ok(found) => {
                    for path in found {
                        text.push_str(&format!(
                            "\nA previous session was left in {}: move it back to {} or run `jaunt logout`.",
                            path.display(),
                            store.dir().display()
                        ));
                    }
                }
                Err(err) => return failure(err),
            }
            return report_lines(&text, ExitCode::from(EXIT_FAILED));
        }
        Err(err) => return failure(err),
    };
    let agent = SshAgent::new(environment.ssh_auth_sock.clone());
    let view = agent_view(&store, &agent);
    let include = include_target(environment, &home).ok();
    let program = env::current_exe().ok();
    let ensure_home = custom_home(environment, &home);
    let command = program.as_deref().map(|program| EnsureCommand {
        program,
        home: ensure_home.as_deref(),
        profile: &args.profile,
    });
    let ssh = ssh_view(&store, include.as_ref(), command.as_ref());
    let mut stdout = io::stdout().lock();
    if let Err(err) = render(&mut stdout, &session, now, &view, &ssh) {
        return failure(format!("cannot write to the terminal: {err}"));
    }
    let mut valid = session.is_valid_at(now);
    if args.online
        && let Err(err) = check_online(&mut stdout, &store, &session.server)
    {
        if err.is_rejection() {
            eprintln!("jaunt: {err}");
            valid = false;
        } else {
            eprintln!("jaunt: warning: the server could not confirm this sign-in: {err}");
        }
    }
    if valid {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FAILED)
    }
}

fn ensure_ssh_setup(environment: &Environment, home: &Path) -> Option<SshSetup> {
    let user_home = environment
        .user_home
        .as_deref()
        .filter(|path| path.is_absolute())?;
    let line = include_line(home, user_home).ok()?;
    let program = env::current_exe().ok()?;
    Some(SshSetup {
        include: IncludeTarget {
            config_path: user_home.join(".ssh").join("config"),
            line,
        },
        program,
        ensure_home: custom_home(environment, home),
    })
}

fn explicit_home(home: Option<&PathBuf>, environment: &Environment) -> Result<PathBuf, String> {
    match home {
        Some(home) if home.is_absolute() => Ok(home.clone()),
        Some(_) => Err("--home must be an absolute path".to_owned()),
        None => resolve_home(
            environment.jaunt_home.clone(),
            environment.user_home.clone(),
        )
        .map_err(|err| err.to_string()),
    }
}

fn ensure_request(args: &EnsureArgs, environment: &Environment) -> Result<EnsureRequest, String> {
    let home = explicit_home(args.home.as_ref(), environment)?;
    Ok(EnsureRequest {
        renew: RenewOptions {
            ssh: ensure_ssh_setup(environment, &home),
            custom_home: custom_home(environment, &home).is_some(),
            home,
            profile: args.profile.clone(),
            deadline: SIGN_IN_DEADLINE,
        },
        quiet: args.quiet,
    })
}

pub fn run_ensure_with(args: &EnsureArgs, environment: &Environment, io: EnsureIo<'_>) -> u8 {
    match ensure_request(args, environment) {
        Ok(request) => crate::ensure::run(&request, io),
        Err(message) => {
            drop(writeln!(io.stderr, "jaunt: {message}"));
            EXIT_USAGE
        }
    }
}

pub fn run_ensure(args: &EnsureArgs, environment: &Environment) -> ExitCode {
    let agent = SshAgent::new(environment.ssh_auth_sock.clone());
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let terminal = stderr.is_terminal();
    let io = EnsureIo {
        stdout: &mut stdout,
        stderr: &mut stderr,
        terminal,
        browser: &SystemBrowser,
        agent: &agent,
        consent: &TerminalPrompt,
        clock: &SystemTime::now,
    };
    ExitCode::from(run_ensure_with(args, environment, io))
}

pub fn run_proxy(command: &ProxyCommand, environment: &Environment) -> ExitCode {
    match command {
        ProxyCommand::Ssh(args) => run_proxy_ssh(args, environment),
    }
}

fn run_proxy_ssh(args: &ProxySshArgs, environment: &Environment) -> ExitCode {
    let home = match explicit_home(args.home.as_ref(), environment) {
        Ok(home) => home,
        Err(message) => return usage_error(message),
    };
    let now = match now_secs() {
        Ok(now) => now,
        Err(code) => return code,
    };
    let store = ProfileStore::new(&home, &args.profile);
    match proxy_ssh(&store, &args.profile, now) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => failure(err),
    }
}

const NO_SERVICES: &str =
    "this server does not list Kubernetes clusters, databases or TCP services";

pub fn run_ls(args: &LsArgs, environment: &Environment) -> ExitCode {
    let home = match home_for(environment) {
        Ok(home) => home,
        Err(code) => return code,
    };
    let store = ProfileStore::new(&home, &args.profile);
    let session = match Session::load(&store) {
        Ok(Some(session)) => session,
        Ok(None) => {
            return failure(format!(
                "not signed in (profile `{}`): run `jaunt login`",
                args.profile
            ));
        }
        Err(err) => return failure(err),
    };
    let token = match store.read_token() {
        Ok(Some(token)) => token,
        Ok(None) => return failure("the API token file is missing: run `jaunt login`"),
        Err(err) => return failure(err),
    };
    let client = match ApiClient::new(&session.server) {
        Ok(client) => client,
        Err(err) => return failure(err),
    };
    match args.kind {
        ListKind::Ssh => list_hosts(args, &store, &client, &token),
        ListKind::All => list_everything(args, &store, &client, &token),
        ListKind::Kube | ListKind::Db | ListKind::Tcp => list_services(args, &client, &token),
    }
}

fn fetch_nodes(client: &ApiClient, token: &Secret) -> Result<NodeList, ExitCode> {
    match client.nodes(token) {
        Ok(list) => Ok(list),
        Err(ApiError::Unauthorized) => Err(failure("your session expired: run `jaunt login`")),
        Err(err) => Err(failure(err)),
    }
}

fn fetch_services(client: &ApiClient, token: &Secret) -> Result<Option<ServiceList>, ExitCode> {
    match client.services(token) {
        Ok(list) => Ok(Some(list)),
        Err(ApiError::Unauthorized) => Err(failure("your session expired: run `jaunt login`")),
        Err(err) if is_missing_route(err) || err == ApiError::NotConfigured => Ok(None),
        Err(err) => Err(failure(err)),
    }
}

fn list_services(args: &LsArgs, client: &ApiClient, token: &Secret) -> ExitCode {
    let list = match fetch_services(client, token) {
        Ok(Some(list)) => select_services(list, args.kind),
        Ok(None) => return failure(NO_SERVICES),
        Err(code) => return code,
    };
    let rendered = match args.format {
        OutputFormat::Json => match render_services_json(&list) {
            Ok(text) => text,
            Err(err) => return failure(format!("cannot format the answer: {err}")),
        },
        OutputFormat::Text => render_kinds_text(&Listing {
            nodes: None,
            suffix: None,
            services: Some(&list),
        }),
    };
    report_lines(&rendered, ExitCode::SUCCESS)
}

fn list_everything(
    args: &LsArgs,
    store: &ProfileStore,
    client: &ApiClient,
    token: &Secret,
) -> ExitCode {
    let nodes = match fetch_nodes(client, token) {
        Ok(nodes) => nodes,
        Err(code) => return code,
    };
    let services = match fetch_services(client, token) {
        Ok(services) => services,
        Err(code) => return code,
    };
    if services.is_none() {
        eprintln!("jaunt: note: {NO_SERVICES}; only hosts are shown");
    }
    let rendered = match args.format {
        OutputFormat::Json => match render_everything_json(&nodes, services.as_ref()) {
            Ok(text) => text,
            Err(err) => return failure(format!("cannot format the answer: {err}")),
        },
        OutputFormat::Text => {
            let suffix = match display_suffix(store, client) {
                Ok(suffix) => suffix,
                Err(code) => return code,
            };
            render_kinds_text(&Listing {
                nodes: Some(&nodes),
                suffix: suffix.as_deref(),
                services: services.as_ref(),
            })
        }
    };
    report_lines(&rendered, ExitCode::SUCCESS)
}

fn list_hosts(args: &LsArgs, store: &ProfileStore, client: &ApiClient, token: &Secret) -> ExitCode {
    let list = match fetch_nodes(client, token) {
        Ok(list) => list,
        Err(code) => return code,
    };
    let rendered = match args.format {
        OutputFormat::Json => match render_json(&list) {
            Ok(text) => text,
            Err(err) => return failure(format!("cannot format the answer: {err}")),
        },
        OutputFormat::Text => {
            let suffix = match display_suffix(store, client) {
                Ok(suffix) => suffix,
                Err(code) => return code,
            };
            render_text(&list, suffix.as_deref())
        }
    };
    report_lines(&rendered, ExitCode::SUCCESS)
}

pub fn run_admin(args: &AdminArgs, environment: &Environment) -> ExitCode {
    match (&args.token, &args.command) {
        (Some(source), AdminCommand::Whoami(whoami_args)) => {
            run_token_whoami(source, args.server.as_ref(), whoami_args, environment)
        }
        (Some(_), AdminCommand::Tokens { .. }) => usage_error(
            "--token works only with `whoami`: creating, listing and revoking tokens needs your own signed sign-in",
        ),
        (None, AdminCommand::Whoami(whoami_args)) => run_admin_whoami(whoami_args, environment),
        (None, AdminCommand::Tokens { command }) => run_tokens(command, environment),
    }
}

fn run_token_whoami(
    source: &TokenSource,
    server: Option<&ServerUrl>,
    args: &AdminWhoamiArgs,
    environment: &Environment,
) -> ExitCode {
    let token = match read_admin_token(source, env::var_os(ADMIN_TOKEN_ENV)) {
        Ok(token) => token,
        Err(err) => return usage_error(err),
    };
    let server = match server {
        Some(server) => server.clone(),
        None => {
            let home = match home_for(environment) {
                Ok(home) => home,
                Err(code) => return code,
            };
            match ProfileStore::new(&home, &args.profile).read_server() {
                Ok(Some(server)) => server,
                Ok(None) => {
                    return usage_error("no server given: pass --server URL or set JAUNT_SERVER");
                }
                Err(err) => return failure(err),
            }
        }
    };
    let identity = match token_whoami(&server, &token) {
        Ok(identity) => identity,
        Err(err) => return failure(err),
    };
    let rendered = match args.format {
        OutputFormat::Json => match serde_json::to_string_pretty(&identity) {
            Ok(text) => text,
            Err(err) => return failure(format!("cannot format the answer: {err}")),
        },
        OutputFormat::Text => render_token_identity(&identity),
    };
    report_lines(&rendered, ExitCode::SUCCESS)
}

fn run_tokens(command: &TokensCommand, environment: &Environment) -> ExitCode {
    let profile = match command {
        TokensCommand::Create(args) => &args.profile,
        TokensCommand::Ls(args) => &args.profile,
        TokensCommand::Revoke(args) => &args.profile,
    };
    let home = match home_for(environment) {
        Ok(home) => home,
        Err(code) => return code,
    };
    let store = ProfileStore::new(&home, profile);
    let context = AdminContext {
        store: &store,
        agent_socket: environment.ssh_auth_sock.as_ref(),
        clock: &SystemTime::now,
        agent_timeout: AGENT_TIMEOUT,
    };
    match command {
        TokensCommand::Create(args) => run_token_create(&context, args),
        TokensCommand::Ls(args) => run_token_list(&context, args),
        TokensCommand::Revoke(args) => match revoke_token(&context, &args.id) {
            Ok(()) => report_lines(
                &format!("Revoked token {}.", crate::display::printable(&args.id)),
                ExitCode::SUCCESS,
            ),
            Err(err) => failure(err),
        },
    }
}

fn run_token_create(context: &AdminContext<'_>, args: &TokenCreateArgs) -> ExitCode {
    let request = NewToken {
        name: args.name.clone(),
        scope: args
            .scope
            .iter()
            .map(|permission| permission.as_str().to_owned())
            .collect(),
        ttl_secs: args.ttl,
        cidrs: args.cidr.clone(),
    };
    let created = match create_token(context, &request) {
        Ok(created) => created,
        Err(err) => return failure(err),
    };
    match args.format {
        OutputFormat::Json => {
            let mut body = match serde_json::to_value(&created.token) {
                Ok(body) => body,
                Err(err) => return failure(format!("cannot format the answer: {err}")),
            };
            if let Some(object) = body.as_object_mut() {
                object.insert(
                    "secret".to_owned(),
                    serde_json::Value::String(created.secret.expose().to_owned()),
                );
            }
            eprintln!("jaunt: the secret is shown only this once: store it now");
            report_lines(&body.to_string(), ExitCode::SUCCESS)
        }
        OutputFormat::Text => {
            eprintln!("{}", render_created(&created));
            report_lines(created.secret.expose(), ExitCode::SUCCESS)
        }
    }
}

fn run_token_list(context: &AdminContext<'_>, args: &TokenListArgs) -> ExitCode {
    let list = match list_tokens(context) {
        Ok(list) => list,
        Err(err) => return failure(err),
    };
    let rendered = match args.format {
        OutputFormat::Json => match serde_json::to_string_pretty(&list) {
            Ok(text) => text,
            Err(err) => return failure(format!("cannot format the answer: {err}")),
        },
        OutputFormat::Text => {
            let now = match now_secs() {
                Ok(now) => now,
                Err(code) => return code,
            };
            render_token_list(&list, now)
        }
    };
    report_lines(&rendered, ExitCode::SUCCESS)
}

fn run_admin_whoami(args: &AdminWhoamiArgs, environment: &Environment) -> ExitCode {
    let home = match home_for(environment) {
        Ok(home) => home,
        Err(code) => return code,
    };
    let store = ProfileStore::new(&home, &args.profile);
    let context = AdminContext {
        store: &store,
        agent_socket: environment.ssh_auth_sock.as_ref(),
        clock: &SystemTime::now,
        agent_timeout: AGENT_TIMEOUT,
    };
    let identity = match whoami(&context) {
        Ok(identity) => identity,
        Err(err) => return failure(err),
    };
    let rendered = match args.format {
        OutputFormat::Json => match serde_json::to_string_pretty(&identity) {
            Ok(text) => text,
            Err(err) => return failure(format!("cannot format the answer: {err}")),
        },
        OutputFormat::Text => render_identity(&identity),
    };
    report_lines(&rendered, ExitCode::SUCCESS)
}

fn display_suffix(store: &ProfileStore, client: &ApiClient) -> Result<Option<String>, ExitCode> {
    match store.read_client_config() {
        Ok(Some(config)) => return Ok(Some(config.ssh_suffix)),
        Ok(None) => {}
        Err(err) => return Err(failure(err)),
    }
    match client.client_config().map(validate) {
        Ok(Ok(config)) => Ok(Some(config.ssh_suffix)),
        Ok(Err(err)) => {
            eprintln!("jaunt: note: host names are shown without the SSH domain: {err}");
            Ok(None)
        }
        Err(err) => {
            eprintln!("jaunt: note: host names are shown without the SSH domain: {err}");
            Ok(None)
        }
    }
}

fn report_lines(text: &str, code: ExitCode) -> ExitCode {
    match writeln!(io::stdout().lock(), "{text}") {
        Ok(()) => code,
        Err(err) => failure(format!("cannot write to the terminal: {err}")),
    }
}

pub fn run_logout(args: &LogoutArgs, environment: &Environment) -> ExitCode {
    let home = match home_for(environment) {
        Ok(home) => home,
        Err(code) => return code,
    };
    let store = ProfileStore::new(&home, &args.profile);
    let lock = if home.is_dir() {
        let deadline = Instant::now() + Duration::from_secs(DEFAULT_TIMEOUT_SECS);
        match lock_profile(&home, &args.profile, deadline, &mut io::stderr()) {
            Ok(lock) => Some(lock),
            Err(err) => return failure(err),
        }
    } else {
        None
    };
    let agent = SshAgent::new(environment.ssh_auth_sock.clone());
    let outcome = logout(&store, &agent);
    if let Err(err) = store.clear_failure_marker() {
        eprintln!("jaunt: warning: the record of an earlier failed sign-in was not removed: {err}");
    }
    drop(lock);
    match outcome {
        Ok(report) => {
            if let Some(warning) = &report.agent_warning {
                eprintln!("jaunt: warning: the key may still be loaded in ssh-agent: {warning}");
            }
            if report.directory_kept {
                eprintln!(
                    "jaunt: warning: {} still contains other files and was kept",
                    store.dir().display()
                );
            }
            let text = if report.was_signed_in {
                "Signed out."
            } else {
                "Already signed out."
            };
            report_lines(text, ExitCode::SUCCESS)
        }
        Err(err) => failure(err),
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{Environment, custom_home, ensure_ssh_setup};
    use crate::profile::ProfileName;
    use crate::ssh_config::{EnsureCommand, ensure_match_line};

    fn environment(user_home: Option<&str>) -> Environment {
        Environment {
            jaunt_home: None,
            user_home: user_home.map(PathBuf::from),
            ssh_auth_sock: None,
        }
    }

    #[test]
    fn only_a_home_other_than_the_default_is_pinned_in_the_generated_command() {
        let cases = [
            (Some("/home/u"), "/home/u/.jaunt", None),
            (Some("/home/u"), "/srv/jaunt", Some("/srv/jaunt")),
            (None, "/home/u/.jaunt", Some("/home/u/.jaunt")),
            (Some("relative"), "/home/u/.jaunt", Some("/home/u/.jaunt")),
        ];
        for (user_home, home, pinned) in cases {
            assert_eq!(
                custom_home(&environment(user_home), Path::new(home)),
                pinned.map(PathBuf::from),
                "{user_home:?} {home}"
            );
        }
    }

    #[test]
    fn the_rendered_line_for_the_default_home_has_no_home_option() {
        let environment = environment(Some("/home/u"));
        let setup = ensure_ssh_setup(&environment, Path::new("/home/u/.jaunt")).unwrap();
        let profile = ProfileName::default_name();

        let line = ensure_match_line(
            "example.test",
            &EnsureCommand {
                program: &setup.program,
                home: setup.ensure_home.as_deref(),
                profile: &profile,
            },
        )
        .unwrap();

        assert_eq!(setup.ensure_home, None);
        assert!(!line.contains("--home"), "{line}");
        assert!(
            line.ends_with(" ensure --profile default --quiet\""),
            "{line}"
        );
    }
}
