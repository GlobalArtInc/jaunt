use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;
use std::time::SystemTime;

use jaunt_proto::ADMIN_TOKEN_ENV;
use rustix::process::{Pid, Signal, kill_process};
use tokio::process::{Child, Command};
use tokio::sync::oneshot;

use crate::local_listen::{ListenError, PG_SOCKET_PORT, bind_loopback, lock_database_dir, run_dir};
use crate::local_proxy::{
    LocalListener, RunError, StopKind, StopSignals, Target, proxy_runtime, serve,
};
use crate::service_dial::{DialKind, ServiceDialer, ServiceName};
use crate::store::ProfileStore;

pub const PSQL: &str = "psql";
pub const PSQL_ENV_REMOVED: [&str; 4] =
    ["PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE", ADMIN_TOKEN_ENV];
const EXECUTABLE_BITS: u32 = 0o111;
const EXIT_FAILED: u8 = 1;
const SIGNAL_EXIT_BASE: i32 = 128;
const USER_PLACEHOLDER: &str = "<db user>";
const DATABASE_PLACEHOLDER: &str = "<db>";

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error(transparent)]
    Run(#[from] RunError),
    #[error("{path} is not valid UTF-8, which psql needs in a host name")]
    NotUtf8 { path: PathBuf },
    #[error(
        "psql was not found in the absolute directories of PATH: install the PostgreSQL client, or run `jaunt db proxy` and use another client"
    )]
    PsqlMissing,
    #[error("cannot run psql: {0}")]
    Psql(io::Error),
}

impl From<ListenError> for DbError {
    fn from(err: ListenError) -> DbError {
        DbError::Run(RunError::Listen(err))
    }
}

pub struct ConnectRequest {
    pub user: Option<String>,
    pub database: Option<String>,
    pub psql_args: Vec<OsString>,
}

pub fn conninfo_value(value: &str) -> String {
    let plain = !value.is_empty()
        && !value
            .chars()
            .any(|ch| ch.is_whitespace() || ch == '\'' || ch == '\\');
    if plain {
        return value.to_owned();
    }
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for ch in value.chars() {
        if ch == '\'' || ch == '\\' {
            quoted.push('\\');
        }
        quoted.push(ch);
    }
    quoted.push('\'');
    quoted
}

pub fn conninfo(host: &str, port: u16) -> String {
    format!("host={} port={port}", conninfo_value(host))
}

pub fn connect_conninfo(host: &str, user: Option<&str>, database: Option<&str>) -> String {
    let mut text = format!(
        "host={} hostaddr={} port={PG_SOCKET_PORT}",
        conninfo_value(host),
        conninfo_value("")
    );
    if let Some(user) = user {
        text.push_str(" user=");
        text.push_str(&conninfo_value(user));
    }
    if let Some(database) = database {
        text.push_str(" dbname=");
        text.push_str(&conninfo_value(database));
    }
    text
}

pub fn shell_word(text: &str) -> String {
    let double_quotable = !text
        .chars()
        .any(|ch| matches!(ch, '"' | '\\' | '$' | '`' | '!') || ch.is_control());
    if double_quotable {
        return format!("\"{text}\"");
    }
    format!("'{}'", text.replace('\'', r"'\''"))
}

pub fn psql_line(host: &str, port: u16) -> String {
    let info = format!(
        "{} user={USER_PLACEHOLDER} dbname={DATABASE_PLACEHOLDER}",
        conninfo(host, port)
    );
    format!("{PSQL} {}", shell_word(&info))
}

fn utf8(path: &Path) -> Result<&str, DbError> {
    path.to_str().ok_or_else(|| DbError::NotUtf8 {
        path: path.to_owned(),
    })
}

pub fn proxy(
    store: &ProfileStore,
    dialer: Arc<ServiceDialer>,
    name: &ServiceName,
    tcp: Option<SocketAddr>,
) -> Result<(), DbError> {
    let target = Arc::new(Target::new(dialer, DialKind::Db, name.clone()));
    let runtime = proxy_runtime()?;
    let outcome = runtime.block_on(async {
        let mut signals = StopSignals::install().map_err(RunError::Signals)?;
        match tcp {
            Some(address) => {
                let listener = LocalListener::tcp(vec![bind_loopback(address)?])?;
                for bound in listener.addresses() {
                    eprintln!(
                        "jaunt: warning: every user of this computer can connect to {bound} and reach database `{name}` as you"
                    );
                    println!("{}", psql_line(&bound.ip().to_string(), bound.port()));
                }
                serve(listener, target, signals.stopped()).await;
            }
            None => {
                let dir = lock_database_dir(store.dir(), name)?;
                let host = utf8(dir.path())?.to_owned();
                let (listener, socket) = dir.bind()?;
                let listener = LocalListener::unix(listener, socket.path())?;
                eprintln!(
                    "jaunt: listening on {} for database `{name}`; stop with Ctrl-C",
                    socket.path().display()
                );
                println!("{}", psql_line(&host, PG_SOCKET_PORT));
                serve(listener, target, signals.stopped()).await;
                drop(socket);
                drop(dir);
            }
        }
        Ok(())
    });
    runtime.shutdown_background();
    outcome
}

pub fn find_psql(path: Option<&OsStr>) -> Option<PathBuf> {
    env::split_paths(path?)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(PSQL))
        .find(|candidate| {
            fs::metadata(candidate).is_ok_and(|meta| {
                meta.is_file() && meta.permissions().mode() & EXECUTABLE_BITS != 0
            })
        })
}

pub fn psql_command(program: &Path, conninfo: &str, extra: &[OsString]) -> Command {
    let mut command = Command::new(program);
    command
        .arg(conninfo)
        .args(extra)
        .env("PGSSLMODE", "disable");
    for name in PSQL_ENV_REMOVED {
        command.env_remove(name);
    }
    command
}

pub fn exit_code(status: ExitStatus) -> u8 {
    match (status.code(), status.signal()) {
        (Some(code), _) => u8::try_from(code).unwrap_or(EXIT_FAILED),
        (None, Some(signal)) => {
            u8::try_from(SIGNAL_EXIT_BASE.saturating_add(signal)).unwrap_or(EXIT_FAILED)
        }
        (None, None) => EXIT_FAILED,
    }
}

pub fn connect(
    store: &ProfileStore,
    dialer: Arc<ServiceDialer>,
    name: &ServiceName,
    request: &ConnectRequest,
) -> Result<u8, DbError> {
    let target = Arc::new(Target::new(dialer, DialKind::Db, name.clone()));
    let program = find_psql(env::var_os("PATH").as_deref()).ok_or(DbError::PsqlMissing)?;
    let dir = run_dir(store.dir(), SystemTime::now())?;
    let info = connect_conninfo(
        utf8(dir.path())?,
        request.user.as_deref(),
        request.database.as_deref(),
    );
    let runtime = proxy_runtime()?;
    let outcome = runtime.block_on(async {
        let mut signals = StopSignals::install().map_err(RunError::Signals)?;
        let (listener, socket) = dir.bind()?;
        let listener = LocalListener::unix(listener, socket.path())?;
        let mut child = psql_command(&program, &info, &request.psql_args)
            .spawn()
            .map_err(DbError::Psql)?;
        let (finished, done) = oneshot::channel::<()>();
        let proxy = serve(listener, target, async {
            drop(done.await);
        });
        let watched = watch(&mut child, &mut signals, finished);
        let ((), status) = tokio::join!(proxy, watched);
        drop(socket);
        status.map(exit_code).map_err(DbError::Psql)
    });
    runtime.shutdown_background();
    drop(dir);
    outcome
}

async fn watch(
    child: &mut Child,
    signals: &mut StopSignals,
    finished: oneshot::Sender<()>,
) -> io::Result<ExitStatus> {
    let status = loop {
        tokio::select! {
            biased;
            status = child.wait() => break status,
            Some(kind) = signals.next() => pass_on(child, kind),
        }
    };
    let _ = finished.send(());
    status
}

pub fn passed_to_psql(kind: StopKind) -> Option<Signal> {
    match kind {
        StopKind::Terminate => Some(Signal::TERM),
        StopKind::Hangup => Some(Signal::HUP),
        StopKind::Interrupt => None,
    }
}

fn pass_on(child: &Child, kind: StopKind) {
    let Some(signal) = passed_to_psql(kind) else {
        return;
    };
    let pid = child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(Pid::from_raw);
    if let Some(pid) = pid
        && let Err(err) = kill_process(pid, signal)
    {
        eprintln!("jaunt: cannot pass the stop signal to psql: {err}");
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    use std::os::unix::fs::PermissionsExt;

    use rustix::process::Signal;

    use super::{
        connect_conninfo, conninfo_value, exit_code, find_psql, passed_to_psql, psql_line,
        shell_word,
    };
    use crate::local_proxy::StopKind;

    #[test]
    fn conninfo_values_are_quoted_only_when_libpq_needs_it() {
        let cases = [
            (
                "/home/a/.jaunt/default/db/orders",
                "/home/a/.jaunt/default/db/orders",
            ),
            ("app", "app"),
            ("", "''"),
            ("two words", "'two words'"),
            ("it's", r"'it\'s'"),
            (r"back\slash", r"'back\\slash'"),
            ("x host=evil", "'x host=evil'"),
            ("tab\there", "'tab\there'"),
        ];
        for (value, expected) in cases {
            assert_eq!(conninfo_value(value), expected, "{value:?}");
        }
        assert_eq!(
            connect_conninfo("/d", Some("app"), Some("orders db")),
            "host=/d hostaddr='' port=5432 user=app dbname='orders db'"
        );
        assert_eq!(
            connect_conninfo("/d", None, None),
            "host=/d hostaddr='' port=5432"
        );
    }

    #[test]
    fn the_printed_line_survives_a_shell() {
        assert_eq!(
            psql_line("/home/a/.jaunt/default/db/orders", 5432),
            r#"psql "host=/home/a/.jaunt/default/db/orders port=5432 user=<db user> dbname=<db>""#
        );
        assert_eq!(
            psql_line("127.0.0.1", 54321),
            r#"psql "host=127.0.0.1 port=54321 user=<db user> dbname=<db>""#
        );
        assert_eq!(shell_word("a$b"), "'a$b'");
        assert_eq!(shell_word("it's $x"), r"'it'\''s $x'");
        assert_eq!(shell_word("plain"), "\"plain\"");
    }

    #[test]
    fn term_and_hup_are_passed_to_psql_and_int_is_left_to_the_terminal() {
        assert_eq!(passed_to_psql(StopKind::Terminate), Some(Signal::TERM));
        assert_eq!(passed_to_psql(StopKind::Hangup), Some(Signal::HUP));
        assert_eq!(passed_to_psql(StopKind::Interrupt), None);
    }

    #[test]
    fn the_exit_code_of_psql_is_passed_on() {
        assert_eq!(exit_code(ExitStatus::from_raw(0)), 0);
        assert_eq!(exit_code(ExitStatus::from_raw(3 << 8)), 3);
        assert_eq!(exit_code(ExitStatus::from_raw(15)), 143);
        assert_eq!(exit_code(ExitStatus::from_raw(1)), 129);
    }

    #[test]
    fn psql_is_looked_up_only_in_absolute_directories_of_path() {
        let root = tempfile::tempdir().unwrap();
        let program = |dir: &str, mode: u32| {
            let dir = root.path().join(dir);
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join("psql");
            fs::write(&path, "#!/bin/sh\n").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            path
        };
        program("plain", 0o644);
        let wanted = program("bin", 0o755);
        program("later", 0o755);
        let joined = |dirs: &[&str]| {
            dirs.iter()
                .map(|dir| {
                    if dir.starts_with('/') || dir.is_empty() || *dir == "." {
                        (*dir).to_owned()
                    } else {
                        root.path().join(dir).display().to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(":")
        };

        let found = find_psql(Some(joined(&["", ".", "plain", "bin", "later"]).as_ref()));

        assert_eq!(found, Some(wanted));
        assert_eq!(find_psql(Some(joined(&["", ".", "plain"]).as_ref())), None);
        assert_eq!(find_psql(None), None);
    }
}
