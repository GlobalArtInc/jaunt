use std::fs::{self, DirBuilder};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use jaunt::lock::ProfileLock;
use jaunt_proto::{ADMIN_TOKEN_ENV, GATE_ALPN_SSH, GATE_ALPN_SVC, ServiceKind, ServiceSummary};
use rustix::process::{Pid, Signal, kill_process};

use crate::cli::{base_command, jaunt, stderr, stdout};
use crate::gate::{GATE_NAME, TestCa, run_bounded};
use crate::support::{API_TOKEN, Behavior, FakeServer, now_secs, serial_section, write_script};
use crate::svc_fake::{
    App, DEADLINE, FakeSvc, Pki, SSL_REQUEST, Setup, TRAILER, issuing_api, json_alpn, poll_until,
    requiring_client, short_tempdir, sign_in, svc_services_json,
};

const POLL: Duration = Duration::from_millis(20);
const CAP: usize = 64;
const REFUSED_TCP: &str = "jaunt: the gate refused the connection (no access, service unavailable or revoked): run `jaunt ls --kind tcp` to see what you can reach";
const CAP_NOTICE: &str = "jaunt: refused a local connection: 64 connections are already open";
const WAIT_NOTICE: &str = "jaunt: waiting for another sign-in of this profile to finish";

struct Stand {
    _root: tempfile::TempDir,
    home: PathBuf,
    api: FakeServer,
    svc: FakeSvc,
}

impl Stand {
    fn new(inner_name: &str, app: App, change: impl FnOnce(&mut Setup, &Pki)) -> Stand {
        let pki = Pki::new();
        let mut setup = Setup::standard(&pki, inner_name, app);
        change(&mut setup, &pki);
        let svc = FakeSvc::start(setup);
        let root = short_tempdir();
        let home = root.path().join("h");
        let ssh_end = i64::try_from(now_secs()).unwrap() + 3600;
        let api = issuing_api(&pki, ssh_end);
        sign_in(
            &home,
            &api,
            ssh_end,
            Some(&svc_services_json(svc.port, &pki)),
        );
        Stand {
            _root: root,
            home,
            api,
            svc,
        }
    }

    fn database() -> Stand {
        Stand::new(&format!("orders.db.{GATE_NAME}"), App::Postgres, |_, _| {})
    }

    fn tcp(change: impl FnOnce(&mut Setup, &Pki)) -> Stand {
        Stand::new(&format!("grafana.tcp.{GATE_NAME}"), App::Echo, change)
    }

    fn db_dir(&self) -> PathBuf {
        self.home.join("default").join("db")
    }
}

struct Running {
    child: Option<Child>,
    lines: mpsc::Receiver<String>,
    errors: mpsc::Receiver<String>,
    seen_errors: Vec<String>,
}

struct Finished {
    status: ExitStatus,
    stdout: Vec<String>,
    stderr: String,
}

fn launch(mut command: Command, args: &[&str]) -> Running {
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let out = child.stdout.take().unwrap();
    let (line_tx, lines) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(out).lines() {
            let Ok(line) = line else { break };
            if line_tx.send(line).is_err() {
                break;
            }
        }
    });
    let err = child.stderr.take().unwrap();
    let (error_tx, errors) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(err).lines() {
            let Ok(line) = line else { break };
            if error_tx.send(line).is_err() {
                break;
            }
        }
    });
    Running {
        child: Some(child),
        lines,
        errors,
        seen_errors: Vec::new(),
    }
}

impl Running {
    fn has_ended(&mut self) -> bool {
        self.child
            .as_mut()
            .is_some_and(|child| child.try_wait().unwrap().is_some())
    }

    fn error_line(&mut self) -> String {
        let line = self
            .errors
            .recv_timeout(DEADLINE)
            .expect("nothing was printed on standard error in time");
        self.seen_errors.push(line.clone());
        line
    }

    fn line(&self) -> String {
        self.lines
            .recv_timeout(DEADLINE)
            .expect("nothing was printed on standard output in time")
    }

    fn signal(&self, signal: Signal) {
        let id = self.child.as_ref().unwrap().id();
        let pid = Pid::from_raw(i32::try_from(id).unwrap()).unwrap();
        kill_process(pid, signal).unwrap();
    }

    fn finish(mut self) -> Finished {
        let mut child = self.child.take().unwrap();
        let deadline = Instant::now() + DEADLINE;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                drop(child.kill());
                drop(child.wait());
                panic!("the process did not stop in time");
            }
            thread::sleep(POLL);
        };
        let mut rest = Vec::new();
        while let Ok(line) = self.lines.recv_timeout(DEADLINE) {
            rest.push(line);
        }
        let mut errors = std::mem::take(&mut self.seen_errors);
        while let Ok(line) = self.errors.recv_timeout(DEADLINE) {
            errors.push(line);
        }
        let stderr = errors.iter().map(|line| format!("{line}\n")).collect();
        Finished {
            status,
            stdout: rest,
            stderr,
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            drop(child.kill());
            drop(child.wait());
        }
    }
}

fn exchange<S: Read + Write>(stream: &mut S, postgres: bool, payload: &[u8]) {
    if postgres {
        stream.write_all(&SSL_REQUEST).unwrap();
        let mut answer = [0_u8; 1];
        stream.read_exact(&mut answer).unwrap();
        assert_eq!(&answer, b"N");
    }
    stream.write_all(payload).unwrap();
    let mut echoed = vec![0_u8; payload.len()];
    stream.read_exact(&mut echoed).unwrap();
    assert_eq!(echoed, payload);
}

fn finish_exchange(mut stream: impl Read, end_write: impl FnOnce()) {
    end_write();
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, TRAILER);
}

fn private_dir(path: &Path, mode: u32) {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn assert_private_dir(path: &Path) {
    let meta = fs::symlink_metadata(path).unwrap();
    assert!(meta.is_dir(), "{}", path.display());
    assert_eq!(
        meta.permissions().mode() & 0o777,
        0o700,
        "{}",
        path.display()
    );
}

fn bounded(home: &Path, args: &[&str]) -> Output {
    let mut command = base_command(home);
    command.args(args);
    run_bounded(command, b"", false)
}

fn one_line(text: &str) -> &str {
    assert_eq!(text.lines().count(), 1, "{text}");
    text.trim_end()
}

#[test]
fn db_proxy_serves_a_private_socket_transparently_and_removes_it_on_a_signal() {
    for signal in [Signal::TERM, Signal::INT, Signal::HUP] {
        let stand = Stand::database();
        let dir = stand.db_dir().join("orders");
        let socket = dir.join(".s.PGSQL.5432");
        let running = launch(base_command(&stand.home), &["db", "proxy", "orders"]);

        let line = running.line();

        assert_eq!(
            line,
            format!(
                "psql \"host={} port=5432 user=<db user> dbname=<db>\"",
                dir.display()
            )
        );
        assert_private_dir(&stand.db_dir());
        assert_private_dir(&dir);
        let meta = fs::symlink_metadata(&socket).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let mut client = UnixStream::connect(&socket).unwrap();
        client.set_read_timeout(Some(DEADLINE)).unwrap();
        exchange(&mut client, true, b"startup");
        let reader = client.try_clone().unwrap();
        finish_exchange(reader, || client.shutdown(Shutdown::Write).unwrap());
        running.signal(signal);
        let finished = running.finish();
        assert_eq!(
            finished.status.code(),
            Some(0),
            "{signal:?}: {}",
            finished.stderr
        );
        assert!(
            !finished.stderr.contains(WAIT_NOTICE),
            "{}",
            finished.stderr
        );
        assert!(fs::symlink_metadata(&socket).is_err(), "{signal:?}");
        assert!(!dir.exists(), "{signal:?}");
        assert!(stand.db_dir().is_dir());
        let session = stand.svc.log(|log| log.sessions[0].clone());
        assert_eq!(session.inner_sni, Some(format!("orders.db.{GATE_NAME}")));
        assert_eq!(session.first_bytes, SSL_REQUEST);
        assert!(session.client_ended);
    }
}

fn hold_lock(dir: &Path) -> ProfileLock {
    ProfileLock::acquire(
        dir,
        &dir.join(".lock"),
        Instant::now() + DEADLINE,
        &mut || {},
    )
    .unwrap()
}

#[test]
fn db_proxy_refuses_unsafe_directories_and_a_held_lock_and_replaces_a_dead_socket() {
    type Prepare = fn(&Path, &Path, &Path) -> Option<ProfileLock>;
    let cases: Vec<(&str, Prepare, Option<&str>)> = vec![
        (
            "the profile directory is open",
            |profile, _, _| {
                fs::set_permissions(profile, fs::Permissions::from_mode(0o755)).unwrap();
                None
            },
            Some("/h/default can be used by other users"),
        ),
        (
            "the db directory is open",
            |_, db, _| {
                private_dir(db, 0o755);
                None
            },
            Some("/db can be used by other users"),
        ),
        (
            "the socket directory lets the group in",
            |_, db, _| {
                private_dir(db, 0o700);
                private_dir(&db.join("orders"), 0o750);
                None
            },
            Some("/db/orders can be used by other users"),
        ),
        (
            "the socket directory lets others in",
            |_, db, _| {
                private_dir(db, 0o700);
                private_dir(&db.join("orders"), 0o701);
                None
            },
            Some("/db/orders can be used by other users"),
        ),
        (
            "the socket directory is a symbolic link",
            |_, db, _| {
                private_dir(db, 0o700);
                let elsewhere = db.with_file_name("elsewhere");
                private_dir(&elsewhere, 0o700);
                symlink(&elsewhere, db.join("orders")).unwrap();
                None
            },
            Some("/db/orders is a symbolic link"),
        ),
        (
            "a file stands where the socket goes",
            |_, db, socket| {
                private_dir(&db.join("orders"), 0o700);
                fs::write(socket, b"keep").unwrap();
                None
            },
            Some(".s.PGSQL.5432 is not a socket"),
        ),
        (
            "another proxy holds the directory",
            |_, db, socket| {
                private_dir(&db.join("orders"), 0o700);
                drop(UnixListener::bind(socket).unwrap());
                Some(hold_lock(&db.join("orders")))
            },
            Some("a proxy is already running in"),
        ),
        (
            "the lock file is a symbolic link to a file",
            |profile, db, _| {
                private_dir(&db.join("orders"), 0o700);
                fs::write(profile.join("target"), b"untouched").unwrap();
                symlink(profile.join("target"), db.join("orders").join(".lock")).unwrap();
                None
            },
            Some("/db/orders/.lock is not a lock file of yours"),
        ),
        (
            "the lock file is a directory",
            |_, db, _| {
                private_dir(&db.join("orders").join(".lock"), 0o700);
                None
            },
            Some("/db/orders/.lock is not a lock file of yours"),
        ),
        (
            "the lock file is a FIFO",
            |_, db, _| {
                private_dir(&db.join("orders"), 0o700);
                let made = Command::new("mkfifo")
                    .arg(db.join("orders").join(".lock"))
                    .status()
                    .unwrap();
                assert!(made.success());
                None
            },
            Some("/db/orders/.lock is not a lock file of yours"),
        ),
        (
            "a socket left by a proxy that died",
            |_, db, socket| {
                private_dir(&db.join("orders"), 0o700);
                fs::write(db.join("orders").join(".lock"), b"").unwrap();
                drop(UnixListener::bind(socket).unwrap());
                None
            },
            None,
        ),
    ];
    let fifo_possible = Command::new("mkfifo")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok();
    for (case, prepare, refusal) in cases {
        if case == "the lock file is a FIFO" && !fifo_possible {
            eprintln!("skipped {case}: no mkfifo program on this machine");
            continue;
        }
        let stand = Stand::database();
        let profile = stand.home.join("default");
        let socket = stand.db_dir().join("orders").join(".s.PGSQL.5432");
        let held = prepare(&profile, &stand.db_dir(), &socket);
        let before = fs::symlink_metadata(&socket).ok().map(|meta| meta.ino());
        let mut command = base_command(&stand.home);

        match refusal {
            Some(expected) => {
                command.args(["db", "proxy", "orders"]);
                let output = run_bounded(command, b"", false);
                assert_eq!(output.status.code(), Some(1), "{case}");
                let text = stderr(&output);
                let line = one_line(&text);
                assert!(
                    line.starts_with("jaunt: ") && line.contains(expected),
                    "{case}: {line}"
                );
                assert_eq!(
                    fs::symlink_metadata(&socket).ok().map(|meta| meta.ino()),
                    before,
                    "{case}"
                );
            }
            None => {
                let running = launch(command, &["db", "proxy", "orders"]);
                assert!(running.line().starts_with("psql "), "{case}");
                let meta = fs::symlink_metadata(&socket).unwrap();
                assert_eq!(meta.permissions().mode() & 0o777, 0o600, "{case}");
                assert_ne!(Some(meta.ino()), before, "{case}");
                running.signal(Signal::TERM);
                let finished = running.finish();
                assert_eq!(
                    finished.status.code(),
                    Some(0),
                    "{case}: {}",
                    finished.stderr
                );
            }
        }
        if case == "a file stands where the socket goes" {
            assert_eq!(fs::read(&socket).unwrap(), b"keep");
        }
        if case == "the lock file is a symbolic link to a file" {
            assert_eq!(fs::read(profile.join("target")).unwrap(), b"untouched");
        }
        drop(held);
        assert_eq!(stand.svc.log(|log| log.accepted), 0, "{case}");
    }
}

#[test]
fn of_two_proxies_started_together_for_one_database_exactly_one_runs() {
    let stand = Stand::database();
    let dir = stand.db_dir().join("orders");
    let mut runs = [
        launch(base_command(&stand.home), &["db", "proxy", "orders"]),
        launch(base_command(&stand.home), &["db", "proxy", "orders"]),
    ];

    let deadline = Instant::now() + DEADLINE;
    let loser = loop {
        if let Some(index) = runs.iter_mut().position(Running::has_ended) {
            break index;
        }
        assert!(Instant::now() < deadline, "neither proxy stopped");
        thread::sleep(POLL);
    };

    let [first, second] = runs;
    let (winner, loser) = if loser == 0 {
        (second, first)
    } else {
        (first, second)
    };
    let refused = loser.finish();
    assert_eq!(refused.status.code(), Some(1), "{}", refused.stderr);
    assert_eq!(
        one_line(&refused.stderr),
        format!("jaunt: a proxy is already running in {}", dir.display())
    );
    assert!(winner.line().starts_with("psql "));
    winner.signal(Signal::TERM);
    let finished = winner.finish();
    assert_eq!(finished.status.code(), Some(0), "{}", finished.stderr);
    assert!(!dir.exists());
}

#[test]
fn a_socket_path_longer_than_the_system_allows_is_one_clear_line() {
    let pki = Pki::new();
    let svc = FakeSvc::start(Setup::standard(
        &pki,
        &format!("orders.db.{GATE_NAME}"),
        App::Postgres,
    ));
    let root = short_tempdir();
    let home = root.path().join("a".repeat(80)).join("h");
    let ssh_end = i64::try_from(now_secs()).unwrap() + 3600;
    let api = issuing_api(&pki, ssh_end);
    sign_in(
        &home,
        &api,
        ssh_end,
        Some(&svc_services_json(svc.port, &pki)),
    );

    let output = bounded(&home, &["db", "proxy", "orders"]);

    assert_eq!(output.status.code(), Some(1));
    let text = stderr(&output);
    let line = one_line(&text);
    assert!(
        line.starts_with("jaunt: ")
            && line.ends_with(
                ".s.PGSQL.5432 is too long for a socket on this system: set JAUNT_HOME to a shorter directory"
            ),
        "{line}"
    );
    assert!(!home.join("default/db/orders").exists());
}

#[test]
fn the_tcp_flag_takes_only_loopback_and_warns_that_every_local_user_may_connect() {
    let stand = Stand::database();
    for value in [
        "0.0.0.0:5432",
        "10.0.0.1",
        "localhost:5432",
        "[::]:5432",
        "127.0.0.2",
        "example.com",
    ] {
        let output = bounded(&stand.home, &["db", "proxy", "orders", "--tcp", value]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{value}: {}",
            stderr(&output)
        );
        assert!(stderr(&output).contains("127.0.0.1 or ::1"), "{value}");
    }
    let running = launch(
        base_command(&stand.home),
        &["db", "proxy", "orders", "--tcp"],
    );

    let line = running.line();

    let port: u16 = line
        .strip_prefix("psql \"host=127.0.0.1 port=")
        .and_then(|rest| rest.strip_suffix(" user=<db user> dbname=<db>\""))
        .unwrap_or_else(|| panic!("{line}"))
        .parse()
        .unwrap();
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.set_read_timeout(Some(DEADLINE)).unwrap();
    exchange(&mut client, true, b"startup");
    let reader = client.try_clone().unwrap();
    finish_exchange(reader, || client.shutdown(Shutdown::Write).unwrap());
    running.signal(Signal::TERM);
    let finished = running.finish();
    assert_eq!(finished.status.code(), Some(0), "{}", finished.stderr);
    let warning = format!(
        "jaunt: warning: every user of this computer can connect to 127.0.0.1:{port} and reach database `orders` as you"
    );
    assert!(
        finished.stderr.lines().any(|line| line == warning),
        "{}",
        finished.stderr
    );
    assert!(!stand.db_dir().exists());
    assert_eq!(stand.svc.log(|log| log.accepted), 1);
}

fn tcp_port(running: &Running) -> u16 {
    let line = running.line();
    let address: SocketAddr = line
        .strip_prefix("Listening on ")
        .unwrap_or_else(|| panic!("{line}"))
        .parse()
        .unwrap();
    assert_eq!(address.ip().to_string(), "127.0.0.1");
    address.port()
}

fn open_tcp(port: u16) -> TcpStream {
    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(DEADLINE)).unwrap();
    stream
}

#[test]
fn proxy_tcp_dials_once_per_local_connection_through_both_layers_on_loopback_only() {
    let stand = Stand::tcp(|_, _| {});
    let running = launch(base_command(&stand.home), &["proxy", "tcp", "grafana"]);
    let port = tcp_port(&running);

    let mut first = open_tcp(port);
    let mut second = open_tcp(port);
    exchange(&mut first, false, b"one");
    exchange(&mut second, false, b"two");
    for stream in [first, second] {
        let reader = stream.try_clone().unwrap();
        finish_exchange(reader, || stream.shutdown(Shutdown::Write).unwrap());
    }

    running.signal(Signal::TERM);
    let finished = running.finish();
    assert_eq!(finished.status.code(), Some(0), "{}", finished.stderr);
    for line in &finished.stdout {
        let address: SocketAddr = line.strip_prefix("Listening on ").unwrap().parse().unwrap();
        assert!(address.ip().is_loopback(), "{line}");
        assert_eq!(address.port(), port);
    }
    let sessions = stand.svc.log(|log| log.sessions.clone());
    assert_eq!(sessions.len(), 2);
    for session in sessions {
        assert_eq!(session.inner_sni, Some(format!("grafana.tcp.{GATE_NAME}")));
        assert!(session.client_ended);
    }
}

#[test]
fn at_most_64_local_connections_are_carried_and_the_rest_are_closed_with_a_throttled_notice() {
    let stand = Stand::tcp(|_, _| {});
    let running = launch(base_command(&stand.home), &["proxy", "tcp", "grafana"]);
    let port = tcp_port(&running);
    let mut carried: Vec<TcpStream> = (0..CAP).map(|_| open_tcp(port)).collect();
    for stream in &mut carried {
        exchange(stream, false, b"x");
    }
    let refusing_since = Instant::now();

    for _ in 0..2 {
        let mut extra = open_tcp(port);
        drop(extra.write_all(b"x"));
        let mut seen = Vec::new();
        drop(extra.read_to_end(&mut seen));
        assert!(seen.is_empty());
    }
    drop(carried.pop());
    stand
        .svc
        .wait_for("the closed connection to reach the agent", |log| {
            log.sessions
                .iter()
                .filter(|session| session.client_ended)
                .count()
                == 1
        });
    poll_until("a free slot", || {
        let mut stream = open_tcp(port);
        if stream.write_all(b"y").is_err() {
            return false;
        }
        let mut answer = [0_u8; 1];
        stream.read_exact(&mut answer).is_ok() && answer == *b"y"
    });
    let refusing_for = refusing_since.elapsed();

    running.signal(Signal::TERM);
    let finished = running.finish();
    assert_eq!(finished.status.code(), Some(0), "{}", finished.stderr);
    let notices = finished
        .stderr
        .lines()
        .filter(|line| line.starts_with(CAP_NOTICE))
        .count();
    let allowed = usize::try_from(refusing_for.as_secs() / 10).unwrap() + 1;
    assert!(
        (1..=allowed).contains(&notices),
        "{notices} notices in {refusing_for:?}: {}",
        finished.stderr
    );
    assert_eq!(stand.svc.log(|log| log.accepted), CAP + 1);
}

#[test]
fn a_refusal_by_the_gate_or_the_agent_is_one_line_naming_the_listing() {
    type Change = fn(&mut Setup, &Pki);
    let cases: Vec<(&str, Change)> = vec![
        ("the gate closes before the inner handshake", |setup, _| {
            setup.inner = None;
        }),
        ("the gate does not take the certificate", |setup, pki| {
            setup.outer = requiring_client(
                pki.internal.server_leaf(GATE_NAME),
                &TestCa::new("strangers"),
                false,
                &[GATE_ALPN_SVC],
            );
        }),
        ("the agent does not take the certificate", |setup, pki| {
            setup.inner = Some(requiring_client(
                pki.internal
                    .server_leaf(&format!("grafana.tcp.{GATE_NAME}")),
                &TestCa::new("strangers"),
                false,
                &[],
            ));
        }),
    ];
    for (case, change) in cases {
        let stand = Stand::tcp(change);
        let running = launch(base_command(&stand.home), &["proxy", "tcp", "grafana"]);
        let port = tcp_port(&running);

        let started = Instant::now();
        for _ in 0..2 {
            let mut stream = open_tcp(port);
            drop(stream.write_all(b"x"));
            let mut seen = Vec::new();
            drop(stream.read_to_end(&mut seen));
            assert!(seen.is_empty(), "{case}");
        }
        let took = started.elapsed();

        running.signal(Signal::TERM);
        let finished = running.finish();
        let refusals = finished
            .stderr
            .lines()
            .filter(|line| line.contains("refused the connection"))
            .collect::<Vec<_>>();
        let allowed = usize::try_from(took.as_secs() / 10).unwrap() + 1;
        assert!(
            (1..=allowed).contains(&refusals.len()),
            "{case}: {} lines in {took:?}: {}",
            refusals.len(),
            finished.stderr
        );
        assert!(
            refusals.iter().all(|line| line.starts_with(REFUSED_TCP)),
            "{case}: {}",
            finished.stderr
        );
    }
}

struct Tools {
    root: tempfile::TempDir,
}

impl Tools {
    fn new() -> Tools {
        let tools = Tools {
            root: tempfile::tempdir().unwrap(),
        };
        for dir in ["out", "bin", "rel"] {
            fs::create_dir(tools.root.path().join(dir)).unwrap();
        }
        write_script(
            &tools.root.path().join("rel"),
            "psql",
            &format!(": > '{}/decoy'\nexit 3\n", tools.out().display()),
        );
        tools
    }

    fn out(&self) -> PathBuf {
        self.root.path().join("out")
    }

    fn psql(&self, body: &str) {
        write_script(&self.root.path().join("bin"), "psql", body);
    }

    fn command(&self, home: &Path, path: &str) -> Command {
        let mut command = base_command(home);
        command.current_dir(self.root.path()).env("PATH", path);
        command
    }

    fn path(&self) -> String {
        format!(
            "rel::{}:/usr/bin:/bin",
            self.root.path().join("bin").display()
        )
    }
}

fn connect_dirs(db: &Path) -> Vec<String> {
    match fs::read_dir(db) {
        Ok(entries) => entries
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.starts_with(".connect-"))
            .collect(),
        Err(_) => Vec::new(),
    }
}

#[test]
fn db_connect_runs_psql_from_path_on_a_private_socket_passes_its_status_and_cleans_up() {
    let _serial = serial_section();
    let cases: Vec<(&[&str], &str, &[&str])> = vec![
        (
            &[
                "--user",
                "app",
                "--database",
                "orders main",
                "--",
                "-c",
                "select 1",
            ],
            " user=app dbname='orders main'",
            &["-c", "select 1"],
        ),
        (&[], "", &[]),
    ];
    for (extra, conninfo_tail, passed) in cases {
        let stand = Stand::database();
        let tools = Tools::new();
        let out = tools.out();
        tools.psql(&format!(
            "for arg in \"$@\"; do printf '%s\\n' \"$arg\"; done > '{out}/args'\n\
             env > '{out}/env'\n\
             for dir in '{db}'/.connect-*; do\n\
             if [ -S \"$dir/.s.PGSQL.5432\" ]; then printf '%s\\n' \"$dir\" > '{out}/socket'; fi\n\
             done\n\
             exit 7\n",
            out = out.display(),
            db = stand.db_dir().display(),
        ));
        let mut command = tools.command(&stand.home, &tools.path());
        command
            .env(ADMIN_TOKEN_ENV, "jat_secret_that_must_not_leak")
            .env("PGSERVICE", "elsewhere")
            .env("PGSERVICEFILE", "/tmp/elsewhere.conf")
            .env("PGHOSTADDR", "192.0.2.1");
        let mut args = vec!["db", "connect", "orders"];
        args.extend_from_slice(extra);
        command.args(&args);

        let output = run_bounded(command, b"", false);

        assert_eq!(output.status.code(), Some(7), "{}", stderr(&output));
        assert!(!out.join("decoy").exists());
        let socket_dir = fs::read_to_string(out.join("socket")).unwrap();
        let socket_dir = socket_dir.trim_end();
        let recorded = fs::read_to_string(out.join("args")).unwrap();
        let mut lines = recorded.lines();
        assert_eq!(
            lines.next().unwrap(),
            format!("host={socket_dir} hostaddr='' port=5432{conninfo_tail}")
        );
        assert_eq!(lines.collect::<Vec<_>>(), passed);
        let environment = fs::read_to_string(out.join("env")).unwrap();
        assert!(environment.lines().any(|line| line == "PGSSLMODE=disable"));
        for removed in [ADMIN_TOKEN_ENV, "PGSERVICE", "PGSERVICEFILE", "PGHOSTADDR"] {
            assert!(
                !environment
                    .lines()
                    .any(|line| line.starts_with(&format!("{removed}="))),
                "{removed}"
            );
        }
        assert!(!environment.contains("jat_secret_that_must_not_leak"));
        assert!(!environment.contains(API_TOKEN) && !recorded.contains(API_TOKEN));
        assert!(fs::symlink_metadata(socket_dir).is_err());
        assert!(connect_dirs(&stand.db_dir()).is_empty());
    }

    let stand = Stand::database();
    let tools = Tools::new();
    for empty in [&["--user", ""][..], &["--database", ""]] {
        let mut command = tools.command(&stand.home, &tools.path());
        command.args(["db", "connect", "orders"]).args(empty);
        let output = run_bounded(command, b"", false);
        assert_eq!(output.status.code(), Some(2), "{empty:?}");
        assert!(stderr(&output).contains("must not be empty"), "{empty:?}");
    }
    let mut command = tools.command(&stand.home, "rel:.:");
    command.args(["db", "connect", "orders"]);
    let output = run_bounded(command, b"", false);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        one_line(&stderr(&output)),
        "jaunt: psql was not found in the absolute directories of PATH: install the PostgreSQL client, or run `jaunt db proxy` and use another client"
    );
    assert!(!tools.out().join("decoy").exists());
    assert!(connect_dirs(&stand.db_dir()).is_empty());
}

#[test]
fn db_connect_passes_term_and_hup_to_psql_survives_int_and_cleans_up() {
    let _serial = serial_section();
    let cases: [(&[Signal], &str, i32); 3] = [
        (&[Signal::TERM], "TERM\n", 143),
        (&[Signal::HUP], "HUP\n", 129),
        (&[Signal::INT, Signal::TERM], "TERM\n", 143),
    ];
    for (signals, recorded, code) in cases {
        let stand = Stand::database();
        let tools = Tools::new();
        let out = tools.out();
        tools.psql(&format!(
            "out='{out}'\n\
             trap 'echo TERM >> \"$out/signals\"; kill $idle 2>/dev/null; exit 143' TERM\n\
             trap 'echo HUP >> \"$out/signals\"; kill $idle 2>/dev/null; exit 129' HUP\n\
             trap 'echo INT >> \"$out/signals\"' INT\n\
             sleep 60 </dev/null >/dev/null 2>&1 &\n\
             idle=$!\n\
             : > \"$out/ready\"\n\
             while :; do wait \"$idle\" && break; done\n\
             exit 0\n",
            out = out.display(),
        ));
        let running = launch(
            tools.command(&stand.home, &tools.path()),
            &["db", "connect", "orders"],
        );
        poll_until("psql to start", || out.join("ready").exists());
        let run_dirs = connect_dirs(&stand.db_dir());
        assert_eq!(run_dirs.len(), 1);

        for signal in signals {
            running.signal(*signal);
        }
        let finished = running.finish();

        assert_eq!(
            finished.status.code(),
            Some(code),
            "{signals:?}: {}",
            finished.stderr
        );
        assert_eq!(
            fs::read_to_string(out.join("signals")).unwrap(),
            recorded,
            "{signals:?}"
        );
        assert!(connect_dirs(&stand.db_dir()).is_empty(), "{signals:?}");
    }
}

fn run_dir_with(db: &Path, name: &str, files: &[&str], lock_age: Option<Duration>) -> PathBuf {
    let dir = db.join(name);
    private_dir(&dir, 0o700);
    for file in files {
        match *file {
            ".s.PGSQL.5432" => drop(UnixListener::bind(dir.join(file)).unwrap()),
            _ => fs::write(dir.join(file), b"").unwrap(),
        }
    }
    if let Some(age) = lock_age {
        fs::File::options()
            .write(true)
            .open(dir.join(".lock.new"))
            .unwrap()
            .set_modified(SystemTime::now() - age)
            .unwrap();
    }
    dir
}

#[test]
fn db_connect_removes_run_directories_nobody_holds_and_leaves_the_rest() {
    let _serial = serial_section();
    let stand = Stand::database();
    let db = stand.db_dir();
    private_dir(&db, 0o700);
    let old = Some(Duration::from_secs(600));
    let stale = run_dir_with(
        &db,
        ".connect-0123456789abcdef",
        &[".lock", ".s.PGSQL.5432"],
        None,
    );
    let unfinished = run_dir_with(&db, ".connect-1111111111111111", &[".lock.new"], old);
    let young = run_dir_with(&db, ".connect-2222222222222222", &[".lock.new"], None);
    let with_files = run_dir_with(&db, ".connect-4444444444444444", &[".lock", "keep"], None);
    let unfinished_with_files = run_dir_with(
        &db,
        ".connect-5555555555555555",
        &[".lock.new", "keep"],
        old,
    );
    let live = run_dir_with(&db, ".connect-fedcba9876543210", &[], None);
    let held = hold_lock(&live);
    let unlike = run_dir_with(&db, ".connect-old", &[".lock"], None);
    let elsewhere = run_dir_with(
        &stand.home,
        "elsewhere",
        &[".lock", ".s.PGSQL.5432", "keep"],
        None,
    );
    symlink(&elsewhere, db.join(".connect-3333333333333333")).unwrap();
    let tools = Tools::new();
    tools.psql("exit 0\n");

    let output = run_bounded(
        {
            let mut command = tools.command(&stand.home, &tools.path());
            command.args(["db", "connect", "orders"]);
            command
        },
        b"",
        false,
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(!stale.exists());
    assert!(!unfinished.exists());
    assert!(young.join(".lock.new").exists());
    assert!(with_files.join(".lock").exists() && with_files.join("keep").exists());
    assert!(unfinished_with_files.join(".lock.new").exists());
    assert!(live.join(".lock").exists());
    assert!(unlike.join(".lock").exists());
    assert_eq!(
        crate::support::names(&elsewhere),
        [".lock", ".s.PGSQL.5432", "keep"]
    );
    let mut left = connect_dirs(&db);
    left.sort();
    assert_eq!(
        left,
        [
            ".connect-2222222222222222",
            ".connect-3333333333333333",
            ".connect-4444444444444444",
            ".connect-5555555555555555",
            ".connect-fedcba9876543210",
            ".connect-old",
        ]
    );
    let text = stderr(&output);
    let warnings: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("warning"))
        .collect();
    assert_eq!(warnings.len(), 1, "{text}");
    assert!(
        warnings[0].starts_with("jaunt: warning: 2 stale run directories under ")
            && warnings[0].contains("holds files that jaunt did not make"),
        "{text}"
    );
    drop(held);
}

#[test]
fn a_killed_db_connect_leaves_no_lock_behind_and_the_next_run_removes_its_directory() {
    let _serial = serial_section();
    let stand = Stand::database();
    let db = stand.db_dir();
    let tools = Tools::new();
    let out = tools.out();
    tools.psql(&format!(
        "exec </dev/null >/dev/null 2>&1\n\
         sleep 60 &\n\
         echo \"$$ $!\" > '{out}/pids'\n\
         : > '{out}/ready'\n\
         wait\n",
        out = out.display(),
    ));
    let running = launch(
        tools.command(&stand.home, &tools.path()),
        &["db", "connect", "orders"],
    );
    poll_until("psql to start", || out.join("ready").exists());
    let left = connect_dirs(&db);
    assert_eq!(left.len(), 1);
    let run = db.join(&left[0]);

    running.signal(Signal::KILL);
    let finished = running.finish();

    assert_eq!(finished.status.code(), None);
    assert!(run.join(".lock").exists());
    let probe = ProfileLock::acquire(&run, &run.join(".lock"), Instant::now(), &mut || {});
    assert!(
        probe.is_ok(),
        "the killed run's lock is still held: {probe:?}"
    );
    drop(probe);
    let next = Tools::new();
    next.psql("exit 0\n");
    let mut command = next.command(&stand.home, &next.path());
    command.args(["db", "connect", "orders"]);
    let output = run_bounded(command, b"", false);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(!run.exists());
    assert!(connect_dirs(&db).is_empty());
    let pids = fs::read_to_string(out.join("pids")).unwrap();
    for pid in pids.split_whitespace() {
        let pid = Pid::from_raw(pid.parse().unwrap()).unwrap();
        let _ = kill_process(pid, Signal::KILL);
    }
}

#[test]
fn a_start_that_waits_for_the_profile_lock_says_so_once_and_then_goes_on() {
    let stand = Stand::database();
    let held = ProfileLock::acquire(
        &stand.home,
        &stand.home.join(".default.lock"),
        Instant::now() + DEADLINE,
        &mut || {},
    )
    .unwrap();
    let mut running = launch(base_command(&stand.home), &["db", "proxy", "orders"]);

    let notice = running.error_line();

    assert_eq!(notice, WAIT_NOTICE);
    drop(held);
    assert!(running.line().starts_with("psql "));
    running.signal(Signal::TERM);
    let finished = running.finish();
    assert_eq!(finished.status.code(), Some(0), "{}", finished.stderr);
    assert_eq!(
        finished
            .stderr
            .lines()
            .filter(|line| *line == WAIT_NOTICE)
            .count(),
        1,
        "{}",
        finished.stderr
    );
}

#[test]
fn proxy_tcp_also_listens_on_the_ipv6_loopback_when_it_can() {
    if std::net::TcpListener::bind("[::1]:0").is_err() {
        eprintln!("skipped: ::1 cannot be bound on this machine");
        return;
    }
    let stand = Stand::tcp(|_, _| {});
    let running = launch(base_command(&stand.home), &["proxy", "tcp", "grafana"]);
    let port = tcp_port(&running);

    let second = running.line();

    assert_eq!(second, format!("Listening on [::1]:{port}"));
    let mut stream = TcpStream::connect(("::1", port)).unwrap();
    stream.set_read_timeout(Some(DEADLINE)).unwrap();
    exchange(&mut stream, false, b"six");
    let reader = stream.try_clone().unwrap();
    finish_exchange(reader, || stream.shutdown(Shutdown::Write).unwrap());
    running.signal(Signal::TERM);
    let finished = running.finish();
    assert_eq!(finished.status.code(), Some(0), "{}", finished.stderr);
    assert_eq!(stand.svc.log(|log| log.accepted), 1);
}

#[test]
fn a_service_name_must_be_one_dns_label_before_anything_happens() {
    let stand = Stand::database();
    let too_long = "a".repeat(64);
    let cases: Vec<Vec<&str>> = vec![
        vec!["db", "proxy", "Orders"],
        vec!["db", "proxy", "../orders"],
        vec!["db", "proxy", "a_b"],
        vec!["db", "proxy", too_long.as_str()],
        vec!["db", "connect", "a.b"],
        vec!["db", "connect", "orders/x"],
        vec!["proxy", "tcp", "gra fana"],
        vec!["proxy", "tcp", ""],
    ];
    for args in cases {
        let output = bounded(&stand.home, &args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(stderr(&output).contains("one DNS label"), "{args:?}");
    }
    assert!(!stand.db_dir().exists());
    assert_eq!(stand.svc.log(|log| log.accepted), 0);
    assert_eq!(stand.api.seen(|seen| seen.x509_requests.len()), 0);
}

#[test]
fn an_older_server_or_gate_is_named_in_one_line() {
    let pki = Pki::new();
    let root = short_tempdir();
    let home = root.path().join("h");
    let ssh_end = i64::try_from(now_secs()).unwrap() + 3600;
    let api = FakeServer::start(Behavior {
        services: Some(vec![
            ServiceSummary {
                kind: ServiceKind::Postgres,
                name: "orders".to_owned(),
                labels: Default::default(),
                connected: true,
            },
            ServiceSummary {
                kind: ServiceKind::Tcp,
                name: "grafana".to_owned(),
                labels: Default::default(),
                connected: true,
            },
        ]),
        ..Behavior::default()
    });
    sign_in(&home, &api, ssh_end, None);
    let not_offered = "jaunt: profile `default` holds no TLS settings of the gate, so databases and TCP services cannot be reached: run `jaunt login --profile default`; if this message stays, the server does not offer them";
    for args in [
        &["db", "proxy", "orders"][..],
        &["db", "connect", "orders"],
        &["proxy", "tcp", "grafana"],
    ] {
        let output = bounded(&home, args);
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert_eq!(one_line(&stderr(&output)), not_offered, "{args:?}");
    }
    let mut only_ssh = svc_services_json(1, &pki);
    json_alpn(&mut only_ssh, &[GATE_ALPN_SSH]);
    fs::write(home.join("default/services.json"), only_ssh.to_string()).unwrap();
    let output = bounded(&home, &["db", "proxy", "orders"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        one_line(&stderr(&output)),
        "jaunt: the gate of profile `default` does not accept database and TCP connections (jaunt-svc/1): if the server offers them now, run `jaunt login --profile default`"
    );

    let listed = jaunt(&home, &["db", "ls"]);
    let same = jaunt(&home, &["ls", "--kind", "db"]);
    assert_eq!(listed.status.code(), Some(0), "{}", stderr(&listed));
    assert_eq!(stdout(&listed), stdout(&same));
    assert_eq!(
        stdout(&listed),
        "KIND  NAME    LABELS  CONNECTED\ndb    orders  -       yes\n"
    );
    let json = jaunt(&home, &["db", "ls", "--format", "json"]);
    assert_eq!(
        stdout(&json),
        stdout(&jaunt(&home, &["ls", "--kind", "db", "--format", "json"]))
    );

    let old_root = tempfile::tempdir().unwrap();
    let old_home = old_root.path().join("state");
    let old = FakeServer::start(Behavior::default());
    sign_in(&old_home, &old, ssh_end, None);
    let listed = jaunt(&old_home, &["db", "ls"]);
    assert_eq!(listed.status.code(), Some(1));
    assert_eq!(
        stderr(&listed),
        "jaunt: this server does not list Kubernetes clusters, databases or TCP services\n"
    );
}
