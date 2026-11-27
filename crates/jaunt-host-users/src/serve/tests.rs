use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use super::{HELPER_DEADLINE, Ledger, Node, Notes, System, Ticket, handle};
use crate::config::{ConfigError, HostUsersConfig, Settings};
use crate::directory::DirectoryUse;
use crate::journal::Severity;
use crate::names::Name;
use crate::protocol::{FailedStage, Reference, Response, SessionLabel};
use crate::rules::Reason;
use crate::state::{AccountState, State};
use crate::store::{LOCK_WAIT, StoreError};
use crate::sys::{LOOKUP_BUDGET, LOOKUP_TIMEOUT, Tool, ToolError};
use crate::system::{
    FileFacts, FileKind, Files, FilesError, GroupEntry, LookupError, PasswdEntry, Runner,
    RunnerError, ToolExit, Users,
};
use crate::testing::{NOW, candidate, enabled_config, name};
use crate::useradd::{USERADD_TIMEOUT, USERDEL_TIMEOUT, useradd_args};

const USERADD: &str = "/usr/sbin/useradd";
const USERDEL: &str = "/usr/sbin/userdel";

fn config() -> HostUsersConfig {
    enabled_config("  groups: [devs]\n  uid_min: 30000\n  uid_max: 30999\n")
}

fn failed(stage: FailedStage, exit_code: Option<i32>) -> Response {
    Response::Failed { stage, exit_code }
}

#[derive(Default)]
struct World {
    accounts: BTreeMap<Name, PasswdEntry>,
    groups: BTreeMap<Name, GroupEntry>,
    paths: BTreeMap<PathBuf, FileFacts>,
    chmod_fails: bool,
}

#[derive(Clone, Default)]
struct Host(Rc<RefCell<World>>);

impl Host {
    fn new() -> Self {
        let host = Self::default();
        let root = |kind| FileFacts {
            kind,
            uid: 0,
            mode: 0o755,
        };
        for directory in ["/", "/home", "/etc", "/etc/skel"] {
            host.world()
                .paths
                .insert(directory.into(), root(FileKind::Directory));
        }
        host.world()
            .paths
            .insert("/bin/bash".into(), root(FileKind::Regular));
        host.add_group("devs", 500);
        host
    }

    fn world(&self) -> std::cell::RefMut<'_, World> {
        self.0.borrow_mut()
    }

    fn add_group(&self, group: &str, gid: u32) {
        self.world().groups.insert(
            name(group),
            GroupEntry {
                name: name(group),
                gid,
            },
        );
    }

    fn add_account(&self, login: &str, with_home: bool) {
        let uid = 30_000 + u32::try_from(self.world().accounts.len()).unwrap();
        let home = format!("/home/{login}");
        self.world().accounts.insert(
            name(login),
            PasswdEntry {
                name: name(login),
                uid,
                gid: uid,
                home: home.clone(),
                shell: "/bin/bash".to_owned(),
            },
        );
        self.add_group(login, uid);
        if with_home {
            self.world().paths.insert(
                home.into(),
                FileFacts {
                    kind: FileKind::Directory,
                    uid,
                    mode: 0o700,
                },
            );
        }
    }

    fn remove_account(&self, login: &str) {
        let mut world = self.world();
        world.accounts.remove(&name(login));
        world.groups.remove(&name(login));
        world.paths.remove(Path::new(&format!("/home/{login}")));
    }

    fn has_account(&self, login: &str) -> bool {
        self.0.borrow().accounts.contains_key(&name(login))
    }

    fn mode_of(&self, path: &str) -> Option<u32> {
        self.0
            .borrow()
            .paths
            .get(Path::new(path))
            .map(|facts| facts.mode)
    }
}

impl Users for Host {
    fn passwd(&self, login: &Name) -> Result<Option<PasswdEntry>, LookupError> {
        Ok(self.0.borrow().accounts.get(login).cloned())
    }

    fn passwd_many(&self, logins: &[Name]) -> Result<Vec<Option<PasswdEntry>>, LookupError> {
        logins.iter().map(|login| self.passwd(login)).collect()
    }

    fn group(&self, group: &Name) -> Result<Option<GroupEntry>, LookupError> {
        Ok(self.0.borrow().groups.get(group).cloned())
    }
}

impl Files for Host {
    fn lstat(&self, path: &Path) -> Result<Option<FileFacts>, FilesError> {
        Ok(self.0.borrow().paths.get(path).copied())
    }

    fn chmod_directory_nofollow(
        &self,
        path: &Path,
        owner: u32,
        mode: u32,
    ) -> Result<(), FilesError> {
        let mut world = self.world();
        let refuse = world.chmod_fails;
        match world.paths.get_mut(path) {
            Some(facts) if !refuse && facts.kind == FileKind::Directory && facts.uid == owner => {
                facts.mode = mode;
                Ok(())
            }
            _ => Err(FilesError {
                op: "fchmod",
                path: path.to_path_buf(),
                source: io::Error::from(io::ErrorKind::PermissionDenied),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Useradd {
    Creates(Option<i32>),
    CreatesWithoutHome,
    TimesOutAfterCreating,
    Leaves(Option<i32>),
    CannotStart,
    BreaksAfterCreating,
}

struct Tools {
    host: Host,
    useradd: Useradd,
    userdel_removes: bool,
    calls: Vec<(PathBuf, Vec<String>)>,
}

impl Runner for Tools {
    fn run(
        &mut self,
        program: &Path,
        args: &[String],
        _timeout: Duration,
    ) -> Result<ToolExit, RunnerError> {
        self.calls.push((program.to_path_buf(), args.to_vec()));
        let login = args.last().cloned().unwrap_or_default();
        let exit = |code, timed_out| ToolExit {
            code,
            timed_out,
            stderr: Vec::new(),
        };
        if program == Path::new(USERDEL) {
            if self.userdel_removes {
                self.host.remove_account(&login);
            }
            return Ok(exit(Some(0), false));
        }
        let broken = |program: &Path| RunnerError {
            program: program.to_path_buf(),
            source: io::Error::from(io::ErrorKind::BrokenPipe),
        };
        Ok(match self.useradd {
            Useradd::Creates(code) => {
                self.host.add_account(&login, true);
                exit(code, false)
            }
            Useradd::CreatesWithoutHome => {
                self.host.add_account(&login, false);
                exit(Some(0), false)
            }
            Useradd::TimesOutAfterCreating => {
                self.host.add_account(&login, true);
                exit(None, true)
            }
            Useradd::Leaves(code) => exit(code, false),
            Useradd::CannotStart => return Err(broken(program)),
            Useradd::BreaksAfterCreating => {
                self.host.add_account(&login, true);
                return Err(broken(program));
            }
        })
    }
}

#[derive(Default)]
struct Disk {
    state: RefCell<State>,
    saves: Cell<usize>,
    failing_save: Option<usize>,
}

impl Ledger for Disk {
    fn load(&self) -> Result<State, StoreError> {
        Ok(self.state.borrow().clone())
    }

    fn save(&self, state: &State) -> Result<(), StoreError> {
        let count = self.saves.get() + 1;
        self.saves.set(count);
        if self.failing_save == Some(count) {
            return Err(StoreError::Io {
                op: "write",
                path: PathBuf::from("/var/lib/jaunt-host-users/accounts.json"),
                source: io::Error::from(io::ErrorKind::StorageFull),
            });
        }
        *self.state.borrow_mut() = state.clone();
        Ok(())
    }
}

struct FakeNode {
    config: Option<HostUsersConfig>,
    broken: bool,
    missing_useradd: bool,
}

impl Node for FakeNode {
    fn settings(&self) -> Result<Settings, ConfigError> {
        if self.broken {
            return Err(ConfigError::TooLarge);
        }
        Ok(self
            .config
            .clone()
            .map_or(Settings::Disabled, Settings::Enabled))
    }

    fn shells(&self) -> Result<String, FilesError> {
        Ok("/bin/sh\n/bin/bash\n".to_owned())
    }

    fn directory(&self) -> Result<DirectoryUse, FilesError> {
        Ok(DirectoryUse::Local)
    }

    fn tool(&self, tool: &Tool) -> Result<PathBuf, ToolError> {
        if self.missing_useradd && tool.name == "useradd" {
            return Err(ToolError::Missing { name: tool.name });
        }
        Ok(PathBuf::from(format!("/usr/sbin/{}", tool.name)))
    }
}

struct Harness {
    host: Host,
    disk: Disk,
    node: FakeNode,
    tools: Tools,
}

impl Harness {
    fn new(useradd: Useradd) -> Self {
        let host = Host::new();
        Self {
            host: host.clone(),
            disk: Disk::default(),
            node: FakeNode {
                config: Some(config()),
                broken: false,
                missing_useradd: false,
            },
            tools: Tools {
                host,
                useradd,
                userdel_removes: true,
                calls: Vec::new(),
            },
        }
    }

    fn ask(&mut self, login: &str) -> (Response, Notes) {
        let login = name(login);
        let reference = Reference::parse("H-0000ABCD").unwrap();
        let session = SessionLabel::parse("s-1").unwrap();
        let ticket = Ticket {
            login: &login,
            reference: &reference,
            session: &session,
        };
        let (users, files) = (self.host.clone(), self.host.clone());
        let mut notes = Notes::default();
        let mut system = System {
            users: &users,
            files: &files,
            runner: &mut self.tools,
            node: &self.node,
            now: NOW,
        };
        let response = handle(&ticket, &self.disk, &mut system, &mut notes);
        (response, notes)
    }

    fn record(&self, login: &str) -> Option<(AccountState, Option<u32>)> {
        self.disk
            .state
            .borrow()
            .record(&name(login))
            .map(|record| (record.state(), record.uid()))
    }
}

#[test]
fn a_new_login_is_created_verified_bound_activated_and_given_the_home_mode() {
    let mut harness = Harness::new(Useradd::Creates(Some(0)));
    let (response, notes) = harness.ask("alice");
    assert_eq!(
        response,
        Response::Created {
            uid: 30_000,
            home: "/home/alice".to_owned(),
            groups: vec![name("alice"), name("devs")],
        }
    );
    assert_eq!(notes.severity, Severity::Info);
    let config = config();
    assert_eq!(
        harness.tools.calls,
        [(
            PathBuf::from(USERADD),
            useradd_args(&config, &candidate(&config, "alice"))
        )]
    );
    assert_eq!(harness.host.mode_of("/home/alice"), Some(0o750));
    assert_eq!(
        harness.record("alice"),
        Some((AccountState::Active, Some(30_000)))
    );

    let (again, _) = harness.ask("alice");
    assert_eq!(again, Response::Exists);
    assert_eq!(harness.tools.calls.len(), 1);
}

#[test]
fn disabled_misconfigured_refused_and_toolless_requests_run_nothing_and_record_nothing() {
    type Prepare = fn(&mut Harness);
    let cases: [(Prepare, Response, Severity); 4] = [
        (
            |harness| harness.node.config = None,
            Response::Disabled,
            Severity::Info,
        ),
        (
            |harness| harness.node.broken = true,
            Response::Disabled,
            Severity::Warning,
        ),
        (
            |harness| harness.host.add_group("alice", 31_000),
            Response::Refused {
                reason: Reason::GroupCollision,
            },
            Severity::Info,
        ),
        (
            |harness| harness.node.missing_useradd = true,
            failed(FailedStage::Tool, None),
            Severity::Warning,
        ),
    ];
    for (index, (prepare, expected, severity)) in cases.into_iter().enumerate() {
        let mut harness = Harness::new(Useradd::Creates(Some(0)));
        prepare(&mut harness);
        let (response, notes) = harness.ask("alice");
        assert_eq!(response, expected, "case {index}");
        assert_eq!(notes.severity, severity, "case {index}");
        assert!(harness.tools.calls.is_empty(), "case {index}");
        assert_eq!(
            *harness.disk.state.borrow(),
            State::default(),
            "case {index}"
        );
    }
}

#[test]
fn useradd_never_runs_when_the_pending_record_cannot_be_saved() {
    let mut harness = Harness::new(Useradd::Creates(Some(0)));
    harness.disk.failing_save = Some(1);
    let (response, notes) = harness.ask("alice");
    assert_eq!(response, failed(FailedStage::State, None));
    assert_eq!(notes.severity, Severity::Warning);
    assert!(harness.tools.calls.is_empty());
    assert!(!harness.host.has_account("alice"));
}

#[test]
fn a_failed_useradd_is_rolled_back_abandoned_or_kept_exactly_as_the_library_permits() {
    use AccountState::Unconfirmed;
    use FailedStage::{Partial, Useradd as Stage};
    use Severity::{Error, Info, Warning};
    use Useradd::{BreaksAfterCreating, CannotStart, Creates, Leaves, TimesOutAfterCreating};
    let refused = Response::Refused {
        reason: Reason::UidRange,
    };
    for (index, (useradd, userdel_removes, response, record, left, removal_ran, severity)) in [
        (
            Creates(Some(12)),
            true,
            failed(Stage, Some(12)),
            None,
            false,
            true,
            Warning,
        ),
        (
            Creates(Some(10)),
            true,
            failed(Stage, Some(10)),
            None,
            false,
            true,
            Warning,
        ),
        (
            TimesOutAfterCreating,
            true,
            failed(Stage, None),
            None,
            false,
            true,
            Warning,
        ),
        (
            Creates(Some(12)),
            false,
            failed(Partial, Some(12)),
            Some(Unconfirmed),
            true,
            true,
            Error,
        ),
        (
            Creates(Some(9)),
            true,
            failed(Stage, Some(9)),
            None,
            true,
            false,
            Warning,
        ),
        (
            Creates(Some(1)),
            true,
            failed(Partial, Some(1)),
            Some(Unconfirmed),
            true,
            false,
            Error,
        ),
        (
            Leaves(Some(4)),
            true,
            refused.clone(),
            None,
            false,
            false,
            Info,
        ),
        (
            Leaves(Some(1)),
            true,
            failed(Stage, Some(1)),
            None,
            false,
            false,
            Warning,
        ),
        (
            CannotStart,
            true,
            failed(FailedStage::Tool, None),
            None,
            false,
            false,
            Warning,
        ),
        (
            BreaksAfterCreating,
            true,
            failed(Partial, None),
            Some(Unconfirmed),
            true,
            false,
            Error,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut harness = Harness::new(useradd);
        harness.tools.userdel_removes = userdel_removes;
        let (got, notes) = harness.ask("alice");
        assert_eq!(got, response, "case {index}");
        assert_eq!(
            harness.record("alice").map(|(state, _)| state),
            record,
            "case {index}"
        );
        assert_eq!(harness.host.has_account("alice"), left, "case {index}");
        assert_eq!(notes.severity, severity, "case {index}");
        assert_eq!(
            harness.disk.state.borrow().attempts().count(),
            1,
            "case {index}"
        );
        let removal: Vec<_> = harness
            .tools
            .calls
            .iter()
            .filter(|(program, _)| program == Path::new(USERDEL))
            .map(|(_, args)| args.clone())
            .collect();
        if removal_ran {
            assert_eq!(removal, [["--remove", "--", "alice"]], "case {index}");
            assert_eq!(
                notes.removal.map(|removal| removal.removed),
                Some(userdel_removes),
                "case {index}"
            );
        } else {
            assert!(removal.is_empty(), "case {index}");
        }
    }
}

#[test]
fn an_account_that_does_not_match_the_request_is_kept_unconfirmed_and_never_removed() {
    let mut harness = Harness::new(Useradd::CreatesWithoutHome);
    let (response, notes) = harness.ask("alice");
    assert_eq!(response, failed(FailedStage::Verify, None));
    assert_eq!(notes.severity, Severity::Error);
    assert_eq!(
        harness.record("alice"),
        Some((AccountState::Unconfirmed, None))
    );
    assert_eq!(harness.tools.calls.len(), 1);
    assert!(harness.host.has_account("alice"));
}

#[test]
fn a_home_mode_that_could_not_be_set_is_repaired_by_the_next_request() {
    let mut harness = Harness::new(Useradd::Creates(Some(0)));
    harness.host.world().chmod_fails = true;
    let (response, notes) = harness.ask("alice");
    assert_eq!(response, failed(FailedStage::Partial, None));
    assert_eq!(notes.severity, Severity::Error);
    assert_eq!(
        harness.record("alice"),
        Some((AccountState::Pending, Some(30_000)))
    );
    assert_eq!(harness.host.mode_of("/home/alice"), Some(0o700));

    harness.host.world().chmod_fails = false;
    let (response, notes) = harness.ask("bob");
    assert!(
        matches!(response, Response::Created { uid: 30_001, .. }),
        "{response:?}"
    );
    assert_eq!(notes.settled.unconfirmed, [name("alice")]);
    assert_eq!(notes.repaired, [name("alice")]);
    assert_eq!(notes.severity, Severity::Warning);
    assert_eq!(harness.host.mode_of("/home/alice"), Some(0o750));
    assert_eq!(
        harness.record("alice"),
        Some((AccountState::Unconfirmed, Some(30_000)))
    );
}

#[test]
fn the_worst_case_of_one_request_fits_the_time_the_agent_waits_for_the_helper() {
    let worst: Duration = [LOCK_WAIT, USERADD_TIMEOUT, USERDEL_TIMEOUT, LOOKUP_BUDGET]
        .iter()
        .sum();
    assert_eq!(HELPER_DEADLINE, Duration::from_secs(10));
    assert!(worst <= HELPER_DEADLINE, "{worst:?}");
    assert!(LOOKUP_TIMEOUT <= LOOKUP_BUDGET);
}
