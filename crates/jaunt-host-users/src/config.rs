use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

use crate::names::{Name, NameRules, PRIVILEGED_GROUPS};
use crate::paths::is_clean_absolute_path;
use crate::system::{FileFacts, FileKind, Files, FilesError, LookupError, Users};
use crate::useradd::SKEL_DIR;

pub const MAX_CONFIG_BYTES: usize = 64 * 1024;
pub const MIN_UID: u32 = 1000;
pub const MAX_UID: u32 = 59_999;
pub const MAX_USERS_LIMIT: u32 = 1000;
pub const MAX_GROUPS: usize = 32;
pub const MAX_HOME_BYTES: usize = 128;
pub const MAX_LOGIN_BYTES: usize = 32;

const MAX_SHELL_BYTES: usize = 128;
const MAX_HOME_BASE_BYTES: usize = MAX_HOME_BYTES - 1 - MAX_LOGIN_BYTES;
const SYSTEM_DIRECTORIES: [&str; 13] = [
    "/", "/etc", "/usr", "/var", "/bin", "/sbin", "/lib", "/boot", "/dev", "/proc", "/sys", "/run",
    "/root",
];
const DEFAULT_SHELL: &str = "/bin/bash";
const DEFAULT_HOME_BASE: &str = "/home";
const DEFAULT_HOME_MODE: &str = "0750";
const DEFAULT_UID_MIN: u32 = 30_000;
const DEFAULT_UID_MAX: u32 = 30_999;
const DEFAULT_MAX_USERS: u32 = 100;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostUsersSection {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub privileged_groups: Vec<String>,
    #[serde(default = "default_shell")]
    pub shell: String,
    #[serde(default = "default_home_base")]
    pub home_base: String,
    #[serde(default = "default_home_mode")]
    pub home_mode: String,
    #[serde(default = "default_uid_min")]
    pub uid_min: u32,
    #[serde(default = "default_uid_max")]
    pub uid_max: u32,
    #[serde(default = "default_max_users")]
    pub max_users: u32,
    #[serde(default)]
    pub names: NamesSection,
    #[serde(default)]
    pub allow_with_directory: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamesSection {
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub deny_prefixes: Vec<String>,
    #[serde(default)]
    pub allow_prefixes: Vec<String>,
}

impl Default for HostUsersSection {
    fn default() -> Self {
        Self {
            enabled: false,
            groups: Vec::new(),
            privileged_groups: Vec::new(),
            shell: default_shell(),
            home_base: default_home_base(),
            home_mode: default_home_mode(),
            uid_min: DEFAULT_UID_MIN,
            uid_max: DEFAULT_UID_MAX,
            max_users: DEFAULT_MAX_USERS,
            names: NamesSection::default(),
            allow_with_directory: false,
        }
    }
}

fn default_shell() -> String {
    DEFAULT_SHELL.to_owned()
}

fn default_home_base() -> String {
    DEFAULT_HOME_BASE.to_owned()
}

fn default_home_mode() -> String {
    DEFAULT_HOME_MODE.to_owned()
}

fn default_uid_min() -> u32 {
    DEFAULT_UID_MIN
}

fn default_uid_max() -> u32 {
    DEFAULT_UID_MAX
}

fn default_max_users() -> u32 {
    DEFAULT_MAX_USERS
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeMode {
    Owner,
    OwnerAndGroup,
    Everyone,
}

impl HomeMode {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "0700" => Some(Self::Owner),
            "0750" => Some(Self::OwnerAndGroup),
            "0755" => Some(Self::Everyone),
            _ => None,
        }
    }

    pub fn bits(self) -> u32 {
        match self {
            Self::Owner => 0o700,
            Self::OwnerAndGroup => 0o750,
            Self::Everyone => 0o755,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostUsersConfig {
    groups: Vec<Name>,
    privileged_groups: Vec<Name>,
    shell: String,
    home_base: String,
    home_mode: HomeMode,
    uid_min: u32,
    uid_max: u32,
    max_users: u32,
    names: NameRules,
    allow_with_directory: bool,
}

impl HostUsersConfig {
    pub fn groups(&self) -> &[Name] {
        &self.groups
    }

    pub fn privileged_groups(&self) -> &[Name] {
        &self.privileged_groups
    }

    pub fn supplementary_groups(&self) -> impl Iterator<Item = &Name> {
        self.groups.iter().chain(self.privileged_groups.iter())
    }

    pub fn shell(&self) -> &str {
        &self.shell
    }

    pub fn home_base(&self) -> &str {
        &self.home_base
    }

    pub fn home_mode(&self) -> HomeMode {
        self.home_mode
    }

    pub fn uid_min(&self) -> u32 {
        self.uid_min
    }

    pub fn uid_max(&self) -> u32 {
        self.uid_max
    }

    pub fn max_users(&self) -> u32 {
        self.max_users
    }

    pub fn names(&self) -> &NameRules {
        &self.names
    }

    pub fn allow_with_directory(&self) -> bool {
        self.allow_with_directory
    }

    pub fn home_of(&self, login: &Name) -> String {
        format!("{}/{}", self.home_base, login)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settings {
    Disabled,
    Enabled(HostUsersConfig),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntaxLocation {
    pub line: Option<u64>,
    pub column: Option<u64>,
}

impl fmt::Display for SyntaxLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.line, self.column) {
            (Some(line), Some(column)) => write!(f, "line {line}, column {column}"),
            (Some(line), None) => write!(f, "line {line}"),
            _ => f.write_str("unknown position"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrustProblem {
    #[error("it is a symbolic link")]
    Symlink,
    #[error("it has the wrong file type")]
    WrongKind,
    #[error("it is not owned by root")]
    NotOwnedByRoot,
    #[error("group or others may write to it")]
    Writable,
    #[error("others may not execute it")]
    NotExecutable,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("the agent configuration is larger than {MAX_CONFIG_BYTES} bytes")]
    TooLarge,
    #[error(
        "the agent configuration is not valid YAML or host_users does not match the schema ({at})"
    )]
    Syntax { at: SyntaxLocation },
    #[error("host_users.{field}[{index}] is not a portable name")]
    Name { field: &'static str, index: usize },
    #[error(
        "host_users.groups[{index}] is a privileged group; only host_users.privileged_groups may list it"
    )]
    PrivilegedGroup { index: usize },
    #[error("host_users lists the same group more than once")]
    DuplicateGroup,
    #[error("host_users lists more than {MAX_GROUPS} groups")]
    TooManyGroups,
    #[error("host_users.shell must be a plain absolute path of at most {MAX_SHELL_BYTES} bytes")]
    Shell,
    #[error(
        "host_users.home_base must be a plain absolute path of at most {MAX_HOME_BASE_BYTES} bytes"
    )]
    HomeBase,
    #[error("host_users.home_base must not be a system directory such as /etc or /usr")]
    HomeBaseSystem,
    #[error("host_users.home_mode must be \"0700\", \"0750\" or \"0755\"")]
    HomeMode,
    #[error("host_users.uid_min must be at least {MIN_UID}")]
    UidMin,
    #[error("host_users.uid_max must be at most {MAX_UID}")]
    UidMax,
    #[error("host_users.max_users must be between 1 and {MAX_USERS_LIMIT}")]
    MaxUsers,
    #[error("host_users.uid_min..=uid_max must hold at least max_users ids")]
    UidRange,
    #[error("{path} must be a plain absolute path")]
    ConfigPath { path: PathBuf },
    #[error("{path} does not exist")]
    Missing { path: PathBuf },
    #[error("{path} cannot be trusted: {problem}")]
    Untrusted {
        path: PathBuf,
        problem: TrustProblem,
    },
    #[error("host_users.shell is not listed in /etc/shells")]
    ShellNotListed,
    #[error("group {name} from host_users does not exist")]
    GroupMissing { name: Name },
    #[error(transparent)]
    Lookup(#[from] LookupError),
    #[error(transparent)]
    Files(#[from] FilesError),
}

#[derive(Deserialize)]
struct AgentFileView {
    #[serde(default)]
    host_users: Option<HostUsersSection>,
}

pub fn parse_agent_file(text: &str) -> Result<HostUsersSection, ConfigError> {
    parse_agent_section(text).map(Option::unwrap_or_default)
}

pub fn parse_agent_section(text: &str) -> Result<Option<HostUsersSection>, ConfigError> {
    if text.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge);
    }
    let meaningful = text
        .lines()
        .map(str::trim)
        .any(|line| !line.is_empty() && !line.starts_with('#') && line != "---");
    if !meaningful {
        return Ok(None);
    }
    let options = serde_saphyr::options! { with_snippet: false };
    let view: AgentFileView =
        serde_saphyr::from_str_with_options(text, options).map_err(|error| {
            let location = error.location();
            ConfigError::Syntax {
                at: SyntaxLocation {
                    line: location.as_ref().map(|at| at.line()),
                    column: location.as_ref().map(|at| at.column()),
                },
            }
        })?;
    Ok(view.host_users)
}

impl HostUsersSection {
    pub fn settings(&self) -> Result<Settings, ConfigError> {
        let config = self.validate()?;
        if self.enabled {
            Ok(Settings::Enabled(config))
        } else {
            Ok(Settings::Disabled)
        }
    }

    fn validate(&self) -> Result<HostUsersConfig, ConfigError> {
        let groups = names_of(&self.groups, "groups")?;
        let privileged_groups = names_of(&self.privileged_groups, "privileged_groups")?;
        if let Some(index) = groups
            .iter()
            .position(|group| PRIVILEGED_GROUPS.contains(&group.as_str()))
        {
            return Err(ConfigError::PrivilegedGroup { index });
        }
        let total = groups.len() + privileged_groups.len();
        if total > MAX_GROUPS {
            return Err(ConfigError::TooManyGroups);
        }
        let distinct: BTreeSet<&Name> = groups.iter().chain(privileged_groups.iter()).collect();
        if distinct.len() != total {
            return Err(ConfigError::DuplicateGroup);
        }
        if !is_clean_absolute_path(&self.shell, MAX_SHELL_BYTES) {
            return Err(ConfigError::Shell);
        }
        if !is_clean_absolute_path(&self.home_base, MAX_HOME_BASE_BYTES) {
            return Err(ConfigError::HomeBase);
        }
        if SYSTEM_DIRECTORIES.contains(&self.home_base.as_str()) {
            return Err(ConfigError::HomeBaseSystem);
        }
        let home_mode = HomeMode::parse(&self.home_mode).ok_or(ConfigError::HomeMode)?;
        if self.uid_min < MIN_UID {
            return Err(ConfigError::UidMin);
        }
        if self.uid_max > MAX_UID {
            return Err(ConfigError::UidMax);
        }
        if self.max_users == 0 || self.max_users > MAX_USERS_LIMIT {
            return Err(ConfigError::MaxUsers);
        }
        let room = self
            .uid_max
            .checked_sub(self.uid_min)
            .map(|span| u64::from(span) + 1);
        if room.is_none_or(|room| room < u64::from(self.max_users)) {
            return Err(ConfigError::UidRange);
        }
        let names = NameRules {
            deny: names_of(&self.names.deny, "names.deny")?,
            deny_prefixes: names_of(&self.names.deny_prefixes, "names.deny_prefixes")?,
            allow_prefixes: names_of(&self.names.allow_prefixes, "names.allow_prefixes")?,
        };
        Ok(HostUsersConfig {
            groups,
            privileged_groups,
            shell: self.shell.clone(),
            home_base: self.home_base.clone(),
            home_mode,
            uid_min: self.uid_min,
            uid_max: self.uid_max,
            max_users: self.max_users,
            names,
            allow_with_directory: self.allow_with_directory,
        })
    }
}

fn names_of(values: &[String], field: &'static str) -> Result<Vec<Name>, ConfigError> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| Name::parse(value).map_err(|_| ConfigError::Name { field, index }))
        .collect()
}

pub fn trust_problem(facts: &FileFacts, expected: FileKind) -> Option<TrustProblem> {
    if facts.kind == FileKind::Symlink {
        Some(TrustProblem::Symlink)
    } else if facts.kind != expected {
        Some(TrustProblem::WrongKind)
    } else if facts.uid != 0 {
        Some(TrustProblem::NotOwnedByRoot)
    } else if facts.writable_by_group_or_others() {
        Some(TrustProblem::Writable)
    } else {
        None
    }
}

fn require_trusted(
    files: &dyn Files,
    path: &Path,
    expected: FileKind,
) -> Result<FileFacts, ConfigError> {
    let facts = files.lstat(path)?.ok_or_else(|| ConfigError::Missing {
        path: path.to_path_buf(),
    })?;
    match trust_problem(&facts, expected) {
        None => Ok(facts),
        Some(problem) => Err(ConfigError::Untrusted {
            path: path.to_path_buf(),
            problem,
        }),
    }
}

fn root_down(path: &Path) -> Vec<&Path> {
    let mut chain: Vec<&Path> = path.ancestors().collect();
    chain.reverse();
    chain
}

fn is_plain_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

pub fn check_config_trust(path: &Path, files: &dyn Files) -> Result<(), ConfigError> {
    let Some(parent) = path.parent().filter(|_| is_plain_absolute(path)) else {
        return Err(ConfigError::ConfigPath {
            path: path.to_path_buf(),
        });
    };
    for directory in root_down(parent) {
        require_trusted(files, directory, FileKind::Directory)?;
    }
    require_trusted(files, path, FileKind::Regular).map(|_| ())
}

pub fn check_host(
    config: &HostUsersConfig,
    shells: &str,
    users: &dyn Users,
    files: &dyn Files,
) -> Result<(), ConfigError> {
    if !shells.lines().any(|line| line.trim() == config.shell()) {
        return Err(ConfigError::ShellNotListed);
    }
    let shell = Path::new(config.shell());
    let facts = require_trusted(files, shell, FileKind::Regular)?;
    if !facts.executable_by_others() {
        return Err(ConfigError::Untrusted {
            path: shell.to_path_buf(),
            problem: TrustProblem::NotExecutable,
        });
    }
    for directory in root_down(Path::new(config.home_base()))
        .into_iter()
        .chain(root_down(Path::new(SKEL_DIR)))
    {
        require_trusted(files, directory, FileKind::Directory)?;
    }
    for group in config.supplementary_groups() {
        if users.group(group)?.is_none() {
            return Err(ConfigError::GroupMissing {
                name: group.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
