use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use jaunt_host_users::{
    DirectoryUse, HostUsersSection, MAX_STATE_BYTES, SERVICE_UNIT_TEMPLATE, SOCKET_UNIT_TEMPLATE,
    STATE_DIR, STATE_FILE, State, StateError, TOOL_PATHS, detect_directory, parse_agent_section,
};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use serde::Deserialize;

use super::args::InstallOptions;
use super::env::{DirSpec, Env, Ledger, Replaced};
use super::error::InstallError;
use super::files::{self, Existing};
use super::layout::{HELPER_SERVICE_PATH, HELPER_SOCKET_PATH, HELPER_SOCKET_UNIT, UNIT_DIR};
use super::render;
use super::service;
use super::sshd::Effective;

pub const HELPER_NAME: &str = "jaunt-host-users";
const NSSWITCH_CONF: &str = "/etc/nsswitch.conf";
const SSSD_CONF: &str = "/etc/sssd/sssd.conf";
const GROUP_OR_OTHER_WRITE: u32 = 0o022;
const OWNER_EXECUTE: u32 = 0o100;
const UNIT_MODE: u32 = 0o644;
const SETUID_OR_SETGID: u32 = 0o6000;
const SECTION_KEY: &str = "host_users";
const PLACEHOLDER_OPEN: &str = "{{";
const ROOT_ONLY_PLACES: &str = "the account helper runs as root, so jaunt-agent and jaunt-host-users must live where every parent directory is owned by root and writable only by root, for example /usr/bin (where the .deb installs them) or /opt/jaunt/bin (create it root:root 0755), with --binary pointing there";

pub fn existing_section(
    env: &Env<'_>,
    config: &str,
    content: &[u8],
) -> Result<Option<HostUsersSection>, InstallError> {
    let text = String::from_utf8_lossy(content);
    let refuse = |reason: String| InstallError::InvalidHostUsersSection {
        path: config.to_string(),
        reason,
    };
    match parse_agent_section(&text) {
        Ok(Some(section)) => {
            if let Err(error) = crate::run::config::load(&env.layout.path(config)) {
                return Err(refuse(format!(
                    "it has a host_users section, and the agent cannot load it ({error})"
                )));
            }
            match section.settings() {
                Ok(_) => Ok(Some(section)),
                Err(error) => Err(refuse(format!(
                    "its host_users section is not valid ({error})"
                ))),
            }
        }
        Ok(None) => Ok(None),
        Err(error) if text.contains(SECTION_KEY) => Err(refuse(format!(
            "it mentions host_users, and its host_users section cannot be read ({error})"
        ))),
        Err(_) => Ok(None),
    }
}

pub fn desired_section(
    existing: Option<HostUsersSection>,
    create_accounts: bool,
) -> Option<HostUsersSection> {
    match (existing, create_accounts) {
        (existing, false) => existing,
        (existing, true) => Some(HostUsersSection {
            enabled: true,
            ..existing.unwrap_or_default()
        }),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SectionOnly {
    host_users: HostUsersSection,
}

pub fn same_config(existing: &[u8], state_dir: &str, section: &HostUsersSection) -> bool {
    let Ok(text) = std::str::from_utf8(existing) else {
        return false;
    };
    let Some(rest) = text.strip_prefix(&render::agent_config(state_dir)) else {
        return false;
    };
    let only_the_section = serde_saphyr::from_str::<SectionOnly>(rest)
        .is_ok_and(|parsed| parsed.host_users == *section);
    only_the_section
        && parse_agent_section(text).is_ok_and(|parsed| parsed.as_ref() == Some(section))
}

pub fn kept_section_note(env: &mut Env<'_>, config: &str, section: &HostUsersSection) {
    env.report.info(format!(
        "kept: the host_users section of {config} as it was (enabled: {}); install without --create-accounts never turns account creation off: to do that, set `enabled: false` in that section and run `systemctl restart jaunt-agent`",
        section.enabled
    ));
}

pub fn helper_path(binary: &str) -> String {
    match binary.rsplit_once('/') {
        Some((parent, _)) if !parent.is_empty() => format!("{parent}/{HELPER_NAME}"),
        _ => format!("/{HELPER_NAME}"),
    }
}

fn refuse(path: &str, reason: String) -> InstallError {
    InstallError::CreateAccountsRefused {
        path: path.to_string(),
        reason,
    }
}

fn lstat(env: &Env<'_>, virtual_path: &str) -> Result<Option<Metadata>, InstallError> {
    let path = env.layout.path(virtual_path);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(InstallError::io("stat", &path)(source)),
    }
}

enum Unsafe {
    Owner(u32),
    Writable(u32),
}

fn unsafe_owner_or_mode(env: &Env<'_>, metadata: &Metadata) -> Option<Unsafe> {
    let mode = metadata.permissions().mode() & 0o7777;
    if metadata.uid() != env.root_uid {
        Some(Unsafe::Owner(metadata.uid()))
    } else if mode & GROUP_OR_OTHER_WRITE != 0 {
        Some(Unsafe::Writable(mode))
    } else {
        None
    }
}

fn check_helper_file(env: &Env<'_>, helper: &str, metadata: &Metadata) -> Result<(), InstallError> {
    let mode = metadata.permissions().mode() & 0o7777;
    match unsafe_owner_or_mode(env, metadata) {
        Some(Unsafe::Owner(uid)) => {
            return Err(refuse(
                helper,
                format!(
                    "is owned by uid {uid}, not by root; the account helper runs as root from this path, so run `chown root:root {helper}` and run install again"
                ),
            ));
        }
        Some(Unsafe::Writable(mode)) => {
            return Err(refuse(
                helper,
                format!(
                    "is writable by group or others (mode {mode:04o}); the account helper runs as root from this path, so run `chmod go-w {helper}` and run install again"
                ),
            ));
        }
        None => {}
    }
    if mode & SETUID_OR_SETGID != 0 {
        return Err(refuse(
            helper,
            format!(
                "has the setuid or setgid bit (mode {mode:04o}); the account helper must not carry either, so run `chmod 0755 {helper}` and run install again"
            ),
        ));
    }
    if mode & OWNER_EXECUTE == 0 {
        return Err(refuse(
            helper,
            format!("is not executable; run `chmod 0755 {helper}` and run install again"),
        ));
    }
    Ok(())
}

pub fn verify_helper(env: &mut Env<'_>, binary: &str) -> Result<String, InstallError> {
    if binary.rsplit('/').next() == Some(HELPER_NAME) {
        return Err(refuse(
            binary,
            format!(
                "is the account helper itself; give --binary the path of jaunt-agent and put {HELPER_NAME} next to it"
            ),
        ));
    }
    let helper = helper_path(binary);
    let Some(metadata) = lstat(env, &helper)? else {
        return Err(refuse(
            &helper,
            format!(
                "does not exist; the account helper must sit next to jaunt-agent under exactly this name: install it with `install -o root -g root -m 0755 {HELPER_NAME} {helper}` and run install again"
            ),
        ));
    };
    let kind = metadata.file_type();
    if kind.is_symlink() {
        return Err(refuse(
            &helper,
            "is a symbolic link; install the binary itself at this path and run install again"
                .to_string(),
        ));
    }
    if kind.is_dir() {
        return Err(refuse(
            &helper,
            format!(
                "is a directory, not the {HELPER_NAME} binary; remove it, install the binary at this path and run install again"
            ),
        ));
    }
    if !kind.is_file() {
        return Err(refuse(
            &helper,
            format!(
                "is not a regular file; install the {HELPER_NAME} binary at this path and run install again"
            ),
        ));
    }
    check_helper_file(env, &helper, &metadata)?;
    check_ancestors(env, &helper)?;
    env.report.info(format!(
        "verified: {helper} is a regular file owned by root, and only root can change it or the directories above it"
    ));
    Ok(helper)
}

pub fn check_state_dir(state_dir: &str) -> Result<(), InstallError> {
    let inside = state_dir == STATE_DIR
        || state_dir
            .strip_prefix(STATE_DIR)
            .is_some_and(|rest| rest.starts_with('/'));
    if inside {
        return Err(refuse(
            state_dir,
            format!(
                "is the state directory of {HELPER_NAME} or inside it; give jaunt-agent its own --state-dir such as /var/lib/jaunt and run install again"
            ),
        ));
    }
    Ok(())
}

fn check_ancestors(env: &Env<'_>, helper: &str) -> Result<(), InstallError> {
    let mut problems = Vec::new();
    let mut writable = Vec::new();
    for ancestor in Path::new(helper).ancestors().skip(1) {
        let directory = ancestor.to_string_lossy().into_owned();
        match directory_problem(env, &directory)? {
            None => {}
            Some(Unsafe::Owner(uid)) => {
                problems.push((directory, format!("is owned by uid {uid}, not by root")));
            }
            Some(Unsafe::Writable(mode)) => {
                problems.push((
                    directory.clone(),
                    format!("is writable by group or others (mode {mode:04o})"),
                ));
                writable.push(directory);
            }
        }
    }
    let Some(((first, first_problem), rest)) = problems.split_first() else {
        return Ok(());
    };
    let mut reason = first_problem.clone();
    for (directory, problem) in rest {
        reason.push_str(&format!("; {directory} {problem}"));
    }
    reason.push_str(&format!("; {ROOT_ONLY_PLACES}"));
    if !writable.is_empty() {
        reason.push_str(&format!(
            "; run `chmod g-w,o-w {}` instead only if you know that is safe",
            writable.join(" ")
        ));
    }
    Err(refuse(first, reason))
}

fn directory_problem(env: &Env<'_>, directory: &str) -> Result<Option<Unsafe>, InstallError> {
    let Some(metadata) = lstat(env, directory)? else {
        return Err(refuse(
            directory,
            "disappeared while it was being checked; run install again".to_string(),
        ));
    };
    if metadata.file_type().is_symlink() {
        return Err(refuse(
            directory,
            "is a symbolic link; the account helper runs as root from below it, so give --binary a path whose directories are real (for example /usr/bin instead of /bin) and run install again".to_string(),
        ));
    }
    if !metadata.is_dir() {
        return Err(refuse(
            directory,
            "is not a directory; give --binary the real path of jaunt-agent and run install again"
                .to_string(),
        ));
    }
    Ok(unsafe_owner_or_mode(env, &metadata))
}

pub fn check_unit_paths(env: &Env<'_>) -> Result<(), InstallError> {
    for unit in [HELPER_SOCKET_PATH, HELPER_SERVICE_PATH] {
        match files::read_regular_no_follow(&env.layout.path(unit))? {
            Existing::Absent | Existing::Regular(_) => {}
            Existing::NotRegular => {
                return Err(refuse(
                    unit,
                    "is a symbolic link or not a regular file (a masked unit is a link to /dev/null); unmask or remove it and run install again".to_string(),
                ));
            }
            Existing::Oversized => {
                return Err(refuse(
                    unit,
                    "is larger than 64 KiB, so it is not a unit written by jaunt-agent; move it away and run install again".to_string(),
                ));
            }
        }
    }
    Ok(())
}

pub fn warn_about_sshd_rules(env: &mut Env<'_>, config: &str, effective: &[&Effective]) {
    let set = |key: &str| effective.iter().any(|dump| !dump.values(key).is_empty());
    let mut advice = Vec::new();
    if set("allowusers") {
        advice.push(format!(
            "AllowUsers is set, and the accounts that jaunt-agent creates are not in it: add each one, or switch to AllowGroups with a group that the helper assigns through `groups` of the host_users section in {config}"
        ));
    }
    if set("allowgroups") {
        advice.push(format!(
            "AllowGroups is set: add to it a group listed in `groups` of the host_users section in {config}, or the created accounts cannot log in"
        ));
    }
    if !advice.is_empty() {
        env.report
            .warn(format!("`sshd -T` shows that {}", advice.join("; also, ")));
    }
}

pub fn warn_about_host(
    env: &mut Env<'_>,
    config: &str,
    selinux_enforcing: bool,
) -> Result<(), InstallError> {
    let mut missing = Vec::new();
    for (tool, candidates) in TOOL_PATHS {
        let mut found = false;
        for candidate in candidates {
            if files::exists(&env.layout.path(candidate))? {
                found = true;
                break;
            }
        }
        if !found {
            missing.push(format!("{tool} (looked for {})", candidates.join(" and ")));
        }
    }
    if !missing.is_empty() {
        env.report.warn(format!(
            "not found: {}; the account helper refuses to create accounts until these tools are installed",
            missing.join(", ")
        ));
    }
    let nsswitch = files::read_optional(&env.layout.path(NSSWITCH_CONF))?
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
    let sssd_configured = files::exists(&env.layout.path(SSSD_CONF))?;
    if detect_directory(nsswitch.as_deref(), sssd_configured) == DirectoryUse::Network {
        env.report.warn(format!(
            "{NSSWITCH_CONF} takes users from a directory service (ldap, nis, winbind, or sss with {SSSD_CONF}); account creation stays off unless `allow_with_directory: true` is set in the host_users section of {config}"
        ));
    }
    if selinux_enforcing {
        env.report.warn(
            "SELinux is Enforcing; after the first account is created, check by hand that its home directory carries the user home label (`ls -Zd <home>`)",
        );
    }
    Ok(())
}

pub struct UnitFiles {
    files: Vec<(&'static str, String)>,
}

pub fn render_unit_files(
    templates: [(&'static str, &str); 2],
    helper: &str,
    opts: &InstallOptions,
    home_base: &str,
) -> Result<UnitFiles, InstallError> {
    let mut files = Vec::new();
    for (unit, template) in templates {
        let content = render::helper_unit(template, helper, &opts.config, &opts.user, home_base);
        if content.contains(PLACEHOLDER_OPEN) {
            return Err(refuse(
                unit,
                "still holds an unfilled placeholder after rendering; this jaunt-agent does not match its unit templates, so nothing was written".to_string(),
            ));
        }
        files.push((unit, content));
    }
    Ok(UnitFiles { files })
}

pub fn prepare_units(
    env: &mut Env<'_>,
    opts: &InstallOptions,
    helper: &str,
    section: &HostUsersSection,
) -> Result<UnitFiles, InstallError> {
    let units = render_unit_files(
        [
            (HELPER_SOCKET_PATH, SOCKET_UNIT_TEMPLATE),
            (HELPER_SERVICE_PATH, SERVICE_UNIT_TEMPLATE),
        ],
        helper,
        opts,
        &section.home_base,
    )?;
    let default_home_base = HostUsersSection::default().home_base;
    if section.home_base != default_home_base
        && !files::exists(&env.layout.path(&section.home_base))?
    {
        env.report.warn(format!(
            "home_base {} of the host_users section in {} does not exist; the account helper service cannot start until it does, so create it (owned by root, not writable by group or others)",
            section.home_base, opts.config
        ));
    }
    Ok(units)
}

pub fn write_units(
    env: &mut Env<'_>,
    units: &UnitFiles,
    ledger: &mut Ledger,
) -> Result<bool, InstallError> {
    env.ensure_dir(
        UNIT_DIR,
        &DirSpec {
            mode: 0o755,
            owner: None,
            enforce: false,
        },
        ledger,
    )?;
    let mut changed = false;
    for (unit, content) in &units.files {
        let unit = *unit;
        let written = env.write_file(unit, content, UNIT_MODE)?;
        changed |= written.changed;
        if !written.changed || env.dry_run {
            continue;
        }
        let path = env.layout.path(unit);
        match written.previous {
            None => ledger.files.push(path),
            Some(previous) => ledger.replaced.push(Replaced {
                path,
                content: previous,
                mode: written.previous_mode.unwrap_or(UNIT_MODE),
            }),
        }
        if let Some(error) = written.sync_error {
            return Err(error);
        }
    }
    Ok(changed)
}

pub fn manual_steps_note(env: &mut Env<'_>) {
    env.report.info(format!(
        "next: run `systemctl daemon-reload` and `systemctl enable --now {HELPER_SOCKET_UNIT}` before you start or restart jaunt-agent, so that it creates accounts"
    ));
}

pub fn holds_helper_units(env: &Env<'_>, ledger: &Ledger) -> bool {
    let units = [
        env.layout.path(HELPER_SOCKET_PATH),
        env.layout.path(HELPER_SERVICE_PATH),
    ];
    ledger
        .files
        .iter()
        .chain(ledger.replaced.iter().map(|replaced| &replaced.path))
        .any(|path| units.contains(path))
}

pub fn removed_section_note(env: &mut Env<'_>, config: &str, content: &[u8]) {
    let text = String::from_utf8_lossy(content);
    if !matches!(parse_agent_section(&text), Ok(Some(_))) {
        return;
    }
    if env.dry_run {
        env.report.plan(format!(
            "remove the host_users section together with {config}; the accounts it created stay"
        ));
    } else {
        env.report.info(format!(
            "removed: the host_users section went with {config}; the accounts it created stay"
        ));
    }
}

pub fn units_present(env: &Env<'_>) -> Result<bool, InstallError> {
    Ok(files::exists(&env.layout.path(HELPER_SOCKET_PATH))?
        || files::exists(&env.layout.path(HELPER_SERVICE_PATH))?)
}

pub fn remove_units(env: &mut Env<'_>, manage_service: bool) -> Result<(), InstallError> {
    if manage_service {
        service::stop_and_disable_unit(env, HELPER_SOCKET_UNIT);
    }
    env.remove_file(HELPER_SOCKET_PATH)?;
    env.remove_file(HELPER_SERVICE_PATH)?;
    report_kept_accounts(env);
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum CountProblem {
    #[error("it is a symbolic link or not a regular file")]
    NotRegular,
    #[error("{0}")]
    Io(io::Error),
    #[error("{0}")]
    State(StateError),
}

fn state_file() -> String {
    format!("{STATE_DIR}/{STATE_FILE}")
}

fn count_accounts(path: &Path) -> Result<usize, CountProblem> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(0),
        Err(Errno::LOOP) => return Err(CountProblem::NotRegular),
        Err(errno) => return Err(CountProblem::Io(io::Error::from(errno))),
    };
    let file = File::from(fd);
    let metadata = file.metadata().map_err(CountProblem::Io)?;
    if !metadata.is_file() {
        return Err(CountProblem::NotRegular);
    }
    let limit = u64::try_from(MAX_STATE_BYTES).unwrap_or(u64::MAX);
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(CountProblem::Io)?;
    State::from_json(&bytes)
        .map(|state| state.accounts().len())
        .map_err(CountProblem::State)
}

fn report_kept_accounts(env: &mut Env<'_>) {
    let file = state_file();
    match count_accounts(&env.layout.path(&file)) {
        Ok(count) => env.report.info(format!(
            "kept: {count} account(s) listed in {file}, their home directories, {STATE_DIR} and the {HELPER_NAME} binary; run `{HELPER_NAME} list` to see them"
        )),
        Err(problem) => env.report.warn(format!(
            "could not read {file} ({problem}); the accounts it lists, their home directories, {STATE_DIR} and the {HELPER_NAME} binary are kept; run `{HELPER_NAME} list` to see them"
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::super::args::{InstallOptions, UninstallOptions};
    use super::super::error::InstallError;
    use super::super::install::install;
    use super::super::layout::{HELPER_SERVICE_PATH, HELPER_SOCKET_PATH};
    use super::super::render;
    use super::super::report::Level;
    use super::super::testing::{FakeConfig, Harness, options};
    use super::super::uninstall::uninstall;

    const HELPER: &str = "/usr/local/bin/jaunt-host-users";
    const CONFIG: &str = "/etc/jaunt/agent.yaml";
    const STATE: &str = "/var/lib/jaunt-host-users/accounts.json";
    const TWO_ACCOUNTS: &str = concat!(
        r#"{"v":1,"accounts":["#,
        r#"{"login":"alice","uid":30001,"gid":30001,"home":"/home/alice","created_at":1700000000,"ref":"H-0000ABCD","session":"s-9","state":"active"},"#,
        r#"{"login":"bob","home":"/home/bob","created_at":1700000000,"ref":"H-0000ABCE","session":"s-10","state":"pending"}"#,
        r#"],"attempts":[]}"#,
    );
    const SOCKET_WARNING: &str = "AllowGroups is set: add to it a group listed in `groups`";
    const DIRECTORY_WARNING: &str = "takes users from a directory service";
    const SELINUX_WARNING: &str = "carries the user home label";
    const TOOLS_WARNING: &str = "not found: useradd";

    fn flagged() -> InstallOptions {
        InstallOptions {
            create_accounts: true,
            ..options()
        }
    }

    fn with_services(create_accounts: bool) -> InstallOptions {
        InstallOptions {
            create_accounts,
            no_service: false,
            ..options()
        }
    }

    fn chmod(harness: &Harness, path: &str, mode: u32) {
        fs::set_permissions(harness.root.path_of(path), Permissions::from_mode(mode)).unwrap();
    }

    fn mode(harness: &Harness, path: &str) -> u32 {
        fs::symlink_metadata(harness.root.path_of(path))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    fn place_helper(harness: &Harness, path: &str) {
        harness.root.write(path, "#!/bin/sh\n");
        chmod(harness, path, 0o755);
        for ancestor in Path::new(path).ancestors().skip(1) {
            chmod(harness, &ancestor.to_string_lossy(), 0o755);
        }
    }

    fn place_tools(harness: &Harness) {
        for tool in ["/usr/sbin/useradd", "/usr/sbin/userdel", "/usr/bin/getent"] {
            harness.root.write(tool, "");
        }
    }

    fn ready(config: FakeConfig) -> Harness {
        let harness = Harness::new(config);
        place_helper(&harness, HELPER);
        place_tools(&harness);
        harness
    }

    fn run(harness: &mut Harness, opts: &InstallOptions) -> Result<(), InstallError> {
        let mut env = harness.env();
        install(&mut env, opts)
    }

    fn run_uninstall(harness: &mut Harness, purge: bool) -> Result<(), InstallError> {
        let opts = UninstallOptions {
            purge,
            no_service: false,
            config: CONFIG.to_string(),
            state_dir: "/var/lib/jaunt".to_string(),
        };
        let mut env = harness.env();
        uninstall(&mut env, &opts)
    }

    fn systemctl_calls(harness: &Harness) -> Vec<String> {
        harness
            .calls()
            .into_iter()
            .filter(|call| call.starts_with("systemctl"))
            .collect()
    }

    fn mentions_helper(harness: &Harness) -> bool {
        harness.report.contains(Level::Info, "jaunt-host-users")
            || harness.report.contains(Level::Warn, "jaunt-host-users")
            || harness.report.contains(Level::Info, "account(s)")
    }

    #[test]
    fn without_the_flag_no_unit_no_section_and_no_helper_command_appear() {
        let mut harness = ready(FakeConfig {
            sshd_allow_groups: Some("admins".to_string()),
            selinux: Some("Enforcing\n".to_string()),
            ..FakeConfig::default()
        });
        harness
            .root
            .write("/etc/nsswitch.conf", "passwd: files ldap\n");
        fs::remove_file(harness.root.path_of(HELPER)).unwrap();
        harness.live = true;
        run(&mut harness, &with_services(false)).unwrap();
        assert!(!harness.root.path_of(HELPER_SOCKET_PATH).exists());
        assert!(!harness.root.path_of(HELPER_SERVICE_PATH).exists());
        assert_eq!(
            harness.root.read(CONFIG).unwrap(),
            render::agent_config("/var/lib/jaunt")
        );
        assert!(
            harness
                .calls()
                .iter()
                .all(|call| !call.contains("jaunt-host-users") && !call.contains("try-restart"))
        );
        assert!(!mentions_helper(&harness));
        assert!(!harness.report.contains(Level::Info, "host_users"));
        for warning in [
            SOCKET_WARNING,
            DIRECTORY_WARNING,
            SELINUX_WARNING,
            TOOLS_WARNING,
        ] {
            assert!(!harness.report.contains(Level::Warn, warning), "{warning}");
        }
    }

    #[test]
    fn the_units_and_the_section_are_rendered_exactly_from_the_options() {
        let mut harness = Harness::new(FakeConfig::default());
        place_helper(&harness, "/opt/jaunt/bin/jaunt-host-users");
        let opts = InstallOptions {
            user: "svc".to_string(),
            binary: "/opt/jaunt/bin/jaunt-agent".to_string(),
            config: "/opt/jaunt/agent.yaml".to_string(),
            ..flagged()
        };
        run(&mut harness, &opts).unwrap();
        assert_eq!(
            harness.root.read(HELPER_SOCKET_PATH).unwrap(),
            concat!(
                "[Unit]\n",
                "Description=Jaunt host account helper socket\n",
                "\n",
                "[Socket]\n",
                "ListenStream=/run/jaunt/host-users.sock\n",
                "SocketUser=root\n",
                "SocketGroup=svc\n",
                "SocketMode=0660\n",
                "Accept=yes\n",
                "MaxConnections=4\n",
                "RemoveOnStop=yes\n",
                "\n",
                "[Install]\n",
                "WantedBy=sockets.target\n",
            )
        );
        let service = harness.root.read(HELPER_SERVICE_PATH).unwrap();
        assert!(!service.contains("{{"), "{service}");
        for line in [
            "ExecStart=/opt/jaunt/bin/jaunt-host-users serve --config /opt/jaunt/agent.yaml --agent-user svc",
            "ReadWritePaths=/etc /home -/var/spool/mail /var/log",
        ] {
            assert!(service.lines().any(|l| l == line), "missing {line}");
        }
        assert_eq!(
            service,
            render::helper_unit(
                jaunt_host_users::SERVICE_UNIT_TEMPLATE,
                "/opt/jaunt/bin/jaunt-host-users",
                "/opt/jaunt/agent.yaml",
                "svc",
                "/home",
            )
        );
        assert_eq!(mode(&harness, HELPER_SOCKET_PATH), 0o644);
        assert_eq!(mode(&harness, HELPER_SERVICE_PATH), 0o644);
        assert_eq!(
            harness.root.read("/opt/jaunt/agent.yaml").unwrap(),
            render::agent_config_with_host_users(
                "/var/lib/jaunt",
                &jaunt_host_users::HostUsersSection {
                    enabled: true,
                    ..Default::default()
                }
            )
        );
        assert!(harness.report.contains(
            Level::Info,
            "verified: /opt/jaunt/bin/jaunt-host-users is a regular file owned by root"
        ));
    }

    const EDITED_SECTION: &str = "host_users:\n  enabled: true\n  groups: [staff]\n  names:\n    deny: [guest]\n    allow_prefixes: [ext-]\n";

    fn edited(section: &str) -> String {
        render::agent_config("/var/lib/jaunt") + section
    }

    #[test]
    fn hand_edited_groups_and_names_survive_a_rerun_with_the_flag() {
        let mut harness = ready(FakeConfig::default());
        run(&mut harness, &flagged()).unwrap();
        harness.root.write(CONFIG, &edited(EDITED_SECTION));
        harness.report = Default::default();
        run(&mut harness, &flagged()).unwrap();
        assert_eq!(harness.root.read(CONFIG).unwrap(), edited(EDITED_SECTION));
        assert!(
            harness
                .report
                .contains(Level::Info, "unchanged: /etc/jaunt/agent.yaml")
        );

        harness.live = true;
        let before = harness.root.snapshot();
        run(&mut harness, &with_services(true)).unwrap();
        assert_eq!(harness.root.snapshot(), before);
        assert!(
            !systemctl_calls(&harness)
                .iter()
                .any(|c| c.contains("try-restart"))
        );
    }

    #[test]
    fn a_rerun_without_the_flag_keeps_the_section_verbatim_and_touches_no_unit() {
        let mut harness = ready(FakeConfig::default());
        harness.live = true;
        run(&mut harness, &with_services(true)).unwrap();
        harness.root.write(CONFIG, &edited(EDITED_SECTION));
        let before = harness.root.snapshot();
        harness.runner.calls.clear();
        harness.report = Default::default();
        run(&mut harness, &with_services(false)).unwrap();
        assert_eq!(harness.root.snapshot(), before);
        assert!(
            harness
                .calls()
                .iter()
                .all(|call| !call.contains("jaunt-host-users") && !call.contains("try-restart"))
        );
        assert!(harness.report.contains(
            Level::Info,
            "kept: the host_users section of /etc/jaunt/agent.yaml as it was (enabled: true)"
        ));
        assert!(
            harness
                .report
                .contains(Level::Info, "set `enabled: false` in that section")
        );
    }

    #[test]
    fn a_disabled_section_becomes_enabled_with_the_flag_and_keeps_its_values() {
        let mut harness = ready(FakeConfig::default());
        harness.root.write(
            CONFIG,
            &edited("host_users:\n  enabled: false\n  groups: [staff]\n  uid_min: 40000\n  uid_max: 40099\n"),
        );
        run(&mut harness, &flagged()).unwrap();
        let section =
            jaunt_host_users::parse_agent_file(&harness.root.read(CONFIG).unwrap()).unwrap();
        assert_eq!(
            section,
            jaunt_host_users::HostUsersSection {
                enabled: true,
                groups: vec!["staff".to_string()],
                uid_min: 40_000,
                uid_max: 40_099,
                ..Default::default()
            }
        );
    }

    #[test]
    fn an_invalid_existing_section_refuses_before_any_change() {
        for (name, section) in [
            (
                "uid below the minimum",
                "host_users:\n  enabled: true\n  uid_min: 10\n",
            ),
            ("unknown key", "host_users:\n  enable: true\n"),
            ("privileged group", "host_users:\n  groups: [sudo]\n"),
            ("broken yaml", "host_users:\n  groups: [staff\n"),
        ] {
            for create_accounts in [false, true] {
                let mut harness = ready(FakeConfig::default());
                harness.live = true;
                harness.root.write(CONFIG, &edited(section));
                let before = harness.root.snapshot();
                let error = run(&mut harness, &with_services(create_accounts)).unwrap_err();
                let text = error.to_string();
                assert!(
                    matches!(error, InstallError::InvalidHostUsersSection { .. }),
                    "{name}: {text}"
                );
                assert!(
                    text.contains("remove the host_users section"),
                    "{name}: {text}"
                );
                assert_eq!(harness.root.snapshot(), before, "{name}");
                assert_eq!(harness.calls(), vec!["id -u".to_string()], "{name}");
            }
        }
    }

    #[test]
    fn a_broken_managed_config_without_the_section_is_still_rewritten() {
        let mut harness = ready(FakeConfig::default());
        harness.root.write(CONFIG, &edited("inner: [oops\n"));
        run(&mut harness, &options()).unwrap();
        assert_eq!(
            harness.root.read(CONFIG).unwrap(),
            render::agent_config("/var/lib/jaunt")
        );
    }

    type Prepare = fn(&mut Harness, &mut InstallOptions);

    #[test]
    fn every_refusal_of_the_helper_or_its_units_comes_before_any_change() {
        let cases: [(&str, Prepare, &str, &str); 19] = [
            (
                "missing",
                |harness, _| fs::remove_file(harness.root.path_of(HELPER)).unwrap(),
                HELPER,
                "does not exist",
            ),
            (
                "wrong name",
                |harness, _| {
                    fs::rename(
                        harness.root.path_of(HELPER),
                        harness.root.path_of("/usr/local/bin/jaunt-host-users-1.0"),
                    )
                    .unwrap()
                },
                HELPER,
                "under exactly this name",
            ),
            (
                "binary names the helper",
                |_, opts| opts.binary = HELPER.to_string(),
                HELPER,
                "is the account helper itself",
            ),
            (
                "symlink",
                |harness, _| {
                    place_helper(harness, "/opt/real/jaunt-host-users");
                    fs::remove_file(harness.root.path_of(HELPER)).unwrap();
                    std::os::unix::fs::symlink(
                        harness.root.path_of("/opt/real/jaunt-host-users"),
                        harness.root.path_of(HELPER),
                    )
                    .unwrap();
                },
                HELPER,
                "is a symbolic link; install the binary itself",
            ),
            (
                "directory",
                |harness, _| {
                    fs::remove_file(harness.root.path_of(HELPER)).unwrap();
                    fs::create_dir(harness.root.path_of(HELPER)).unwrap();
                    chmod(harness, HELPER, 0o755);
                },
                HELPER,
                "is a directory",
            ),
            (
                "not owned by root",
                |harness, _| harness.root_uid = harness.root_uid.wrapping_add(1),
                HELPER,
                "not by root",
            ),
            (
                "group-writable",
                |harness, _| chmod(harness, HELPER, 0o775),
                HELPER,
                "writable by group or others (mode 0775)",
            ),
            (
                "not executable",
                |harness, _| chmod(harness, HELPER, 0o644),
                HELPER,
                "is not executable",
            ),
            (
                "writable parent",
                |harness, _| chmod(harness, "/usr/local", 0o777),
                "/usr/local",
                "writable by group or others (mode 0777)",
            ),
            (
                "symlinked parent",
                |harness, _| {
                    place_helper(harness, "/opt/bin/jaunt-host-users");
                    fs::remove_dir_all(harness.root.path_of("/usr/local/bin")).unwrap();
                    std::os::unix::fs::symlink(
                        harness.root.path_of("/opt/bin"),
                        harness.root.path_of("/usr/local/bin"),
                    )
                    .unwrap();
                },
                "/usr/local/bin",
                "is a symbolic link; the account helper runs as root from below it",
            ),
            (
                "masked socket unit",
                |harness, _| {
                    fs::create_dir_all(harness.root.path_of("/etc/systemd/system")).unwrap();
                    std::os::unix::fs::symlink(
                        "/dev/null",
                        harness.root.path_of(HELPER_SOCKET_PATH),
                    )
                    .unwrap();
                },
                HELPER_SOCKET_PATH,
                "a masked unit is a link to /dev/null",
            ),
            (
                "masked service unit",
                |harness, _| {
                    fs::create_dir_all(harness.root.path_of("/etc/systemd/system")).unwrap();
                    std::os::unix::fs::symlink(
                        "/dev/null",
                        harness.root.path_of(HELPER_SERVICE_PATH),
                    )
                    .unwrap();
                },
                HELPER_SERVICE_PATH,
                "a masked unit is a link to /dev/null",
            ),
            (
                "fifo",
                |harness, _| {
                    fs::remove_file(harness.root.path_of(HELPER)).unwrap();
                    let status = std::process::Command::new("mkfifo")
                        .arg(harness.root.path_of(HELPER))
                        .status()
                        .unwrap();
                    assert!(status.success());
                },
                HELPER,
                "is not a regular file",
            ),
            (
                "setuid",
                |harness, _| chmod(harness, HELPER, 0o4755),
                HELPER,
                "has the setuid or setgid bit (mode 4755)",
            ),
            (
                "setgid",
                |harness, _| chmod(harness, HELPER, 0o2755),
                HELPER,
                "has the setuid or setgid bit (mode 2755)",
            ),
            (
                "other-writable",
                |harness, _| chmod(harness, HELPER, 0o757),
                HELPER,
                "writable by group or others (mode 0757)",
            ),
            (
                "writable root",
                |harness, _| chmod(harness, "/", 0o777),
                "/",
                "writable by group or others (mode 0777)",
            ),
            (
                "agent state dir is the helper state dir",
                |_, opts| opts.state_dir = "/var/lib/jaunt-host-users".to_string(),
                "/var/lib/jaunt-host-users",
                "is the state directory of jaunt-host-users or inside it",
            ),
            (
                "agent state dir inside the helper state dir",
                |_, opts| opts.state_dir = "/var/lib/jaunt-host-users/agent".to_string(),
                "/var/lib/jaunt-host-users/agent",
                "is the state directory of jaunt-host-users or inside it",
            ),
        ];
        for (name, prepare, path, reason) in cases {
            let mut harness = ready(FakeConfig::default());
            harness.live = true;
            let mut opts = with_services(true);
            prepare(&mut harness, &mut opts);
            let before = harness.root.snapshot();
            let error = run(&mut harness, &opts).unwrap_err();
            let text = error.to_string();
            assert!(
                matches!(&error, InstallError::CreateAccountsRefused { path: p, .. } if p == path),
                "{name}: {text}"
            );
            assert!(text.contains(reason), "{name}: {text}");
            assert!(text.contains("nothing was changed"), "{name}: {text}");
            assert_eq!(harness.root.snapshot(), before, "{name}");
            assert_eq!(harness.calls(), vec!["id -u".to_string()], "{name}");
        }
    }

    #[test]
    fn the_socket_is_enabled_after_the_reload_and_before_the_agent_restart() {
        let mut harness = ready(FakeConfig::default());
        harness.live = true;
        run(&mut harness, &with_services(true)).unwrap();
        assert_eq!(
            systemctl_calls(&harness),
            [
                "systemctl daemon-reload",
                "systemctl reload ssh",
                "systemctl enable jaunt-agent",
                "systemctl enable --now jaunt-host-users.socket",
                "systemctl try-restart jaunt-agent",
            ]
        );
    }

    #[test]
    fn no_service_writes_the_units_and_runs_no_systemctl() {
        let mut harness = ready(FakeConfig::default());
        harness.live = true;
        run(&mut harness, &flagged()).unwrap();
        assert!(harness.root.path_of(HELPER_SOCKET_PATH).is_file());
        assert!(harness.root.path_of(HELPER_SERVICE_PATH).is_file());
        assert!(systemctl_calls(&harness).is_empty());
        assert!(harness.report.contains(
            Level::Info,
            "`systemctl enable --now jaunt-host-users.socket` before you start or restart jaunt-agent"
        ));
    }

    #[test]
    fn dry_run_plans_the_units_and_the_socket_and_changes_nothing() {
        let mut harness = ready(FakeConfig::default());
        harness.live = true;
        harness.dry_run = true;
        let before = harness.root.snapshot();
        run(&mut harness, &with_services(true)).unwrap();
        assert_eq!(harness.root.snapshot(), before);
        for plan in [
            "plan: write /etc/systemd/system/jaunt-host-users.socket (mode 0644)",
            "plan: write /etc/systemd/system/jaunt-host-users@.service (mode 0644)",
            "plan: run systemctl enable --now jaunt-host-users.socket",
            "plan: run systemctl try-restart jaunt-agent",
        ] {
            assert!(harness.report.contains(Level::Info, plan), "{plan}");
        }
        assert!(systemctl_calls(&harness).is_empty());
    }

    #[test]
    fn a_failed_install_removes_new_units_and_restores_replaced_ones() {
        let mut harness = ready(FakeConfig {
            sshd_t_rejects_trust_line: true,
            ..FakeConfig::default()
        });
        harness.live = true;
        let before = harness.root.snapshot();
        run(&mut harness, &with_services(true)).unwrap_err();
        assert_eq!(harness.root.snapshot(), before);
        assert!(systemctl_calls(&harness).is_empty());

        let mut harness = ready(FakeConfig {
            sshd_t_rejects_trust_line: true,
            ..FakeConfig::default()
        });
        harness.root.write(HELPER_SOCKET_PATH, "[Socket]\nold\n");
        harness.root.write(HELPER_SERVICE_PATH, "[Service]\nold\n");
        chmod(&harness, HELPER_SOCKET_PATH, 0o600);
        let before = harness.root.snapshot();
        run(&mut harness, &flagged()).unwrap_err();
        assert_eq!(harness.root.snapshot(), before);
        assert_eq!(mode(&harness, HELPER_SOCKET_PATH), 0o600);
        assert_eq!(
            harness.root.read(HELPER_SERVICE_PATH).unwrap(),
            "[Service]\nold\n"
        );
    }

    #[test]
    fn turning_the_flag_on_restarts_a_running_agent_once_and_a_second_run_changes_nothing() {
        let mut harness = ready(FakeConfig::default());
        harness.live = true;
        run(&mut harness, &with_services(false)).unwrap();
        assert!(
            !systemctl_calls(&harness)
                .iter()
                .any(|c| c.contains("try-restart"))
        );

        harness.runner.calls.clear();
        harness.report = Default::default();
        run(&mut harness, &with_services(true)).unwrap();
        assert!(
            harness
                .report
                .contains(Level::Info, "wrote: /etc/jaunt/agent.yaml")
        );
        assert!(systemctl_calls(&harness).ends_with(&[
            "systemctl enable --now jaunt-host-users.socket".to_string(),
            "systemctl try-restart jaunt-agent".to_string(),
        ]));

        harness.runner.calls.clear();
        let before = harness.root.snapshot();
        run(&mut harness, &with_services(true)).unwrap();
        assert_eq!(harness.root.snapshot(), before);
        assert!(
            !systemctl_calls(&harness)
                .iter()
                .any(|c| c.contains("try-restart"))
        );
        assert!(
            systemctl_calls(&harness)
                .contains(&"systemctl enable --now jaunt-host-users.socket".to_string())
        );

        let mut harness = ready(FakeConfig::default());
        run(&mut harness, &flagged()).unwrap();
        harness.report = Default::default();
        run(&mut harness, &flagged()).unwrap();
        for path in [HELPER_SOCKET_PATH, HELPER_SERVICE_PATH, CONFIG] {
            assert!(
                harness
                    .report
                    .contains(Level::Info, &format!("unchanged: {path}")),
                "{path}"
            );
        }
    }

    type Setup = fn(&mut Harness);

    #[test]
    fn each_warning_appears_only_under_its_condition() {
        let cases: [(&str, Setup, [bool; 4]); 8] = [
            ("quiet host", |_| {}, [false; 4]),
            (
                "sshd AllowGroups",
                |harness| harness.runner.config.sshd_allow_groups = Some("admins".to_string()),
                [true, false, false, false],
            ),
            (
                "sshd AllowGroups only for loopback",
                |harness| {
                    harness.runner.config.sshd_loopback_allow_groups = Some("admins".to_string())
                },
                [true, false, false, false],
            ),
            (
                "ldap in nsswitch",
                |harness| {
                    harness
                        .root
                        .write("/etc/nsswitch.conf", "passwd: files ldap\n")
                },
                [false, true, false, false],
            ),
            (
                "sss with sssd.conf",
                |harness| {
                    harness
                        .root
                        .write("/etc/nsswitch.conf", "passwd: files sss\n");
                    harness.root.write("/etc/sssd/sssd.conf", "[sssd]\n");
                },
                [false, true, false, false],
            ),
            (
                "sss without sssd.conf",
                |harness| {
                    harness
                        .root
                        .write("/etc/nsswitch.conf", "passwd: files sss\n")
                },
                [false; 4],
            ),
            (
                "SELinux enforcing",
                |harness| harness.runner.config.selinux = Some("Enforcing\n".to_string()),
                [false, false, true, false],
            ),
            (
                "useradd missing",
                |harness| fs::remove_file(harness.root.path_of("/usr/sbin/useradd")).unwrap(),
                [false, false, false, true],
            ),
        ];
        for (name, setup, expected) in cases {
            let mut harness = ready(FakeConfig::default());
            harness.live = true;
            setup(&mut harness);
            run(&mut harness, &flagged()).unwrap();
            let seen = [
                SOCKET_WARNING,
                DIRECTORY_WARNING,
                SELINUX_WARNING,
                TOOLS_WARNING,
            ]
            .map(|warning| harness.report.contains(Level::Warn, warning));
            assert_eq!(seen, expected, "{name}");
        }
    }

    #[test]
    fn uninstall_removes_the_units_and_keeps_accounts_state_and_helper() {
        for purge in [false, true] {
            let mut harness = ready(FakeConfig::default());
            harness.live = true;
            run(&mut harness, &with_services(true)).unwrap();
            harness.root.write(STATE, TWO_ACCOUNTS);
            harness.runner.calls.clear();
            harness.report = Default::default();
            run_uninstall(&mut harness, purge).unwrap();
            assert!(
                !harness.root.path_of(HELPER_SOCKET_PATH).exists(),
                "{purge}"
            );
            assert!(
                !harness.root.path_of(HELPER_SERVICE_PATH).exists(),
                "{purge}"
            );
            assert_eq!(harness.root.read(STATE).unwrap(), TWO_ACCOUNTS, "{purge}");
            assert!(harness.root.path_of(HELPER).is_file(), "{purge}");
            assert!(
                harness.report.contains(
                    Level::Info,
                    "kept: 2 account(s) listed in /var/lib/jaunt-host-users/accounts.json"
                ),
                "{purge}"
            );
            assert!(
                harness
                    .report
                    .contains(Level::Info, "run `jaunt-host-users list` to see them"),
                "{purge}"
            );
            let calls = systemctl_calls(&harness);
            assert_eq!(
                calls[..4],
                [
                    "systemctl stop jaunt-agent",
                    "systemctl disable jaunt-agent",
                    "systemctl stop jaunt-host-users.socket",
                    "systemctl disable jaunt-host-users.socket",
                ],
                "{purge}"
            );
            assert_eq!(
                calls.last().map(String::as_str),
                Some("systemctl daemon-reload")
            );
            assert!(
                !calls.iter().any(|c| c.contains("jaunt-host-users@")),
                "{purge}"
            );
        }
    }

    #[test]
    fn uninstall_counts_a_missing_state_as_zero_and_reports_an_unreadable_one() {
        let mut harness = ready(FakeConfig::default());
        run(&mut harness, &flagged()).unwrap();
        harness.report = Default::default();
        run_uninstall(&mut harness, false).unwrap();
        assert!(harness.report.contains(Level::Info, "kept: 0 account(s)"));

        let mut harness = ready(FakeConfig::default());
        run(&mut harness, &flagged()).unwrap();
        harness.root.write(STATE, "{not json");
        harness.report = Default::default();
        run_uninstall(&mut harness, false).unwrap();
        assert!(harness.report.contains(
            Level::Warn,
            "could not read /var/lib/jaunt-host-users/accounts.json (the state file is not valid JSON"
        ));
        assert!(harness.root.path_of(STATE).is_file());
    }

    #[test]
    fn uninstall_of_an_install_without_the_flag_says_nothing_about_accounts() {
        let mut harness = ready(FakeConfig::default());
        run(&mut harness, &options()).unwrap();
        harness.root.write(STATE, TWO_ACCOUNTS);
        harness.report = Default::default();
        run_uninstall(&mut harness, true).unwrap();
        assert!(!mentions_helper(&harness));
        assert_eq!(harness.root.read(STATE).unwrap(), TWO_ACCOUNTS);
    }

    #[test]
    fn a_writable_ancestor_names_the_directory_its_mode_and_root_only_places() {
        let mut harness = ready(FakeConfig::default());
        chmod(&harness, "/usr/local", 0o2775);
        let text = run(&mut harness, &flagged()).unwrap_err().to_string();
        for part in [
            "/usr/local is writable by group or others (mode 2775)",
            "/usr/bin",
            "/opt/jaunt/bin",
            "chmod g-w,o-w /usr/local",
        ] {
            assert!(text.contains(part), "{part}: {text}");
        }
    }

    #[test]
    fn a_parent_directory_owned_by_another_uid_is_refused() {
        let mut harness = ready(FakeConfig::default());
        harness.root_uid = harness.root_uid.wrapping_add(1);
        let env = harness.env();
        let text = super::check_ancestors(&env, HELPER)
            .unwrap_err()
            .to_string();
        assert!(text.contains("/usr/local/bin is owned by uid"), "{text}");
        assert!(text.contains("/usr/bin"), "{text}");
    }

    #[test]
    fn a_rendered_unit_with_an_unfilled_placeholder_is_refused_before_writing() {
        let error = super::render_unit_files(
            [
                (HELPER_SOCKET_PATH, "[Socket]\nSocketGroup={{user}}\n"),
                (
                    HELPER_SERVICE_PATH,
                    "[Service]\nExecStart={{binary}} {{unknown}}\n",
                ),
            ],
            HELPER,
            &flagged(),
            "/home",
        )
        .err()
        .unwrap();
        assert!(
            matches!(&error, InstallError::CreateAccountsRefused { path, .. } if path == HELPER_SERVICE_PATH),
            "{error}"
        );
        assert!(error.to_string().contains("unfilled placeholder"));
        assert!(
            super::render_unit_files(
                [
                    (HELPER_SOCKET_PATH, jaunt_host_users::SOCKET_UNIT_TEMPLATE),
                    (HELPER_SERVICE_PATH, jaunt_host_users::SERVICE_UNIT_TEMPLATE),
                ],
                HELPER,
                &flagged(),
                "/home",
            )
            .is_ok()
        );
    }

    #[test]
    fn the_home_base_of_the_kept_section_reaches_the_unit_and_a_change_updates_it() {
        let mut harness = ready(FakeConfig::default());
        fs::create_dir_all(harness.root.path_of("/srv/home")).unwrap();
        fs::create_dir_all(harness.root.path_of("/srv/people")).unwrap();
        harness.root.write(
            CONFIG,
            &edited("host_users:\n  enabled: true\n  home_base: /srv/home\n"),
        );
        run(&mut harness, &flagged()).unwrap();
        let service = harness.root.read(HELPER_SERVICE_PATH).unwrap();
        assert!(
            service
                .lines()
                .any(|line| line == "ReadWritePaths=/etc /srv/home -/var/spool/mail /var/log"),
            "{service}"
        );
        assert!(!harness.report.contains(Level::Warn, "does not exist"));

        harness.root.write(
            CONFIG,
            &edited("host_users:\n  enabled: true\n  home_base: /srv/people\n"),
        );
        harness.report = Default::default();
        run(&mut harness, &flagged()).unwrap();
        let service = harness.root.read(HELPER_SERVICE_PATH).unwrap();
        assert!(
            service
                .lines()
                .any(|line| line == "ReadWritePaths=/etc /srv/people -/var/spool/mail /var/log"),
            "{service}"
        );
        assert!(harness.report.contains(
            Level::Info,
            "wrote: /etc/systemd/system/jaunt-host-users@.service"
        ));
    }

    #[test]
    fn a_missing_home_base_warns_only_when_it_is_not_the_default() {
        let mut harness = ready(FakeConfig::default());
        run(&mut harness, &flagged()).unwrap();
        assert!(!harness.root.path_of("/home").exists());
        assert!(!harness.report.contains(Level::Warn, "does not exist"));

        let mut harness = ready(FakeConfig::default());
        harness.root.write(
            CONFIG,
            &edited("host_users:\n  enabled: false\n  home_base: /srv/missing\n"),
        );
        run(&mut harness, &flagged()).unwrap();
        assert!(harness.report.contains(
            Level::Warn,
            "home_base /srv/missing of the host_users section in /etc/jaunt/agent.yaml does not exist"
        ));
    }

    #[test]
    fn allow_users_asks_for_each_account_or_allow_groups() {
        let mut harness = ready(FakeConfig {
            sshd_allow_users: Some("alice".to_string()),
            ..FakeConfig::default()
        });
        run(&mut harness, &flagged()).unwrap();
        assert!(harness.report.contains(
            Level::Warn,
            "AllowUsers is set, and the accounts that jaunt-agent creates are not in it: add each one, or switch to AllowGroups"
        ));
        assert!(!harness.report.contains(Level::Warn, SOCKET_WARNING));
    }

    #[test]
    fn units_missing_under_an_enabled_section_restart_the_agent_again() {
        let mut harness = ready(FakeConfig::default());
        harness.live = true;
        run(&mut harness, &with_services(true)).unwrap();
        fs::remove_file(harness.root.path_of(HELPER_SOCKET_PATH)).unwrap();
        fs::remove_file(harness.root.path_of(HELPER_SERVICE_PATH)).unwrap();
        harness.runner.calls.clear();
        run(&mut harness, &with_services(true)).unwrap();
        assert!(
            systemctl_calls(&harness).ends_with(&["systemctl try-restart jaunt-agent".to_string()])
        );
    }

    #[test]
    fn a_failure_after_the_commit_names_the_helper_units_only_when_this_run_wrote_them() {
        let mut harness = ready(FakeConfig {
            daemon_reload_ok: false,
            ..FakeConfig::default()
        });
        harness.live = true;
        let text = run(&mut harness, &with_services(true))
            .unwrap_err()
            .to_string();
        assert!(
            text.contains("the jaunt-host-users units stay in place"),
            "{text}"
        );

        let text = run(&mut harness, &with_services(true))
            .unwrap_err()
            .to_string();
        assert!(!text.contains("jaunt-host-users units"), "{text}");
        assert!(text.contains("stay in place"), "{text}");
    }

    #[test]
    fn uninstall_does_not_follow_a_symlinked_state_file_and_refuses_an_oversized_one() {
        let mut harness = ready(FakeConfig::default());
        run(&mut harness, &flagged()).unwrap();
        harness.root.write("/srv/accounts.json", TWO_ACCOUNTS);
        fs::create_dir_all(harness.root.path_of("/var/lib/jaunt-host-users")).unwrap();
        std::os::unix::fs::symlink(
            harness.root.path_of("/srv/accounts.json"),
            harness.root.path_of(STATE),
        )
        .unwrap();
        run_uninstall(&mut harness, false).unwrap();
        assert!(harness.report.contains(
            Level::Warn,
            "could not read /var/lib/jaunt-host-users/accounts.json (it is a symbolic link"
        ));
        assert!(!harness.report.contains(Level::Info, "kept: 2 account(s)"));

        let mut harness = ready(FakeConfig::default());
        run(&mut harness, &flagged()).unwrap();
        let big = " ".repeat(jaunt_host_users::MAX_STATE_BYTES + 1);
        harness.root.write(STATE, &big);
        run_uninstall(&mut harness, false).unwrap();
        assert!(harness.report.contains(
            Level::Warn,
            "could not read /var/lib/jaunt-host-users/accounts.json (the state file is larger than"
        ));
    }

    #[test]
    fn uninstall_with_only_the_service_unit_left_still_removes_it() {
        let mut harness = ready(FakeConfig::default());
        harness.root.write(HELPER_SERVICE_PATH, "[Service]\n");
        run_uninstall(&mut harness, false).unwrap();
        assert!(!harness.root.path_of(HELPER_SERVICE_PATH).exists());
        assert!(harness.report.contains(Level::Info, "kept: 0 account(s)"));
    }

    #[test]
    fn uninstall_says_the_section_goes_with_the_config_file() {
        let mut harness = ready(FakeConfig::default());
        run(&mut harness, &flagged()).unwrap();
        run_uninstall(&mut harness, false).unwrap();
        assert!(harness.report.contains(
            Level::Info,
            "removed: the host_users section went with /etc/jaunt/agent.yaml; the accounts it created stay"
        ));

        let mut harness = ready(FakeConfig::default());
        run(&mut harness, &options()).unwrap();
        run_uninstall(&mut harness, false).unwrap();
        assert!(!harness.report.contains(Level::Info, "host_users section"));
    }

    #[test]
    fn same_config_needs_the_head_byte_for_byte_and_exactly_the_wanted_section() {
        let wanted = jaunt_host_users::HostUsersSection {
            enabled: true,
            groups: vec!["staff".to_string()],
            ..Default::default()
        };
        let section = "host_users:\n  enabled: true\n  groups: [staff]\n";
        for (name, text, same) in [
            ("plain", edited(section), true),
            ("comment", edited(&format!("{section}# note\n")), true),
            (
                "other values",
                edited("host_users:\n  enabled: true\n"),
                false,
            ),
            (
                "another key",
                edited(&format!("{section}extra: 1\n")),
                false,
            ),
            (
                "second document",
                edited(&format!("{section}---\nstate_dir: /x\n")),
                false,
            ),
            (
                "section in a second document",
                edited(&format!("---\n{section}")),
                false,
            ),
            ("crlf", edited(section).replace('\n', "\r\n"), false),
            (
                "other head",
                format!("# Managed by jaunt-agent. Do not edit.\nlog_level: info\n{section}"),
                false,
            ),
        ] {
            assert_eq!(
                super::same_config(text.as_bytes(), "/var/lib/jaunt", &wanted),
                same,
                "{name}"
            );
        }
    }

    #[test]
    fn existing_configs_are_kept_or_refused_exactly_as_the_agent_loader_reads_them() {
        let head = render::agent_config("/var/lib/jaunt");
        let cases: [(&str, String, Option<bool>); 12] = [
            (
                "indented key",
                format!("{head}  host_users:\n    enabled: true\n"),
                Some(false),
            ),
            (
                "quoted key",
                format!("{head}\"host_users\":\n  enabled: true\n  groups: [staff]\n"),
                Some(true),
            ),
            (
                "duplicate key",
                format!("{head}host_users:\n  groups: [a]\nhost_users:\n  groups: [b]\n"),
                None,
            ),
            (
                "two documents",
                format!("{head}---\nhost_users:\n  groups: [staff]\n"),
                None,
            ),
            (
                "tab indentation",
                format!("{head}host_users:\n\tenabled: true\n"),
                Some(false),
            ),
            (
                "document end marker",
                format!("{head}host_users:\n  groups: [staff]\n...\n"),
                Some(true),
            ),
            (
                "crlf in the section",
                format!("{head}host_users:\r\n  groups: [staff]\r\n"),
                Some(true),
            ),
            (
                "comments",
                format!("{head}# note host\nhost_users:  # mine\n  groups: [staff]  # admins\n"),
                Some(true),
            ),
            (
                "null section",
                format!("{head}host_users: null\n"),
                Some(true),
            ),
            (
                "unknown top-level key",
                format!("{head}host_users:\n  groups: [staff]\nextra: 1\n"),
                Some(false),
            ),
            (
                "a list that mentions it",
                "# Managed by jaunt-agent. Do not edit.\n- host_users\n".to_string(),
                Some(false),
            ),
            (
                "not yaml and no section",
                "# Managed by jaunt-agent. Do not edit.\n: : [\n".to_string(),
                Some(true),
            ),
        ];
        for (name, text, expected_kept) in cases {
            let mut harness = ready(FakeConfig::default());
            harness.root.write(CONFIG, &text);
            let path = harness.root.path_of(CONFIG);
            let loaded = crate::run::config::load(&path);
            let parsed = jaunt_host_users::parse_agent_section(&text);
            let mentions = text.contains("host_users");
            let kept = match &parsed {
                Ok(Some(section)) => loaded.is_ok() && section.settings().is_ok(),
                Ok(None) => true,
                Err(_) => !mentions,
            };
            if let Some(expected) = expected_kept {
                assert_eq!(kept, expected, "{name}: {loaded:?} {parsed:?}");
            }
            let before = harness.root.snapshot();
            let result = run(&mut harness, &options());
            if !kept {
                let error = result.unwrap_err();
                let message = error.to_string();
                assert!(
                    matches!(error, InstallError::InvalidHostUsersSection { .. }),
                    "{name}: {message}"
                );
                assert!(
                    !message.contains("section is not valid") || matches!(parsed, Ok(Some(_))),
                    "{name}: {message}"
                );
                assert_eq!(harness.root.snapshot(), before, "{name}");
                continue;
            }
            result.unwrap_or_else(|error| panic!("{name}: {error}"));
            let after = crate::run::config::load(&path).unwrap();
            match (loaded, &parsed) {
                (Ok(loaded), Ok(Some(_))) => {
                    assert_eq!(after.host_users, loaded.host_users, "{name}")
                }
                _ => assert_eq!(
                    harness.root.read(CONFIG).unwrap(),
                    render::agent_config("/var/lib/jaunt"),
                    "{name}"
                ),
            }
        }
    }

    const ESCAPED_KEYS: [(&str, &str); 3] = [
        ("hex escape", "\"host\\x5Fusers\":\n"),
        ("unicode escape", "\"host\\u005Fusers\":\n"),
        ("folded explicit key", "? \"host_\\\n  users\"\n:\n"),
    ];
    const ESCAPED_VALUES: &str =
        "  enabled: false\n  groups: [staff]\n  uid_min: 40000\n  uid_max: 40099\n";

    #[test]
    fn a_section_under_an_escaped_key_is_found_and_kept() {
        let operator = jaunt_host_users::HostUsersSection {
            enabled: false,
            groups: vec!["staff".to_string()],
            uid_min: 40_000,
            uid_max: 40_099,
            ..Default::default()
        };
        for (name, key) in ESCAPED_KEYS {
            let text = edited(&format!("{key}{ESCAPED_VALUES}"));
            assert!(!text.contains("host_users"), "{name}");
            let mut harness = ready(FakeConfig::default());
            harness.root.write(CONFIG, &text);
            let loaded = crate::run::config::load(&harness.root.path_of(CONFIG)).unwrap();
            assert_eq!(loaded.host_users, operator, "{name}");

            run(&mut harness, &options()).unwrap();
            assert_eq!(harness.root.read(CONFIG).unwrap(), text, "{name}");
            assert!(
                harness
                    .report
                    .contains(Level::Info, "kept: the host_users section"),
                "{name}"
            );

            run(&mut harness, &flagged()).unwrap();
            let after = crate::run::config::load(&harness.root.path_of(CONFIG)).unwrap();
            assert_eq!(
                after.host_users,
                jaunt_host_users::HostUsersSection {
                    enabled: true,
                    ..operator.clone()
                },
                "{name}"
            );
        }
    }

    #[test]
    fn a_config_that_mentions_the_section_only_in_a_comment_is_rewritten() {
        let text = edited("# host_users: later\n");
        let mut harness = ready(FakeConfig::default());
        harness.root.write(CONFIG, &text);
        run(&mut harness, &options()).unwrap();
        assert_eq!(
            harness.root.read(CONFIG).unwrap(),
            render::agent_config("/var/lib/jaunt")
        );

        let mut harness = ready(FakeConfig::default());
        harness.root.write(CONFIG, &text);
        run(&mut harness, &flagged()).unwrap();
        let after = crate::run::config::load(&harness.root.path_of(CONFIG)).unwrap();
        assert_eq!(
            after.host_users,
            jaunt_host_users::HostUsersSection {
                enabled: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn a_dry_run_uninstall_plans_the_section_removal_instead_of_claiming_it() {
        let mut harness = ready(FakeConfig::default());
        run(&mut harness, &flagged()).unwrap();
        harness.dry_run = true;
        harness.report = Default::default();
        run_uninstall(&mut harness, false).unwrap();
        assert!(
            !harness
                .report
                .contains(Level::Info, "removed: the host_users section")
        );
        assert!(harness.report.contains(
            Level::Info,
            "plan: remove the host_users section together with /etc/jaunt/agent.yaml"
        ));
        assert!(harness.root.path_of(CONFIG).is_file());
    }

    #[test]
    fn every_unsafe_ancestor_is_listed_in_one_refusal() {
        let mut harness = ready(FakeConfig::default());
        chmod(&harness, "/usr/local", 0o2775);
        chmod(&harness, "/usr/local/bin", 0o2775);
        let text = run(&mut harness, &flagged()).unwrap_err().to_string();
        for part in [
            "/usr/local/bin is writable by group or others (mode 2775); /usr/local is writable by group or others (mode 2775)",
            "chmod g-w,o-w /usr/local/bin /usr/local",
            "/opt/jaunt/bin",
        ] {
            assert!(text.contains(part), "{part}: {text}");
        }
    }
}
