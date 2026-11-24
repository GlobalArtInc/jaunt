use std::fs;
use std::path::PathBuf;

use super::account::{self, Inspection};
use super::args::InstallOptions;
use super::env::{DirSpec, Env, Ledger, Replaced, Written, require_root};
use super::error::{
    ConfigTestOutcome, DROPIN_AND_UNIT_REMAIN, DROPIN_REMAINS, InstallError, RollbackOutcome,
};
use super::files::{self, Existing, RegularFile};
use super::layout::{
    CONFIG_DIR, DROPIN_DIR, DROPIN_PATH, INNER_CA_FILE, SERVICE_NAME, SSHD_CONFIG, UNIT_DIR,
    UNIT_PATH, inner_ca_path,
};
use super::render::{self, is_foreign};
use super::runner::{Output, RunnerError, excerpt};
use super::scan::find_user_ca_directives;
use super::service;
use super::sshd::{
    Effective, Expect, LOOPBACK_DEPLOY_SPEC, PROBES, Sshd, includes_dropin, preexisting_trust,
    serves_loopback,
};

pub fn install(env: &mut Env<'_>, opts: &InstallOptions) -> Result<(), InstallError> {
    require_root(env)?;
    let sshd = Sshd::locate(env.layout, &env.path_env)?;
    let inspection = preflight(env, &sshd, opts)?;
    let mut ledger = Ledger::default();
    if let Err(error) = stage_changes(env, &sshd, opts, &inspection, &mut ledger) {
        return Err(handle_stage_failure(env, opts, &ledger, error));
    }
    install_unit(env, opts)?;
    service_actions(env, opts)?;
    env.report.info(
        "next: run `jaunt-agent enroll --server <URL> --name <NAME>` to enroll this node, then `systemctl start jaunt-agent`",
    );
    Ok(())
}

fn stage_changes(
    env: &mut Env<'_>,
    sshd: &Sshd,
    opts: &InstallOptions,
    inspection: &Inspection,
    ledger: &mut Ledger,
) -> Result<(), InstallError> {
    ledger.preexisting_group_gid = inspection.group_gid.clone();
    account::ensure(env, &opts.user, &opts.state_dir, inspection, ledger)?;
    prepare_directories(env, opts, ledger)?;
    write_agent_config(env, opts, ledger)?;
    install_dropin(env, sshd, opts, ledger)
}

fn should_undo(error: &InstallError) -> bool {
    !matches!(
        error,
        InstallError::AfterCommit { .. }
            | InstallError::Validation {
                rollback: RollbackOutcome::Failed { .. },
                ..
            }
    )
}

fn handle_stage_failure(
    env: &mut Env<'_>,
    opts: &InstallOptions,
    ledger: &Ledger,
    error: InstallError,
) -> InstallError {
    if should_undo(&error) {
        undo(env, opts, ledger);
    } else if !matches!(error, InstallError::AfterCommit { .. }) {
        env.report.warn(
            "not cleaning up: the drop-in could not be rolled back, so the account, the state directory, inner-ca.pub and the agent configuration stay in place for it",
        );
    }
    error
}

fn after_commit(step: &str, error: &InstallError, remains: &'static str) -> InstallError {
    let detail = match error {
        InstallError::CommandFailed { status, stderr, .. } => format!("{status}: {stderr}"),
        other => other.to_string(),
    };
    InstallError::AfterCommit {
        step: step.to_string(),
        detail,
        remains,
    }
}

fn sshd_checked(sshd: &Sshd, tail: &[&str], output: Output) -> Result<Output, InstallError> {
    if output.success() {
        Ok(output)
    } else {
        Err(InstallError::CommandFailed {
            command: sshd.command_text(tail),
            status: output.status_text(),
            stderr: excerpt(&output.stderr),
        })
    }
}

fn refuse_existing_trust(
    scope: String,
    effective: &Effective,
    allowed: Option<&str>,
) -> Result<(), InstallError> {
    match preexisting_trust(effective, allowed) {
        None => Ok(()),
        Some(paths) => Err(InstallError::UserCaAlreadyTrusted { scope, paths }),
    }
}

fn preflight(
    env: &mut Env<'_>,
    sshd: &Sshd,
    opts: &InstallOptions,
) -> Result<Inspection, InstallError> {
    let config_path = env.layout.path(SSHD_CONFIG);
    let config_text =
        fs::read_to_string(&config_path).map_err(InstallError::io("read", &config_path))?;
    if !includes_dropin(&config_text) {
        return Err(InstallError::IncludeMissing {
            config: PathBuf::from(SSHD_CONFIG),
        });
    }

    if let Some(existing) = files::read_optional(&env.layout.path(DROPIN_PATH))?
        && is_foreign(&existing)
    {
        return Err(InstallError::ForeignDropin {
            path: DROPIN_PATH.to_string(),
        });
    }
    check_config_replaceable(env, &opts.config)?;
    if let Some(finding) = find_user_ca_directives(env.layout)?.into_iter().next() {
        return Err(InstallError::UserCaDirective {
            file: finding.file,
            line: finding.line,
            value: finding.value,
        });
    }

    let dump = sshd.effective(env, None)?;
    let dump = sshd_checked(sshd, &["-T"], dump)?;
    let global = Effective::parse(&dump.stdout);
    let listen = global.values("listenaddress");
    if !serves_loopback(&listen) {
        let listen = if listen.is_empty() {
            "none".to_string()
        } else {
            listen.join(", ")
        };
        return Err(InstallError::LoopbackNotServed { listen });
    }
    refuse_existing_trust("the global configuration".to_string(), &global, None)?;

    let ca_path = inner_ca_path(&opts.state_dir);
    let mut loopback = Effective::default();
    for (index, probe) in PROBES.iter().enumerate() {
        let output = sshd.effective(env, Some(probe.spec))?;
        let output = sshd_checked(sshd, &["-T", "-C", probe.spec], output)?;
        let effective = Effective::parse(&output.stdout);
        let allowed = (probe.expect == Expect::Trusted).then_some(ca_path.as_str());
        refuse_existing_trust(
            format!("connections matching `{}`", probe.spec),
            &effective,
            allowed,
        )?;
        if index == 0 {
            loopback = effective;
        }
    }
    warn_about_per_user_trust(env, sshd, &loopback)?;
    warn_about_loopback_settings(env, &loopback);

    check_state_dir_adoptable(env, &opts.state_dir)?;
    let inspection = account::inspect(env, &opts.user, &opts.state_dir)?;
    warn_about_selinux(env);
    env.report.info(
        "preflight passed: sshd includes the drop-in directory and serves loopback; no TrustedUserCAKeys was found in the configuration files or in the `sshd -T` probes",
    );
    Ok(inspection)
}

fn warn_about_per_user_trust(
    env: &mut Env<'_>,
    sshd: &Sshd,
    root_loopback: &Effective,
) -> Result<(), InstallError> {
    let output = sshd.effective(env, Some(LOOPBACK_DEPLOY_SPEC))?;
    let output = sshd_checked(sshd, &["-T", "-C", LOOPBACK_DEPLOY_SPEC], output)?;
    let deploy = Effective::parse(&output.stdout);
    let for_root = root_loopback.values("trustedusercakeys");
    let for_deploy = deploy.values("trustedusercakeys");
    if for_root != for_deploy {
        env.report.warn(format!(
            "`sshd -T` reports different TrustedUserCAKeys values for loopback connections of user root ({}) and user deploy ({}); check the per-user Match blocks of the sshd configuration",
            for_root.join(" "),
            for_deploy.join(" ")
        ));
    }
    Ok(())
}

fn warn_about_loopback_settings(env: &mut Env<'_>, loopback: &Effective) {
    if loopback.first("pubkeyauthentication") == Some("no") {
        env.report.warn(
            "sshd has `pubkeyauthentication no` for loopback connections; the agent logs in with a certificate and will be refused",
        );
    }
    if let Some(methods) = loopback.first("authenticationmethods")
        && methods != "any"
    {
        env.report.warn(format!(
            "sshd has a non-default `authenticationmethods {methods}` for loopback connections; the agent logs in with a certificate only and may be refused"
        ));
    }
}

fn warn_about_selinux(env: &mut Env<'_>) {
    if !env.live {
        return;
    }
    match env.query("getenforce", &[]) {
        Ok(output) if output.stdout.trim().eq_ignore_ascii_case("enforcing") => {
            env.report.warn(
                "SELinux is Enforcing; the label of the state directory may need review so that sshd can read inner-ca.pub",
            );
        }
        Ok(_) | Err(RunnerError::NotFound { .. }) => {}
        Err(error) => env
            .report
            .warn(format!("could not determine the SELinux mode: {error}")),
    }
}

const CONFIG_MODE: u32 = 0o644;

fn check_config_replaceable(env: &Env<'_>, config: &str) -> Result<(), InstallError> {
    existing_config(env, config).map(|_| ())
}

fn existing_config(env: &Env<'_>, config: &str) -> Result<Option<RegularFile>, InstallError> {
    let refuse = |reason: &'static str| InstallError::ForeignConfig {
        path: config.to_string(),
        reason,
    };
    match files::read_regular_no_follow(&env.layout.path(config))? {
        Existing::Absent => Ok(None),
        Existing::NotRegular => Err(refuse("it is a symbolic link or not a regular file")),
        Existing::Oversized => Err(refuse(
            "it is larger than 64 KiB, so it is not a configuration written by jaunt-agent",
        )),
        Existing::Regular(file) if is_foreign(&file.content) => Err(refuse(
            "it already exists and was not written by jaunt-agent (it does not start with the line `# Managed by jaunt-agent. Do not edit.`)",
        )),
        Existing::Regular(file) => Ok(Some(file)),
    }
}

fn config_parent(config: &str) -> &str {
    match config.rsplit_once('/') {
        Some((parent, _)) if !parent.is_empty() => parent,
        _ => "/",
    }
}

fn write_agent_config(
    env: &mut Env<'_>,
    opts: &InstallOptions,
    ledger: &mut Ledger,
) -> Result<(), InstallError> {
    let config = opts.config.as_str();
    let parent = config_parent(config);
    if parent != CONFIG_DIR {
        env.ensure_dir(
            parent,
            &DirSpec {
                mode: 0o755,
                owner: None,
                enforce: false,
            },
            ledger,
        )?;
    }
    let content = render::agent_config(&opts.state_dir);
    let previous = existing_config(env, config)?;
    let same_content = previous
        .as_ref()
        .is_some_and(|file| file.content == content.as_bytes());
    let settled = previous.as_ref().is_some_and(|file| {
        file.mode == CONFIG_MODE && (!env.live || (file.uid == 0 && file.gid == 0))
    });
    if same_content && settled {
        env.report.info(format!("unchanged: {config}"));
        return Ok(());
    }
    if env.dry_run {
        if same_content {
            env.report.plan(format!(
                "fix permissions of {config} (mode {CONFIG_MODE:04o}, owner root:root)"
            ));
        } else {
            env.report
                .plan(format!("write {config} (mode {CONFIG_MODE:04o})"));
            env.report.plan_block(&content);
        }
        return Ok(());
    }
    let path = env.layout.path(config);
    let sync_error = files::write_atomic(&path, content.as_bytes(), CONFIG_MODE)?;
    match previous {
        None => ledger.files.push(path),
        Some(file) => ledger.replaced.push(Replaced {
            path,
            content: file.content,
            mode: file.mode,
        }),
    }
    if same_content {
        env.report.info(format!(
            "fixed permissions: {config} (mode {CONFIG_MODE:04o}, owner root:root)"
        ));
    } else {
        env.report
            .info(format!("wrote: {config} (mode {CONFIG_MODE:04o})"));
    }
    match sync_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn check_state_dir_adoptable(env: &Env<'_>, state_dir: &str) -> Result<(), InstallError> {
    let path = env.layout.path(state_dir);
    let refuse = |reason: &'static str| InstallError::StateDirNotOurs {
        path: state_dir.to_string(),
        reason,
    };
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(InstallError::io("stat", &path)(source)),
    };
    if !metadata.is_dir() {
        return Err(refuse("it is a symbolic link or not a directory"));
    }
    if files::exists(&path.join(INNER_CA_FILE))? || files::is_empty_dir(&path)? {
        return Ok(());
    }
    Err(refuse(
        "it exists, is not empty and has no inner-ca.pub, so it is not a Jaunt state directory",
    ))
}

fn prepare_directories(
    env: &mut Env<'_>,
    opts: &InstallOptions,
    ledger: &mut Ledger,
) -> Result<(), InstallError> {
    env.ensure_dir(
        CONFIG_DIR,
        &DirSpec {
            mode: 0o755,
            owner: None,
            enforce: false,
        },
        ledger,
    )?;
    env.ensure_dir(
        &opts.state_dir,
        &DirSpec {
            mode: 0o700,
            owner: Some(&opts.user),
            enforce: true,
        },
        ledger,
    )?;
    env.ensure_empty_file(&inner_ca_path(&opts.state_dir), 0o644, &opts.user, ledger)
}

fn install_dropin(
    env: &mut Env<'_>,
    sshd: &Sshd,
    opts: &InstallOptions,
    ledger: &mut Ledger,
) -> Result<(), InstallError> {
    env.ensure_dir(
        DROPIN_DIR,
        &DirSpec {
            mode: 0o755,
            owner: None,
            enforce: false,
        },
        ledger,
    )?;
    let written = env.write_file(DROPIN_PATH, &render::dropin(&opts.state_dir), 0o644)?;
    finish_dropin(env, sshd, &inner_ca_path(&opts.state_dir), written)
}

fn finish_dropin(
    env: &mut Env<'_>,
    sshd: &Sshd,
    ca_path: &str,
    written: Written,
) -> Result<(), InstallError> {
    if env.dry_run {
        for command in sshd.validation_plan() {
            env.report.plan(format!("validate: run {command}"));
        }
        return Ok(());
    }
    match sshd.validate_dropin(env, ca_path) {
        Ok(()) => {
            if let Some(error) = &written.sync_error {
                return Err(after_commit(
                    "syncing the sshd drop-in directory",
                    error,
                    DROPIN_REMAINS,
                ));
            }
            env.report.info(
                "validated: `sshd -t` passes; `sshd -T -C` shows the inner CA for the loopback probes and no user CA for the outside probes",
            );
            Ok(())
        }
        Err(problem) => {
            let rollback = roll_back(env, sshd, &written);
            Err(InstallError::Validation { problem, rollback })
        }
    }
}

fn roll_back(env: &mut Env<'_>, sshd: &Sshd, written: &Written) -> RollbackOutcome {
    let path = env.layout.path(DROPIN_PATH);
    let action = match (&written.previous, written.changed) {
        (_, false) => "left the existing drop-in in place",
        (Some(previous), true) => {
            let mode = written.previous_mode.unwrap_or(0o644);
            match files::write_atomic(&path, previous, mode) {
                Ok(None) => "restored the previous drop-in",
                Ok(Some(error)) => {
                    return RollbackOutcome::Failed {
                        reason: format!(
                            "the previous drop-in was restored but could not be synced: {error}"
                        ),
                    };
                }
                Err(error) => {
                    return RollbackOutcome::Failed {
                        reason: error.to_string(),
                    };
                }
            }
        }
        (None, true) => match files::remove_file(&path) {
            Ok(_) => "removed the new drop-in",
            Err(error) => {
                return RollbackOutcome::Failed {
                    reason: error.to_string(),
                };
            }
        },
    };
    let config_test = match sshd.syntax_check(env) {
        Ok(output) if output.success() => ConfigTestOutcome::Passed,
        Ok(output) => ConfigTestOutcome::Failed(excerpt(&output.stderr)),
        Err(error) => ConfigTestOutcome::Failed(error.to_string()),
    };
    RollbackOutcome::Done {
        action,
        config_test,
    }
}

fn undo(env: &mut Env<'_>, opts: &InstallOptions, ledger: &Ledger) {
    if env.dry_run || ledger.is_empty() {
        return;
    }
    for adopted in ledger.adopted.iter().rev() {
        if let Err(error) = files::set_mode(&adopted.path, adopted.mode) {
            env.report.warn(format!(
                "could not restore the mode of {}: {error}",
                adopted.path.display()
            ));
        }
        if env.live {
            let owner = format!("{}:{}", adopted.uid, adopted.gid);
            let path = adopted.path.to_string_lossy().into_owned();
            account::run_or_warn(env, "chown", &[&owner, &path]);
        }
    }
    for replaced in ledger.replaced.iter().rev() {
        match files::write_atomic(&replaced.path, &replaced.content, replaced.mode) {
            Ok(None) => {}
            Ok(Some(error)) => env.report.warn(format!(
                "restored {} but could not sync its directory: {error}",
                replaced.path.display()
            )),
            Err(error) => env.report.warn(format!(
                "could not restore the previous {}: {error}",
                replaced.path.display()
            )),
        }
    }
    for file in ledger.files.iter().rev() {
        match files::remove_file(file) {
            Ok(_) => {}
            Err(error) => env
                .report
                .warn(format!("could not remove {}: {error}", file.display())),
        }
    }
    for dir in ledger.dirs.iter().rev() {
        match files::remove_dir(dir) {
            Ok(_) => {}
            Err(error) => env
                .report
                .warn(format!("left {} in place: {error}", dir.display())),
        }
    }
    account::undo(env, &opts.user, ledger);
    env.report
        .info("cleaned up everything this failed run created");
}

fn install_unit(env: &mut Env<'_>, opts: &InstallOptions) -> Result<(), InstallError> {
    let step = "writing the unit file";
    let mut ledger = Ledger::default();
    env.ensure_dir(
        UNIT_DIR,
        &DirSpec {
            mode: 0o755,
            owner: None,
            enforce: false,
        },
        &mut ledger,
    )
    .map_err(|error| after_commit(step, &error, DROPIN_REMAINS))?;
    let unit = render::unit(&opts.user, &opts.binary, &opts.config, &opts.state_dir);
    let written = env
        .write_file(UNIT_PATH, &unit, 0o644)
        .map_err(|error| after_commit(step, &error, DROPIN_REMAINS))?;
    match written.sync_error {
        Some(error) => Err(after_commit(step, &error, DROPIN_AND_UNIT_REMAIN)),
        None => Ok(()),
    }
}

fn service_actions(env: &mut Env<'_>, opts: &InstallOptions) -> Result<(), InstallError> {
    if !service::manage(env, opts.no_service) {
        service::skipped_note(env, opts.no_service);
        return Ok(());
    }
    service::daemon_reload(env).map_err(|error| {
        after_commit("`systemctl daemon-reload`", &error, DROPIN_AND_UNIT_REMAIN)
    })?;
    service::reload_sshd(env)
        .map_err(|error| after_commit("the sshd reload", &error, DROPIN_AND_UNIT_REMAIN))?;
    service::enable(env).map_err(|error| {
        after_commit(
            &format!("`systemctl enable {SERVICE_NAME}`"),
            &error,
            DROPIN_AND_UNIT_REMAIN,
        )
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;

    use super::super::args::InstallOptions;
    use super::super::env::{Ledger, Written};
    use super::super::error::{
        ConfigTestOutcome, DROPIN_REMAINS, InstallError, RollbackOutcome, ValidationProblem,
    };
    use super::super::layout::{DROPIN_PATH, UNIT_PATH};
    use super::super::render;
    use super::super::report::Level;
    use super::super::sshd::{LOOPBACK_DEPLOY_SPEC, PROBES, Sshd};
    use super::super::testing::{FakeConfig, Harness, Setup, options, symlink_to_managed_config};
    use super::{finish_dropin, handle_stage_failure, install, should_undo};
    use crate::run::config;

    const CA: &str = "/var/lib/jaunt/inner-ca.pub";
    const CONFIG: &str = "/etc/jaunt/agent.yaml";

    fn run(harness: &mut Harness, opts: &InstallOptions) -> Result<(), InstallError> {
        let mut env = harness.env();
        install(&mut env, opts)
    }

    fn with_services() -> InstallOptions {
        InstallOptions {
            no_service: false,
            ..options()
        }
    }

    fn mode(harness: &Harness, path: &str) -> u32 {
        fs::metadata(harness.root.path_of(path))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    fn chmod(harness: &Harness, path: &str, mode: u32) {
        fs::set_permissions(harness.root.path_of(path), fs::Permissions::from_mode(mode)).unwrap();
    }

    fn has_call(harness: &Harness, prefix: &str) -> bool {
        harness.calls().iter().any(|call| call.starts_with(prefix))
    }

    #[test]
    fn installs_files_with_expected_content_and_modes() {
        let mut harness = Harness::new(FakeConfig::default());
        run(&mut harness, &options()).unwrap();
        assert_eq!(
            harness.root.read(DROPIN_PATH).unwrap(),
            "# Managed by jaunt-agent. Do not edit.\nMatch Address 127.0.0.1,::1\n    TrustedUserCAKeys /var/lib/jaunt/inner-ca.pub\n"
        );
        let unit = harness.root.read(UNIT_PATH).unwrap();
        assert!(unit.contains("NoNewPrivileges=yes\n"));
        assert!(
            unit.contains(
                "ExecStart=/usr/local/bin/jaunt-agent run --config /etc/jaunt/agent.yaml\n"
            )
        );
        assert!(unit.contains("\nLimitCORE=0\nMemorySwapMax=0\n"));
        assert_eq!(
            harness.root.read(CONFIG).unwrap(),
            "# Managed by jaunt-agent. Do not edit.\nstate_dir: /var/lib/jaunt\nlog_level: info\n"
        );
        assert_eq!(mode(&harness, DROPIN_PATH), 0o644);
        assert_eq!(mode(&harness, UNIT_PATH), 0o644);
        assert_eq!(mode(&harness, CONFIG), 0o644);
        assert_eq!(mode(&harness, "/etc/jaunt"), 0o755);
        assert_eq!(mode(&harness, "/var/lib/jaunt"), 0o700);
        assert_eq!(mode(&harness, "/var/lib/jaunt/inner-ca.pub"), 0o644);
        assert_eq!(
            harness.root.read("/var/lib/jaunt/inner-ca.pub").unwrap(),
            ""
        );
        assert!(!has_call(&harness, "systemctl"));
    }

    #[test]
    fn commands_run_in_the_documented_order() {
        let mut harness = Harness::new(FakeConfig::default());
        harness.live = true;
        run(&mut harness, &with_services()).unwrap();
        let sshd = "/usr/sbin/sshd -f /etc/ssh/sshd_config";
        let probe_commands = |specs: Vec<&str>| -> Vec<String> {
            specs
                .into_iter()
                .map(|spec| format!("{sshd} -T -C {spec}"))
                .collect()
        };
        let probe_specs: Vec<&str> = PROBES.iter().map(|probe| probe.spec).collect();
        let mut expected = vec!["id -u".to_string(), format!("{sshd} -T")];
        expected.extend(probe_commands(probe_specs.clone()));
        expected.extend(probe_commands(vec![LOOPBACK_DEPLOY_SPEC]));
        expected.extend(
            [
                "getent group jaunt",
                "getent passwd jaunt",
                "getenforce",
                "groupadd --system jaunt",
                "useradd --system --gid jaunt --home-dir /var/lib/jaunt --no-create-home --shell /usr/sbin/nologin jaunt",
                "chown jaunt:jaunt /var/lib/jaunt",
                "chown jaunt:jaunt /var/lib/jaunt/inner-ca.pub",
            ]
            .map(String::from),
        );
        expected.push(format!("{sshd} -t"));
        expected.extend(probe_commands(probe_specs));
        expected.extend(
            [
                "systemctl daemon-reload",
                "systemctl reload ssh",
                "systemctl enable jaunt-agent",
            ]
            .map(String::from),
        );
        assert_eq!(harness.calls(), expected);
    }

    #[test]
    fn second_run_changes_nothing_and_keeps_the_inner_ca_file() {
        let mut harness = Harness::new(FakeConfig::default());
        run(&mut harness, &options()).unwrap();
        harness
            .root
            .write("/var/lib/jaunt/inner-ca.pub", "ssh-ed25519 AAAA\n");
        let before = harness.root.snapshot();
        harness.report = Default::default();
        run(&mut harness, &options()).unwrap();
        assert_eq!(harness.root.snapshot(), before);
        assert!(harness.report.contains(
            Level::Info,
            "unchanged: /etc/ssh/sshd_config.d/50-jaunt.conf"
        ));
        assert!(harness.report.contains(
            Level::Info,
            "unchanged: /etc/systemd/system/jaunt-agent.service"
        ));
        assert!(
            harness
                .report
                .contains(Level::Info, "unchanged: /etc/jaunt/agent.yaml")
        );
    }

    #[test]
    fn identical_files_with_a_different_mode_get_their_permissions_fixed() {
        let mut harness = Harness::new(FakeConfig::default());
        run(&mut harness, &options()).unwrap();
        chmod(&harness, DROPIN_PATH, 0o600);
        chmod(&harness, UNIT_PATH, 0o666);
        chmod(&harness, CONFIG, 0o600);
        harness.report = Default::default();
        run(&mut harness, &options()).unwrap();
        assert_eq!(mode(&harness, DROPIN_PATH), 0o644);
        assert_eq!(mode(&harness, UNIT_PATH), 0o644);
        assert_eq!(mode(&harness, CONFIG), 0o644);
        assert!(harness.report.contains(
            Level::Info,
            "fixed permissions: /etc/ssh/sshd_config.d/50-jaunt.conf"
        ));
        assert!(
            !harness
                .report
                .contains(Level::Info, "unchanged: /etc/ssh/sshd_config.d")
        );
    }

    #[test]
    fn identical_files_owned_by_someone_else_are_chowned_to_root_when_live() {
        let mut harness = Harness::new(FakeConfig::default());
        run(&mut harness, &options()).unwrap();
        let not_root = fs::metadata(harness.root.path_of(DROPIN_PATH))
            .unwrap()
            .uid()
            != 0;
        harness.live = true;
        harness.runner.calls.clear();
        run(&mut harness, &options()).unwrap();
        let chowned = harness
            .calls()
            .contains(&format!("chown root:root {DROPIN_PATH}"));
        assert_eq!(chowned, not_root);
        assert!(!has_call(&harness, &format!("chown root:root {CONFIG}")));
        assert_eq!(
            harness
                .report
                .contains(Level::Info, "fixed permissions: /etc/jaunt/agent.yaml"),
            not_root
        );
    }

    #[test]
    fn a_config_with_the_right_content_but_a_wrong_mode_is_rewritten_and_restored_on_failure() {
        let mut harness = Harness::new(FakeConfig {
            sshd_t_rejects_trust_line: true,
            ..FakeConfig::default()
        });
        harness
            .root
            .write(CONFIG, &render::agent_config("/var/lib/jaunt"));
        chmod(&harness, CONFIG, 0o600);
        run(&mut harness, &options()).unwrap_err();
        assert_eq!(mode(&harness, CONFIG), 0o600);
        assert!(
            harness
                .report
                .contains(Level::Info, "fixed permissions: /etc/jaunt/agent.yaml")
        );
    }

    #[test]
    fn a_custom_config_in_an_existing_directory_leaves_its_mode_alone() {
        let mut harness = Harness::new(FakeConfig::default());
        fs::create_dir_all(harness.root.path_of("/opt/jaunt")).unwrap();
        chmod(&harness, "/opt/jaunt", 0o750);
        let opts = InstallOptions {
            config: "/opt/jaunt/agent.yaml".to_string(),
            ..options()
        };
        run(&mut harness, &opts).unwrap();
        assert_eq!(mode(&harness, "/opt/jaunt"), 0o750);
        assert_eq!(mode(&harness, "/opt/jaunt/agent.yaml"), 0o644);
    }

    #[test]
    fn existing_etc_jaunt_keeps_its_mode_and_an_existing_state_dir_is_tightened() {
        let mut harness = Harness::new(FakeConfig::default());
        harness.root.write("/etc/jaunt/other.yaml", "x: 1\n");
        chmod(&harness, "/etc/jaunt", 0o750);
        harness
            .root
            .write("/var/lib/jaunt/inner-ca.pub", "ssh-ed25519 AAAA\n");
        chmod(&harness, "/var/lib/jaunt", 0o755);
        run(&mut harness, &options()).unwrap();
        assert_eq!(mode(&harness, "/etc/jaunt"), 0o750);
        assert_eq!(mode(&harness, "/var/lib/jaunt"), 0o700);
        assert_eq!(
            harness.root.read("/var/lib/jaunt/inner-ca.pub").unwrap(),
            "ssh-ed25519 AAAA\n"
        );
    }

    #[test]
    fn foreign_state_dir_is_refused_before_any_change_and_never_touched() {
        let mut harness = Harness::new(FakeConfig::default());
        harness.live = true;
        harness.root.write("/var/lib/jaunt/precious", "data");
        chmod(&harness, "/var/lib/jaunt", 0o755);
        let before = harness.root.snapshot();
        let error = run(&mut harness, &options()).unwrap_err();
        assert!(
            matches!(error, InstallError::StateDirNotOurs { .. }),
            "{error}"
        );
        assert_eq!(harness.root.snapshot(), before);
        assert!(!has_call(&harness, "chown"));
        assert!(!has_call(&harness, "groupadd"));
        assert!(!has_call(&harness, "useradd"));
    }

    #[test]
    fn symlinked_state_dir_is_refused() {
        let mut harness = Harness::new(FakeConfig::default());
        fs::create_dir_all(harness.root.path_of("/var/lib")).unwrap();
        fs::create_dir_all(harness.root.path_of("/srv/elsewhere")).unwrap();
        std::os::unix::fs::symlink(
            harness.root.path_of("/srv/elsewhere"),
            harness.root.path_of("/var/lib/jaunt"),
        )
        .unwrap();
        let error = run(&mut harness, &options()).unwrap_err();
        assert!(
            matches!(error, InstallError::StateDirNotOurs { .. }),
            "{error}"
        );
    }

    #[test]
    fn empty_existing_state_dir_is_adopted() {
        let mut harness = Harness::new(FakeConfig::default());
        fs::create_dir_all(harness.root.path_of("/var/lib/jaunt")).unwrap();
        chmod(&harness, "/var/lib/jaunt", 0o755);
        run(&mut harness, &options()).unwrap();
        assert_eq!(mode(&harness, "/var/lib/jaunt"), 0o700);
    }

    #[test]
    fn failed_validation_removes_the_new_dropin_and_leaves_a_clean_machine() {
        let mut harness = Harness::new(FakeConfig::default());
        harness.live = true;
        harness.runner.config.sshd_t_rejects_trust_line = true;
        let before = harness.root.snapshot();
        let error = run(&mut harness, &with_services()).unwrap_err();
        assert!(matches!(
            error,
            InstallError::Validation {
                problem: ValidationProblem::ConfigTest { .. },
                rollback: RollbackOutcome::Done {
                    config_test: ConfigTestOutcome::Passed,
                    ..
                },
            }
        ));
        assert_eq!(harness.root.snapshot(), before);
        let calls = harness.calls();
        assert_eq!(calls.iter().filter(|c| c.ends_with(" -t")).count(), 2);
        assert!(!has_call(&harness, "systemctl"));
        assert!(calls.contains(&"userdel jaunt".to_string()));
        assert!(!has_call(&harness, "groupdel"));
        assert!(!has_call(&harness, "groupadd --system --gid"));
    }

    #[test]
    fn failed_install_removes_a_group_it_created_when_userdel_leaves_it_behind() {
        let mut harness = Harness::new(FakeConfig {
            userdel_keeps_group: true,
            sshd_t_rejects_trust_line: true,
            ..FakeConfig::default()
        });
        harness.live = true;
        run(&mut harness, &options()).unwrap_err();
        let calls = harness.calls();
        assert!(calls.contains(&"userdel jaunt".to_string()));
        assert!(calls.contains(&"groupdel jaunt".to_string()));
    }

    #[test]
    fn failed_install_recreates_a_preexisting_group_that_userdel_removed() {
        let mut harness = Harness::new(FakeConfig {
            existing_group: true,
            sshd_t_rejects_trust_line: true,
            ..FakeConfig::default()
        });
        harness.live = true;
        run(&mut harness, &options()).unwrap_err();
        let calls = harness.calls();
        assert!(calls.contains(&"userdel jaunt".to_string()));
        assert!(calls.contains(&"groupadd --system --gid 995 jaunt".to_string()));
        assert!(!has_call(&harness, "groupdel"));
        assert!(
            harness
                .report
                .contains(Level::Info, "re-created group jaunt (gid 995)")
        );

        let mut harness = Harness::new(FakeConfig {
            existing_group: true,
            existing_user_shell: Some("/usr/sbin/nologin".to_string()),
            sshd_t_rejects_trust_line: true,
            ..FakeConfig::default()
        });
        harness.live = true;
        run(&mut harness, &options()).unwrap_err();
        assert!(!has_call(&harness, "userdel"));
        assert!(!has_call(&harness, "groupdel"));
    }

    #[test]
    fn rollback_reports_when_sshd_still_rejects_the_configuration() {
        let mut harness = Harness::new(FakeConfig {
            sshd_t_always_fails: true,
            ..FakeConfig::default()
        });
        let error = run(&mut harness, &options()).unwrap_err();
        assert!(matches!(
            error,
            InstallError::Validation {
                rollback: RollbackOutcome::Done {
                    config_test: ConfigTestOutcome::Failed(_),
                    ..
                },
                ..
            }
        ));
        assert!(error.to_string().contains("STILL FAILS"), "{error}");
    }

    #[test]
    fn failed_validation_restores_the_previous_dropin_with_its_mode() {
        let mut harness = Harness::new(FakeConfig {
            sshd_t_rejects_trust_line: true,
            ..FakeConfig::default()
        });
        let previous = format!("{}\n# previous\n", render::MANAGED_HEADER);
        harness.root.write(DROPIN_PATH, &previous);
        chmod(&harness, DROPIN_PATH, 0o600);
        let error = run(&mut harness, &options()).unwrap_err();
        assert!(error.to_string().contains("restored the previous drop-in"));
        assert_eq!(harness.root.read(DROPIN_PATH).unwrap(), previous);
        assert_eq!(mode(&harness, DROPIN_PATH), 0o600);
    }

    #[test]
    fn foreign_dropin_is_refused_before_any_change_and_left_intact() {
        let mut harness = Harness::new(FakeConfig::default());
        harness.live = true;
        harness
            .root
            .write(DROPIN_PATH, "# somebody else's file\nLogLevel DEBUG\n");
        let before = harness.root.snapshot();
        let error = run(&mut harness, &options()).unwrap_err();
        assert!(
            matches!(error, InstallError::ForeignDropin { .. }),
            "{error}"
        );
        assert_eq!(harness.root.snapshot(), before);
        for mutating in ["groupadd", "useradd", "chown", "systemctl"] {
            assert!(!has_call(&harness, mutating), "{mutating}");
        }
    }

    #[test]
    fn an_empty_dropin_is_overwritten_and_an_own_one_is_accepted() {
        for existing in ["", render::dropin("/var/lib/jaunt").as_str()] {
            let mut harness = Harness::new(FakeConfig::default());
            harness.root.write(DROPIN_PATH, existing);
            run(&mut harness, &options()).unwrap();
            assert_eq!(
                harness.root.read(DROPIN_PATH).unwrap(),
                render::dropin("/var/lib/jaunt")
            );
        }
    }

    #[test]
    fn a_custom_state_dir_reaches_the_agent_through_the_config_file() {
        let mut harness = Harness::new(FakeConfig::default());
        let opts = InstallOptions {
            state_dir: "/srv/jaunt/state".to_string(),
            ..options()
        };
        run(&mut harness, &opts).unwrap();
        let loaded = config::load(&harness.root.path_of(CONFIG)).unwrap();
        assert_eq!(loaded.state_dir, Some(PathBuf::from("/srv/jaunt/state")));
        assert_eq!(loaded.log_level.as_deref(), Some("info"));
    }

    #[test]
    fn foreign_config_is_refused_before_any_change_and_left_intact() {
        let setups: [(Setup, &str); 4] = [
            (
                |harness| harness.root.write(CONFIG, "state_dir: /srv/mine/state\n"),
                "was not written by jaunt-agent",
            ),
            (
                |harness| {
                    let big = render::agent_config("/var/lib/jaunt") + &"#".repeat(64 * 1024);
                    harness.root.write(CONFIG, &big);
                },
                "larger than 64 KiB",
            ),
            (
                |harness| symlink_to_managed_config(&harness.root, CONFIG),
                "symbolic link or not a regular file",
            ),
            (
                |harness| fs::create_dir_all(harness.root.path_of(CONFIG)).unwrap(),
                "symbolic link or not a regular file",
            ),
        ];
        for (setup, reason) in setups {
            let mut harness = Harness::new(FakeConfig::default());
            harness.live = true;
            setup(&harness);
            let before = harness.root.snapshot();
            let error = run(&mut harness, &options()).unwrap_err();
            assert!(
                matches!(error, InstallError::ForeignConfig { .. }),
                "{error}"
            );
            assert!(error.to_string().contains(reason), "{error}");
            assert!(error.to_string().contains(CONFIG), "{error}");
            assert_eq!(harness.root.snapshot(), before);
            for mutating in ["groupadd", "useradd", "chown", "systemctl"] {
                assert!(!has_call(&harness, mutating), "{mutating}");
            }
        }
    }

    #[test]
    fn an_empty_config_and_an_own_one_for_another_state_dir_are_rewritten() {
        for existing in ["", render::agent_config("/srv/old/state").as_str()] {
            let mut harness = Harness::new(FakeConfig::default());
            harness.root.write(CONFIG, existing);
            run(&mut harness, &options()).unwrap();
            assert_eq!(
                harness.root.read(CONFIG).unwrap(),
                render::agent_config("/var/lib/jaunt")
            );
            assert!(
                harness
                    .report
                    .contains(Level::Info, "wrote: /etc/jaunt/agent.yaml (mode 0644)")
            );
        }
    }

    #[test]
    fn failed_validation_restores_the_previous_config_with_its_mode() {
        let mut harness = Harness::new(FakeConfig {
            sshd_t_rejects_trust_line: true,
            ..FakeConfig::default()
        });
        let previous = render::agent_config("/srv/old/state");
        harness.root.write(CONFIG, &previous);
        chmod(&harness, CONFIG, 0o600);
        run(&mut harness, &options()).unwrap_err();
        assert_eq!(harness.root.read(CONFIG).unwrap(), previous);
        assert_eq!(mode(&harness, CONFIG), 0o600);
    }

    #[test]
    fn a_config_in_a_custom_directory_is_written_there_and_removed_with_it_on_failure() {
        let opts = InstallOptions {
            config: "/opt/jaunt/conf/agent.yaml".to_string(),
            ..options()
        };
        let mut harness = Harness::new(FakeConfig::default());
        run(&mut harness, &opts).unwrap();
        assert_eq!(
            harness.root.read("/opt/jaunt/conf/agent.yaml").unwrap(),
            render::agent_config("/var/lib/jaunt")
        );
        assert!(
            harness
                .root
                .read(UNIT_PATH)
                .unwrap()
                .contains("run --config /opt/jaunt/conf/agent.yaml\n")
        );

        let mut harness = Harness::new(FakeConfig {
            sshd_t_rejects_trust_line: true,
            ..FakeConfig::default()
        });
        let before = harness.root.snapshot();
        run(&mut harness, &opts).unwrap_err();
        assert_eq!(harness.root.snapshot(), before);
    }

    #[test]
    fn trust_that_leaks_beyond_loopback_is_rejected_and_rolled_back() {
        let mut harness = Harness::new(FakeConfig {
            leak_trust_outside_loopback: true,
            ..FakeConfig::default()
        });
        let error = run(&mut harness, &options()).unwrap_err();
        assert!(
            matches!(
                error,
                InstallError::Validation {
                    problem: ValidationProblem::Mismatch { .. },
                    ..
                }
            ),
            "{error}"
        );
        assert!(error.to_string().contains(PROBES[2].spec), "{error}");
        assert_eq!(harness.root.read(DROPIN_PATH), None);
    }

    #[test]
    fn sync_error_after_the_rename_still_goes_through_validation() {
        let sync_error = || InstallError::Io {
            op: "fsync",
            path: PathBuf::from("/etc/ssh/sshd_config.d"),
            source: std::io::Error::other("injected"),
        };
        let written = |sync_error| Written {
            previous: None,
            previous_mode: None,
            changed: true,
            sync_error,
        };

        let mut harness = Harness::new(FakeConfig::default());
        harness
            .root
            .write(DROPIN_PATH, &render::dropin("/var/lib/jaunt"));
        let sshd = Sshd::locate(&harness.layout, "").unwrap();
        let mut env = harness.env();
        let error = finish_dropin(&mut env, &sshd, CA, written(Some(sync_error()))).unwrap_err();
        assert!(matches!(error, InstallError::AfterCommit { .. }), "{error}");
        assert!(
            error
                .to_string()
                .contains("the validated sshd drop-in stays in place")
        );
        assert!(!error.to_string().contains("unit file"), "{error}");
        assert!(harness.root.read(DROPIN_PATH).is_some());

        let mut harness = Harness::new(FakeConfig {
            sshd_t_rejects_trust_line: true,
            ..FakeConfig::default()
        });
        harness
            .root
            .write(DROPIN_PATH, &render::dropin("/var/lib/jaunt"));
        let sshd = Sshd::locate(&harness.layout, "").unwrap();
        let mut env = harness.env();
        let error = finish_dropin(&mut env, &sshd, CA, written(Some(sync_error()))).unwrap_err();
        assert!(matches!(error, InstallError::Validation { .. }), "{error}");
        assert_eq!(harness.root.read(DROPIN_PATH), None);
    }

    #[test]
    fn preexisting_user_ca_trust_refuses_before_any_change() {
        for config in [
            FakeConfig {
                foreign_global_ca: Some("/etc/ssh/corp-ca.pub".to_string()),
                ..FakeConfig::default()
            },
            FakeConfig {
                deploy_user_ca: Some("/etc/ssh/corp-ca.pub".to_string()),
                foreign_global_ca: Some("/etc/ssh/corp-ca.pub".to_string()),
                ..FakeConfig::default()
            },
        ] {
            let mut harness = Harness::new(config);
            harness.live = true;
            let before = harness.root.snapshot();
            let error = run(&mut harness, &options()).unwrap_err();
            assert!(
                matches!(error, InstallError::UserCaAlreadyTrusted { .. }),
                "{error}"
            );
            assert!(error.to_string().contains("/etc/ssh/corp-ca.pub"));
            assert!(
                error
                    .to_string()
                    .contains("trusts no user CA for outside connections")
            );
            assert_eq!(harness.root.snapshot(), before);
            for mutating in ["groupadd", "useradd", "chown", "systemctl"] {
                assert!(!has_call(&harness, mutating), "{mutating}");
            }
        }
    }

    #[test]
    fn foreign_ca_on_one_outside_subnet_or_only_for_loopback_refuses_before_any_change() {
        for client in ["203.0.113.9", "10.255.255.1", "127.0.0.1", "::1"] {
            let mut harness = Harness::new(FakeConfig {
                foreign_ca_for_client: Some((
                    client.to_string(),
                    "/etc/ssh/lan-ca.pub".to_string(),
                )),
                ..FakeConfig::default()
            });
            harness.live = true;
            let before = harness.root.snapshot();
            let error = run(&mut harness, &options()).unwrap_err();
            assert!(
                matches!(error, InstallError::UserCaAlreadyTrusted { .. }),
                "{client}: {error}"
            );
            assert!(
                error.to_string().contains("/etc/ssh/lan-ca.pub"),
                "{client}: {error}"
            );
            assert_eq!(harness.root.snapshot(), before, "{client}");
            for mutating in ["groupadd", "useradd", "chown", "systemctl"] {
                assert!(!has_call(&harness, mutating), "{client}: {mutating}");
            }
        }
    }

    #[test]
    fn our_own_trust_leaking_to_outside_addresses_refuses_before_any_change() {
        let mut harness = Harness::new(FakeConfig {
            leak_trust_outside_loopback: true,
            ..FakeConfig::default()
        });
        harness
            .root
            .write(DROPIN_PATH, &render::dropin("/var/lib/jaunt"));
        let before = harness.root.snapshot();
        let error = run(&mut harness, &options()).unwrap_err();
        assert!(
            matches!(error, InstallError::UserCaAlreadyTrusted { .. }),
            "{error}"
        );
        assert!(error.to_string().contains(CA), "{error}");
        assert_eq!(harness.root.snapshot(), before);
    }

    #[test]
    fn user_ca_directives_in_config_files_refuse_with_file_and_line() {
        let cases = [
            (
                "/etc/ssh/sshd_config.d/10-corp.conf",
                "Port 22\nMatch Address 192.168.0.0/16\n    TrustedUserCAKeys /etc/ssh/corp-ca.pub\n",
                "/etc/ssh/sshd_config.d/10-corp.conf:3:",
            ),
            (
                "/etc/ssh/sshd_config.d/20-users.conf",
                "Match User deploy\n    TrustedUserCAKeys /etc/ssh/corp-ca.pub\n",
                "/etc/ssh/sshd_config.d/20-users.conf:2:",
            ),
            (
                "/etc/ssh/sshd_config",
                "Include /etc/ssh/sshd_config.d/*.conf\nTrustedUserCAKeys /etc/ssh/corp-ca.pub\n",
                "/etc/ssh/sshd_config:2:",
            ),
        ];
        for (file, content, expected) in cases {
            let mut harness = Harness::new(FakeConfig::default());
            harness.live = true;
            harness.root.write(file, content);
            let before = harness.root.snapshot();
            let error = run(&mut harness, &options()).unwrap_err();
            assert!(
                matches!(error, InstallError::UserCaDirective { .. }),
                "{error}"
            );
            let text = error.to_string();
            assert!(text.contains(expected), "{text}");
            assert!(text.contains("/etc/ssh/corp-ca.pub"), "{text}");
            assert!(
                text.contains("trusts no user CA for outside connections"),
                "{text}"
            );
            assert_eq!(harness.root.snapshot(), before);
            assert_eq!(harness.calls(), vec!["id -u".to_string()]);
        }
    }

    #[test]
    fn trusted_user_ca_keys_none_and_our_own_dropin_do_not_block_the_install() {
        let mut harness = Harness::new(FakeConfig::default());
        harness.root.write(
            "/etc/ssh/sshd_config.d/10-none.conf",
            "TrustedUserCAKeys none\n",
        );
        run(&mut harness, &options()).unwrap();
        run(&mut harness, &options()).unwrap();
    }

    #[test]
    fn per_user_probe_difference_only_warns_without_claiming_an_override() {
        let mut harness = Harness::new(FakeConfig {
            deploy_user_ca: Some("/etc/ssh/deploy-ca.pub".to_string()),
            ..FakeConfig::default()
        });
        run(&mut harness, &options()).unwrap();
        assert!(
            harness
                .report
                .contains(Level::Warn, "user deploy (/etc/ssh/deploy-ca.pub)")
        );
        assert!(!harness.report.contains(Level::Warn, "overrides"));
    }

    #[test]
    fn success_lines_claim_only_what_was_checked() {
        let mut harness = Harness::new(FakeConfig::default());
        run(&mut harness, &options()).unwrap();
        assert!(harness.report.contains(
            Level::Info,
            "no TrustedUserCAKeys was found in the configuration files or in the `sshd -T` probes"
        ));
        assert!(harness.report.contains(
            Level::Info,
            "`sshd -T -C` shows the inner CA for the loopback probes and no user CA for the outside probes"
        ));
    }

    #[test]
    fn missing_include_refuses_without_touching_anything() {
        let mut harness = Harness::new(FakeConfig::default());
        harness.root.write("/etc/ssh/sshd_config", "Port 22\n");
        let before = harness.root.snapshot();
        let error = run(&mut harness, &options()).unwrap_err();
        assert!(matches!(error, InstallError::IncludeMissing { .. }));
        assert_eq!(harness.root.snapshot(), before);
        assert_eq!(harness.calls(), vec!["id -u".to_string()]);
    }

    #[test]
    fn loopback_not_served_refuses_with_an_instruction() {
        let mut harness = Harness::new(FakeConfig {
            listen: vec!["192.0.2.1:22".to_string()],
            ..FakeConfig::default()
        });
        harness.live = true;
        let before = harness.root.snapshot();
        let error = run(&mut harness, &options()).unwrap_err();
        assert!(matches!(error, InstallError::LoopbackNotServed { .. }));
        assert!(error.to_string().contains("ListenAddress 127.0.0.1"));
        assert_eq!(harness.root.snapshot(), before);
        assert!(!has_call(&harness, "getent"));
    }

    #[test]
    fn refuses_to_run_as_non_root() {
        let mut harness = Harness::new(FakeConfig {
            uid: "1000".to_string(),
            ..FakeConfig::default()
        });
        let error = run(&mut harness, &options()).unwrap_err();
        assert!(matches!(error, InstallError::NotRoot { .. }));
        assert_eq!(harness.calls(), vec!["id -u".to_string()]);
    }

    #[test]
    fn dry_run_prints_the_plan_and_changes_nothing() {
        let mut harness = Harness::new(FakeConfig::default());
        harness.live = true;
        harness.dry_run = true;
        let before = harness.root.snapshot();
        run(&mut harness, &with_services()).unwrap();
        assert_eq!(harness.root.snapshot(), before);
        assert!(harness.report.contains(
            Level::Info,
            "plan: write /etc/ssh/sshd_config.d/50-jaunt.conf"
        ));
        assert!(
            harness
                .report
                .contains(Level::Info, "plan: write /etc/jaunt/agent.yaml (mode 0644)")
        );
        assert!(harness.report.contains(Level::Info, "plan: run useradd"));
        assert!(
            harness
                .report
                .contains(Level::Info, "plan: run systemctl enable jaunt-agent")
        );
        let mutating = ["groupadd", "useradd", "chown", "systemctl", "userdel"];
        assert!(
            !harness
                .calls()
                .iter()
                .any(|c| mutating.iter().any(|m| c.contains(m)) || c.ends_with(" -t"))
        );
    }

    #[test]
    fn root_other_than_slash_skips_live_system_commands() {
        let mut harness = Harness::new(FakeConfig::default());
        run(&mut harness, &with_services()).unwrap();
        let live_only = [
            "getent",
            "groupadd",
            "useradd",
            "chown",
            "systemctl",
            "getenforce",
        ];
        assert!(
            !harness
                .calls()
                .iter()
                .any(|c| live_only.iter().any(|l| c.starts_with(l)))
        );
    }

    #[test]
    fn sshd_reload_tries_ssh_then_sshd_and_warns_when_both_fail() {
        let cases = [
            (true, true, vec!["systemctl reload ssh"], false),
            (
                false,
                true,
                vec!["systemctl reload ssh", "systemctl reload sshd"],
                false,
            ),
            (
                false,
                false,
                vec!["systemctl reload ssh", "systemctl reload sshd"],
                true,
            ),
        ];
        for (ssh_ok, sshd_ok, reloads, warns) in cases {
            let mut harness = Harness::new(FakeConfig {
                reload_ssh_ok: ssh_ok,
                reload_sshd_ok: sshd_ok,
                ..FakeConfig::default()
            });
            harness.live = true;
            run(&mut harness, &with_services()).unwrap();
            let calls = harness.calls();
            let seen: Vec<&str> = calls
                .iter()
                .map(String::as_str)
                .filter(|c| c.starts_with("systemctl reload"))
                .collect();
            assert_eq!(seen, reloads);
            assert_eq!(
                harness
                    .report
                    .contains(Level::Warn, "systemctl reload sshd"),
                warns
            );
            assert!(calls.contains(&"systemctl enable jaunt-agent".to_string()));
        }
    }

    #[test]
    fn failed_daemon_reload_says_what_stays_in_place_and_keeps_everything() {
        let mut harness = Harness::new(FakeConfig {
            daemon_reload_ok: false,
            ..FakeConfig::default()
        });
        harness.live = true;
        let error = run(&mut harness, &with_services()).unwrap_err();
        assert!(matches!(error, InstallError::AfterCommit { .. }), "{error}");
        let text = error.to_string();
        assert!(text.contains("`systemctl daemon-reload`"), "{text}");
        assert!(text.contains("stay in place"), "{text}");
        assert!(harness.root.read(DROPIN_PATH).is_some());
        assert!(harness.root.read(UNIT_PATH).is_some());
        assert!(!has_call(&harness, "userdel"));
    }

    #[test]
    fn existing_account_must_be_a_nologin_account_with_the_state_dir_as_home() {
        let mut harness = Harness::new(FakeConfig {
            existing_group: true,
            existing_user_shell: Some("/usr/sbin/nologin".to_string()),
            ..FakeConfig::default()
        });
        harness.live = true;
        run(&mut harness, &options()).unwrap();
        assert!(!has_call(&harness, "useradd"));
        assert!(!has_call(&harness, "groupadd"));

        for (shell, home) in [
            ("/bin/bash", "/var/lib/jaunt"),
            ("/usr/sbin/nologin", "/usr/sbin"),
        ] {
            let mut harness = Harness::new(FakeConfig {
                existing_group: true,
                existing_user_shell: Some(shell.to_string()),
                existing_user_home: home.to_string(),
                ..FakeConfig::default()
            });
            harness.live = true;
            let before = harness.root.snapshot();
            let error = run(&mut harness, &options()).unwrap_err();
            assert!(matches!(error, InstallError::UserNotOurs { .. }), "{error}");
            assert_eq!(harness.root.snapshot(), before);
            assert!(!has_call(&harness, "chown"));
        }
    }

    #[test]
    fn missing_useradd_and_groupadd_fall_back_to_adduser_and_addgroup() {
        let mut harness = Harness::new(FakeConfig {
            useradd_missing: true,
            groupadd_missing: true,
            ..FakeConfig::default()
        });
        harness.live = true;
        run(&mut harness, &options()).unwrap();
        let calls = harness.calls();
        assert!(calls.contains(&"addgroup --system jaunt".to_string()));
        assert!(calls.contains(&"adduser --system --ingroup jaunt --home /var/lib/jaunt --no-create-home --shell /usr/sbin/nologin jaunt".to_string()));
    }

    #[test]
    fn risky_loopback_settings_and_selinux_produce_warnings() {
        let mut harness = Harness::new(FakeConfig {
            pubkeyauthentication: "no".to_string(),
            authenticationmethods: "publickey,password".to_string(),
            selinux: Some("Enforcing\n".to_string()),
            ..FakeConfig::default()
        });
        harness.live = true;
        run(&mut harness, &options()).unwrap();
        assert!(
            harness
                .report
                .contains(Level::Warn, "pubkeyauthentication no")
        );
        assert!(
            harness
                .report
                .contains(Level::Warn, "authenticationmethods publickey,password")
        );
        assert!(harness.report.contains(Level::Warn, "SELinux is Enforcing"));
    }

    fn ledger_with_artifacts(harness: &Harness) -> Ledger {
        let dir = harness.root.path_of("/var/lib/jaunt");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("inner-ca.pub");
        fs::write(&file, "").unwrap();
        Ledger {
            dirs: vec![dir],
            files: vec![file],
            ..Ledger::default()
        }
    }

    fn after_commit_error() -> InstallError {
        InstallError::AfterCommit {
            step: "syncing".to_string(),
            detail: "injected".to_string(),
            remains: DROPIN_REMAINS,
        }
    }

    fn validation_error(rollback: RollbackOutcome) -> InstallError {
        InstallError::Validation {
            problem: ValidationProblem::ConfigTest {
                stderr: "bad".to_string(),
            },
            rollback,
        }
    }

    #[test]
    fn only_failures_before_the_commit_and_with_a_good_rollback_are_undone() {
        let done = || RollbackOutcome::Done {
            action: "removed the new drop-in",
            config_test: ConfigTestOutcome::Passed,
        };
        let failed = || RollbackOutcome::Failed {
            reason: "stuck".to_string(),
        };
        assert!(should_undo(&validation_error(done())));
        assert!(!should_undo(&validation_error(failed())));
        assert!(!should_undo(&after_commit_error()));
        assert!(should_undo(&InstallError::NotRoot {
            uid: "1".to_string()
        }));
    }

    #[test]
    fn a_failure_handler_keeps_everything_after_the_commit_or_a_failed_rollback() {
        for (error, cleaned, warned) in [
            (after_commit_error(), false, false),
            (
                validation_error(RollbackOutcome::Failed {
                    reason: "stuck".to_string(),
                }),
                false,
                true,
            ),
            (
                validation_error(RollbackOutcome::Done {
                    action: "removed the new drop-in",
                    config_test: ConfigTestOutcome::Passed,
                }),
                true,
                false,
            ),
        ] {
            let mut harness = Harness::new(FakeConfig::default());
            let ledger = ledger_with_artifacts(&harness);
            let mut env = harness.env();
            handle_stage_failure(&mut env, &options(), &ledger, error);
            assert_eq!(!harness.root.path_of("/var/lib/jaunt").exists(), cleaned);
            assert_eq!(
                harness.report.contains(Level::Warn, "not cleaning up"),
                warned
            );
        }
    }

    #[test]
    fn a_failed_install_restores_the_mode_and_owner_of_an_adopted_state_dir() {
        let mut harness = Harness::new(FakeConfig {
            sshd_t_rejects_trust_line: true,
            ..FakeConfig::default()
        });
        harness.live = true;
        fs::create_dir_all(harness.root.path_of("/var/lib/jaunt")).unwrap();
        chmod(&harness, "/var/lib/jaunt", 0o755);
        let facts = fs::metadata(harness.root.path_of("/var/lib/jaunt")).unwrap();
        run(&mut harness, &options()).unwrap_err();
        assert_eq!(mode(&harness, "/var/lib/jaunt"), 0o755);
        assert!(harness.calls().contains(&format!(
            "chown {}:{} /var/lib/jaunt",
            facts.uid(),
            facts.gid()
        )));
    }

    #[test]
    fn a_failed_install_removes_ancestors_that_a_halfway_mkdir_created() {
        let mut harness = Harness::new(FakeConfig::default());
        let long = "x".repeat(300);
        let opts = InstallOptions {
            state_dir: format!("/srv/{long}/state"),
            ..options()
        };
        let before = harness.root.snapshot();
        run(&mut harness, &opts).unwrap_err();
        assert_eq!(harness.root.snapshot(), before);
    }
}
