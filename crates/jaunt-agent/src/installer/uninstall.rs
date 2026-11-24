use std::fs;

use super::account;
use super::args::UninstallOptions;
use super::env::{Env, require_root};
use super::error::InstallError;
use super::files;
use super::layout::{DROPIN_PATH, INNER_CA_FILE, SYSTEM_USER, UNIT_PATH};
use super::render::{DROPIN_HEADER, is_foreign_dropin};
use super::runner::excerpt;
use super::service;
use super::sshd::{Sshd, split_keyword};
use crate::paths::check_state_dir;

pub fn uninstall(env: &mut Env<'_>, opts: &UninstallOptions) -> Result<(), InstallError> {
    require_root(env)?;
    let unit_present = files::exists(&env.layout.path(UNIT_PATH))?;
    let dropin = files::read_optional(&env.layout.path(DROPIN_PATH))?;
    let foreign = dropin.as_deref().is_some_and(is_foreign_dropin);
    let ours = dropin.as_deref().filter(|bytes| !is_foreign_dropin(bytes));
    if foreign {
        env.report.warn(format!(
            "not removing {DROPIN_PATH}: it was not written by jaunt-agent (it does not start with the line `{DROPIN_HEADER}`)"
        ));
    }
    if !unit_present && ours.is_none() && !opts.purge {
        if !foreign {
            env.report.info("nothing to uninstall");
        }
        return Ok(());
    }

    let sshd = locate_sshd(env, ours.is_some())?;
    let state_dir = if opts.purge {
        Some(purge_target(ours, &opts.state_dir)?)
    } else {
        None
    };
    let manage_service = service::manage(env, opts.no_service);
    if !manage_service {
        service::skipped_note(env, opts.no_service);
    }

    if unit_present {
        if manage_service {
            service::stop_and_disable(env);
        }
        env.remove_file(UNIT_PATH)?;
    }
    if ours.is_some() {
        env.remove_file(DROPIN_PATH)?;
        if let Some(sshd) = &sshd {
            check_config_after_removal(env, sshd)?;
            if manage_service {
                service::reload_sshd(env)?;
            }
        }
    }
    if unit_present && manage_service {
        service::daemon_reload_or_warn(env)?;
    }

    if let Some(state_dir) = state_dir {
        purge_state_dir(env, &state_dir)?;
        account::remove(env, SYSTEM_USER, &state_dir)?;
    }
    Ok(())
}

fn locate_sshd(env: &mut Env<'_>, needed: bool) -> Result<Option<Sshd>, InstallError> {
    if !needed {
        return Ok(None);
    }
    match Sshd::locate(env.layout, &env.path_env) {
        Ok(sshd) => Ok(Some(sshd)),
        Err(InstallError::SshdNotFound) => {
            env.report.warn(
                "sshd was not found; the drop-in is removed without validating the sshd configuration and without reloading sshd",
            );
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn check_config_after_removal(env: &mut Env<'_>, sshd: &Sshd) -> Result<(), InstallError> {
    if env.dry_run {
        env.report
            .plan(format!("run {}", sshd.command_text(&["-t"])));
        return Ok(());
    }
    let output = sshd.syntax_check(env)?;
    if output.success() {
        env.report
            .info("validated: sshd accepts the configuration without the drop-in");
        Ok(())
    } else {
        Err(InstallError::ConfigBrokenAfterRemoval {
            stderr: excerpt(&output.stderr),
        })
    }
}

fn purge_target(dropin: Option<&[u8]>, fallback: &str) -> Result<String, InstallError> {
    let recorded = dropin
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .and_then(state_dir_from_dropin);
    let state_dir = recorded.unwrap_or_else(|| fallback.to_string());
    check_state_dir(&state_dir).map_err(|reason| InstallError::UnsafePurgeTarget {
        path: state_dir.clone(),
        reason,
    })?;
    Ok(state_dir)
}

fn state_dir_from_dropin(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (keyword, value) = split_keyword(line.trim());
        if !keyword.eq_ignore_ascii_case("trustedusercakeys") {
            return None;
        }
        value
            .trim()
            .strip_suffix(&format!("/{INNER_CA_FILE}"))
            .map(str::to_string)
    })
}

fn purge_state_dir(env: &mut Env<'_>, state_dir: &str) -> Result<(), InstallError> {
    let path = env.layout.path(state_dir);
    let refuse = |reason: &'static str| InstallError::UnsafePurgeTarget {
        path: state_dir.to_string(),
        reason,
    };
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            env.report.info(format!("already absent: {state_dir}"));
            return Ok(());
        }
        Err(source) => return Err(InstallError::io("stat", &path)(source)),
    };
    if !metadata.is_dir() {
        return Err(refuse("is a symlink or not a directory"));
    }
    if !files::exists(&path.join(INNER_CA_FILE))? {
        return Err(refuse(
            "does not contain inner-ca.pub, so it does not look like a Jaunt state directory",
        ));
    }
    if env.dry_run {
        env.report
            .plan(format!("remove directory {state_dir} and everything in it"));
        return Ok(());
    }
    files::remove_dir_all(&path)?;
    env.report.info(format!("removed: {state_dir}"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::super::args::{InstallOptions, UninstallOptions};
    use super::super::error::InstallError;
    use super::super::install::install;
    use super::super::layout::{DROPIN_PATH, UNIT_PATH};
    use super::super::render;
    use super::super::report::Level;
    use super::super::testing::{FakeConfig, Harness, options};
    use super::{state_dir_from_dropin, uninstall};

    fn installed(config: FakeConfig) -> Harness {
        let mut harness = Harness::new(config);
        let mut env = harness.env();
        install(&mut env, &options()).unwrap();
        harness.runner.calls.clear();
        harness
    }

    fn run(harness: &mut Harness, opts: &UninstallOptions) -> Result<(), InstallError> {
        let mut env = harness.env();
        uninstall(&mut env, opts)
    }

    fn plain() -> UninstallOptions {
        UninstallOptions {
            purge: false,
            no_service: false,
            state_dir: "/var/lib/jaunt".to_string(),
        }
    }

    fn purging() -> UninstallOptions {
        UninstallOptions {
            purge: true,
            ..plain()
        }
    }

    fn has_call(harness: &Harness, prefix: &str) -> bool {
        harness.calls().iter().any(|call| call.starts_with(prefix))
    }

    fn service_user() -> FakeConfig {
        FakeConfig {
            existing_group: true,
            existing_user_shell: Some("/usr/sbin/nologin".to_string()),
            ..FakeConfig::default()
        }
    }

    #[test]
    fn removes_unit_and_dropin_in_order_and_keeps_state_and_user() {
        let mut harness = installed(FakeConfig::default());
        harness.live = true;
        run(&mut harness, &plain()).unwrap();
        assert_eq!(harness.root.read(UNIT_PATH), None);
        assert_eq!(harness.root.read(DROPIN_PATH), None);
        assert!(harness.root.path_of("/var/lib/jaunt/inner-ca.pub").exists());
        let sshd = "/usr/sbin/sshd -f /etc/ssh/sshd_config";
        assert_eq!(
            harness.calls(),
            vec![
                "id -u".to_string(),
                "systemctl stop jaunt-agent".to_string(),
                "systemctl disable jaunt-agent".to_string(),
                format!("{sshd} -t"),
                "systemctl reload ssh".to_string(),
                "systemctl daemon-reload".to_string(),
            ]
        );
    }

    #[test]
    fn no_service_removes_files_without_systemctl() {
        let mut harness = installed(FakeConfig::default());
        harness.live = true;
        let opts = UninstallOptions {
            no_service: true,
            ..plain()
        };
        run(&mut harness, &opts).unwrap();
        assert_eq!(harness.root.read(DROPIN_PATH), None);
        assert!(!has_call(&harness, "systemctl"));
    }

    #[test]
    fn failing_stop_and_disable_only_warn_and_the_files_are_still_removed() {
        let mut harness = installed(FakeConfig::default());
        harness.live = true;
        harness.runner.config.systemctl_stop_ok = false;
        run(&mut harness, &plain()).unwrap();
        assert!(
            harness
                .report
                .contains(Level::Warn, "systemctl stop jaunt-agent")
        );
        assert_eq!(harness.root.read(UNIT_PATH), None);
        assert_eq!(harness.root.read(DROPIN_PATH), None);
    }

    #[test]
    fn missing_sshd_binary_skips_validation_and_reload_with_a_warning() {
        let mut harness = installed(FakeConfig::default());
        harness.live = true;
        fs::remove_file(harness.root.path_of("/usr/sbin/sshd")).unwrap();
        run(&mut harness, &plain()).unwrap();
        assert!(harness.report.contains(Level::Warn, "sshd was not found"));
        assert_eq!(harness.root.read(DROPIN_PATH), None);
        assert!(!has_call(&harness, "systemctl reload"));
        assert!(!harness.calls().iter().any(|c| c.ends_with(" -t")));
    }

    #[test]
    fn unconfigured_system_is_a_no_op() {
        let mut harness = Harness::new(FakeConfig::default());
        let before = harness.root.snapshot();
        run(&mut harness, &plain()).unwrap();
        assert_eq!(harness.root.snapshot(), before);
        assert_eq!(harness.calls(), vec!["id -u".to_string()]);
    }

    #[test]
    fn broken_config_after_removal_is_reported_without_reloading() {
        let mut harness = installed(FakeConfig::default());
        harness.runner.config.sshd_t_always_fails = true;
        harness.live = true;
        let error = run(&mut harness, &plain()).unwrap_err();
        assert!(matches!(
            error,
            InstallError::ConfigBrokenAfterRemoval { .. }
        ));
        assert!(!has_call(&harness, "systemctl reload"));
    }

    #[test]
    fn purge_removes_state_dir_and_the_jaunt_user_and_group() {
        let mut harness = installed(service_user());
        harness.live = true;
        run(&mut harness, &purging()).unwrap();
        assert!(!harness.root.path_of("/var/lib/jaunt").exists());
        let calls = harness.calls();
        assert!(calls.contains(&"userdel jaunt".to_string()));
        assert!(!calls.iter().any(|c| c.starts_with("groupdel")));
    }

    #[test]
    fn purge_removes_an_empty_group_that_userdel_left_behind() {
        let mut harness = installed(FakeConfig {
            userdel_keeps_group: true,
            ..service_user()
        });
        harness.live = true;
        run(&mut harness, &purging()).unwrap();
        assert!(has_call(&harness, "groupdel jaunt"));
    }

    #[test]
    fn purge_does_not_remove_a_group_that_has_members() {
        let mut harness = installed(FakeConfig {
            group_members: "alice".to_string(),
            ..service_user()
        });
        harness.live = true;
        run(&mut harness, &purging()).unwrap();
        assert!(has_call(&harness, "userdel jaunt"));
        assert!(!has_call(&harness, "groupdel"));
        assert!(harness.report.contains(
            Level::Warn,
            "not removing group jaunt: it still has members"
        ));
    }

    #[test]
    fn a_failing_userdel_makes_the_purge_fail() {
        let mut harness = installed(FakeConfig {
            userdel_exit: 8,
            ..service_user()
        });
        harness.live = true;
        let error = run(&mut harness, &purging()).unwrap_err();
        assert!(
            matches!(&error, InstallError::CommandFailed { command, status, .. }
                if command == "userdel jaunt" && status == "exit code 8"),
            "{error}"
        );
    }

    #[test]
    fn a_foreign_dropin_is_left_alone_with_a_warning_and_never_parsed() {
        let mut harness = Harness::new(service_user());
        harness.root.write(
            DROPIN_PATH,
            "# somebody else's file\nTrustedUserCAKeys /etc/important/inner-ca.pub\n",
        );
        harness.root.write("/etc/important/inner-ca.pub", "keep");
        harness.root.write("/var/lib/jaunt/inner-ca.pub", "");
        harness.live = true;
        run(&mut harness, &plain()).unwrap();
        assert!(harness.root.read(DROPIN_PATH).is_some());
        assert!(harness.report.contains(
            Level::Warn,
            "not removing /etc/ssh/sshd_config.d/50-jaunt.conf"
        ));
        assert_eq!(harness.calls(), vec!["id -u".to_string()]);

        run(&mut harness, &purging()).unwrap();
        assert!(harness.root.read(DROPIN_PATH).is_some());
        assert_eq!(
            harness.root.read("/etc/important/inner-ca.pub").unwrap(),
            "keep"
        );
        assert!(!harness.root.path_of("/var/lib/jaunt").exists());
    }

    #[test]
    fn a_unit_file_alone_is_removed() {
        let mut harness = Harness::new(FakeConfig::default());
        harness.root.write(UNIT_PATH, "[Unit]\n");
        harness.live = true;
        run(&mut harness, &plain()).unwrap();
        assert_eq!(harness.root.read(UNIT_PATH), None);
        assert_eq!(
            harness.calls(),
            vec![
                "id -u".to_string(),
                "systemctl stop jaunt-agent".to_string(),
                "systemctl disable jaunt-agent".to_string(),
                "systemctl daemon-reload".to_string(),
            ]
        );
    }

    #[test]
    fn missing_systemctl_only_warns_and_the_purge_still_runs() {
        let mut harness = installed(service_user());
        harness.live = true;
        harness.runner.config.systemctl_missing = true;
        run(&mut harness, &purging()).unwrap();
        assert_eq!(harness.root.read(UNIT_PATH), None);
        assert_eq!(harness.root.read(DROPIN_PATH), None);
        assert!(!harness.root.path_of("/var/lib/jaunt").exists());
        assert!(
            harness
                .report
                .contains(Level::Warn, "systemctl was not found")
        );
        assert!(has_call(&harness, "userdel jaunt"));
    }

    #[test]
    fn purge_keeps_a_human_account_named_jaunt_and_says_so() {
        let mut harness = Harness::new(FakeConfig {
            existing_group: true,
            existing_user_shell: Some("/bin/bash".to_string()),
            existing_user_home: "/home/jaunt".to_string(),
            ..FakeConfig::default()
        });
        harness.root.write("/var/lib/jaunt/inner-ca.pub", "");
        harness.live = true;
        run(&mut harness, &purging()).unwrap();
        assert!(
            harness
                .report
                .contains(Level::Warn, "not removing user jaunt")
        );
        assert!(!has_call(&harness, "userdel"));
        assert!(!has_call(&harness, "groupdel"));
        assert!(!harness.root.path_of("/var/lib/jaunt").exists());
    }

    #[test]
    fn purge_without_dropin_and_unit_falls_back_to_the_default_state_dir() {
        let mut harness = Harness::new(service_user());
        harness.root.write("/var/lib/jaunt/inner-ca.pub", "");
        harness.live = true;
        run(&mut harness, &purging()).unwrap();
        assert!(!harness.root.path_of("/var/lib/jaunt").exists());
        assert!(has_call(&harness, "userdel jaunt"));
    }

    #[test]
    fn purge_without_dropin_uses_the_state_dir_option() {
        let mut harness = Harness::new(FakeConfig {
            existing_user_home: "/srv/jaunt/state".to_string(),
            ..service_user()
        });
        harness.root.write("/srv/jaunt/state/inner-ca.pub", "");
        harness.root.write("/var/lib/jaunt/inner-ca.pub", "");
        harness.live = true;
        let opts = UninstallOptions {
            state_dir: "/srv/jaunt/state".to_string(),
            ..purging()
        };
        run(&mut harness, &opts).unwrap();
        assert!(!harness.root.path_of("/srv/jaunt/state").exists());
        assert!(harness.root.path_of("/var/lib/jaunt").exists());
        assert!(has_call(&harness, "userdel jaunt"));
    }

    #[test]
    fn non_live_purge_touches_no_account() {
        let mut harness = installed(service_user());
        run(&mut harness, &purging()).unwrap();
        assert!(!harness.root.path_of("/var/lib/jaunt").exists());
        for prefix in ["getent", "userdel", "groupdel"] {
            assert!(!has_call(&harness, prefix), "{prefix}");
        }
    }

    #[test]
    fn purge_refuses_a_state_dir_recorded_in_the_dropin_that_is_a_system_directory() {
        let mut harness = installed(FakeConfig::default());
        harness.root.write(DROPIN_PATH, &render::dropin("/etc"));
        let error = run(&mut harness, &purging()).unwrap_err();
        assert!(matches!(error, InstallError::UnsafePurgeTarget { .. }));
        assert!(harness.root.path_of("/var/lib/jaunt").exists());
        assert!(harness.root.read(UNIT_PATH).is_some());
    }

    #[test]
    fn purge_refuses_system_directories_even_when_the_marker_file_is_there() {
        let mut harness = Harness::new(FakeConfig::default());
        harness.root.write("/etc/ssh/jaunt-state/inner-ca.pub", "");
        harness
            .root
            .write(DROPIN_PATH, &render::dropin("/etc/ssh/jaunt-state"));
        let error = run(&mut harness, &purging()).unwrap_err();
        assert!(matches!(error, InstallError::UnsafePurgeTarget { .. }));
        assert!(
            harness
                .root
                .path_of("/etc/ssh/jaunt-state/inner-ca.pub")
                .exists()
        );
        assert!(harness.root.read(DROPIN_PATH).is_some());
    }

    #[test]
    fn purge_refuses_a_directory_without_the_marker_file() {
        let mut harness = installed(FakeConfig::default());
        fs::remove_file(harness.root.path_of("/var/lib/jaunt/inner-ca.pub")).unwrap();
        harness.root.write("/var/lib/jaunt/precious", "data");
        let error = run(&mut harness, &purging()).unwrap_err();
        assert!(matches!(error, InstallError::UnsafePurgeTarget { .. }));
        assert_eq!(
            harness.root.read("/var/lib/jaunt/precious").unwrap(),
            "data"
        );
    }

    #[test]
    fn purge_refuses_a_state_dir_that_is_a_symlink_and_leaves_the_target_alone() {
        let mut harness = Harness::new(service_user());
        harness.root.write("/srv/elsewhere/inner-ca.pub", "");
        harness.root.write("/srv/elsewhere/precious", "data");
        fs::create_dir_all(harness.root.path_of("/var/lib")).unwrap();
        std::os::unix::fs::symlink(
            harness.root.path_of("/srv/elsewhere"),
            harness.root.path_of("/var/lib/jaunt"),
        )
        .unwrap();
        harness.live = true;
        let error = run(&mut harness, &purging()).unwrap_err();
        assert!(matches!(error, InstallError::UnsafePurgeTarget { .. }));
        assert_eq!(
            harness.root.read("/srv/elsewhere/precious").unwrap(),
            "data"
        );
        assert!(harness.root.path_of("/srv/elsewhere/inner-ca.pub").exists());
        assert!(!has_call(&harness, "userdel"));
    }

    #[test]
    fn dry_run_changes_nothing() {
        let mut harness = installed(FakeConfig::default());
        harness.live = true;
        harness.dry_run = true;
        let before = harness.root.snapshot();
        run(&mut harness, &purging()).unwrap();
        assert_eq!(harness.root.snapshot(), before);
        assert!(!has_call(&harness, "systemctl"));
    }

    #[test]
    fn state_dir_is_read_back_from_the_dropin() {
        let text = InstallOptions {
            state_dir: "/srv/jaunt/state".to_string(),
            ..options()
        };
        let rendered = super::super::render::dropin(&text.state_dir);
        assert_eq!(
            state_dir_from_dropin(&rendered),
            Some("/srv/jaunt/state".to_string())
        );
        assert_eq!(state_dir_from_dropin("Port 22\n"), None);
    }
}
