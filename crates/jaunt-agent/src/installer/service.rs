use super::env::{Env, checked};
use super::error::InstallError;
use super::layout::SERVICE_NAME;
use super::runner::{RunnerError, command_line, excerpt};

pub fn manage(env: &Env<'_>, no_service: bool) -> bool {
    !no_service && env.live
}

pub fn skipped_note(env: &mut Env<'_>, no_service: bool) {
    if no_service {
        env.report.info("skipped service actions (--no-service)");
    } else {
        env.report.info("skipped (root is not /): service actions");
    }
}

pub fn daemon_reload(env: &mut Env<'_>) -> Result<(), InstallError> {
    env.act_checked("systemctl", &["daemon-reload"]).map(|_| ())
}

pub fn daemon_reload_or_warn(env: &mut Env<'_>) -> Result<(), InstallError> {
    match env.act("systemctl", &["daemon-reload"]) {
        Ok(output) => checked("systemctl", &["daemon-reload"], output).map(|_| ()),
        Err(RunnerError::NotFound { .. }) => {
            env.report
                .warn("systemctl was not found; run `systemctl daemon-reload` yourself if systemd is in use");
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

pub fn enable(env: &mut Env<'_>) -> Result<(), InstallError> {
    env.act_checked("systemctl", &["enable", SERVICE_NAME])
        .map(|_| ())
}

pub fn stop_and_disable(env: &mut Env<'_>) {
    for action in ["stop", "disable"] {
        let args = [action, SERVICE_NAME];
        match env.act("systemctl", &args) {
            Ok(output) if output.success() => {}
            Ok(output) => env.report.warn(format!(
                "`{}` failed ({}): {}; continuing with the removal",
                command_line("systemctl", &args),
                output.status_text(),
                excerpt(&output.stderr)
            )),
            Err(error) => env.report.warn(format!(
                "`{}` could not run ({error}); continuing with the removal",
                command_line("systemctl", &args)
            )),
        }
    }
}

pub fn reload_sshd(env: &mut Env<'_>) -> Result<(), InstallError> {
    let mut failures = Vec::new();
    for unit in ["ssh", "sshd"] {
        let output = match env.act("systemctl", &["reload", unit]) {
            Ok(output) => output,
            Err(RunnerError::NotFound { .. }) => {
                failures.push("systemctl was not found".to_string());
                break;
            }
            Err(error) => return Err(error.into()),
        };
        if output.success() {
            if !env.dry_run {
                env.report.info(format!("reloaded: {unit}"));
            }
            return Ok(());
        }
        failures.push(format!(
            "systemctl reload {unit}: {}",
            excerpt(&output.stderr)
        ));
    }
    env.report.warn(format!(
        "sshd could not be reloaded ({}); run `systemctl reload sshd` (Debian and Ubuntu: `systemctl reload ssh`) yourself so that the new configuration takes effect",
        failures.join("; ")
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::report::Level;
    use super::super::testing::{FakeConfig, Harness};
    use super::reload_sshd;

    #[test]
    fn a_missing_systemctl_is_a_warning_when_reloading_sshd() {
        let mut harness = Harness::new(FakeConfig {
            systemctl_missing: true,
            ..FakeConfig::default()
        });
        harness.live = true;
        let mut env = harness.env();
        reload_sshd(&mut env).unwrap();
        assert!(
            harness
                .report
                .contains(Level::Warn, "systemctl was not found")
        );
        assert_eq!(harness.calls(), vec!["systemctl reload ssh".to_string()]);
    }
}
