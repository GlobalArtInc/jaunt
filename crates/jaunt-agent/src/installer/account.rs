use super::env::{Env, Ledger, checked};
use super::error::InstallError;
use super::layout::NOLOGIN_SHELL;
use super::runner::{RunnerError, command_line, excerpt};

pub struct Inspection {
    pub group_exists: bool,
    pub group_gid: Option<String>,
    pub user_exists: bool,
}

pub fn lookup(
    env: &mut Env<'_>,
    database: &str,
    name: &str,
) -> Result<Option<String>, InstallError> {
    let args = [database, name];
    let output = env.query("getent", &args)?;
    match output.code {
        Some(0) => Ok(Some(output.stdout)),
        Some(2) => Ok(None),
        _ => checked("getent", &args, output).map(|_| None),
    }
}

fn is_nologin(shell: &str) -> bool {
    matches!(shell.rsplit('/').next(), Some("nologin" | "false"))
}

fn service_account_problem(entry: &str, state_dir: &str) -> Option<String> {
    let fields: Vec<&str> = entry.trim().split(':').collect();
    let [_, _, _, _, _, home, shell] = fields.as_slice() else {
        return Some("unexpected account database entry".to_string());
    };
    if !is_nologin(shell) {
        return Some(format!("its login shell is {shell}, not nologin"));
    }
    if *home != state_dir {
        return Some(format!(
            "its home directory is {home}, not the state directory {state_dir}"
        ));
    }
    None
}

fn group_members(entry: &str) -> &str {
    entry.trim().rsplit(':').next().unwrap_or("")
}

fn group_gid(entry: &str) -> Option<String> {
    entry
        .trim()
        .split(':')
        .nth(2)
        .filter(|gid| !gid.is_empty() && gid.chars().all(|c| c.is_ascii_digit()))
        .map(str::to_string)
}

pub fn inspect(env: &mut Env<'_>, user: &str, state_dir: &str) -> Result<Inspection, InstallError> {
    if !env.live {
        return Ok(Inspection {
            group_exists: false,
            group_gid: None,
            user_exists: false,
        });
    }
    let group = lookup(env, "group", user)?;
    let group_exists = group.is_some();
    let group_gid = group.as_deref().and_then(group_gid);
    let user_exists = match lookup(env, "passwd", user)? {
        Some(entry) => {
            if let Some(reason) = service_account_problem(&entry, state_dir) {
                return Err(InstallError::UserNotOurs {
                    user: user.to_string(),
                    reason,
                });
            }
            true
        }
        None => false,
    };
    Ok(Inspection {
        group_exists,
        group_gid,
        user_exists,
    })
}

fn run_with_fallback(
    env: &mut Env<'_>,
    primary: (&str, &[&str]),
    fallback: (&str, &[&str]),
) -> Result<(), InstallError> {
    match env.act(primary.0, primary.1) {
        Ok(output) => checked(primary.0, primary.1, output).map(|_| ()),
        Err(RunnerError::NotFound { program }) => {
            env.report.info(format!(
                "{program} not found, using {}",
                command_line(fallback.0, fallback.1)
            ));
            env.act_checked(fallback.0, fallback.1).map(|_| ())
        }
        Err(error) => Err(error.into()),
    }
}

pub fn ensure(
    env: &mut Env<'_>,
    user: &str,
    state_dir: &str,
    inspection: &Inspection,
    ledger: &mut Ledger,
) -> Result<(), InstallError> {
    if !env.live {
        env.report
            .info("skipped (root is not /): group and user setup");
        return Ok(());
    }
    if inspection.group_exists {
        env.report.info(format!("present: group {user}"));
    } else {
        run_with_fallback(
            env,
            ("groupadd", &["--system", user]),
            ("addgroup", &["--system", user]),
        )?;
        ledger.group = !env.dry_run;
    }
    if inspection.user_exists {
        env.report.info(format!("present: user {user}"));
        return Ok(());
    }
    run_with_fallback(
        env,
        (
            "useradd",
            &[
                "--system",
                "--gid",
                user,
                "--home-dir",
                state_dir,
                "--no-create-home",
                "--shell",
                NOLOGIN_SHELL,
                user,
            ],
        ),
        (
            "adduser",
            &[
                "--system",
                "--ingroup",
                user,
                "--home",
                state_dir,
                "--no-create-home",
                "--shell",
                NOLOGIN_SHELL,
                user,
            ],
        ),
    )?;
    ledger.user = !env.dry_run;
    Ok(())
}

pub fn run_or_warn(env: &mut Env<'_>, program: &str, args: &[&str]) {
    match env.act(program, args) {
        Ok(output) if output.success() => {}
        Ok(output) => env.report.warn(format!(
            "`{}` failed ({}): {}",
            command_line(program, args),
            output.status_text(),
            excerpt(&output.stderr)
        )),
        Err(error) => env.report.warn(format!(
            "`{}` could not run: {error}",
            command_line(program, args)
        )),
    }
}

fn restore_group(env: &mut Env<'_>, user: &str, gid: &str) {
    match lookup(env, "group", user) {
        Ok(Some(_)) => {}
        Ok(None) => {
            let result = run_with_fallback(
                env,
                ("groupadd", &["--system", "--gid", gid, user]),
                ("addgroup", &["--system", "--gid", gid, user]),
            );
            match result {
                Ok(()) => env.report.info(format!(
                    "re-created group {user} (gid {gid}), which existed before and which userdel removed"
                )),
                Err(error) => env.report.warn(format!(
                    "group {user} (gid {gid}) existed before this run and userdel removed it; re-create it with `groupadd --system --gid {gid} {user}` ({error})"
                )),
            }
        }
        Err(error) => env.report.warn(format!(
            "could not check that group {user} survived userdel: {error}"
        )),
    }
}

pub fn undo(env: &mut Env<'_>, user: &str, ledger: &Ledger) {
    if ledger.user {
        run_or_warn(env, "userdel", &[user]);
        if let Some(gid) = &ledger.preexisting_group_gid {
            restore_group(env, user, gid);
        }
    }
    if ledger.group {
        match lookup(env, "group", user) {
            Ok(Some(_)) => run_or_warn(env, "groupdel", &[user]),
            Ok(None) => {}
            Err(error) => env.report.warn(format!(
                "could not look up group {user} to remove it: {error}"
            )),
        }
    }
}

pub fn remove(env: &mut Env<'_>, user: &str, state_dir: &str) -> Result<(), InstallError> {
    if !env.live {
        env.report
            .info("skipped (root is not /): user and group removal");
        return Ok(());
    }
    let Some(entry) = lookup(env, "passwd", user)? else {
        env.report.info(format!("already absent: user {user}"));
        return Ok(());
    };
    if let Some(problem) = service_account_problem(&entry, state_dir) {
        env.report.warn(format!(
            "not removing user {user} and its group: {problem}, so it does not look like the Jaunt service account"
        ));
        return Ok(());
    }
    let kept_gid = lookup(env, "group", user)?
        .filter(|group| !group_members(group).is_empty())
        .and_then(|group| group_gid(&group));
    env.act_checked("userdel", &[user])?;
    match lookup(env, "group", user)? {
        Some(group) if group_members(&group).is_empty() => {
            env.act_checked("groupdel", &[user])?;
        }
        Some(_) => env
            .report
            .warn(format!("not removing group {user}: it still has members")),
        None => {
            if let Some(gid) = kept_gid {
                restore_group(env, user, &gid);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{group_gid, group_members, is_nologin, service_account_problem};

    #[test]
    fn nologin_shells_table() {
        for (shell, expected) in [
            ("/usr/sbin/nologin", true),
            ("/sbin/nologin", true),
            ("/bin/false", true),
            ("/bin/bash", false),
            ("/bin/sh", false),
            ("", false),
        ] {
            assert_eq!(is_nologin(shell), expected, "{shell}");
        }
    }

    #[test]
    fn service_account_must_be_nologin_with_the_state_dir_as_home() {
        let state = "/var/lib/jaunt";
        let cases = [
            ("jaunt:x:995:995::/var/lib/jaunt:/usr/sbin/nologin\n", true),
            ("jaunt:x:995:995::/var/lib/jaunt:/bin/false", true),
            ("jaunt:x:1000:1000:Jo:/home/jaunt:/bin/bash", false),
            ("jaunt:x:1000:1000::/home/jaunt:/usr/sbin/nologin", false),
            ("daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin", false),
            ("jaunt:x:995:995::/var/lib/jaunt:/bin/bash", false),
            ("jaunt:x:995", false),
        ];
        for (entry, ok) in cases {
            assert_eq!(
                service_account_problem(entry, state).is_none(),
                ok,
                "{entry}"
            );
        }
    }

    #[test]
    fn group_members_are_the_last_field() {
        assert_eq!(group_members("jaunt:x:995:\n"), "");
        assert_eq!(group_members("jaunt:x:995:alice,bob\n"), "alice,bob");
    }

    #[test]
    fn group_gid_is_the_numeric_third_field() {
        assert_eq!(group_gid("jaunt:x:995:\n").as_deref(), Some("995"));
        assert_eq!(group_gid("jaunt:x:abc:").as_deref(), None);
        assert_eq!(group_gid("jaunt").as_deref(), None);
    }
}
