use std::path::PathBuf;

use clap::Args;

use super::error::InstallError;
use super::layout::{
    DEFAULT_CONFIG, DEFAULT_STATE_DIR, DROPIN_DIR, DROPIN_PATH, Layout, SSHD_CONFIG, UNIT_DIR,
    UNIT_PATH,
};
use crate::paths::{check_absolute_path, check_state_dir};

#[derive(Debug, Args)]
pub struct InstallArgs {
    #[arg(long, default_value = "jaunt")]
    pub user: String,
    #[arg(long, default_value = "/usr/local/bin/jaunt-agent")]
    pub binary: String,
    #[arg(long, default_value = DEFAULT_CONFIG)]
    pub config: String,
    #[arg(long, default_value = DEFAULT_STATE_DIR)]
    pub state_dir: String,
    #[arg(long, default_value = "/")]
    pub root: PathBuf,
    #[arg(long)]
    pub no_service: bool,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long)]
    pub create_accounts: bool,
}

#[derive(Debug, Args)]
pub struct UninstallArgs {
    #[arg(long)]
    pub purge: bool,
    #[arg(long, default_value = DEFAULT_CONFIG)]
    pub config: String,
    #[arg(long, default_value = DEFAULT_STATE_DIR)]
    pub state_dir: String,
    #[arg(long, default_value = "/")]
    pub root: PathBuf,
    #[arg(long)]
    pub no_service: bool,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub user: String,
    pub binary: String,
    pub config: String,
    pub state_dir: String,
    pub no_service: bool,
    pub create_accounts: bool,
}

#[derive(Debug, Clone)]
pub struct UninstallOptions {
    pub purge: bool,
    pub no_service: bool,
    pub config: String,
    pub state_dir: String,
}

impl InstallOptions {
    pub fn from_args(args: &InstallArgs) -> Result<Self, InstallError> {
        check_user(&args.user).map_err(invalid("--user"))?;
        check_absolute_path(&args.binary).map_err(invalid("--binary"))?;
        check_absolute_path(&args.config).map_err(invalid("--config"))?;
        check_state_dir(&args.state_dir).map_err(invalid("--state-dir"))?;
        check_config_location(&args.config, &args.state_dir).map_err(invalid("--config"))?;
        Ok(Self {
            user: args.user.clone(),
            binary: args.binary.clone(),
            config: args.config.clone(),
            state_dir: args.state_dir.clone(),
            no_service: args.no_service,
            create_accounts: args.create_accounts,
        })
    }
}

impl InstallArgs {
    pub fn layout(&self) -> Result<Layout, InstallError> {
        Layout::new(&self.root)
    }
}

impl UninstallArgs {
    pub fn layout(&self) -> Result<Layout, InstallError> {
        Layout::new(&self.root)
    }

    pub fn options(&self) -> Result<UninstallOptions, InstallError> {
        check_state_dir(&self.state_dir).map_err(invalid("--state-dir"))?;
        check_absolute_path(&self.config).map_err(invalid("--config"))?;
        check_config_location(&self.config, &self.state_dir).map_err(invalid("--config"))?;
        Ok(UninstallOptions {
            purge: self.purge,
            no_service: self.no_service,
            config: self.config.clone(),
            state_dir: self.state_dir.clone(),
        })
    }
}

fn invalid(name: &'static str) -> impl Fn(&'static str) -> InstallError {
    move |reason| InstallError::InvalidArgument { name, reason }
}

const PRIVATE_TMP_DIRS: &[&str] = &["/tmp", "/var/tmp"];
const PROTECTED_HOME_DIRS: &[&str] = &["/home", "/root", "/run/user"];
const SERVICE_CONFIG_DIRS: &[&str] = &[DROPIN_DIR, "/etc/ssh", UNIT_DIR, "/etc/systemd"];

fn is_within(path: &str, dir: &str) -> bool {
    path == dir
        || path
            .strip_prefix(dir)
            .is_some_and(|rest| rest.starts_with('/'))
}

pub fn check_config_location(config: &str, state_dir: &str) -> Result<(), &'static str> {
    if [DROPIN_PATH, UNIT_PATH, SSHD_CONFIG].contains(&config) {
        return Err("must not be one of the files that install manages for sshd or systemd");
    }
    if SERVICE_CONFIG_DIRS.iter().any(|dir| is_within(config, dir)) {
        return Err(
            "must not be inside /etc/ssh or /etc/systemd, where sshd and systemd would read it as their own configuration; use a path such as /etc/jaunt/agent.yaml",
        );
    }
    if PRIVATE_TMP_DIRS.iter().any(|dir| is_within(config, dir)) {
        return Err(
            "is under /tmp or /var/tmp, which the service's PrivateTmp=yes replaces with an empty private directory; use a path such as /etc/jaunt/agent.yaml",
        );
    }
    if PROTECTED_HOME_DIRS.iter().any(|dir| is_within(config, dir)) {
        return Err(
            "is under /home, /root or /run/user, which the service's ProtectHome=yes makes unreadable; use a path such as /etc/jaunt/agent.yaml",
        );
    }
    if is_within(config, state_dir) {
        return Err("must not be inside the state directory, which belongs to the service account");
    }
    Ok(())
}

pub fn check_user(value: &str) -> Result<(), &'static str> {
    let mut chars = value.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == '_');
    let rest_ok =
        chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if !first_ok || !rest_ok || value.len() > 32 {
        return Err(
            "must be 1 to 32 characters: a lowercase letter or _ first, then lowercase letters, digits, _ or -",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::super::error::InstallError;
    use super::{InstallArgs, InstallOptions, UninstallArgs, check_config_location, check_user};

    #[test]
    fn user_name_table() {
        for (value, ok) in [
            ("jaunt", true),
            ("_jaunt-agent2", true),
            ("", false),
            ("Jaunt", false),
            ("1jaunt", false),
            ("ja unt", false),
            ("jaunt\nroot", false),
            ("a23456789012345678901234567890123", false),
        ] {
            assert_eq!(check_user(value).is_ok(), ok, "{value:?}");
        }
    }

    #[test]
    fn uninstall_validates_config_with_the_install_rules() {
        let args = |config: &str| UninstallArgs {
            purge: false,
            config: config.to_string(),
            state_dir: "/var/lib/jaunt".to_string(),
            root: PathBuf::from("/"),
            no_service: true,
            dry_run: false,
        };
        assert_eq!(
            args("/opt/jaunt/agent.yaml").options().unwrap().config,
            "/opt/jaunt/agent.yaml"
        );
        for config in [
            "relative.yaml",
            "/etc/jaunt/../agent.yaml",
            "/var/lib/jaunt/agent.yaml",
            "/etc/ssh/sshd_config",
        ] {
            assert!(
                matches!(
                    args(config).options(),
                    Err(InstallError::InvalidArgument {
                        name: "--config",
                        ..
                    })
                ),
                "{config}"
            );
        }
    }

    #[test]
    fn install_rejects_a_config_inside_the_state_dir() {
        let args = InstallArgs {
            user: "jaunt".to_string(),
            binary: "/usr/local/bin/jaunt-agent".to_string(),
            config: "/var/lib/jaunt/agent.yaml".to_string(),
            state_dir: "/var/lib/jaunt".to_string(),
            root: PathBuf::from("/"),
            no_service: true,
            dry_run: false,
            create_accounts: false,
        };
        assert!(matches!(
            InstallOptions::from_args(&args),
            Err(InstallError::InvalidArgument {
                name: "--config",
                ..
            })
        ));
    }

    #[test]
    fn config_location_table() {
        for (config, expected) in [
            ("/etc/jaunt/agent.yaml", None),
            ("/opt/jaunt/agent.yaml", None),
            ("/var/lib/jaunt-agent.yaml", None),
            ("/var/lib/jauntx/agent.yaml", None),
            ("/tmpfoo/agent.yaml", None),
            ("/etc/sshd/agent.yaml", None),
            ("/var/lib/jaunt", Some("inside the state directory")),
            (
                "/var/lib/jaunt/agent.yaml",
                Some("inside the state directory"),
            ),
            (
                "/var/lib/jaunt/sub/agent.yaml",
                Some("inside the state directory"),
            ),
            (
                "/etc/ssh/sshd_config.d/50-jaunt.conf",
                Some("files that install manages"),
            ),
            (
                "/etc/systemd/system/jaunt-agent.service",
                Some("files that install manages"),
            ),
            ("/etc/ssh/sshd_config", Some("files that install manages")),
            ("/etc/ssh/agent.yaml", Some("/etc/ssh or /etc/systemd")),
            (
                "/etc/ssh/sshd_config.d/agent.yaml",
                Some("/etc/ssh or /etc/systemd"),
            ),
            ("/etc/systemd/agent.yaml", Some("/etc/ssh or /etc/systemd")),
            (
                "/etc/systemd/system/agent.yaml",
                Some("/etc/ssh or /etc/systemd"),
            ),
            ("/tmp/agent.yaml", Some("PrivateTmp=yes")),
            ("/var/tmp/jaunt/agent.yaml", Some("PrivateTmp=yes")),
            ("/home/alice/agent.yaml", Some("ProtectHome=yes")),
            ("/root/agent.yaml", Some("ProtectHome=yes")),
            ("/run/user/0/agent.yaml", Some("ProtectHome=yes")),
        ] {
            match (check_config_location(config, "/var/lib/jaunt"), expected) {
                (Ok(()), None) => {}
                (Err(reason), Some(part)) => assert!(reason.contains(part), "{config}: {reason}"),
                (result, _) => panic!("{config}: unexpected {result:?}"),
            }
        }
    }
}
