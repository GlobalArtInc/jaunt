use std::path::PathBuf;

use clap::Args;

use super::error::InstallError;
use super::layout::{DEFAULT_STATE_DIR, Layout};

const SYSTEM_TOP_LEVEL: &[&str] = &[
    "bin", "boot", "dev", "etc", "lib", "lib32", "lib64", "libx32", "proc", "root", "run", "sbin",
    "sys", "usr",
];

#[derive(Debug, Args)]
pub struct InstallArgs {
    #[arg(long, default_value = "jaunt")]
    pub user: String,
    #[arg(long, default_value = "/usr/local/bin/jaunt-agent")]
    pub binary: String,
    #[arg(long, default_value = "/etc/jaunt/agent.yaml")]
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

#[derive(Debug, Args)]
pub struct UninstallArgs {
    #[arg(long)]
    pub purge: bool,
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
}

#[derive(Debug, Clone)]
pub struct UninstallOptions {
    pub purge: bool,
    pub no_service: bool,
    pub state_dir: String,
}

impl InstallOptions {
    pub fn from_args(args: &InstallArgs) -> Result<Self, InstallError> {
        check_user(&args.user).map_err(invalid("--user"))?;
        check_absolute_path(&args.binary).map_err(invalid("--binary"))?;
        check_absolute_path(&args.config).map_err(invalid("--config"))?;
        check_state_dir(&args.state_dir).map_err(invalid("--state-dir"))?;
        Ok(Self {
            user: args.user.clone(),
            binary: args.binary.clone(),
            config: args.config.clone(),
            state_dir: args.state_dir.clone(),
            no_service: args.no_service,
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
        Ok(UninstallOptions {
            purge: self.purge,
            no_service: self.no_service,
            state_dir: self.state_dir.clone(),
        })
    }
}

fn invalid(name: &'static str) -> impl Fn(&'static str) -> InstallError {
    move |reason| InstallError::InvalidArgument { name, reason }
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

pub fn check_absolute_path(value: &str) -> Result<(), &'static str> {
    if !value.starts_with('/') {
        return Err("must be an absolute path");
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '+'))
    {
        return Err("may contain only ASCII letters, digits and the characters / . _ - +");
    }
    if value
        .split('/')
        .skip(1)
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("must be normalized: no trailing slash, empty, . or .. components");
    }
    Ok(())
}

pub fn check_state_dir(value: &str) -> Result<(), &'static str> {
    check_absolute_path(value)?;
    let components: Vec<&str> = value.split('/').skip(1).collect();
    if components.first() == Some(&"home") {
        return Err(
            "is under /home, where the service's ProtectHome=yes makes it unusable; use a directory such as /var/lib/jaunt",
        );
    }
    if components
        .first()
        .is_some_and(|top| SYSTEM_TOP_LEVEL.contains(top))
    {
        return Err(
            "is inside a system directory; use a dedicated directory such as /var/lib/jaunt",
        );
    }
    if components.len() < 3 {
        return Err("must be at least three levels deep, for example /var/lib/jaunt");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{check_absolute_path, check_state_dir, check_user};

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
    fn path_table_rejects_anything_that_could_inject_config_lines() {
        for (value, ok) in [
            ("/usr/local/bin/jaunt-agent", true),
            ("/etc/jaunt/agent.yaml", true),
            ("relative/path", false),
            ("", false),
            ("/var/lib/jaunt/", false),
            ("/var//lib", false),
            ("/var/lib/../etc", false),
            ("/var/lib/jaunt extra", false),
            ("/var/lib/jaunt\nTrustedUserCAKeys /x", false),
            ("/var/lib/jaunt%h", false),
            ("/var/lib/$HOME", false),
            ("/var/lib/\"x\"", false),
        ] {
            assert_eq!(check_absolute_path(value).is_ok(), ok, "{value:?}");
        }
    }

    #[test]
    fn state_dir_must_be_dedicated_and_deep_enough() {
        for (value, ok) in [
            ("/var/lib/jaunt", true),
            ("/opt/jaunt/state", true),
            ("/srv/jaunt/state", true),
            ("/", false),
            ("/var", false),
            ("/var/lib", false),
            ("/home", false),
            ("/home/alice", false),
            ("/home/svc/jaunt", false),
            ("/home/svc/jaunt/state", false),
            ("/srv/jaunt", false),
            ("/etc", false),
            ("/etc/ssh", false),
            ("/etc/ssh/jaunt", false),
            ("/usr/local/lib/jaunt", false),
            ("/boot/efi/jaunt", false),
            ("/lib64/jaunt/state", false),
            ("/proc/1/jaunt", false),
            ("/root/jaunt/state", false),
        ] {
            assert_eq!(check_state_dir(value).is_ok(), ok, "{value:?}");
        }
    }
}
