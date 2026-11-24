use std::path::PathBuf;

use clap::Args;

use super::error::InstallError;
use super::layout::{DEFAULT_STATE_DIR, Layout};
use crate::paths::{check_absolute_path, check_state_dir};

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

#[cfg(test)]
mod tests {
    use super::check_user;

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
}
