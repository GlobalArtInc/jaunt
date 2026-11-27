use std::path::PathBuf;

use super::error::InstallError;
use super::files::{self, FileFacts};
use super::layout::Layout;
use super::report::Report;
use super::runner::{Output, Runner, RunnerError, command_line, excerpt};

pub struct Env<'a> {
    pub layout: &'a Layout,
    pub runner: &'a mut dyn Runner,
    pub report: &'a mut Report,
    pub dry_run: bool,
    pub live: bool,
    pub path_env: String,
    pub root_uid: u32,
}

pub struct DirSpec<'a> {
    pub mode: u32,
    pub owner: Option<&'a str>,
    pub enforce: bool,
}

pub struct Written {
    pub previous: Option<Vec<u8>>,
    pub previous_mode: Option<u32>,
    pub changed: bool,
    pub sync_error: Option<InstallError>,
}

#[derive(Debug)]
pub struct Adopted {
    pub path: PathBuf,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug)]
pub struct Replaced {
    pub path: PathBuf,
    pub content: Vec<u8>,
    pub mode: u32,
}

#[derive(Debug, Default)]
pub struct Ledger {
    pub dirs: Vec<PathBuf>,
    pub files: Vec<PathBuf>,
    pub replaced: Vec<Replaced>,
    pub adopted: Vec<Adopted>,
    pub group: bool,
    pub user: bool,
    pub preexisting_group_gid: Option<String>,
}

impl Ledger {
    pub fn is_empty(&self) -> bool {
        self.dirs.is_empty()
            && self.files.is_empty()
            && self.replaced.is_empty()
            && self.adopted.is_empty()
            && !self.group
            && !self.user
    }
}

pub fn checked(program: &str, args: &[&str], output: Output) -> Result<Output, InstallError> {
    if output.success() {
        Ok(output)
    } else {
        Err(InstallError::CommandFailed {
            command: command_line(program, args),
            status: output.status_text(),
            stderr: excerpt(&output.stderr),
        })
    }
}

impl Env<'_> {
    pub fn query(&mut self, program: &str, args: &[&str]) -> Result<Output, RunnerError> {
        self.runner.run(program, args)
    }

    pub fn query_checked(&mut self, program: &str, args: &[&str]) -> Result<Output, InstallError> {
        let output = self.query(program, args)?;
        checked(program, args, output)
    }

    pub fn act(&mut self, program: &str, args: &[&str]) -> Result<Output, RunnerError> {
        if self.dry_run {
            self.report
                .plan(format!("run {}", command_line(program, args)));
            return Ok(Output::success_empty());
        }
        self.runner.run(program, args)
    }

    pub fn act_checked(&mut self, program: &str, args: &[&str]) -> Result<Output, InstallError> {
        let output = self.act(program, args)?;
        checked(program, args, output)
    }

    pub fn write_file(
        &mut self,
        virtual_path: &str,
        content: &str,
        mode: u32,
    ) -> Result<Written, InstallError> {
        let path = self.layout.path(virtual_path);
        let previous = files::read_optional(&path)?;
        let facts = files::file_facts(&path)?;
        let previous_mode = facts.as_ref().map(|facts| facts.mode);
        let changed = previous.as_deref() != Some(content.as_bytes());
        let mut sync_error = None;
        if !changed {
            if let Some(facts) = facts {
                self.settle_permissions(virtual_path, mode, &facts)?;
            }
        } else if self.dry_run {
            self.report
                .plan(format!("write {virtual_path} (mode {mode:04o})"));
            self.report.plan_block(content);
        } else {
            sync_error = files::write_atomic(&path, content.as_bytes(), mode)?;
            self.report
                .info(format!("wrote: {virtual_path} (mode {mode:04o})"));
        }
        Ok(Written {
            previous,
            previous_mode,
            changed,
            sync_error,
        })
    }

    fn settle_permissions(
        &mut self,
        virtual_path: &str,
        mode: u32,
        facts: &FileFacts,
    ) -> Result<(), InstallError> {
        let mode_wrong = facts.mode != mode;
        let owner_wrong = self.live && (facts.uid != 0 || facts.gid != 0);
        if !mode_wrong && !owner_wrong {
            self.report.info(format!("unchanged: {virtual_path}"));
            return Ok(());
        }
        if self.dry_run {
            self.report.plan(format!(
                "fix permissions of {virtual_path} (mode {mode:04o}, owner root:root)"
            ));
            return Ok(());
        }
        if mode_wrong {
            files::set_mode(&self.layout.path(virtual_path), mode)?;
        }
        if owner_wrong {
            self.act_checked(
                "chown",
                &["root:root", &self.layout.path_string(virtual_path)],
            )?;
        }
        self.report.info(format!(
            "fixed permissions: {virtual_path} (mode {mode:04o}, owner root:root)"
        ));
        Ok(())
    }

    pub fn ensure_dir(
        &mut self,
        virtual_path: &str,
        spec: &DirSpec<'_>,
        ledger: &mut Ledger,
    ) -> Result<(), InstallError> {
        let path = self.layout.path(virtual_path);
        let owner = spec.owner.map(|user| format!("{user}:{user}"));
        if self.dry_run {
            self.report.plan(format!(
                "ensure directory {virtual_path} (mode {:04o}{})",
                spec.mode,
                owner
                    .as_deref()
                    .map(|o| format!(", owner {o}"))
                    .unwrap_or_default()
            ));
            return Ok(());
        }
        if let Some(facts) = files::file_facts(&path)?
            && (spec.enforce || owner.is_some())
        {
            ledger.adopted.push(Adopted {
                path: path.clone(),
                mode: facts.mode,
                uid: facts.uid,
                gid: facts.gid,
            });
        }
        let known = ledger.dirs.len();
        files::ensure_dir(&path, spec.mode, spec.enforce, &mut ledger.dirs)?;
        let was_created = ledger.dirs.len() > known;
        if let Some(owner) = &owner {
            self.chown_live(owner, &self.layout.path_string(virtual_path))?;
        }
        self.report.info(format!(
            "{}: {virtual_path}",
            if was_created { "created" } else { "present" }
        ));
        Ok(())
    }

    pub fn ensure_empty_file(
        &mut self,
        virtual_path: &str,
        mode: u32,
        owner: &str,
        ledger: &mut Ledger,
    ) -> Result<(), InstallError> {
        let path = self.layout.path(virtual_path);
        if self.dry_run {
            self.report.plan(format!(
                "create {virtual_path} empty if absent (mode {mode:04o}, owner {owner}:{owner})"
            ));
            return Ok(());
        }
        if files::create_empty_if_absent(&path, mode)? {
            ledger.files.push(path);
            self.chown_live(
                &format!("{owner}:{owner}"),
                &self.layout.path_string(virtual_path),
            )?;
            self.report.info(format!("created: {virtual_path}"));
        } else {
            self.report.info(format!("present: {virtual_path}"));
        }
        Ok(())
    }

    pub fn remove_file(&mut self, virtual_path: &str) -> Result<(), InstallError> {
        let path = self.layout.path(virtual_path);
        if self.dry_run {
            self.report.plan(format!("remove {virtual_path}"));
            return Ok(());
        }
        if files::remove_file(&path)? {
            self.report.info(format!("removed: {virtual_path}"));
        } else {
            self.report.info(format!("already absent: {virtual_path}"));
        }
        Ok(())
    }

    fn chown_live(&mut self, owner: &str, path: &str) -> Result<(), InstallError> {
        if !self.live {
            self.report
                .info(format!("skipped (root is not /): chown {owner} {path}"));
            return Ok(());
        }
        self.act_checked("chown", &[owner, path]).map(|_| ())
    }
}

pub fn require_root(env: &mut Env<'_>) -> Result<(), InstallError> {
    let output = env.query_checked("id", &["-u"])?;
    let uid = output.stdout.trim();
    if uid.is_empty() || !uid.chars().all(|c| c.is_ascii_digit()) {
        return Err(InstallError::UnexpectedOutput {
            command: "id -u".to_string(),
        });
    }
    if uid != "0" {
        return Err(InstallError::NotRoot {
            uid: uid.to_string(),
        });
    }
    Ok(())
}
