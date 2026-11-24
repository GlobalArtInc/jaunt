use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::ssh_config::{SshConfigError, path_argument};

const SSH_DIR_MODE: u32 = 0o700;
const NEW_FILE_MODE: u32 = 0o600;
const OWNER_WRITE: u32 = 0o200;
const PERMISSION_BITS: u32 = 0o7777;
const MAX_CONFIG_BYTES: u64 = 8 * 1024 * 1024;
const MAX_BACKUPS: u32 = 1000;
const BACKUP_NAME: &str = "config.jaunt-backup";
const DEFAULT_HOME_DIR: &str = ".jaunt";
const GLOB_TAIL: &str = "*/ssh_config";

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludeTarget {
    pub config_path: PathBuf,
    pub line: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncludeOutcome {
    Unchanged,
    Created,
    Added { backup: PathBuf },
}

#[derive(Debug, thiserror::Error)]
pub enum IncludeError {
    #[error("cannot {action} {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("{path} is not a regular file or a link to one")]
    NotARegularFile { path: PathBuf },
    #[error("{path} is too large to edit safely")]
    TooLarge { path: PathBuf },
    #[error(
        "{path} is read-only, so it was left unchanged; add this line at its top yourself: {line}"
    )]
    ReadOnly { path: PathBuf, line: String },
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> IncludeError {
    IncludeError::Io {
        action,
        path: path.to_owned(),
        source,
    }
}

pub fn include_line(jaunt_home: &Path, user_home: &Path) -> Result<String, SshConfigError> {
    let default_home = user_home.join(DEFAULT_HOME_DIR);
    if jaunt_home == default_home {
        return Ok(format!("Include ~/{DEFAULT_HOME_DIR}/{GLOB_TAIL}"));
    }
    let unsafe_path = || SshConfigError::UnsafePath {
        path: jaunt_home.to_owned(),
    };
    let text = jaunt_home
        .to_str()
        .ok_or_else(unsafe_path)?
        .trim_end_matches('/');
    path_argument(text).ok_or_else(unsafe_path)?;
    let glob = format!("{text}/{GLOB_TAIL}");
    let argument = if glob.contains(' ') {
        format!("\"{glob}\"")
    } else {
        glob
    };
    Ok(format!("Include {argument}"))
}

fn opens_a_block(line: &[u8]) -> bool {
    let text = String::from_utf8_lossy(line);
    let keyword = text
        .trim_start()
        .split(|ch: char| ch.is_whitespace() || ch == '=')
        .next()
        .unwrap_or_default();
    keyword.eq_ignore_ascii_case("host") || keyword.eq_ignore_ascii_case("match")
}

fn without_terminator(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

pub fn with_include(content: &[u8], line: &str) -> Option<Vec<u8>> {
    for existing in content.split_inclusive(|byte| *byte == b'\n') {
        let bare = without_terminator(existing);
        if bare == line.as_bytes() {
            return None;
        }
        if opens_a_block(bare) {
            break;
        }
    }
    let first = content.split_inclusive(|byte| *byte == b'\n').next();
    let eol: &[u8] = match first {
        Some(first) if first.ends_with(b"\r\n") => b"\r\n",
        _ => b"\n",
    };
    let first_is_blank =
        first.is_some_and(|first| without_terminator(first).trim_ascii().is_empty());
    let mut updated = Vec::with_capacity(content.len() + line.len() + 4);
    updated.extend_from_slice(line.as_bytes());
    updated.extend_from_slice(eol);
    if first.is_some() && !first_is_blank {
        updated.extend_from_slice(eol);
    }
    updated.extend_from_slice(content);
    Some(updated)
}

fn read_limited(path: &Path) -> Result<Vec<u8>, IncludeError> {
    let file = File::open(path).map_err(|err| io_error("read", path, err))?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| io_error("read", path, err))?;
    if u64::try_from(bytes.len()).is_ok_and(|length| length > MAX_CONFIG_BYTES) {
        return Err(IncludeError::TooLarge {
            path: path.to_owned(),
        });
    }
    Ok(bytes)
}

fn resolve(config_path: &Path) -> Result<Option<PathBuf>, IncludeError> {
    let meta = match fs::symlink_metadata(config_path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(io_error("inspect", config_path, err)),
    };
    let target = if meta.file_type().is_symlink() {
        fs::canonicalize(config_path).map_err(|err| io_error("resolve", config_path, err))?
    } else {
        config_path.to_owned()
    };
    let resolved = fs::metadata(&target).map_err(|err| io_error("inspect", &target, err))?;
    if resolved.is_file() {
        Ok(Some(target))
    } else {
        Err(IncludeError::NotARegularFile { path: target })
    }
}

pub fn include_present(target: &IncludeTarget) -> Result<bool, IncludeError> {
    match resolve(&target.config_path)? {
        None => Ok(false),
        Some(path) => Ok(with_include(&read_limited(&path)?, &target.line).is_none()),
    }
}

pub fn ensure_include(target: &IncludeTarget) -> Result<IncludeOutcome, IncludeError> {
    let config_path = &target.config_path;
    let ssh_dir = config_path
        .parent()
        .ok_or_else(|| IncludeError::NotARegularFile {
            path: config_path.clone(),
        })?;
    match fs::metadata(ssh_dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            return Err(IncludeError::NotARegularFile {
                path: ssh_dir.to_owned(),
            });
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            DirBuilder::new()
                .mode(SSH_DIR_MODE)
                .create(ssh_dir)
                .map_err(|err| io_error("create", ssh_dir, err))?;
        }
        Err(err) => return Err(io_error("inspect", ssh_dir, err)),
    }
    let Some(real_path) = resolve(config_path)? else {
        return create_new(config_path, &target.line);
    };
    let original = read_limited(&real_path)?;
    let Some(updated) = with_include(&original, &target.line) else {
        return Ok(IncludeOutcome::Unchanged);
    };
    let meta = fs::metadata(&real_path).map_err(|err| io_error("inspect", &real_path, err))?;
    let mode = meta.mode() & PERMISSION_BITS;
    if mode & OWNER_WRITE == 0 {
        return Err(IncludeError::ReadOnly {
            path: real_path,
            line: target.line.clone(),
        });
    }
    let directory = real_path.parent().unwrap_or(ssh_dir);
    let temporary = write_temporary(directory, &updated, mode)?;
    let backup = match write_backup(ssh_dir, &original) {
        Ok(backup) => backup,
        Err(err) => {
            drop(fs::remove_file(&temporary));
            return Err(err);
        }
    };
    if let Err(err) = fs::rename(&temporary, &real_path) {
        drop(fs::remove_file(&temporary));
        return Err(io_error("replace", &real_path, err));
    }
    drop(sync_directory(directory));
    Ok(IncludeOutcome::Added { backup })
}

fn create_new(config_path: &Path, line: &str) -> Result<IncludeOutcome, IncludeError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(NEW_FILE_MODE)
        .open(config_path)
        .map_err(|err| io_error("create", config_path, err))?;
    file.write_all(format!("{line}\n").as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|err| io_error("write", config_path, err))?;
    Ok(IncludeOutcome::Created)
}

fn write_temporary(directory: &Path, contents: &[u8], mode: u32) -> Result<PathBuf, IncludeError> {
    let serial = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = directory.join(format!(".config.jaunt-tmp.{}.{serial}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(NEW_FILE_MODE)
        .open(&path)
        .map_err(|err| io_error("create", &path, err))?;
    let written = file
        .write_all(contents)
        .and_then(|()| file.set_permissions(fs::Permissions::from_mode(mode)))
        .and_then(|()| file.sync_all());
    if let Err(err) = written {
        drop(fs::remove_file(&path));
        return Err(io_error("write", &path, err));
    }
    Ok(path)
}

fn write_backup(ssh_dir: &Path, original: &[u8]) -> Result<PathBuf, IncludeError> {
    for attempt in 0..MAX_BACKUPS {
        let name = if attempt == 0 {
            BACKUP_NAME.to_owned()
        } else {
            format!("{BACKUP_NAME}.{attempt}")
        };
        let path = ssh_dir.join(name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(NEW_FILE_MODE)
            .open(&path)
        {
            Ok(mut file) => {
                let written = file.write_all(original).and_then(|()| file.sync_all());
                if let Err(err) = written {
                    drop(fs::remove_file(&path));
                    return Err(io_error("write", &path, err));
                }
                return Ok(path);
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(io_error("create", &path, err)),
        }
    }
    Err(io_error(
        "create a backup of",
        &ssh_dir.join("config"),
        io::Error::other("too many earlier backups exist"),
    ))
}

fn sync_directory(directory: &Path) -> io::Result<()> {
    File::open(directory).and_then(|handle| handle.sync_all())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    use super::{
        IncludeError, IncludeOutcome, IncludeTarget, ensure_include, include_line, include_present,
        with_include,
    };

    const LINE: &str = "Include ~/.jaunt/*/ssh_config";

    fn target(home: &Path) -> IncludeTarget {
        IncludeTarget {
            config_path: home.join(".ssh/config"),
            line: LINE.to_owned(),
        }
    }

    fn text(bytes: Option<Vec<u8>>) -> String {
        String::from_utf8(bytes.unwrap()).unwrap()
    }

    #[test]
    fn the_include_goes_before_everything_and_is_found_again_at_the_top() {
        let cases: [(&str, Option<&str>); 12] = [
            ("", Some("Include ~/.jaunt/*/ssh_config\n")),
            (
                "Host a\n  User x\n",
                Some("Include ~/.jaunt/*/ssh_config\n\nHost a\n  User x\n"),
            ),
            (
                "Match host b\n  User y\n",
                Some("Include ~/.jaunt/*/ssh_config\n\nMatch host b\n  User y\n"),
            ),
            (
                "# note\nHost a\n",
                Some("Include ~/.jaunt/*/ssh_config\n\n# note\nHost a\n"),
            ),
            (
                "\n\nHost a\n",
                Some("Include ~/.jaunt/*/ssh_config\n\n\nHost a\n"),
            ),
            (
                "Host a\r\n  User x\r\n",
                Some("Include ~/.jaunt/*/ssh_config\r\n\r\nHost a\r\n  User x\r\n"),
            ),
            ("Include ~/.jaunt/*/ssh_config\nHost a\n", None),
            ("\n\nInclude ~/.jaunt/*/ssh_config\n\nHost a\n", None),
            ("Include ~/.jaunt/*/ssh_config\r\nHost a\r\n", None),
            (
                "Include other\nInclude ~/.jaunt/*/ssh_config\nHost a\n",
                None,
            ),
            (
                "Host a\nInclude ~/.jaunt/*/ssh_config\n",
                Some("Include ~/.jaunt/*/ssh_config\n\nHost a\nInclude ~/.jaunt/*/ssh_config\n"),
            ),
            (
                "  Include ~/.jaunt/*/ssh_config\nHost a\n",
                Some("Include ~/.jaunt/*/ssh_config\n\n  Include ~/.jaunt/*/ssh_config\nHost a\n"),
            ),
        ];
        for (before, after) in cases {
            let updated = with_include(before.as_bytes(), LINE);
            assert_eq!(
                updated
                    .map(|bytes| String::from_utf8(bytes).unwrap())
                    .as_deref(),
                after,
                "{before:?}"
            );
            if let Some(after) = after {
                assert!(with_include(after.as_bytes(), LINE).is_none(), "{after:?}");
            }
        }
    }

    #[test]
    fn every_spelling_of_a_block_keyword_ends_the_top_of_the_file() {
        for opener in [
            "Host a",
            "host a",
            "HOST a",
            "Host=a",
            "host = a",
            "  Host a",
            "\tHost a",
            "Match all",
            "match all",
            "MATCH host x",
            "Match=all",
        ] {
            let below = format!("{opener}\n{LINE}\n");
            let updated = with_include(below.as_bytes(), LINE).unwrap();
            assert!(
                updated.starts_with(format!("{LINE}\n\n{opener}\n").as_bytes()),
                "{opener:?}"
            );
        }
        for harmless in [
            "HostName a",
            "HostbasedAuthentication yes",
            "Matching x",
            "# Host a",
        ] {
            let above = format!("{harmless}\n{LINE}\nHost b\n");
            assert!(
                with_include(above.as_bytes(), LINE).is_none(),
                "{harmless:?}"
            );
        }
    }

    #[test]
    fn a_config_over_the_size_limit_is_refused_untouched() {
        let (home, config) = home_with_config(Some(""), 0o600);
        let oversized = vec![b'#'; 8 * 1024 * 1024 + 1];
        fs::write(&config, &oversized).unwrap();

        let outcome = ensure_include(&target(home.path()));
        let present = include_present(&target(home.path()));

        assert!(
            matches!(outcome, Err(IncludeError::TooLarge { .. })),
            "{outcome:?}"
        );
        assert!(matches!(present, Err(IncludeError::TooLarge { .. })));
        assert_eq!(fs::read(&config).unwrap(), oversized);
        assert_eq!(names(&home.path().join(".ssh")), ["config"]);

        fs::write(&config, vec![b'#'; 8 * 1024 * 1024]).unwrap();
        assert!(matches!(
            ensure_include(&target(home.path())),
            Ok(IncludeOutcome::Added { .. })
        ));
    }

    #[test]
    fn non_utf8_content_is_kept_byte_for_byte() {
        let before = b"# caf\xe9\nHost a\n";
        let after = with_include(before, LINE).unwrap();
        assert!(after.ends_with(before));
        assert_eq!(text(Some(after[..LINE.len()].to_vec())), LINE);
    }

    #[test]
    fn the_line_names_the_default_home_with_a_tilde_and_other_homes_by_path() {
        let user = Path::new("/home/u");
        assert_eq!(
            include_line(Path::new("/home/u/.jaunt"), user).unwrap(),
            "Include ~/.jaunt/*/ssh_config"
        );
        assert_eq!(
            include_line(Path::new("/srv/jaunt"), user).unwrap(),
            "Include /srv/jaunt/*/ssh_config"
        );
        assert_eq!(
            include_line(Path::new("/srv/my jaunt/"), user).unwrap(),
            "Include \"/srv/my jaunt/*/ssh_config\""
        );
        for bad in ["/srv/a[b]", "/srv/a\nb", "/srv/50%", "/srv/$X", "relative"] {
            assert!(include_line(Path::new(bad), user).is_err(), "{bad:?}");
        }
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    fn home_with_config(content: Option<&str>, file_mode: u32) -> (tempfile::TempDir, PathBuf) {
        let home = tempfile::tempdir().unwrap();
        let config = home.path().join(".ssh/config");
        if let Some(content) = content {
            fs::create_dir(home.path().join(".ssh")).unwrap();
            fs::write(&config, content).unwrap();
            fs::set_permissions(&config, fs::Permissions::from_mode(file_mode)).unwrap();
        }
        (home, config)
    }

    #[test]
    fn a_missing_ssh_directory_and_file_are_created_with_private_modes() {
        let (home, config) = home_with_config(None, 0o600);

        let outcome = ensure_include(&target(home.path())).unwrap();

        assert_eq!(outcome, IncludeOutcome::Created);
        assert_eq!(fs::read_to_string(&config).unwrap(), format!("{LINE}\n"));
        assert_eq!(mode(&config), 0o600);
        assert_eq!(mode(&home.path().join(".ssh")), 0o700);
        assert_eq!(
            ensure_include(&target(home.path())).unwrap(),
            IncludeOutcome::Unchanged
        );
    }

    #[test]
    fn an_existing_file_is_backed_up_once_edited_atomically_and_keeps_its_mode() {
        let before = "Host a\n  User x\n";
        let (home, config) = home_with_config(Some(before), 0o644);
        let ssh = home.path().join(".ssh");

        let outcome = ensure_include(&target(home.path())).unwrap();

        assert_eq!(
            outcome,
            IncludeOutcome::Added {
                backup: ssh.join("config.jaunt-backup")
            }
        );
        assert_eq!(
            fs::read_to_string(&config).unwrap(),
            format!("{LINE}\n\n{before}")
        );
        assert_eq!(mode(&config), 0o644);
        assert_eq!(
            fs::read_to_string(ssh.join("config.jaunt-backup")).unwrap(),
            before
        );
        assert_eq!(names(&ssh), ["config", "config.jaunt-backup"]);

        let after_first = fs::read(&config).unwrap();
        assert_eq!(
            ensure_include(&target(home.path())).unwrap(),
            IncludeOutcome::Unchanged
        );
        assert_eq!(fs::read(&config).unwrap(), after_first);
        assert_eq!(names(&ssh), ["config", "config.jaunt-backup"]);
    }

    #[test]
    fn an_existing_backup_is_never_overwritten() {
        let (home, config) = home_with_config(Some("Host a\n"), 0o600);
        let ssh = home.path().join(".ssh");
        fs::write(ssh.join("config.jaunt-backup"), "precious\n").unwrap();
        fs::write(ssh.join("config.jaunt-backup.1"), "also precious\n").unwrap();

        let outcome = ensure_include(&target(home.path())).unwrap();

        assert_eq!(
            outcome,
            IncludeOutcome::Added {
                backup: ssh.join("config.jaunt-backup.2")
            }
        );
        assert_eq!(
            fs::read_to_string(ssh.join("config.jaunt-backup")).unwrap(),
            "precious\n"
        );
        assert_eq!(
            fs::read_to_string(ssh.join("config.jaunt-backup.1")).unwrap(),
            "also precious\n"
        );
        assert_eq!(
            fs::read_to_string(ssh.join("config.jaunt-backup.2")).unwrap(),
            "Host a\n"
        );
        assert!(fs::read_to_string(&config).unwrap().starts_with(LINE));
    }

    #[test]
    fn a_read_only_config_is_refused_with_nothing_changed() {
        let before = "Host a\n";
        let (home, config) = home_with_config(Some(before), 0o444);
        let ssh = home.path().join(".ssh");

        let outcome = ensure_include(&target(home.path()));

        let Err(IncludeError::ReadOnly { path, line }) = outcome else {
            panic!("expected a read-only refusal, got {outcome:?}");
        };
        assert_eq!(path, config);
        assert_eq!(line, LINE);
        assert_eq!(fs::read_to_string(&config).unwrap(), before);
        assert_eq!(names(&ssh), ["config"]);
        assert_eq!(mode(&config), 0o444);
    }

    #[test]
    fn a_symlinked_config_is_edited_through_the_link_and_the_link_stays() {
        let home = tempfile::tempdir().unwrap();
        let dotfiles = home.path().join("dotfiles");
        let ssh = home.path().join(".ssh");
        fs::create_dir(&dotfiles).unwrap();
        fs::create_dir(&ssh).unwrap();
        let real = dotfiles.join("ssh_config");
        fs::write(&real, "Host a\n").unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o640)).unwrap();
        symlink(&real, ssh.join("config")).unwrap();

        let outcome = ensure_include(&target(home.path())).unwrap();

        assert!(matches!(outcome, IncludeOutcome::Added { .. }));
        assert!(
            fs::symlink_metadata(ssh.join("config"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_to_string(&real).unwrap(),
            format!("{LINE}\n\nHost a\n")
        );
        assert_eq!(mode(&real), 0o640);
        assert_eq!(names(&dotfiles), ["ssh_config"]);
        assert_eq!(
            fs::read_to_string(ssh.join("config.jaunt-backup")).unwrap(),
            "Host a\n"
        );
        assert!(include_present(&target(home.path())).unwrap());
    }

    #[test]
    fn a_dangling_link_or_a_directory_in_place_of_the_config_is_an_error() {
        let home = tempfile::tempdir().unwrap();
        let ssh = home.path().join(".ssh");
        fs::create_dir(&ssh).unwrap();
        symlink(home.path().join("missing"), ssh.join("config")).unwrap();
        assert!(ensure_include(&target(home.path())).is_err());
        fs::remove_file(ssh.join("config")).unwrap();
        fs::create_dir(ssh.join("config")).unwrap();
        assert!(matches!(
            ensure_include(&target(home.path())),
            Err(IncludeError::NotARegularFile { .. })
        ));
        assert_eq!(names(&ssh), ["config"]);
    }

    #[test]
    fn windows_line_endings_are_kept_and_the_second_run_changes_nothing() {
        let (home, config) = home_with_config(Some("Host a\r\n  User x\r\n"), 0o600);

        ensure_include(&target(home.path())).unwrap();
        let first = fs::read(&config).unwrap();

        assert_eq!(
            String::from_utf8(first.clone()).unwrap(),
            format!("{LINE}\r\n\r\nHost a\r\n  User x\r\n")
        );
        assert_eq!(
            ensure_include(&target(home.path())).unwrap(),
            IncludeOutcome::Unchanged
        );
        assert_eq!(fs::read(&config).unwrap(), first);
        assert_eq!(fs::metadata(&config).unwrap().mode() & 0o7777, 0o600);
    }

    #[test]
    fn a_line_that_is_present_only_below_a_host_block_is_added_at_the_top() {
        let (home, config) = home_with_config(Some("Host a\n  User x\n"), 0o600);
        fs::write(&config, format!("Host a\n{LINE}\n")).unwrap();

        let outcome = ensure_include(&target(home.path())).unwrap();

        assert!(matches!(outcome, IncludeOutcome::Added { .. }));
        assert!(
            !include_present(&IncludeTarget {
                config_path: home.path().join("absent"),
                line: LINE.to_owned()
            })
            .unwrap()
        );
        assert!(
            fs::read_to_string(&config)
                .unwrap()
                .starts_with(&format!("{LINE}\n\nHost a\n"))
        );
    }
}
