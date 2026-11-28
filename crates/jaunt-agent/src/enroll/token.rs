use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use zeroize::Zeroizing;

const PREFIX: &str = "jt1.";
const ENCODED_LEN: usize = 43;
pub const MAX_FILE_BYTES: usize = 4096;
const ALLOWED_MODE_BITS: u32 = 0o600;
const REDACTED: &str = "[redacted]";

pub struct JoinToken(Zeroizing<String>);

impl JoinToken {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for JoinToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("JoinToken").field(&REDACTED).finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TokenFileError {
    #[error("cannot open {}: {source}", path.display())]
    Open {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{} is a symbolic link; pass the file itself", path.display())]
    Symlink { path: PathBuf },
    #[error("{} is not a regular file", path.display())]
    NotRegular { path: PathBuf },
    #[error("{} is not owned by the user running the agent (uid {uid})", path.display())]
    Owner { path: PathBuf, uid: u32 },
    #[error("{} has mode {mode:04o}; it must be 0600 or stricter", path.display())]
    Mode { path: PathBuf, mode: u32 },
    #[error("cannot read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{} does not hold a join token", path.display())]
    NotAToken { path: PathBuf },
}

pub fn read_token_file(path: &Path, caller_uid: u32) -> Result<JoinToken, TokenFileError> {
    let owned = || path.to_path_buf();
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = rustix::fs::open(path, flags, Mode::empty()).map_err(|errno| match errno {
        Errno::LOOP | Errno::MLINK => TokenFileError::Symlink { path: owned() },
        other => TokenFileError::Open {
            path: owned(),
            source: io::Error::from(other),
        },
    })?;
    let file = File::from(fd);
    let meta = file.metadata().map_err(|source| TokenFileError::Read {
        path: owned(),
        source,
    })?;
    if !meta.is_file() {
        return Err(TokenFileError::NotRegular { path: owned() });
    }
    if meta.uid() != caller_uid {
        return Err(TokenFileError::Owner {
            path: owned(),
            uid: caller_uid,
        });
    }
    let mode = meta.mode() & 0o7777;
    if mode & !ALLOWED_MODE_BITS != 0 {
        return Err(TokenFileError::Mode {
            path: owned(),
            mode,
        });
    }
    let mut content = Zeroizing::new(Vec::with_capacity(MAX_FILE_BYTES + 1));
    file.take(u64::try_from(MAX_FILE_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut content)
        .map_err(|source| TokenFileError::Read {
            path: owned(),
            source,
        })?;
    parse_token(&content).ok_or_else(|| TokenFileError::NotAToken { path: owned() })
}

pub fn parse_token(content: &[u8]) -> Option<JoinToken> {
    if content.len() > MAX_FILE_BYTES {
        return None;
    }
    let text = std::str::from_utf8(content).ok()?;
    let token = text.trim_matches(|ch: char| ch.is_ascii_whitespace());
    is_join_token(token).then(|| JoinToken(Zeroizing::new(token.to_owned())))
}

fn is_join_token(text: &str) -> bool {
    text.strip_prefix(PREFIX).is_some_and(|encoded| {
        encoded.len() == ENCODED_LEN
            && encoded
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;

    use super::{TokenFileError, read_token_file};
    use crate::fsio::effective_uid;

    const TOKEN: &str = "jt1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn write(path: &Path, content: &str, mode: u32) {
        fs::write(path, content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn a_private_file_of_the_caller_is_read_once_and_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        for (mode, content) in [
            (0o600, format!("{TOKEN}\n")),
            (0o400, format!("  {TOKEN}\r\n\n")),
            (0o600, TOKEN.to_owned()),
        ] {
            let path = dir.path().join("token");
            write(&path, &content, mode);
            let token = read_token_file(&path, effective_uid()).unwrap();
            assert_eq!(token.expose(), TOKEN);
            assert!(!format!("{token:?}").contains(TOKEN));
            fs::remove_file(&path).unwrap();
        }
    }

    #[test]
    fn a_file_that_others_may_read_or_that_is_not_private_is_refused_without_showing_it() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o640, 0o644, 0o604, 0o700, 0o610, 0o4600] {
            let path = dir.path().join(format!("token-{mode:o}"));
            write(&path, TOKEN, 0o600);
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            let error = read_token_file(&path, effective_uid()).unwrap_err();
            assert!(
                matches!(error, TokenFileError::Mode { mode: seen, .. } if seen == mode),
                "{mode:o}: {error}"
            );
            assert!(!error.to_string().contains(TOKEN));
        }
    }

    #[test]
    fn links_directories_missing_files_and_other_owners_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        write(&real, TOKEN, 0o600);
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();

        assert!(matches!(
            read_token_file(&link, effective_uid()),
            Err(TokenFileError::Symlink { .. })
        ));
        assert!(matches!(
            read_token_file(dir.path(), effective_uid()),
            Err(TokenFileError::NotRegular { .. })
        ));
        assert!(matches!(
            read_token_file(&dir.path().join("absent"), effective_uid()),
            Err(TokenFileError::Open { .. })
        ));
        let foreign = read_token_file(&real, effective_uid().wrapping_add(1)).unwrap_err();
        assert!(matches!(foreign, TokenFileError::Owner { .. }), "{foreign}");
        assert!(!foreign.to_string().contains(TOKEN));
    }

    #[test]
    fn content_that_is_not_exactly_one_join_token_is_refused_without_showing_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        for content in [
            String::new(),
            "secret-but-not-a-token".to_owned(),
            format!("{TOKEN}{TOKEN}"),
            format!("{TOKEN}\n{TOKEN}\n"),
            format!("{TOKEN}A"),
            TOKEN.replacen("jt1.", "jt_", 1),
            TOKEN.replacen('A', "+", 1),
            format!("{TOKEN}{}", " ".repeat(5000)),
            format!("\u{feff}{TOKEN}"),
        ] {
            write(&path, &content, 0o600);
            let error = read_token_file(&path, effective_uid()).unwrap_err();
            assert!(
                matches!(error, TokenFileError::NotAToken { .. }),
                "{content:?}: {error}"
            );
            let shown = error.to_string();
            assert!(!shown.contains("secret-but-not-a-token") && !shown.contains(TOKEN));
            fs::remove_file(&path).unwrap();
        }
    }
}
