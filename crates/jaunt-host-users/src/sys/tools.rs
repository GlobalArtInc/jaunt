use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::files::SystemFiles;
use crate::config::TrustProblem;
use crate::system::{FileFacts, FileKind, Files, FilesError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tool {
    pub(crate) name: &'static str,
    pub(crate) candidates: &'static [&'static str],
}

pub(crate) const USERADD: Tool = Tool {
    name: "useradd",
    candidates: &["/usr/sbin/useradd", "/sbin/useradd"],
};
pub(crate) const USERDEL: Tool = Tool {
    name: "userdel",
    candidates: &["/usr/sbin/userdel", "/sbin/userdel"],
};
pub(crate) const GETENT: Tool = Tool {
    name: "getent",
    candidates: &["/usr/bin/getent", "/bin/getent"],
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum ToolError {
    #[error("{name} is not installed in any of the expected places")]
    Missing { name: &'static str },
    #[error("{path} cannot be trusted: {problem}")]
    Untrusted {
        path: PathBuf,
        problem: TrustProblem,
    },
    #[error("cannot inspect {path}: {source}")]
    Inspect {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Files(#[from] FilesError),
}

pub(crate) fn locate(tool: &Tool, owner: u32) -> Result<PathBuf, ToolError> {
    locate_in(tool.name, tool.candidates, &SystemFiles, owner)
}

fn locate_in(
    name: &'static str,
    candidates: &[&str],
    files: &dyn Files,
    owner: u32,
) -> Result<PathBuf, ToolError> {
    for candidate in candidates {
        let real = match fs::canonicalize(candidate) {
            Ok(real) => real,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(ToolError::Inspect {
                    path: PathBuf::from(candidate),
                    source,
                });
            }
        };
        trusted_chain(&real, files, owner)?;
        return Ok(real);
    }
    Err(ToolError::Missing { name })
}

fn trusted_chain(tool: &Path, files: &dyn Files, owner: u32) -> Result<(), ToolError> {
    require(tool, FileKind::Regular, files, owner)?;
    for directory in tool.ancestors().skip(1) {
        require(directory, FileKind::Directory, files, owner)?;
    }
    Ok(())
}

fn require(
    path: &Path,
    expected: FileKind,
    files: &dyn Files,
    owner: u32,
) -> Result<(), ToolError> {
    let facts = files.lstat(path)?.ok_or_else(|| ToolError::Inspect {
        path: path.to_path_buf(),
        source: io::Error::from(io::ErrorKind::NotFound),
    })?;
    match problem(&facts, expected, owner) {
        None => Ok(()),
        Some(problem) => Err(ToolError::Untrusted {
            path: path.to_path_buf(),
            problem,
        }),
    }
}

fn problem(facts: &FileFacts, expected: FileKind, owner: u32) -> Option<TrustProblem> {
    if facts.kind == FileKind::Symlink {
        Some(TrustProblem::Symlink)
    } else if facts.kind != expected {
        Some(TrustProblem::WrongKind)
    } else if facts.uid != owner {
        Some(TrustProblem::NotOwnedByRoot)
    } else if facts.writable_by_group_or_others() {
        Some(TrustProblem::Writable)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    use super::{ToolError, locate_in, trusted_chain};
    use crate::config::TrustProblem;
    use crate::system::FileKind;
    use crate::testing::FakeFiles;

    const USERADD: &str = "/usr/sbin/useradd";

    fn usual() -> FakeFiles {
        FakeFiles::default()
            .root_dirs(&["/", "/usr", "/usr/sbin"])
            .with(USERADD, FileKind::Regular, 0, 0o755)
    }

    #[test]
    fn the_tool_and_every_directory_above_it_must_belong_to_root_and_be_closed() {
        assert!(trusted_chain(Path::new(USERADD), &usual(), 0).is_ok());
        let cases: [(FakeFiles, &str, TrustProblem); 6] = [
            (
                usual().with("/usr/sbin", FileKind::Directory, 0, 0o775),
                "/usr/sbin",
                TrustProblem::Writable,
            ),
            (
                usual().with("/usr", FileKind::Directory, 0, 0o757),
                "/usr",
                TrustProblem::Writable,
            ),
            (
                usual().with("/usr", FileKind::Directory, 1000, 0o755),
                "/usr",
                TrustProblem::NotOwnedByRoot,
            ),
            (
                usual().with("/usr/sbin", FileKind::Symlink, 0, 0o777),
                "/usr/sbin",
                TrustProblem::Symlink,
            ),
            (
                usual().with(USERADD, FileKind::Regular, 1000, 0o755),
                USERADD,
                TrustProblem::NotOwnedByRoot,
            ),
            (
                usual().with(USERADD, FileKind::Regular, 0, 0o775),
                USERADD,
                TrustProblem::Writable,
            ),
        ];
        for (files, path, expected) in cases {
            match trusted_chain(Path::new(USERADD), &files, 0) {
                Err(ToolError::Untrusted {
                    path: found,
                    problem,
                }) => {
                    assert_eq!((found.as_path(), problem), (Path::new(path), expected));
                }
                other => panic!("{path}: {other:?}"),
            }
        }
        assert!(matches!(
            trusted_chain(Path::new(USERADD), &usual().without("/usr"), 0),
            Err(ToolError::Inspect { .. })
        ));
    }

    #[test]
    fn the_first_existing_candidate_is_resolved_and_a_missing_tool_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real-tool");
        let link = dir.path().join("link-tool");
        let missing = dir.path().join("missing-tool");
        fs::write(&real, "#!/bin/sh\n").unwrap();
        symlink(&real, &link).unwrap();
        let canonical = fs::canonicalize(&real).unwrap();
        let files = canonical
            .ancestors()
            .skip(1)
            .fold(FakeFiles::default(), |files, directory| {
                files.with(directory.to_str().unwrap(), FileKind::Directory, 0, 0o755)
            })
            .with(canonical.to_str().unwrap(), FileKind::Regular, 0, 0o755);
        let path = |path: &Path| path.to_str().unwrap().to_owned();

        let found = locate_in("tool", &[&path(&missing), &path(&link)], &files, 0).unwrap();
        assert_eq!(found, canonical);
        assert!(matches!(
            locate_in("tool", &[&path(&missing)], &files, 0),
            Err(ToolError::Missing { name: "tool" })
        ));
    }
}
