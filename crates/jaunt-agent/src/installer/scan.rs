use std::fs;
use std::io;

use super::error::InstallError;
use super::files;
use super::layout::{DROPIN_PATH, Layout, SSHD_CONFIG};
use super::sshd::{segment_matches, split_keyword};

const MAX_INCLUDE_DEPTH: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub value: String,
}

pub fn find_user_ca_directives(layout: &Layout) -> Result<Vec<Finding>, InstallError> {
    let mut findings = Vec::new();
    let mut visited = Vec::new();
    scan_file(layout, SSHD_CONFIG, 0, &mut visited, &mut findings)?;
    Ok(findings)
}

fn scan_file(
    layout: &Layout,
    virtual_path: &str,
    depth: usize,
    visited: &mut Vec<String>,
    findings: &mut Vec<Finding>,
) -> Result<(), InstallError> {
    if virtual_path == DROPIN_PATH
        || depth > MAX_INCLUDE_DEPTH
        || visited.iter().any(|seen| seen == virtual_path)
    {
        return Ok(());
    }
    visited.push(virtual_path.to_string());
    let Some(bytes) = files::read_optional(&layout.path(virtual_path))? else {
        return Ok(());
    };
    let text = String::from_utf8_lossy(&bytes);
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (keyword, rest) = split_keyword(line);
        if keyword.eq_ignore_ascii_case("trustedusercakeys") {
            let value = rest
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches('"');
            if !value.is_empty() && !value.eq_ignore_ascii_case("none") {
                findings.push(Finding {
                    file: virtual_path.to_string(),
                    line: index + 1,
                    value: value.to_string(),
                });
            }
        } else if keyword.eq_ignore_ascii_case("include") {
            for pattern in rest.split_whitespace() {
                for included in expand(layout, pattern.trim_matches('"'))? {
                    scan_file(layout, &included, depth + 1, visited, findings)?;
                }
            }
        }
    }
    Ok(())
}

fn expand(layout: &Layout, pattern: &str) -> Result<Vec<String>, InstallError> {
    let absolute = if pattern.starts_with('/') {
        pattern.to_string()
    } else {
        format!("/etc/ssh/{pattern}")
    };
    let mut candidates = vec![String::new()];
    for segment in absolute.split('/').skip(1) {
        if !segment.contains(['*', '?', '[']) {
            candidates = candidates
                .into_iter()
                .map(|prefix| format!("{prefix}/{segment}"))
                .collect();
            continue;
        }
        let mut next = Vec::new();
        for prefix in &candidates {
            let directory = layout.path(if prefix.is_empty() { "/" } else { prefix });
            let entries = match fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(source)
                    if matches!(
                        source.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) =>
                {
                    continue;
                }
                Err(source) => return Err(InstallError::io("read", &directory)(source)),
            };
            let mut names = Vec::new();
            for entry in entries {
                let entry = entry.map_err(InstallError::io("read", &directory))?;
                names.push(entry.file_name().to_string_lossy().into_owned());
            }
            names.sort();
            for name in names {
                let hidden_ok = !name.starts_with('.') || segment.starts_with('.');
                if hidden_ok && segment_matches(segment, &name) {
                    next.push(format!("{prefix}/{name}"));
                }
            }
        }
        candidates = next;
    }
    Ok(candidates
        .into_iter()
        .filter(|candidate| {
            fs::metadata(layout.path(candidate))
                .map(|meta| meta.is_file())
                .unwrap_or(false)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::super::layout::Layout;
    use super::super::testing::TempRoot;
    use super::{Finding, find_user_ca_directives};

    fn scan(root: &TempRoot) -> Vec<Finding> {
        find_user_ca_directives(&Layout::new(root.path()).unwrap()).unwrap()
    }

    fn finding(file: &str, line: usize, value: &str) -> Finding {
        Finding {
            file: file.to_string(),
            line,
            value: value.to_string(),
        }
    }

    #[test]
    fn directives_are_found_in_every_match_context_with_file_and_line() {
        let root = TempRoot::new();
        root.write(
            "/etc/ssh/sshd_config",
            "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nMatch Address 192.168.0.0/16\n    TrustedUserCAKeys /etc/ssh/lan-ca.pub\n",
        );
        root.write(
            "/etc/ssh/sshd_config.d/10-users.conf",
            "# comment\nMatch User deploy\n  trustedusercakeys=/etc/ssh/deploy-ca.pub\n",
        );
        root.write(
            "/etc/ssh/sshd_config.d/20-global.conf",
            "TrustedUserCAKeys \"/etc/ssh/corp-ca.pub\"\n",
        );
        assert_eq!(
            scan(&root),
            vec![
                finding(
                    "/etc/ssh/sshd_config.d/10-users.conf",
                    3,
                    "/etc/ssh/deploy-ca.pub"
                ),
                finding(
                    "/etc/ssh/sshd_config.d/20-global.conf",
                    1,
                    "/etc/ssh/corp-ca.pub"
                ),
                finding("/etc/ssh/sshd_config", 4, "/etc/ssh/lan-ca.pub"),
            ]
        );
    }

    #[test]
    fn none_comments_and_our_own_dropin_are_not_findings() {
        let root = TempRoot::new();
        root.write(
            "/etc/ssh/sshd_config",
            "Include /etc/ssh/sshd_config.d/*.conf\n#TrustedUserCAKeys /etc/ssh/x.pub\nTrustedUserCAKeys none\n",
        );
        root.write(
            "/etc/ssh/sshd_config.d/50-jaunt.conf",
            "Match Address 127.0.0.1,::1\n    TrustedUserCAKeys /var/lib/jaunt/inner-ca.pub\n",
        );
        assert_eq!(scan(&root), Vec::<Finding>::new());
    }

    #[test]
    fn nested_relative_and_cyclic_includes_are_followed_once() {
        let root = TempRoot::new();
        root.write("/etc/ssh/sshd_config", "Include extra/*.conf sshd_config\n");
        root.write(
            "/etc/ssh/extra/a.conf",
            "Include /etc/ssh/other/deep.conf\nInclude /etc/ssh/extra/a.conf\n",
        );
        root.write(
            "/etc/ssh/other/deep.conf",
            "TrustedUserCAKeys /etc/ssh/deep.pub\n",
        );
        root.write(
            "/etc/ssh/extra/.hidden.conf",
            "TrustedUserCAKeys /etc/ssh/hidden.pub\n",
        );
        assert_eq!(
            scan(&root),
            vec![finding("/etc/ssh/other/deep.conf", 1, "/etc/ssh/deep.pub")]
        );
    }

    #[test]
    fn missing_include_targets_are_ignored() {
        let root = TempRoot::new();
        root.write(
            "/etc/ssh/sshd_config",
            "Include /etc/ssh/nothing.d/*.conf /nonexistent.conf\n",
        );
        assert_eq!(scan(&root), Vec::<Finding>::new());
    }
}
