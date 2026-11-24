const SYSTEM_TOP_LEVEL: &[&str] = &[
    "bin", "boot", "dev", "etc", "lib", "lib32", "lib64", "libx32", "proc", "root", "run", "sbin",
    "sys", "usr",
];

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
    if value == "/" {
        return Err(
            "is the filesystem root, which is not an acceptable location; use a dedicated directory such as /var/lib/jaunt",
        );
    }
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
    use super::{check_absolute_path, check_state_dir};

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
        assert!(
            check_state_dir("/")
                .unwrap_err()
                .contains("not an acceptable location")
        );
    }
}
