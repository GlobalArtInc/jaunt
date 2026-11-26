pub(crate) fn is_clean_absolute_path(path: &str, max_bytes: usize) -> bool {
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    path.len() <= max_bytes
        && !rest.is_empty()
        && rest.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+')
                })
        })
}

#[cfg(test)]
mod tests {
    use super::is_clean_absolute_path;

    #[test]
    fn only_plain_absolute_paths_within_the_limit_are_clean() {
        for (path, clean) in [
            ("/home", true),
            ("/srv/users-1/a.b_c+d", true),
            ("/bin/bash", true),
            ("/", false),
            ("", false),
            ("home", false),
            ("/home/", false),
            ("//home", false),
            ("/home//x", false),
            ("/home/./x", false),
            ("/home/../etc", false),
            ("/home dir", false),
            ("/home:x", false),
            ("/home\n", false),
            ("/h\u{e9}me", false),
        ] {
            assert_eq!(is_clean_absolute_path(path, 64), clean, "{path:?}");
        }
        assert!(is_clean_absolute_path("/abcdefgh", 9));
        assert!(!is_clean_absolute_path("/abcdefghi", 9));
    }
}
