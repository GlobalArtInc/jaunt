const MAX_SSH_LOGIN_BYTES: usize = 32;

pub fn is_portable_login(login: &str) -> bool {
    let bytes = login.as_bytes();
    let Some((first, rest)) = bytes.split_first() else {
        return false;
    };
    bytes.len() <= MAX_SSH_LOGIN_BYTES
        && (first.is_ascii_lowercase() || *first == b'_')
        && rest.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::{MAX_SSH_LOGIN_BYTES, is_portable_login};

    #[test]
    fn only_lowercase_portable_names_up_to_the_limit_are_logins() {
        let longest = "a".repeat(MAX_SSH_LOGIN_BYTES);
        let too_long = "a".repeat(MAX_SSH_LOGIN_BYTES + 1);
        for (login, portable) in [
            ("deploy", true),
            ("_svc", true),
            ("a.b-c_9", true),
            ("root", true),
            (longest.as_str(), true),
            ("Rozmarin", false),
            ("deplOy", false),
            ("9lives", false),
            ("", false),
            (too_long.as_str(), false),
            ("ro ot", false),
            ("-oProxyCommand=x", false),
            (".hidden", false),
            ("a@b", false),
            ("a/b", false),
            ("a\n", false),
            ("a\u{0}b", false),
            ("\u{e9}", false),
            ("d\u{e9}", false),
            ("ro\u{200b}ot", false),
            ("\u{ff41}", false),
        ] {
            assert_eq!(is_portable_login(login), portable, "{login:?}");
        }
    }
}
