const MAX_DB_IDENTIFIER_BYTES: usize = 63;
const DB_SUPERUSER: &str = "postgres";
const RESERVED_DB_ROLE_PREFIX: &str = "pg_";

fn is_identifier(value: &str, first: impl Fn(u8) -> bool, rest: impl Fn(u8) -> bool) -> bool {
    let bytes = value.as_bytes();
    let Some((head, tail)) = bytes.split_first() else {
        return false;
    };
    bytes.len() <= MAX_DB_IDENTIFIER_BYTES && first(*head) && tail.iter().all(|byte| rest(*byte))
}

pub fn is_db_user(value: &str) -> bool {
    is_identifier(
        value,
        |byte| byte.is_ascii_alphabetic() || byte == b'_',
        |byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'),
    )
}

pub fn is_valid_substituted_db_user(value: &str) -> bool {
    is_identifier(
        value,
        |byte| byte.is_ascii_lowercase() || byte == b'_',
        |byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_',
    ) && value != DB_SUPERUSER
        && !value.starts_with(RESERVED_DB_ROLE_PREFIX)
}

pub fn is_db_name(value: &str) -> bool {
    let allowed = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-');
    is_identifier(value, allowed, allowed)
}

pub fn is_valid_substituted_db_name(value: &str) -> bool {
    is_identifier(
        value,
        |byte| byte.is_ascii_lowercase() || byte == b'_',
        |byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_DB_IDENTIFIER_BYTES, is_db_name, is_db_user, is_valid_substituted_db_name,
        is_valid_substituted_db_user,
    };

    #[test]
    fn db_users_follow_the_literal_and_the_stricter_substituted_grammar() {
        let longest = format!("a{}", "b".repeat(MAX_DB_IDENTIFIER_BYTES - 1));
        let too_long = format!("a{}", "b".repeat(MAX_DB_IDENTIFIER_BYTES));
        for (value, literal, substituted) in [
            ("readonly", true, true),
            ("_app", true, true),
            ("alice_2", true, true),
            (longest.as_str(), true, true),
            ("postgresql", true, true),
            ("xpg_x", true, true),
            ("pg", true, true),
            ("Alice", true, false),
            ("aB", true, false),
            ("app_User", true, false),
            ("app$1", true, false),
            ("postgres", true, false),
            ("pg_read_all_data", true, false),
            ("pg_", true, false),
            ("PG_monitor", true, false),
            ("Postgres", true, false),
            ("", false, false),
            ("1app", false, false),
            ("$app", false, false),
            ("a-b", false, false),
            ("a.b", false, false),
            ("a b", false, false),
            ("a@b", false, false),
            ("a\u{0}", false, false),
            ("\u{e9}", false, false),
            (too_long.as_str(), false, false),
        ] {
            assert_eq!(is_db_user(value), literal, "literal {value:?}");
            assert_eq!(
                is_valid_substituted_db_user(value),
                substituted,
                "substituted {value:?}"
            );
        }
    }

    #[test]
    fn db_names_follow_the_literal_and_the_stricter_substituted_grammar() {
        let longest = "a".repeat(MAX_DB_IDENTIFIER_BYTES);
        let too_long = "a".repeat(MAX_DB_IDENTIFIER_BYTES + 1);
        for (value, literal, substituted) in [
            ("app", true, true),
            ("_app.v2-x", true, true),
            ("postgres", true, true),
            ("pg_catalog", true, true),
            (longest.as_str(), true, true),
            ("App", true, false),
            ("aB", true, false),
            ("app.V2", true, false),
            ("9app", true, false),
            ("-app", true, false),
            (".app", true, false),
            ("", false, false),
            ("*", false, false),
            ("a b", false, false),
            ("a/b", false, false),
            ("a$b", false, false),
            ("a\n", false, false),
            ("\u{e9}", false, false),
            (too_long.as_str(), false, false),
        ] {
            assert_eq!(is_db_name(value), literal, "literal {value:?}");
            assert_eq!(
                is_valid_substituted_db_name(value),
                substituted,
                "substituted {value:?}"
            );
        }
    }
}
