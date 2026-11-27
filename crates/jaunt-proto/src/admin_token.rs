pub const ADMIN_TOKEN_PREFIX: &str = "jat_";
pub const ADMIN_TOKEN_ID_BYTES: usize = 8;
pub const ADMIN_TOKEN_SECRET_BYTES: usize = 32;
pub const ADMIN_TOKEN_ID_LEN: usize = 11;
pub const ADMIN_TOKEN_SECRET_LEN: usize = 43;
pub const ADMIN_TOKEN_LEN: usize =
    ADMIN_TOKEN_PREFIX.len() + ADMIN_TOKEN_ID_LEN + 1 + ADMIN_TOKEN_SECRET_LEN;
pub const ADMIN_TOKENS_PATH: &str = "/v1/admin/tokens";
pub const ADMIN_TOKEN_ENV: &str = "JAUNT_ADMIN_TOKEN";
pub const ADMIN_TOKEN_MIN_TTL_SECS: i64 = 60;
pub const ADMIN_TOKEN_MAX_TTL_SECS: i64 = 90 * 86_400;
pub const ADMIN_TOKEN_DEFAULT_TTL_SECS: i64 = 30 * 86_400;
pub const ADMIN_TOKEN_MAX_CIDRS: usize = 16;
pub const ADMIN_TOKEN_MAX_LIVE_PER_CREATOR: u32 = 20;
pub const ADMIN_TOKEN_MAX_DEAD_PER_CREATOR: u32 = 100;
pub const ADMIN_TOKEN_MAX_CREATED_PER_HOUR: u32 = 30;
const _: () = assert!(
    ADMIN_TOKEN_MAX_DEAD_PER_CREATOR
        >= ADMIN_TOKEN_MAX_LIVE_PER_CREATOR + ADMIN_TOKEN_MAX_CREATED_PER_HOUR
);
pub const ADMIN_TOKEN_NAME_MAX_LEN: usize = 64;

fn is_url_safe(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

pub fn is_admin_token_id(id: &str) -> bool {
    id.len() == ADMIN_TOKEN_ID_LEN && id.bytes().all(is_url_safe)
}

pub fn admin_token_id(presented: &str) -> Option<&str> {
    let rest = presented.strip_prefix(ADMIN_TOKEN_PREFIX)?;
    if presented.len() != ADMIN_TOKEN_LEN {
        return None;
    }
    let id = rest.get(..ADMIN_TOKEN_ID_LEN)?;
    let secret = rest.get(ADMIN_TOKEN_ID_LEN..)?.strip_prefix('_')?;
    let well_formed = is_admin_token_id(id)
        && secret.len() == ADMIN_TOKEN_SECRET_LEN
        && secret.bytes().all(is_url_safe);
    well_formed.then_some(id)
}

pub fn is_admin_token_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    bytes.len() <= ADMIN_TOKEN_NAME_MAX_LEN
        && edge(*first)
        && edge(*last)
        && bytes.iter().all(|byte| edge(*byte) || *byte == b'-')
}

pub fn admin_token_path(id: &str) -> String {
    format!("{ADMIN_TOKENS_PATH}/{id}")
}

#[cfg(test)]
mod tests {
    use super::{
        ADMIN_TOKEN_LEN, ADMIN_TOKEN_NAME_MAX_LEN, admin_token_id, admin_token_path,
        is_admin_token_id, is_admin_token_name,
    };

    const ID: &str = "AbC-_09xyzQ";
    const SECRET: &str = "s3cr3t-s3cr3t_s3cr3t-s3cr3t_s3cr3t-s3cr3t_Z";

    #[test]
    fn a_token_is_the_prefix_an_eleven_character_id_an_underscore_and_the_secret() {
        let token = format!("jat_{ID}_{SECRET}");
        assert_eq!(token.len(), ADMIN_TOKEN_LEN);
        assert_eq!(ADMIN_TOKEN_LEN, 59);
        assert_eq!(admin_token_id(&token), Some(ID));
        let underscores = format!("jat_{}", "_".repeat(ADMIN_TOKEN_LEN - 4));
        assert_eq!(admin_token_id(&underscores), Some("___________"));
        for bad in [
            String::new(),
            "jat_".to_owned(),
            token[..ADMIN_TOKEN_LEN - 1].to_owned(),
            format!("{token}A"),
            format!("{token} "),
            format!(" {token}"),
            format!("Jat_{ID}_{SECRET}"),
            format!("jt_{ID}_{SECRET}"),
            format!("jat_{ID}-{SECRET}"),
            format!("jat_{ID}_{}=", &SECRET[..42]),
            format!("jat_{ID}_{}+", &SECRET[..42]),
            format!("jat_{}/_{SECRET}", &ID[..10]),
            format!("jat_{ID}_{}\u{e9}", &SECRET[..41]),
            format!("jat_{ID}{SECRET}A"),
        ] {
            assert_eq!(admin_token_id(&bad), None, "{bad:?}");
        }
    }

    #[test]
    fn ids_are_eleven_url_safe_characters() {
        assert!(is_admin_token_id(ID));
        for bad in [
            "",
            &ID[..10],
            &format!("{ID}A"),
            "AbC-_09xyz/",
            "AbC-_09xyz=",
        ] {
            assert!(!is_admin_token_id(bad), "{bad:?}");
        }
        assert_eq!(admin_token_path(ID), format!("/v1/admin/tokens/{ID}"));
    }

    #[test]
    fn names_are_lowercase_labels_of_at_most_sixty_four_bytes() {
        let longest = "a".repeat(ADMIN_TOKEN_NAME_MAX_LEN);
        let too_long = "a".repeat(ADMIN_TOKEN_NAME_MAX_LEN + 1);
        for (name, valid) in [
            ("ci-audit", true),
            ("a", true),
            ("0", true),
            (longest.as_str(), true),
            (too_long.as_str(), false),
            ("", false),
            ("-ci", false),
            ("ci-", false),
            ("CI", false),
            ("ci audit", false),
            ("ci_audit", false),
            ("ci.audit", false),
            ("ci\u{e9}", false),
        ] {
            assert_eq!(is_admin_token_name(name), valid, "{name:?}");
        }
    }
}
