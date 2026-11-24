use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jaunt_ca::ssh_key::rand_core::{OsRng, RngCore};

use crate::token::{EntropyUnavailable, hash_secret};

const HANDLE_BYTES: usize = 32;
const HANDLE_ENCODED_LEN: usize = 43;
const CODE_LEN: usize = 8;
const CODE_ALPHABET: &[u8; 31] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
const CODE_UNBIASED_LIMIT: u8 = 248;
const CODE_DRAW_ROUNDS: usize = 16;
const MAX_PRESENTED_CODE_LEN: usize = 32;

pub(crate) struct IssuedHandle {
    pub(crate) secret: String,
    pub(crate) hash: String,
}

pub(crate) struct IssuedCode {
    pub(crate) shown: String,
    pub(crate) hash: String,
}

pub(crate) fn issue_handle() -> Result<IssuedHandle, EntropyUnavailable> {
    let mut bytes = [0_u8; HANDLE_BYTES];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| EntropyUnavailable)?;
    let secret = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_secret(&secret);
    Ok(IssuedHandle { secret, hash })
}

pub(crate) fn hash_handle(presented: &str) -> Option<String> {
    let well_formed = presented.len() == HANDLE_ENCODED_LEN
        && presented
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    well_formed.then(|| hash_secret(presented))
}

pub(crate) fn issue_code() -> Result<IssuedCode, EntropyUnavailable> {
    let mut code = String::with_capacity(CODE_LEN);
    for _ in 0..CODE_DRAW_ROUNDS {
        let mut bytes = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| EntropyUnavailable)?;
        for byte in bytes {
            if let Some(ch) = code_char(byte) {
                code.push(ch);
            }
            if code.len() == CODE_LEN {
                let hash = hash_secret(&code);
                let shown = format!("{}-{}", &code[..4], &code[4..]);
                return Ok(IssuedCode { shown, hash });
            }
        }
    }
    Err(EntropyUnavailable)
}

fn code_char(byte: u8) -> Option<char> {
    (byte < CODE_UNBIASED_LIMIT)
        .then(|| char::from(CODE_ALPHABET[usize::from(byte) % CODE_ALPHABET.len()]))
}

pub(crate) fn normalize_code(presented: &str) -> Option<String> {
    if presented.len() > MAX_PRESENTED_CODE_LEN {
        return None;
    }
    let normalized: String = presented
        .chars()
        .filter(|ch| *ch != '-' && *ch != ' ')
        .map(|ch| ch.to_ascii_uppercase())
        .collect();
    let well_formed = normalized.len() == CODE_LEN
        && normalized.bytes().all(|byte| CODE_ALPHABET.contains(&byte));
    well_formed.then_some(normalized)
}

pub(crate) fn hash_code(normalized: &str) -> String {
    hash_secret(normalized)
}

#[cfg(test)]
mod tests {
    use super::{
        CODE_ALPHABET, code_char, hash_code, hash_handle, issue_code, issue_handle, normalize_code,
    };

    #[test]
    fn a_handle_is_forty_three_url_safe_characters_and_only_its_hash_is_kept() {
        let first = issue_handle().unwrap();
        let second = issue_handle().unwrap();
        assert_ne!(first.secret, second.secret);
        assert_eq!(first.secret.len(), 43);
        assert_eq!(hash_handle(&first.secret), Some(first.hash.clone()));
        assert_eq!(first.hash.len(), 64);
        assert!(!first.secret.contains(&first.hash));
        for malformed in [
            "",
            "short",
            &first.secret[1..],
            &format!("{}=", &first.secret[1..]),
        ] {
            assert_eq!(hash_handle(malformed), None, "{malformed}");
        }
    }

    #[test]
    fn a_code_is_shown_as_two_groups_of_four_from_the_unambiguous_alphabet() {
        for _ in 0..200 {
            let issued = issue_code().unwrap();
            let (left, right) = issued.shown.split_once('-').unwrap();
            assert_eq!((left.len(), right.len()), (4, 4), "{}", issued.shown);
            let bare = format!("{left}{right}");
            assert!(
                bare.bytes()
                    .all(|byte| b"23456789ABCDEFGHJKMNPQRSTUVWXYZ".contains(&byte)),
                "{}",
                issued.shown
            );
            assert_eq!(
                normalize_code(&issued.shown).as_deref(),
                Some(bare.as_str())
            );
            assert_eq!(issued.hash, hash_code(&bare));
        }
    }

    #[test]
    fn typed_codes_are_normalized_and_anything_else_is_refused() {
        for (typed, normalized) in [
            ("abcd-2345", Some("ABCD2345")),
            ("ABCD 2345", Some("ABCD2345")),
            (" a b c d 2 3 4 5 ", Some("ABCD2345")),
            ("ABCD2345", Some("ABCD2345")),
            ("ABCD-234", None),
            ("ABCD-23456", None),
            ("ABCD-2O45", None),
            ("ABCD-2145", None),
            ("ABCD-23I5", None),
            ("ABCD-23L5", None),
            ("", None),
            ("ABCD-2345-ABCD-2345-ABCD-2345-ABCD", None),
            ("ÅBCD-2345", None),
        ] {
            assert_eq!(normalize_code(typed).as_deref(), normalized, "{typed:?}");
        }
    }

    #[test]
    fn only_bytes_below_248_map_to_code_characters_and_each_character_is_equally_likely() {
        let mut counts = std::collections::BTreeMap::new();
        for byte in 0..=u8::MAX {
            match code_char(byte) {
                Some(ch) => *counts.entry(ch).or_insert(0_u32) += 1,
                None => assert!(byte >= 248, "{byte}"),
            }
        }
        for byte in 248..=u8::MAX {
            assert_eq!(code_char(byte), None, "{byte}");
        }
        assert_eq!(counts.len(), CODE_ALPHABET.len());
        assert!(counts.values().all(|count| *count == 8), "{counts:?}");
    }
}
