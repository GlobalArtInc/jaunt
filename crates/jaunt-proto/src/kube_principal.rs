const MAX_KUBE_PRINCIPAL_BYTES: usize = 253;
const RESERVED_KUBE_PREFIX: &[u8] = b"system:";

pub fn is_kube_principal(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_KUBE_PRINCIPAL_BYTES
        && bytes.first() != Some(&b'-')
        && bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'@' | b':' | b'+' | b'=' | b'-')
        })
}

pub fn is_valid_substituted_kube_principal(value: &str) -> bool {
    is_kube_principal(value)
        && !value
            .as_bytes()
            .get(..RESERVED_KUBE_PREFIX.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(RESERVED_KUBE_PREFIX))
}

#[cfg(test)]
mod tests {
    use super::{is_kube_principal, is_valid_substituted_kube_principal};

    #[test]
    fn kube_principals_follow_the_grammar_and_reserved_names_are_literal_only() {
        let longest = "a".repeat(253);
        let too_long = "a".repeat(254);
        for (value, literal, substituted) in [
            ("view", true, true),
            ("alice@example.com", true, true),
            ("oidc:platform", true, true),
            ("A.b_c+d=e-f", true, true),
            ("9", true, true),
            ("a-", true, true),
            (longest.as_str(), true, true),
            ("system:masters", true, false),
            ("system:", true, false),
            ("System:masters", true, false),
            ("SYSTEM:authenticated", true, false),
            ("sYsTeM:nodes", true, false),
            ("system", true, true),
            ("systems:x", true, true),
            ("oidc:system:masters", true, true),
            ("", false, false),
            ("-as", false, false),
            (too_long.as_str(), false, false),
            ("a b", false, false),
            ("a/b", false, false),
            ("a,b", false, false),
            ("a\nb", false, false),
            ("a\u{0}b", false, false),
            ("\u{e9}", false, false),
            ("\u{ff53}ystem:masters", false, false),
            ("system\u{200b}:masters", false, false),
        ] {
            assert_eq!(is_kube_principal(value), literal, "literal {value:?}");
            assert_eq!(
                is_valid_substituted_kube_principal(value),
                substituted,
                "substituted {value:?}"
            );
        }
    }
}
