pub const DENIAL_REFERENCE_PREFIX: &str = "D-";
pub const ACCOUNT_REFERENCE_PREFIX: &str = "H-";
pub const AUDIT_REFERENCE_DIGITS: usize = 8;

pub fn is_audit_reference(value: &str) -> bool {
    [DENIAL_REFERENCE_PREFIX, ACCOUNT_REFERENCE_PREFIX]
        .iter()
        .any(|prefix| value.strip_prefix(prefix).is_some_and(is_reference_digits))
}

pub fn is_denial_reference(value: &str) -> bool {
    value
        .strip_prefix(DENIAL_REFERENCE_PREFIX)
        .is_some_and(is_reference_digits)
}

fn is_reference_digits(digits: &str) -> bool {
    digits.len() == AUDIT_REFERENCE_DIGITS
        && digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{is_audit_reference, is_denial_reference};

    #[test]
    fn a_reference_is_d_or_h_and_exactly_eight_upper_case_hex_digits() {
        for accepted in ["D-0123ABCD", "H-9D0311FE", "D-FFFFFFFF", "H-00000000"] {
            assert!(is_audit_reference(accepted), "{accepted}");
        }
        for refused in [
            "",
            "D-",
            "D-0123abcd",
            "d-0123ABCD",
            "X-0123ABCD",
            "D-0123ABC",
            "D-0123ABCDE",
            "D-0123ABCG",
            "D_0123ABCD",
            " D-0123ABCD",
            "D-0123ABCD ",
            "D-0123\u{0661}BCD",
        ] {
            assert!(!is_audit_reference(refused), "{refused:?}");
        }
        assert!(is_denial_reference("D-0123ABCD"));
        assert!(!is_denial_reference("H-0123ABCD"));
    }
}
