pub const ADMIN_SIGNATURE_NAMESPACE: &str = "jaunt-admin@1";
pub const ADMIN_SIGNATURE_LABEL: &str = "jaunt";
pub const ADMIN_CERTIFICATE_HEADER: &str = "jaunt-certificate";
pub const CONTENT_DIGEST_HEADER: &str = "content-digest";
pub const SIGNATURE_INPUT_HEADER: &str = "signature-input";
pub const SIGNATURE_HEADER: &str = "signature";
pub const ADMIN_SIGNATURE_COMPONENTS: [&str; 4] = [
    "@method",
    "@target-uri",
    CONTENT_DIGEST_HEADER,
    ADMIN_CERTIFICATE_HEADER,
];
pub const ADMIN_SIGNATURE_MAX_SKEW_SECS: i64 = 120;
pub const ADMIN_NONCE_MIN_LEN: usize = 22;
pub const ADMIN_NONCE_MAX_LEN: usize = 64;
pub const ADMIN_WHOAMI_PATH: &str = "/v1/admin/whoami";

pub fn admin_signature_params(created: i64, nonce: &str, keyid: u64) -> String {
    let components: Vec<String> = ADMIN_SIGNATURE_COMPONENTS
        .iter()
        .map(|component| format!("\"{component}\""))
        .collect();
    format!(
        "({});created={created};nonce=\"{nonce}\";keyid=\"{keyid}\"",
        components.join(" ")
    )
}

pub fn admin_signature_base(values: [&str; 4], params: &str) -> String {
    let mut base = String::new();
    for (component, value) in ADMIN_SIGNATURE_COMPONENTS.iter().zip(values) {
        base.push_str(&format!("\"{component}\": {value}\n"));
    }
    base.push_str(&format!("\"@signature-params\": {params}"));
    base
}

pub fn is_admin_nonce(nonce: &str) -> bool {
    (ADMIN_NONCE_MIN_LEN..=ADMIN_NONCE_MAX_LEN).contains(&nonce.len())
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::{
        ADMIN_NONCE_MAX_LEN, ADMIN_NONCE_MIN_LEN, admin_signature_base, admin_signature_params,
        is_admin_nonce,
    };

    #[test]
    fn the_signature_base_matches_a_fixed_vector() {
        let params = admin_signature_params(1_700_000_000, "bm9uY2Utbm9uY2Utbm9uY2U", 42);
        assert_eq!(
            params,
            "(\"@method\" \"@target-uri\" \"content-digest\" \"jaunt-certificate\");created=1700000000;nonce=\"bm9uY2Utbm9uY2Utbm9uY2U\";keyid=\"42\""
        );
        assert_eq!(
            admin_signature_base(
                [
                    "GET",
                    "https://jaunt.example/v1/admin/whoami",
                    "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
                    "ssh-ed25519-cert-v01@openssh.com AAAA",
                ],
                &params
            ),
            "\"@method\": GET\n\"@target-uri\": https://jaunt.example/v1/admin/whoami\n\"content-digest\": sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:\n\"jaunt-certificate\": ssh-ed25519-cert-v01@openssh.com AAAA\n\"@signature-params\": (\"@method\" \"@target-uri\" \"content-digest\" \"jaunt-certificate\");created=1700000000;nonce=\"bm9uY2Utbm9uY2Utbm9uY2U\";keyid=\"42\""
        );
    }

    #[test]
    fn nonces_are_base64url_text_of_bounded_length() {
        let shortest = "a".repeat(ADMIN_NONCE_MIN_LEN);
        let longest = "Z9-_".repeat(ADMIN_NONCE_MAX_LEN / 4);
        assert!(is_admin_nonce(&shortest));
        assert!(is_admin_nonce(&longest));
        for bad in [
            "a".repeat(ADMIN_NONCE_MIN_LEN - 1),
            "a".repeat(ADMIN_NONCE_MAX_LEN + 1),
            format!("{}=", "a".repeat(ADMIN_NONCE_MIN_LEN)),
            format!("{}\"", "a".repeat(ADMIN_NONCE_MIN_LEN)),
            format!("{} b", "a".repeat(ADMIN_NONCE_MIN_LEN)),
            format!("{}é", "a".repeat(ADMIN_NONCE_MIN_LEN)),
        ] {
            assert!(!is_admin_nonce(&bad), "{bad:?}");
        }
    }
}
