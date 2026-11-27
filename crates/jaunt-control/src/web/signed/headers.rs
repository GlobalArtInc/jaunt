use axum::http::{HeaderMap, HeaderName};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_ca::ssh_key::Certificate;
use jaunt_proto::{
    ADMIN_CERTIFICATE_HEADER, ADMIN_SIGNATURE_COMPONENTS, ADMIN_SIGNATURE_LABEL,
    CONTENT_DIGEST_HEADER, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER, admin_signature_params,
    is_admin_nonce,
};

use super::Reason;

const MAX_CERTIFICATE_BYTES: usize = 8 * 1024;
const MAX_SIGNATURE_INPUT_BYTES: usize = 1024;
const MAX_SIGNATURE_BYTES: usize = 2048;
const DIGEST_PREFIX: &str = "sha-256=:";
const DIGEST_BYTES: usize = 32;
const MAX_INTEGER_DIGITS: usize = 15;
const MAX_KEYID_DIGITS: usize = 20;
const CREATED: &str = "created";
const NONCE: &str = "nonce";
const KEYID: &str = "keyid";

pub(crate) struct Presented {
    pub(crate) certificate_text: String,
    pub(crate) certificate: Certificate,
    pub(crate) digest_text: String,
    pub(crate) digest: [u8; DIGEST_BYTES],
    pub(crate) covered: Covered,
    pub(crate) signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Covered {
    pub(crate) params_text: String,
    pub(crate) created: i64,
    pub(crate) nonce: String,
    pub(crate) keyid: u64,
}

pub(crate) fn is_signed(headers: &HeaderMap) -> bool {
    [
        SIGNATURE_INPUT_HEADER,
        SIGNATURE_HEADER,
        ADMIN_CERTIFICATE_HEADER,
    ]
    .iter()
    .any(|name| headers.contains_key(*name))
}

pub(crate) fn read(headers: &HeaderMap) -> Result<Presented, Reason> {
    let certificate_text = single(headers, ADMIN_CERTIFICATE_HEADER)?;
    let digest_text = single(headers, CONTENT_DIGEST_HEADER)?;
    let input_text = single(headers, SIGNATURE_INPUT_HEADER)?;
    let signature_text = single(headers, SIGNATURE_HEADER)?;
    let certificate = parse_certificate(certificate_text)?;
    let digest = parse_digest(digest_text)?;
    let covered = parse_signature_input(input_text)?;
    let signature = parse_signature(signature_text)?;
    Ok(Presented {
        certificate_text: certificate_text.to_owned(),
        certificate,
        digest_text: digest_text.to_owned(),
        digest,
        covered,
        signature,
    })
}

fn single<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, Reason> {
    let mut values = headers.get_all(HeaderName::from_static(name)).iter();
    match (values.next(), values.next()) {
        (None, _) => Err(Reason::MissingHeader),
        (Some(_), Some(_)) => Err(Reason::DuplicateHeader),
        (Some(value), None) => value.to_str().map_err(|_| Reason::MalformedHeader),
    }
}

pub(crate) fn parse_certificate(text: &str) -> Result<Certificate, Reason> {
    let shaped = !text.is_empty()
        && text.len() <= MAX_CERTIFICATE_BYTES
        && text.trim() == text
        && text.bytes().all(|byte| (0x20..=0x7e).contains(&byte));
    if !shaped {
        return Err(Reason::MalformedCertificate);
    }
    Certificate::from_openssh(text).map_err(|_| Reason::MalformedCertificate)
}

pub(crate) fn parse_digest(text: &str) -> Result<[u8; DIGEST_BYTES], Reason> {
    let encoded = text
        .strip_prefix(DIGEST_PREFIX)
        .and_then(|rest| rest.strip_suffix(':'))
        .ok_or(Reason::MalformedDigest)?;
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| Reason::MalformedDigest)?;
    <[u8; DIGEST_BYTES]>::try_from(bytes.as_slice()).map_err(|_| Reason::MalformedDigest)
}

pub(crate) fn parse_signature(text: &str) -> Result<Vec<u8>, Reason> {
    let encoded = text
        .strip_prefix(ADMIN_SIGNATURE_LABEL)
        .and_then(|rest| rest.strip_prefix("=:"))
        .and_then(|rest| rest.strip_suffix(':'))
        .ok_or(Reason::MalformedSignature)?;
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| Reason::MalformedSignature)?;
    if bytes.is_empty() || bytes.len() > MAX_SIGNATURE_BYTES {
        return Err(Reason::MalformedSignature);
    }
    Ok(bytes)
}

enum Param {
    Integer(i64),
    Text(String),
}

pub(crate) fn parse_signature_input(text: &str) -> Result<Covered, Reason> {
    if text.len() > MAX_SIGNATURE_INPUT_BYTES {
        return Err(Reason::MalformedSignatureInput);
    }
    let mut cursor = Cursor::new(text);
    let label = cursor.key().ok_or(Reason::MalformedSignatureInput)?;
    if label != ADMIN_SIGNATURE_LABEL {
        return Err(Reason::Label);
    }
    if !cursor.eat(b'=') || !cursor.eat(b'(') {
        return Err(Reason::MalformedSignatureInput);
    }
    let params_start = label.len() + 1;
    let mut components = Vec::new();
    while !cursor.eat(b')') {
        if !components.is_empty() && !cursor.eat(b' ') {
            return Err(Reason::MalformedSignatureInput);
        }
        components.push(cursor.string().ok_or(Reason::MalformedSignatureInput)?);
    }
    let mut params: Vec<(&str, Param)> = Vec::new();
    while cursor.eat(b';') {
        let key = cursor.key().ok_or(Reason::MalformedSignatureInput)?;
        if !cursor.eat(b'=') {
            return Err(Reason::MalformedSignatureInput);
        }
        let value = match cursor.peek() {
            Some(b'"') => Param::Text(cursor.string().ok_or(Reason::MalformedSignatureInput)?),
            _ => Param::Integer(cursor.integer().ok_or(Reason::MalformedSignatureInput)?),
        };
        params.push((key, value));
    }
    if !cursor.is_done() {
        return Err(Reason::MalformedSignatureInput);
    }
    if components != ADMIN_SIGNATURE_COMPONENTS {
        return Err(Reason::Components);
    }
    let (created, nonce, keyid) = match params.as_slice() {
        [
            (CREATED, Param::Integer(created)),
            (NONCE, Param::Text(nonce)),
            (KEYID, Param::Text(keyid)),
        ] => (*created, nonce.clone(), keyid.as_str()),
        _ => return Err(Reason::Parameters),
    };
    if !is_admin_nonce(&nonce) {
        return Err(Reason::Nonce);
    }
    let keyid = parse_keyid(keyid).ok_or(Reason::KeyId)?;
    let covered = Covered {
        params_text: text[params_start..].to_owned(),
        created,
        nonce,
        keyid,
    };
    if canonical(&covered) != text {
        return Err(Reason::MalformedSignatureInput);
    }
    Ok(covered)
}

fn parse_keyid(text: &str) -> Option<u64> {
    let digits = !text.is_empty()
        && text.len() <= MAX_KEYID_DIGITS
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && !text.starts_with('0');
    if digits { text.parse().ok() } else { None }
}

fn canonical(covered: &Covered) -> String {
    format!(
        "{ADMIN_SIGNATURE_LABEL}={}",
        admin_signature_params(covered.created, &covered.nonce, covered.keyid)
    )
}

struct Cursor<'a> {
    text: &'a str,
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(text: &'a str) -> Cursor<'a> {
        Cursor { text, at: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.at).copied()
    }

    fn eat(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn is_done(&self) -> bool {
        self.at == self.text.len()
    }

    fn key(&mut self) -> Option<&'a str> {
        let start = self.at;
        match self.peek() {
            Some(byte) if byte.is_ascii_lowercase() || byte == b'*' => self.at += 1,
            _ => return None,
        }
        while let Some(byte) = self.peek() {
            if byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'-' | b'.' | b'*')
            {
                self.at += 1;
            } else {
                break;
            }
        }
        self.text.get(start..self.at)
    }

    fn string(&mut self) -> Option<String> {
        if !self.eat(b'"') {
            return None;
        }
        let mut value = String::new();
        loop {
            let byte = self.peek()?;
            self.at += 1;
            match byte {
                b'"' => return Some(value),
                b'\\' => {
                    let escaped = self.peek()?;
                    if escaped != b'"' && escaped != b'\\' {
                        return None;
                    }
                    self.at += 1;
                    value.push(char::from(escaped));
                }
                0x20..=0x7e => value.push(char::from(byte)),
                _ => return None,
            }
        }
    }

    fn integer(&mut self) -> Option<i64> {
        let start = self.at;
        self.eat(b'-');
        let digits_start = self.at;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.at += 1;
        }
        let digits = self.at - digits_start;
        if digits == 0 || digits > MAX_INTEGER_DIGITS {
            return None;
        }
        self.text.get(start..self.at)?.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::{
        Covered, is_signed, parse_digest, parse_keyid, parse_signature, parse_signature_input, read,
    };
    use crate::web::signed::Reason;

    const NONCE: &str = "bm9uY2Utbm9uY2Utbm9uY2U";
    const COMPONENTS: &str =
        "(\"@method\" \"@target-uri\" \"content-digest\" \"jaunt-certificate\")";

    fn input(components: &str, params: &str) -> String {
        format!("jaunt={components}{params}")
    }

    fn good_params() -> String {
        format!(";created=1700000000;nonce=\"{NONCE}\";keyid=\"42\"")
    }

    #[test]
    fn the_canonical_signature_input_is_parsed() {
        let text = input(COMPONENTS, &good_params());
        assert_eq!(
            parse_signature_input(&text),
            Ok(Covered {
                params_text: format!("{COMPONENTS}{}", good_params()),
                created: 1_700_000_000,
                nonce: NONCE.to_owned(),
                keyid: 42,
            })
        );
    }

    #[test]
    fn every_deviation_from_the_canonical_signature_input_is_refused() {
        let params = good_params();
        let cases = [
            (
                input(COMPONENTS, &params).replacen("jaunt", "sig1", 1),
                Reason::Label,
            ),
            (
                input("(\"@method\" \"@target-uri\" \"content-digest\")", &params),
                Reason::Components,
            ),
            (
                input(
                    "(\"@method\" \"@target-uri\" \"content-digest\" \"jaunt-certificate\" \"content-type\")",
                    &params,
                ),
                Reason::Components,
            ),
            (
                input(
                    "(\"@method\" \"@path\" \"content-digest\" \"jaunt-certificate\")",
                    &params,
                ),
                Reason::Components,
            ),
            (
                input(
                    "(\"@target-uri\" \"@method\" \"content-digest\" \"jaunt-certificate\")",
                    &params,
                ),
                Reason::Components,
            ),
            (input("()", &params), Reason::Components),
            (
                input(COMPONENTS, &format!(";nonce=\"{NONCE}\";keyid=\"42\"")),
                Reason::Parameters,
            ),
            (
                input(COMPONENTS, &format!("{params};expires=1700000100")),
                Reason::Parameters,
            ),
            (
                input(
                    COMPONENTS,
                    &format!(";nonce=\"{NONCE}\";created=1700000000;keyid=\"42\""),
                ),
                Reason::Parameters,
            ),
            (
                input(
                    COMPONENTS,
                    &format!(";created=\"1\";nonce=\"{NONCE}\";keyid=\"42\""),
                ),
                Reason::Parameters,
            ),
            (
                input(
                    COMPONENTS,
                    ";created=1700000000;nonce=\"short\";keyid=\"42\"",
                ),
                Reason::Nonce,
            ),
            (
                input(
                    COMPONENTS,
                    &format!(";created=1700000000;nonce=\"{NONCE}\";keyid=\"042\""),
                ),
                Reason::KeyId,
            ),
            (
                input(
                    COMPONENTS,
                    &format!(";created=1700000000;nonce=\"{NONCE}\";keyid=\"x\""),
                ),
                Reason::KeyId,
            ),
            (
                input(
                    COMPONENTS,
                    &format!(";created=01700000000;nonce=\"{NONCE}\";keyid=\"42\""),
                ),
                Reason::MalformedSignatureInput,
            ),
            (
                input(
                    "( \"@method\" \"@target-uri\" \"content-digest\" \"jaunt-certificate\")",
                    &params,
                ),
                Reason::MalformedSignatureInput,
            ),
            (
                input(
                    "(\"@method\"  \"@target-uri\" \"content-digest\" \"jaunt-certificate\")",
                    &params,
                ),
                Reason::MalformedSignatureInput,
            ),
            (
                format!("{}, other=()", input(COMPONENTS, &params)),
                Reason::MalformedSignatureInput,
            ),
            (
                input(COMPONENTS, &params.replace(";nonce", "; nonce")),
                Reason::MalformedSignatureInput,
            ),
            (
                input(
                    COMPONENTS,
                    &format!(";created=1234567890123456;nonce=\"{NONCE}\";keyid=\"42\""),
                ),
                Reason::MalformedSignatureInput,
            ),
            (
                input("(\"@method\\x\")", &params),
                Reason::MalformedSignatureInput,
            ),
            ("jaunt".to_owned(), Reason::MalformedSignatureInput),
            (String::new(), Reason::MalformedSignatureInput),
            ("x".repeat(2000), Reason::MalformedSignatureInput),
        ];
        for (text, reason) in cases {
            assert_eq!(parse_signature_input(&text), Err(reason), "{text}");
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic_the_signature_input_parser() {
        let seeds = [
            input(COMPONENTS, &good_params()),
            "jaunt=(\"\\".to_owned(),
            "jaunt=(\"a\" ".to_owned(),
            "jaunt=();created=-".to_owned(),
            "jaunt=();created=".to_owned(),
            "jaunt=();=".to_owned(),
        ];
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        for seed in seeds {
            let bytes = seed.as_bytes();
            for cut in 0..=bytes.len() {
                if let Ok(prefix) = std::str::from_utf8(&bytes[..cut]) {
                    let _ = parse_signature_input(prefix);
                }
            }
            for _ in 0..500 {
                let mut mutated = bytes.to_vec();
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let at = usize::try_from(state % (mutated.len().max(1) as u64)).unwrap();
                if let Some(byte) = mutated.get_mut(at) {
                    *byte = u8::try_from((state >> 8) % 0x5f + 0x20).unwrap();
                }
                if let Ok(text) = String::from_utf8(mutated) {
                    let _ = parse_signature_input(&text);
                }
            }
        }
    }

    #[test]
    fn digests_are_one_sha256_member_of_exactly_32_bytes() {
        let empty = "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:";
        assert!(parse_digest(empty).is_ok());
        for bad in [
            "sha-512=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
            "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
            "sha-256=:AAAA:",
            "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU:",
            "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:, sha-512=:AA==:",
            " sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
            "",
        ] {
            assert_eq!(parse_digest(bad), Err(Reason::MalformedDigest), "{bad}");
        }
    }

    #[test]
    fn signatures_are_one_labelled_binary_member_of_bounded_size() {
        assert_eq!(parse_signature("jaunt=:AQID:"), Ok(vec![1, 2, 3]));
        let huge = format!("jaunt=:{}:", "A".repeat(4000));
        for bad in [
            "sig1=:AQID:",
            "jaunt=AQID",
            "jaunt=:AQID",
            "jaunt=::",
            "jaunt=:AQI:",
            "jaunt=:AQID:, other=:AQID:",
            huge.as_str(),
        ] {
            assert_eq!(
                parse_signature(bad),
                Err(Reason::MalformedSignature),
                "{bad}"
            );
        }
    }

    #[test]
    fn keyids_are_plain_decimal_serials() {
        assert_eq!(parse_keyid("1"), Some(1));
        assert_eq!(parse_keyid("18446744073709551615"), Some(u64::MAX));
        for bad in ["", "0", "01", "-1", "+1", "1 ", "18446744073709551616", "١"] {
            assert_eq!(parse_keyid(bad), None, "{bad}");
        }
    }

    #[test]
    fn missing_and_repeated_headers_are_refused_and_any_signature_header_marks_the_request() {
        let mut headers = HeaderMap::new();
        assert!(!is_signed(&headers));
        headers.insert("content-digest", HeaderValue::from_static("x"));
        assert!(!is_signed(&headers));
        for name in ["signature-input", "signature", "jaunt-certificate"] {
            let mut marked = HeaderMap::new();
            marked.insert(name, HeaderValue::from_static("x"));
            assert!(is_signed(&marked), "{name}");
        }
        assert!(matches!(read(&headers), Err(Reason::MissingHeader)));
        let mut doubled = HeaderMap::new();
        doubled.append("jaunt-certificate", HeaderValue::from_static("a"));
        doubled.append("jaunt-certificate", HeaderValue::from_static("b"));
        assert!(matches!(read(&doubled), Err(Reason::DuplicateHeader)));
    }
}
