use jaunt_proto::FinishResponse;
use ssh_key::certificate::CertType;
use ssh_key::{Certificate, PublicKey};

use crate::key::SessionKey;
use crate::secret::Secret;
use crate::store::ProfileMeta;

const MAX_HOST_CA_KEYS: usize = 16;
const MAX_KEY_LINE_LEN: usize = 1024;
const MAX_TOKEN_LEN: usize = 256;
const MAX_EMAIL_LEN: usize = 254;
const MAX_CLOCK_SKEW_SECS: u64 = 5 * 60;
const MAX_LIFETIME_SECS: u64 = 7 * 24 * 3600;

pub struct VerifiedLogin {
    pub certificate_line: String,
    pub token: Secret,
    pub meta: ProfileMeta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("the server returned a certificate that cannot be read")]
    CertificateUnreadable,
    #[error("the server returned a certificate that is not a user certificate")]
    NotUserCertificate,
    #[error("the server returned a certificate for a different key")]
    WrongKey,
    #[error("the server returned a certificate with unexpected principals")]
    WrongPrincipals,
    #[error("the server returned a certificate that has already expired")]
    Expired,
    #[error("the server returned a certificate that only becomes valid later")]
    NotYetValid,
    #[error("the server returned a certificate with an excessive lifetime")]
    LifetimeTooLong,
    #[error("the certificate does not match the serial, key id or validity the server reported")]
    Inconsistent,
    #[error("the server returned an unusable API token")]
    BadToken,
    #[error("the server returned an unusable account identity")]
    BadIdentity,
    #[error("the server returned an unusable host CA key")]
    BadHostKey,
}

pub fn verify(
    response: FinishResponse,
    key: &SessionKey,
    now_secs: u64,
) -> Result<VerifiedLogin, VerifyError> {
    let FinishResponse {
        certificate,
        serial,
        key_id,
        valid_after,
        valid_before,
        api_token,
        token_expires_at,
        user_id,
        email,
        host_ca_keys,
    } = response;

    let line = certificate.trim_end_matches(['\r', '\n']);
    if line.is_empty() || line.chars().any(char::is_control) {
        return Err(VerifyError::CertificateUnreadable);
    }
    let parsed = Certificate::from_openssh(line).map_err(|_| VerifyError::CertificateUnreadable)?;
    if parsed.cert_type() != CertType::User {
        return Err(VerifyError::NotUserCertificate);
    }
    if parsed.public_key() != key.key_data() {
        return Err(VerifyError::WrongKey);
    }
    if !is_plain_text(&user_id, MAX_EMAIL_LEN) || !is_plain_text(&email, MAX_EMAIL_LEN) {
        return Err(VerifyError::BadIdentity);
    }
    if parsed.valid_principals() != std::slice::from_ref(&user_id) {
        return Err(VerifyError::WrongPrincipals);
    }
    if parsed.valid_before() <= now_secs {
        return Err(VerifyError::Expired);
    }
    if parsed.valid_after() > now_secs.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(VerifyError::NotYetValid);
    }
    let lifetime = parsed
        .valid_before()
        .checked_sub(parsed.valid_after())
        .ok_or(VerifyError::Inconsistent)?;
    if lifetime > MAX_LIFETIME_SECS {
        return Err(VerifyError::LifetimeTooLong);
    }
    let consistent = u64::try_from(serial) == Ok(parsed.serial())
        && parsed.key_id() == key_id
        && u64::try_from(valid_after) == Ok(parsed.valid_after())
        && u64::try_from(valid_before) == Ok(parsed.valid_before());
    if !consistent {
        return Err(VerifyError::Inconsistent);
    }
    if api_token.is_empty()
        || api_token.len() > MAX_TOKEN_LEN
        || !api_token.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(VerifyError::BadToken);
    }
    let host_ca_keys = canonical_host_keys(&host_ca_keys)?;

    Ok(VerifiedLogin {
        certificate_line: line.to_owned(),
        token: Secret::new(api_token),
        meta: ProfileMeta {
            user_id,
            email,
            serial,
            key_id,
            valid_after,
            valid_before,
            token_expires_at,
            host_ca_keys,
        },
    })
}

fn is_plain_text(text: &str, max_len: usize) -> bool {
    !text.is_empty() && text.len() <= max_len && !text.chars().any(char::is_control)
}

fn canonical_host_keys(lines: &[String]) -> Result<Vec<String>, VerifyError> {
    if lines.len() > MAX_HOST_CA_KEYS {
        return Err(VerifyError::BadHostKey);
    }
    lines
        .iter()
        .map(|line| canonical_host_key(line).ok_or(VerifyError::BadHostKey))
        .collect()
}

pub(crate) fn canonical_host_key(line: &str) -> Option<String> {
    if line.is_empty() || line.len() > MAX_KEY_LINE_LEN || line.chars().any(char::is_control) {
        return None;
    }
    let key = PublicKey::from_openssh(line).ok()?;
    PublicKey::from(key.key_data().clone()).to_openssh().ok()
}
