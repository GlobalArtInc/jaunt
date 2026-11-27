mod headers;
mod nonces;

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use axum::http::request::Parts;
use axum::http::{StatusCode, Uri};
use axum::response::Response;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use jaunt_ca::ssh_key::certificate::CertType;
use jaunt_ca::ssh_key::public::KeyData;
use jaunt_ca::ssh_key::{Algorithm, Certificate, HashAlg, PublicKey, SshSig};
use jaunt_ca::{BACKDATE, MAX_USER_VALIDITY, ORIGIN_EXTENSION, TrustSet, Uuid, is_user_key_id};
use jaunt_limits::ClientKey;
use jaunt_proto::{ADMIN_SIGNATURE_MAX_SKEW_SECS, ADMIN_SIGNATURE_NAMESPACE, admin_signature_base};
use jaunt_store::Certificate as CertificateRow;
use sha2::{Digest, Sha256};
use ssh_encoding::{Decode, Reader};

use crate::control::Control;
use crate::device::net::ClientAddress;
use crate::finish::{CERTIFICATE_KIND, key_fingerprint};
use crate::http::{MAX_BODY_BYTES, error_response, server_error};
use crate::limits::too_many_requests;
use crate::principal::{self, Channel, Refusal};

use self::headers::Presented;
use self::nonces::NonceRefusal;
use super::admin_principal::{AdminPrincipal, SignedAdmin};

pub(crate) use self::headers::is_signed;
pub(crate) use self::nonces::NonceCache;

const SSHSIG_VERSION: u32 = 1;
const SIGNATURE_HASH: HashAlg = HashAlg::Sha512;
const ACCEPTED: &str = "accepted";
const REFUSED: &str = "refused";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reason {
    MissingHeader,
    DuplicateHeader,
    MalformedHeader,
    MalformedCertificate,
    MalformedDigest,
    MalformedSignatureInput,
    MalformedSignature,
    Label,
    Components,
    Parameters,
    Nonce,
    KeyId,
    Target,
    UntrustedCa,
    NotUserCertificate,
    KeyAlgorithm,
    CriticalOptions,
    Principal,
    CertificateKeyId,
    WebOrigin,
    Window,
    KeyIdMismatch,
    BadSignature,
    BodyTooLarge,
    MalformedBody,
    UnknownSerial,
    SerialMismatch,
    NotYetValid,
    Expired,
    UnknownUser,
    Revoked,
    Skew,
    BeforeStart,
    DigestMismatch,
    Replayed,
    NonceKeyFull,
    NonceUserFull,
    NonceCacheFull,
    Unavailable,
}

impl Reason {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Reason::MissingHeader => "missing_header",
            Reason::DuplicateHeader => "duplicate_header",
            Reason::MalformedHeader => "malformed_header",
            Reason::MalformedCertificate => "malformed_certificate",
            Reason::MalformedDigest => "malformed_digest",
            Reason::MalformedSignatureInput => "malformed_signature_input",
            Reason::MalformedSignature => "malformed_signature",
            Reason::Label => "label",
            Reason::Components => "covered_components",
            Reason::Parameters => "signature_parameters",
            Reason::Nonce => "malformed_nonce",
            Reason::KeyId => "malformed_keyid",
            Reason::Target => "target",
            Reason::UntrustedCa => "untrusted_ca",
            Reason::NotUserCertificate => "not_user_certificate",
            Reason::KeyAlgorithm => "key_algorithm",
            Reason::CriticalOptions => "critical_options",
            Reason::Principal => "principal",
            Reason::CertificateKeyId => "certificate_key_id",
            Reason::WebOrigin => "web_origin",
            Reason::Window => "window",
            Reason::KeyIdMismatch => "keyid_mismatch",
            Reason::BadSignature => "bad_signature",
            Reason::BodyTooLarge => "body_too_large",
            Reason::MalformedBody => "malformed_body",
            Reason::UnknownSerial => "unknown_serial",
            Reason::SerialMismatch => "serial_mismatch",
            Reason::NotYetValid => "not_yet_valid",
            Reason::Expired => "expired",
            Reason::UnknownUser => "unknown_user",
            Reason::Revoked => "revoked",
            Reason::Skew => "created_skew",
            Reason::BeforeStart => "before_start",
            Reason::DigestMismatch => "digest_mismatch",
            Reason::Replayed => "replayed_nonce",
            Reason::NonceKeyFull => "nonce_key_full",
            Reason::NonceUserFull => "nonce_user_full",
            Reason::NonceCacheFull => "nonce_cache_full",
            Reason::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Denied {
    Unauthorized,
    TooLarge,
    TooMany { retry_after: i64 },
    Server,
}

impl Denied {
    pub(crate) fn into_response(self) -> Response {
        match self {
            Denied::Unauthorized => error_response(StatusCode::UNAUTHORIZED, "unauthorized"),
            Denied::TooLarge => error_response(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            Denied::TooMany { retry_after } => {
                too_many_requests(Duration::from_secs(u64::try_from(retry_after).unwrap_or(1)))
            }
            Denied::Server => server_error(),
        }
    }
}

struct Proven {
    presented: Presented,
    user_id: String,
    serial: u64,
}

struct Verdict {
    reason: Reason,
    denied: Denied,
    fresh: bool,
}

impl Verdict {
    fn stale(reason: Reason, denied: Denied) -> Verdict {
        Verdict {
            reason,
            denied,
            fresh: false,
        }
    }

    fn fresh(reason: Reason, denied: Denied) -> Verdict {
        Verdict {
            reason,
            denied,
            fresh: true,
        }
    }
}

pub(crate) async fn authenticate(control: &Control, request: Request) -> Result<Request, Denied> {
    let (mut parts, body) = request.into_parts();
    let client = parts
        .extensions
        .get::<ClientAddress>()
        .map(|ClientAddress(ip)| *ip);
    let proven = match prove(control, &parts) {
        Ok(proven) => proven,
        Err(reason) => {
            record_unproven(control, reason, client);
            return Err(Denied::Unauthorized);
        }
    };
    let serial = i64::try_from(proven.serial).ok();
    let verdict = match admit(control, &proven, body).await {
        Ok((signed, body)) => {
            record_proven(&parts, ACCEPTED, None, &proven.user_id, serial, client);
            parts
                .extensions
                .insert(AdminPrincipal::SignedRequest(signed));
            return Ok(Request::from_parts(parts, Body::from(body)));
        }
        Err(verdict) => verdict,
    };
    if verdict.fresh {
        record_proven(
            &parts,
            REFUSED,
            Some(verdict.reason),
            &proven.user_id,
            serial,
            client,
        );
    } else {
        record_unproven(control, verdict.reason, client);
    }
    Err(verdict.denied)
}

fn record_unproven(control: &Control, reason: Reason, client: Option<IpAddr>) {
    let address = client.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let Some(suppressed) = control
        .web
        .signed_noise
        .admit(ClientKey::of(address), control.tick())
    else {
        return;
    };
    tracing::info!(
        target: "jaunt::audit",
        event = "admin.signed_request_refused",
        reason = reason.code(),
        client_addr = %address,
        suppressed
    );
}

fn record_proven(
    parts: &Parts,
    decision: &'static str,
    reason: Option<Reason>,
    user_id: &str,
    serial: Option<i64>,
    client: Option<IpAddr>,
) {
    let reason = reason.map(Reason::code);
    let client_addr = client.map(|ip| ip.to_string());
    tracing::info!(
        target: "jaunt::audit",
        event = "admin.signed_request",
        decision,
        reason,
        user_id,
        serial,
        method = parts.method.as_str(),
        path = parts.uri.path(),
        client_addr = client_addr.as_deref()
    );
}

fn prove(control: &Control, parts: &Parts) -> Result<Proven, Reason> {
    let presented = headers::read(&parts.headers)?;
    let target = target_uri(control.public_origin(), &parts.uri).ok_or(Reason::Target)?;
    let user_id = certificate_holder(&presented.certificate, control.ca_snapshot().user_trust())?;
    let serial = presented.certificate.serial();
    if presented.covered.keyid != serial {
        return Err(Reason::KeyIdMismatch);
    }
    let base = admin_signature_base(
        [
            parts.method.as_str(),
            &target,
            &presented.digest_text,
            &presented.certificate_text,
        ],
        &presented.covered.params_text,
    );
    if !signature_holds(
        &presented.signature,
        presented.certificate.public_key(),
        base.as_bytes(),
    ) {
        return Err(Reason::BadSignature);
    }
    Ok(Proven {
        presented,
        user_id,
        serial,
    })
}

async fn admit(
    control: &Control,
    proven: &Proven,
    body: Body,
) -> Result<(SignedAdmin, Vec<u8>), Verdict> {
    let certificate = &proven.presented.certificate;
    let covered = &proven.presented.covered;
    let user_id = proven.user_id.as_str();
    let serial = i64::try_from(proven.serial)
        .map_err(|_| Verdict::stale(Reason::UnknownSerial, Denied::Unauthorized))?;
    let body = read_body(body).await?;
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return Err(Verdict::stale(Reason::Unavailable, Denied::Server));
    };
    if now.secs.abs_diff(covered.created) > ADMIN_SIGNATURE_MAX_SKEW_SECS.unsigned_abs() {
        return Err(Verdict::stale(Reason::Skew, Denied::Unauthorized));
    }
    let Some(started_at) = control.started_at() else {
        tracing::error!(target: "jaunt::control", "the start time of control is unknown");
        return Err(Verdict::stale(Reason::Unavailable, Denied::Server));
    };
    if covered.created < started_at {
        return Err(Verdict::stale(Reason::BeforeStart, Denied::Unauthorized));
    }
    if Sha256::digest(&body).as_slice() != proven.presented.digest.as_slice() {
        return Err(Verdict::stale(Reason::DigestMismatch, Denied::Unauthorized));
    }
    let expires_at = covered
        .created
        .saturating_add(ADMIN_SIGNATURE_MAX_SKEW_SECS);
    control
        .web
        .nonces
        .admit(user_id, serial, &covered.nonce, expires_at, now.secs)
        .map_err(|refusal| match refusal {
            NonceRefusal::Replayed => Verdict::stale(Reason::Replayed, Denied::Unauthorized),
            NonceRefusal::KeyFull { retry_after } => {
                Verdict::fresh(Reason::NonceKeyFull, Denied::TooMany { retry_after })
            }
            NonceRefusal::UserFull { retry_after } => {
                Verdict::fresh(Reason::NonceUserFull, Denied::TooMany { retry_after })
            }
            NonceRefusal::Full { retry_after } => {
                Verdict::fresh(Reason::NonceCacheFull, Denied::TooMany { retry_after })
            }
        })?;

    let refuse = |reason: Reason| Verdict::fresh(reason, Denied::Unauthorized);
    let unavailable = || Verdict::fresh(Reason::Unavailable, Denied::Server);
    let row = match control.store.certificates().get(serial).await {
        Ok(Some(row)) => row,
        Ok(None) => return Err(refuse(Reason::UnknownSerial)),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "loading the certificate of a signed request failed");
            return Err(unavailable());
        }
    };
    if !row_matches(&row, certificate, user_id) {
        return Err(refuse(Reason::SerialMismatch));
    }
    validity(
        certificate.valid_after(),
        certificate.valid_before(),
        &row,
        now.secs,
    )
    .map_err(refuse)?;
    let user = match control.store.users().get(user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return Err(refuse(Reason::UnknownUser)),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "loading the user of a signed request failed");
            return Err(unavailable());
        }
    };
    match principal::refuse_revoked(control, user_id, Some(serial), Channel::SignedAdmin).await {
        Ok(()) => Ok((SignedAdmin { user, serial }, body)),
        Err(Refusal::Revoked) => Err(refuse(Reason::Revoked)),
        Err(Refusal::Unavailable) => Err(unavailable()),
    }
}

async fn read_body(body: Body) -> Result<Vec<u8>, Verdict> {
    match Limited::new(body, MAX_BODY_BYTES).collect().await {
        Ok(collected) => Ok(collected.to_bytes().to_vec()),
        Err(err) if err.downcast_ref::<LengthLimitError>().is_some() => {
            Err(Verdict::stale(Reason::BodyTooLarge, Denied::TooLarge))
        }
        Err(_) => Err(Verdict::stale(Reason::MalformedBody, Denied::Unauthorized)),
    }
}

fn target_uri(public_origin: &str, uri: &Uri) -> Option<String> {
    let path = uri.path_and_query()?.as_str();
    path.starts_with('/')
        .then(|| format!("{public_origin}{path}"))
}

fn certificate_holder(certificate: &Certificate, trust: &TrustSet) -> Result<String, Reason> {
    let authority = certificate.signature_key().fingerprint(HashAlg::Sha256);
    if !trust.contains(&authority) || certificate.verify_signature().is_err() {
        return Err(Reason::UntrustedCa);
    }
    if certificate.cert_type() != CertType::User {
        return Err(Reason::NotUserCertificate);
    }
    if certificate.public_key().algorithm() != Algorithm::Ed25519 {
        return Err(Reason::KeyAlgorithm);
    }
    if !certificate.critical_options().is_empty() {
        return Err(Reason::CriticalOptions);
    }
    let user_id = match certificate.valid_principals() {
        [principal] if is_user_id(principal) => principal.clone(),
        _ => return Err(Reason::Principal),
    };
    if !is_user_key_id(certificate.key_id(), certificate.serial()) {
        return Err(Reason::CertificateKeyId);
    }
    if certificate.extensions().contains_key(ORIGIN_EXTENSION) {
        return Err(Reason::WebOrigin);
    }
    let longest = MAX_USER_VALIDITY.saturating_add(BACKDATE).as_secs();
    if certificate
        .valid_before()
        .saturating_sub(certificate.valid_after())
        > longest
    {
        return Err(Reason::Window);
    }
    Ok(user_id)
}

fn is_user_id(text: &str) -> bool {
    Uuid::parse_str(text).is_ok_and(|uuid| !uuid.is_nil() && uuid.hyphenated().to_string() == text)
}

fn row_matches(row: &CertificateRow, certificate: &Certificate, user_id: &str) -> bool {
    let subject = key_fingerprint(certificate.public_key());
    let authority = key_fingerprint(certificate.signature_key());
    row.user_id == user_id
        && row.key_id == certificate.key_id()
        && row.kind == CERTIFICATE_KIND
        && row.subject_fingerprint.as_deref() == Some(subject.as_str())
        && row
            .ca_fingerprint
            .as_deref()
            .is_none_or(|recorded| recorded == authority)
}

fn validity(
    certificate_after: u64,
    certificate_before: u64,
    row: &CertificateRow,
    now: i64,
) -> Result<(), Reason> {
    let not_before = i64::try_from(certificate_after)
        .unwrap_or(i64::MAX)
        .max(row.valid_after);
    let not_after = i64::try_from(certificate_before)
        .unwrap_or(i64::MAX)
        .min(row.valid_before);
    if now < not_before {
        return Err(Reason::NotYetValid);
    }
    if now >= not_after {
        return Err(Reason::Expired);
    }
    Ok(())
}

fn signature_holds(signature: &[u8], subject: &KeyData, base: &[u8]) -> bool {
    let mut reader = signature;
    let Ok(sshsig) = SshSig::decode(&mut reader) else {
        return false;
    };
    if !reader.is_finished() {
        return false;
    }
    sshsig.version() == SSHSIG_VERSION
        && sshsig.namespace() == ADMIN_SIGNATURE_NAMESPACE
        && sshsig.reserved().is_empty()
        && sshsig.hash_alg() == SIGNATURE_HASH
        && sshsig.public_key() == subject
        && PublicKey::from(subject.clone())
            .verify(ADMIN_SIGNATURE_NAMESPACE, base, &sshsig)
            .is_ok()
}

#[cfg(test)]
mod tests;
