#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DenyReason {
    MalformedQuery,
    UnknownState,
    ProviderError,
    MissingCode,
    RequestMissing,
    RequestNotPending,
    RequestExpired,
    ApproveLost,
    EmailNotVerified,
    IdentityRejected,
    ProviderUnavailable,
    Internal,
}

impl DenyReason {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            DenyReason::MalformedQuery => "malformed_query",
            DenyReason::UnknownState => "unknown_state",
            DenyReason::ProviderError => "provider_error",
            DenyReason::MissingCode => "missing_code",
            DenyReason::RequestMissing => "request_missing",
            DenyReason::RequestNotPending => "request_not_pending",
            DenyReason::RequestExpired => "request_expired",
            DenyReason::ApproveLost => "approve_lost",
            DenyReason::EmailNotVerified => "email_not_verified",
            DenyReason::IdentityRejected => "identity_rejected",
            DenyReason::ProviderUnavailable => "provider_unavailable",
            DenyReason::Internal => "internal",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FinishReason {
    Malformed,
    BodyTooLarge,
    UnknownRequest,
    WrongKind,
    NotApproved,
    Expired,
    BadVerifier,
    BadCompletionCode,
    BadPublicKey,
    LostRace,
    Clock,
    Store,
    Entropy,
    Signing,
    CorruptRecord,
}

impl FinishReason {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            FinishReason::Malformed => "malformed_request",
            FinishReason::BodyTooLarge => "body_too_large",
            FinishReason::UnknownRequest => "unknown_request",
            FinishReason::WrongKind => "wrong_kind",
            FinishReason::NotApproved => "not_approved",
            FinishReason::Expired => "expired",
            FinishReason::BadVerifier => "bad_verifier",
            FinishReason::BadCompletionCode => "bad_completion_code",
            FinishReason::BadPublicKey => "bad_public_key",
            FinishReason::LostRace => "lost_race",
            FinishReason::Clock => "clock",
            FinishReason::Store => "store",
            FinishReason::Entropy => "entropy",
            FinishReason::Signing => "signing",
            FinishReason::CorruptRecord => "corrupt_record",
        }
    }
}

pub(crate) fn login_started(login_id: &str) {
    tracing::info!(target: "jaunt::audit", event = "login.started", login_id);
}

pub(crate) fn login_approved(login_id: &str, user_id: &str, email: &str) {
    tracing::info!(target: "jaunt::audit", event = "login.approved", login_id, user_id, email);
}

pub(crate) fn login_denied(login_id: Option<&str>, reason: DenyReason) {
    tracing::info!(
        target: "jaunt::audit",
        event = "login.denied",
        login_id,
        reason = reason.code()
    );
}

pub(crate) fn cert_issued(login_id: &str, user_id: &str, email: &str, serial: i64) {
    tracing::info!(
        target: "jaunt::audit",
        event = "cert.issued",
        login_id,
        user_id,
        email,
        serial
    );
}

pub(crate) fn finish_failed(login_id: Option<&str>, user_id: Option<&str>, reason: FinishReason) {
    tracing::info!(
        target: "jaunt::audit",
        event = "login.finish_failed",
        login_id,
        user_id,
        reason = reason.code()
    );
}
