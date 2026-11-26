use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use jaunt_store::{
    JoinToken, NameScope, NewJoinToken, Store, StoreError, TokenFailure, TokenRevokeOutcome,
};

use crate::clock::{Clock, Moment};
use crate::join_secrets;
use crate::join_token_audit;
use crate::labels::Labels;
use crate::naming::is_dns_label;

pub const DEFAULT_JOIN_TOKEN_TTL: Duration = Duration::from_secs(60 * 60);
pub const MAX_JOIN_TOKEN_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
pub const MAX_JOIN_TOKEN_USES: u32 = 1000;
const MAX_PREFIX_LEN: usize = 63;
const MAX_AUTHOR_LEN: usize = 128;
const MAX_ID_LEN: usize = 64;
const REDACTED: &str = "[redacted]";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinTokenRequest {
    pub scope: NameScope,
    pub labels: Labels,
    pub uses: u32,
    pub ttl: Duration,
    pub allow_replace: bool,
}

pub struct JoinTokenSecret(String);

impl JoinTokenSecret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for JoinTokenSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

#[derive(Debug)]
pub struct CreatedJoinToken {
    pub secret: JoinTokenSecret,
    pub token: JoinToken,
}

#[derive(Debug, thiserror::Error)]
pub enum JoinTokenError {
    #[error(
        "a node name must be 1 to 63 lowercase letters, digits or -, starting and ending with a letter or digit"
    )]
    InvalidName,
    #[error(
        "a name prefix must be 1 to {MAX_PREFIX_LEN} lowercase letters, digits or -, starting with a letter or digit"
    )]
    InvalidPrefix,
    #[error("the number of uses must be between 1 and {MAX_JOIN_TOKEN_USES}")]
    InvalidUses,
    #[error("the lifetime must be at least one second and at most seven days")]
    InvalidTtl,
    #[error("the operator name is not valid")]
    InvalidAuthor,
    #[error("no join token has this id")]
    UnknownToken,
    #[error("the join token is already revoked")]
    AlreadyRevoked,
    #[error("the clock is before the unix epoch")]
    Clock,
    #[error("the system entropy source failed")]
    Entropy,
    #[error("the database failed: {0}")]
    Store(#[source] StoreError),
}

impl From<StoreError> for JoinTokenError {
    fn from(err: StoreError) -> JoinTokenError {
        JoinTokenError::Store(err)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    Malformed,
    Unknown,
    Expired,
    UsedUp,
    Revoked,
    NameMismatch,
    LabelMismatch,
    ReplaceNotAllowed,
}

impl Refusal {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Refusal::Malformed => "malformed",
            Refusal::Unknown => "unknown",
            Refusal::Expired => "expired",
            Refusal::UsedUp => "used_up",
            Refusal::Revoked => "revoked",
            Refusal::NameMismatch => "name_mismatch",
            Refusal::LabelMismatch => "label_mismatch",
            Refusal::ReplaceNotAllowed => "replace_not_allowed",
        }
    }
}

impl From<TokenFailure> for Refusal {
    fn from(failure: TokenFailure) -> Refusal {
        match failure {
            TokenFailure::Unknown => Refusal::Unknown,
            TokenFailure::Expired => Refusal::Expired,
            TokenFailure::UsedUp => Refusal::UsedUp,
            TokenFailure::Revoked => Refusal::Revoked,
        }
    }
}

pub(crate) fn admits(
    token: &JoinToken,
    name: &str,
    requested_labels: &BTreeMap<String, String>,
) -> Result<(), Refusal> {
    let name_fits = match &token.scope {
        NameScope::Exact(exact) => name == exact,
        NameScope::Prefix(prefix) => name.starts_with(prefix.as_str()),
    };
    if !name_fits {
        return Err(Refusal::NameMismatch);
    }
    let labels_fit = requested_labels
        .iter()
        .all(|(key, value)| token.labels.get(key) == Some(value));
    if !labels_fit {
        return Err(Refusal::LabelMismatch);
    }
    Ok(())
}

#[derive(Clone)]
pub struct JoinTokenAdmin {
    store: Store,
    clock: Clock,
}

impl JoinTokenAdmin {
    pub fn new(store: Store, clock: Clock) -> JoinTokenAdmin {
        JoinTokenAdmin { store, clock }
    }

    pub async fn create(
        &self,
        request: JoinTokenRequest,
        created_by: &str,
    ) -> Result<CreatedJoinToken, JoinTokenError> {
        if !is_valid_author(created_by) {
            return Err(JoinTokenError::InvalidAuthor);
        }
        check_scope(&request.scope)?;
        if request.uses == 0 || request.uses > MAX_JOIN_TOKEN_USES {
            return Err(JoinTokenError::InvalidUses);
        }
        let ttl_secs = request.ttl.as_secs();
        if ttl_secs == 0 || request.ttl.subsec_nanos() != 0 || request.ttl > MAX_JOIN_TOKEN_TTL {
            return Err(JoinTokenError::InvalidTtl);
        }
        let ttl_secs = i64::try_from(ttl_secs).map_err(|_| JoinTokenError::InvalidTtl)?;
        let now = Moment::read(&self.clock).ok_or(JoinTokenError::Clock)?;
        let issued = join_secrets::issue().map_err(|_| JoinTokenError::Entropy)?;
        let token = self
            .store
            .join_tokens()
            .create(
                &NewJoinToken {
                    hash: issued.hash,
                    scope: request.scope,
                    labels: request.labels.into_map(),
                    max_uses: i64::from(request.uses),
                    allow_replace: request.allow_replace,
                    created_by: created_by.to_owned(),
                    ttl_secs,
                },
                now.secs,
            )
            .await?;
        join_token_audit::created(&token);
        Ok(CreatedJoinToken {
            secret: JoinTokenSecret(issued.secret),
            token,
        })
    }

    pub async fn list(&self) -> Result<Vec<JoinToken>, JoinTokenError> {
        Ok(self.store.join_tokens().list().await?)
    }

    pub async fn revoke(&self, id: &str, revoked_by: &str) -> Result<JoinToken, JoinTokenError> {
        if !is_valid_author(revoked_by) {
            return Err(JoinTokenError::InvalidAuthor);
        }
        if id.is_empty() || id.len() > MAX_ID_LEN || !is_visible_ascii(id) {
            return Err(JoinTokenError::UnknownToken);
        }
        let now = Moment::read(&self.clock).ok_or(JoinTokenError::Clock)?;
        match self.store.join_tokens().revoke(id, now.secs).await? {
            TokenRevokeOutcome::Revoked(token) => {
                join_token_audit::revoked(&token, revoked_by);
                Ok(*token)
            }
            TokenRevokeOutcome::AlreadyRevoked => Err(JoinTokenError::AlreadyRevoked),
            TokenRevokeOutcome::Unknown => Err(JoinTokenError::UnknownToken),
        }
    }
}

fn check_scope(scope: &NameScope) -> Result<(), JoinTokenError> {
    match scope {
        NameScope::Exact(name) if is_dns_label(name) => Ok(()),
        NameScope::Exact(_) => Err(JoinTokenError::InvalidName),
        NameScope::Prefix(prefix) if is_name_prefix(prefix) => Ok(()),
        NameScope::Prefix(_) => Err(JoinTokenError::InvalidPrefix),
    }
}

fn is_name_prefix(prefix: &str) -> bool {
    let bytes = prefix.as_bytes();
    bytes.len() <= MAX_PREFIX_LEN
        && bytes
            .first()
            .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn is_visible_ascii(text: &str) -> bool {
    text.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn is_valid_author(author: &str) -> bool {
    !author.is_empty() && author.len() <= MAX_AUTHOR_LEN && is_visible_ascii(author)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use jaunt_store::{JoinToken, NameScope};

    use super::{Refusal, admits, is_name_prefix};

    fn token(scope: NameScope, labels: &[(&str, &str)]) -> JoinToken {
        JoinToken {
            id: "id".to_owned(),
            scope,
            labels: map(labels),
            max_uses: 1,
            uses_left: 1,
            expires_at: 1,
            allow_replace: false,
            created_by: "cli:root".to_owned(),
            created_at: 0,
            revoked_at: None,
        }
    }

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn a_name_must_equal_the_exact_name_or_start_with_the_prefix() {
        let exact = token(NameScope::Exact("db-01".to_owned()), &[]);
        let prefix = token(NameScope::Prefix("web-".to_owned()), &[]);
        let none = map(&[]);
        for (token, name, expected) in [
            (&exact, "db-01", Ok(())),
            (&exact, "db-011", Err(Refusal::NameMismatch)),
            (&exact, "db-0", Err(Refusal::NameMismatch)),
            (&prefix, "web-01", Ok(())),
            (&prefix, "web-", Ok(())),
            (&prefix, "web", Err(Refusal::NameMismatch)),
            (&prefix, "xweb-01", Err(Refusal::NameMismatch)),
        ] {
            assert_eq!(admits(token, name, &none), expected, "{name}");
        }
    }

    #[test]
    fn requested_labels_must_be_among_the_pinned_ones_with_the_same_value() {
        let pinned = token(
            NameScope::Prefix("web-".to_owned()),
            &[("env", "prod"), ("team", "core")],
        );
        for (requested, expected) in [
            (map(&[]), Ok(())),
            (map(&[("env", "prod")]), Ok(())),
            (map(&[("env", "prod"), ("team", "core")]), Ok(())),
            (map(&[("env", "dev")]), Err(Refusal::LabelMismatch)),
            (
                map(&[("env", "prod"), ("role", "db")]),
                Err(Refusal::LabelMismatch),
            ),
            (map(&[("team", "")]), Err(Refusal::LabelMismatch)),
        ] {
            assert_eq!(
                admits(&pinned, "web-01", &requested),
                expected,
                "{requested:?}"
            );
        }
        let bare = token(NameScope::Exact("db-01".to_owned()), &[]);
        assert_eq!(
            admits(&bare, "db-01", &map(&[("env", "prod")])),
            Err(Refusal::LabelMismatch)
        );
    }

    #[test]
    fn a_prefix_is_a_start_of_a_node_name_and_may_end_with_a_hyphen() {
        for good in ["web-", "w", "0", "web-01", &"a".repeat(63)] {
            assert!(is_name_prefix(good), "{good}");
        }
        for bad in [
            "",
            "-web",
            "Web-",
            "web_",
            "web.",
            "w\u{e9}b",
            &"a".repeat(64),
        ] {
            assert!(!is_name_prefix(bad), "{bad}");
        }
    }
}
