use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use jaunt_proto::ControlError as PlaneError;
use jaunt_store::{
    NewRevocation, OpenSessions, Revocation, RevocationCursor, RevocationKind, RevocationPage,
    Session, SessionEndReason, Store, StoreError, Subjects,
};

use crate::clock::{Clock, Moment};
use crate::control::Control;
use crate::killer::{KillReason, KillScope, KillerSlot};
use crate::plane::store_failure;
use crate::session_sweep::RevocationWatch;
use crate::{node_audit, revocation_audit, session_audit};

pub const MAX_REASON_CHARS: usize = 256;
pub const MAX_LIST_PAGE: u32 = 200;
pub const SLOW_REVOCATION_WRITE: Duration = Duration::from_secs(1);
pub const SESSION_CLOSE_BUDGET: Duration = Duration::from_secs(2);
const MAX_AUTHOR_LEN: usize = 128;
const MAX_IDENTIFIER_LEN: usize = 64;
const MAX_SERIAL_DIGITS: usize = 19;

pub(crate) async fn revoked(control: &Control, subjects: Subjects<'_>) -> Result<bool, PlaneError> {
    control
        .store
        .revocations()
        .any_matches(subjects)
        .await
        .map_err(store_failure("checking the revocations"))
}

pub(crate) async fn holder_revoked(
    store: &Store,
    user_id: &str,
    serial: Option<i64>,
) -> Result<bool, StoreError> {
    store
        .revocations()
        .any_matches(Subjects {
            user_id,
            serial,
            node_id: None,
        })
        .await
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeRequest {
    pub kind: RevocationKind,
    pub subject: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revoked {
    pub revocation: Revocation,
    pub created: bool,
    pub terminated: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum RevokeError {
    #[error("the subject is not a valid {}", noun(*.0))]
    InvalidSubject(RevocationKind),
    #[error("the reason must be 1 to {MAX_REASON_CHARS} characters without control characters")]
    InvalidReason,
    #[error("the author name is not valid")]
    InvalidAuthor,
    #[error("no {} matches this subject", noun(*.0))]
    UnknownSubject(RevocationKind),
    #[error("the clock is before the unix epoch")]
    Clock,
    #[error("the database failed: {0}")]
    Store(#[source] StoreError),
    #[error(
        "the revocation is stored and live connections were cut, but the database did not close \
         the open sessions in time; the revocation watch closes them"
    )]
    CloseTimedOut,
}

#[derive(Debug, thiserror::Error)]
pub enum UnrevokeError {
    #[error("no revocation has this id")]
    NotFound,
    #[error("the author name is not valid")]
    InvalidAuthor,
    #[error("the database failed: {0}")]
    Store(#[source] StoreError),
}

#[derive(Debug, thiserror::Error)]
pub enum ListRevocationsError {
    #[error("the page size must be between 1 and {MAX_LIST_PAGE}")]
    PageSize,
    #[error("the database failed: {0}")]
    Store(#[source] StoreError),
}

const fn noun(kind: RevocationKind) -> &'static str {
    match kind {
        RevocationKind::User => "user id",
        RevocationKind::Serial => "certificate serial",
        RevocationKind::Node => "node id",
    }
}

#[derive(Clone)]
pub struct RevocationAdmin {
    store: Store,
    clock: Clock,
    killer: Arc<KillerSlot>,
    watched: Arc<RevocationWatch>,
    close_budget: Duration,
}

impl RevocationAdmin {
    pub fn new(store: Store, clock: Clock) -> RevocationAdmin {
        RevocationAdmin::shared(store, clock, Arc::default(), Arc::default())
    }

    pub(crate) fn shared(
        store: Store,
        clock: Clock,
        killer: Arc<KillerSlot>,
        watched: Arc<RevocationWatch>,
    ) -> RevocationAdmin {
        RevocationAdmin {
            store,
            clock,
            killer,
            watched,
            close_budget: SESSION_CLOSE_BUDGET,
        }
    }

    pub fn with_session_close_budget(mut self, budget: Duration) -> RevocationAdmin {
        self.close_budget = budget;
        self
    }

    pub async fn revoke(
        &self,
        request: &RevokeRequest,
        created_by: &str,
    ) -> Result<Revoked, RevokeError> {
        if !is_valid_reason(&request.reason) {
            return Err(RevokeError::InvalidReason);
        }
        if !is_valid_author(created_by) {
            return Err(RevokeError::InvalidAuthor);
        }
        let now = Moment::read(&self.clock).ok_or(RevokeError::Clock)?;
        let (subject, scope) = self.resolve(request.kind, &request.subject).await?;
        let new = NewRevocation {
            kind: request.kind,
            subject,
            reason: request.reason.clone(),
            created_by: created_by.to_owned(),
        };
        let revocations = self.store.revocations();
        let mut insert = std::pin::pin!(revocations.insert(&new, now.secs));
        let mut cut = false;
        let written = match tokio::time::timeout(SLOW_REVOCATION_WRITE, insert.as_mut()).await {
            Ok(written) => written,
            Err(_) => {
                cut = self
                    .killer
                    .order(scope.clone(), KillReason::Revoked, &[])
                    .await;
                if cut {
                    tracing::warn!(
                        target: "jaunt::control",
                        kind = request.kind.as_str(),
                        "the revocation write is slow; live connections were cut before it finished"
                    );
                }
                insert.await
            }
        };
        let outcome = match written {
            Ok(outcome) => outcome,
            Err(err) => {
                if !cut {
                    self.killer.order(scope, KillReason::Revoked, &[]).await;
                }
                return Err(RevokeError::Store(err));
            }
        };
        if outcome.created {
            revocation_audit::created(
                &outcome.revocation,
                outcome.ended_web_sessions,
                outcome.removed_api_tokens,
            );
        }
        if let Some(node) = &outcome.removed_node {
            node_audit::node_removed(&node.id, &node.name, "revoked", created_by);
        }
        let enforced = self.enforce(scope, now.secs).await;
        if self.killer.current().is_some() {
            self.watched
                .lock_watch()
                .saw(&outcome.revocation.id, outcome.revocation.created_at);
        }
        let terminated = enforced?;
        Ok(Revoked {
            revocation: outcome.revocation,
            created: outcome.created,
            terminated,
        })
    }

    pub async fn remove(&self, id: &str, removed_by: &str) -> Result<Revocation, UnrevokeError> {
        if !is_valid_author(removed_by) {
            return Err(UnrevokeError::InvalidAuthor);
        }
        if !is_identifier(id) {
            return Err(UnrevokeError::NotFound);
        }
        let revocation = self
            .store
            .revocations()
            .delete(id)
            .await
            .map_err(UnrevokeError::Store)?
            .ok_or(UnrevokeError::NotFound)?;
        revocation_audit::removed(&revocation, removed_by);
        Ok(revocation)
    }

    pub async fn list(
        &self,
        after: Option<&RevocationCursor>,
        limit: u32,
    ) -> Result<RevocationPage, ListRevocationsError> {
        if limit == 0 || limit > MAX_LIST_PAGE {
            return Err(ListRevocationsError::PageSize);
        }
        self.store
            .revocations()
            .page(after, limit)
            .await
            .map_err(ListRevocationsError::Store)
    }

    pub(crate) async fn enforce_stored(&self, now: i64) -> Result<usize, StoreError> {
        let closed = self
            .store
            .sessions()
            .close(
                OpenSessions::OfRevokedSubjects,
                SessionEndReason::Revoked,
                now,
            )
            .await?;
        for session in &closed {
            session_audit::closed(session, SessionEndReason::Revoked);
        }
        let mut orders: HashMap<KillScope, Vec<Session>> = HashMap::new();
        let mut failure = None;
        for session in closed {
            let scope = match self.scope_of(&session).await {
                Ok(scope) => scope,
                Err(err) => {
                    failure.get_or_insert(err);
                    KillScope::Sessions
                }
            };
            orders.entry(scope).or_default().push(session);
        }
        let mut terminated = 0;
        for (scope, sessions) in orders {
            self.killer
                .order(scope, KillReason::Revoked, &sessions)
                .await;
            terminated += sessions.len();
        }
        match failure {
            Some(err) => Err(err),
            None => Ok(terminated),
        }
    }

    pub(crate) async fn order_for(&self, revocation: &Revocation) -> Result<bool, StoreError> {
        let scope = match revocation.kind {
            RevocationKind::User => KillScope::User {
                user_id: revocation.subject.clone(),
            },
            RevocationKind::Node => KillScope::Node {
                node_id: revocation.subject.clone(),
            },
            RevocationKind::Serial => {
                let Some(serial) = parse_serial(&revocation.subject) else {
                    return Ok(true);
                };
                let Some(certificate) = self.store.certificates().get(serial).await? else {
                    return Ok(true);
                };
                KillScope::Certificate {
                    user_id: certificate.user_id,
                    serial: u64::try_from(serial).unwrap_or_default(),
                }
            }
        };
        Ok(self.killer.order(scope, KillReason::Revoked, &[]).await)
    }

    async fn scope_of(&self, session: &Session) -> Result<KillScope, StoreError> {
        let revocations = self.store.revocations();
        if revocations
            .find(RevocationKind::User, &session.user_id)
            .await?
            .is_some()
        {
            return Ok(KillScope::User {
                user_id: session.user_id.clone(),
            });
        }
        if revocations
            .find(RevocationKind::Node, &session.node_id)
            .await?
            .is_some()
        {
            return Ok(KillScope::Node {
                node_id: session.node_id.clone(),
            });
        }
        Ok(KillScope::Certificate {
            user_id: session.user_id.clone(),
            serial: u64::try_from(session.serial).unwrap_or_default(),
        })
    }

    async fn enforce(&self, scope: KillScope, now: i64) -> Result<usize, RevokeError> {
        if self.killer.current().is_none() {
            return Ok(0);
        }
        let which = match &scope {
            KillScope::User { user_id } => OpenSessions::OfUser(user_id),
            KillScope::Certificate { serial, .. } => match i64::try_from(*serial) {
                Ok(serial) => OpenSessions::OfSerial(serial),
                Err(_) => {
                    self.killer
                        .order(scope.clone(), KillReason::Revoked, &[])
                        .await;
                    return Err(RevokeError::InvalidSubject(RevocationKind::Serial));
                }
            },
            KillScope::Node { node_id } => OpenSessions::OfNode(node_id),
            KillScope::Sessions => return Ok(0),
        };
        let sessions = self.store.sessions();
        let closing = sessions.close(which, SessionEndReason::Revoked, now);
        let closed = match tokio::time::timeout(self.close_budget, closing).await {
            Ok(Ok(closed)) => closed,
            Ok(Err(err)) => {
                self.killer.order(scope, KillReason::Revoked, &[]).await;
                return Err(RevokeError::Store(err));
            }
            Err(_) => {
                self.killer.order(scope, KillReason::Revoked, &[]).await;
                return Err(RevokeError::CloseTimedOut);
            }
        };
        for session in &closed {
            session_audit::closed(session, SessionEndReason::Revoked);
        }
        self.killer.order(scope, KillReason::Revoked, &closed).await;
        Ok(closed.len())
    }

    async fn resolve(
        &self,
        kind: RevocationKind,
        subject: &str,
    ) -> Result<(String, KillScope), RevokeError> {
        match kind {
            RevocationKind::User => {
                if !is_identifier(subject) {
                    return Err(RevokeError::InvalidSubject(kind));
                }
                self.store
                    .users()
                    .get(subject)
                    .await
                    .map_err(RevokeError::Store)?
                    .ok_or(RevokeError::UnknownSubject(kind))?;
                Ok((
                    subject.to_owned(),
                    KillScope::User {
                        user_id: subject.to_owned(),
                    },
                ))
            }
            RevocationKind::Serial => {
                let serial = parse_serial(subject).ok_or(RevokeError::InvalidSubject(kind))?;
                let certificate = self
                    .store
                    .certificates()
                    .get(serial)
                    .await
                    .map_err(RevokeError::Store)?
                    .ok_or(RevokeError::UnknownSubject(kind))?;
                let unsigned =
                    u64::try_from(serial).map_err(|_| RevokeError::InvalidSubject(kind))?;
                Ok((
                    serial.to_string(),
                    KillScope::Certificate {
                        user_id: certificate.user_id,
                        serial: unsigned,
                    },
                ))
            }
            RevocationKind::Node => {
                if !is_identifier(subject) {
                    return Err(RevokeError::InvalidSubject(kind));
                }
                self.store
                    .nodes()
                    .get(subject)
                    .await
                    .map_err(RevokeError::Store)?
                    .ok_or(RevokeError::UnknownSubject(kind))?;
                Ok((
                    subject.to_owned(),
                    KillScope::Node {
                        node_id: subject.to_owned(),
                    },
                ))
            }
        }
    }
}

fn parse_serial(text: &str) -> Option<i64> {
    let canonical = !text.is_empty()
        && text.len() <= MAX_SERIAL_DIGITS
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && !text.starts_with('0');
    canonical
        .then(|| text.parse::<i64>().ok())
        .flatten()
        .filter(|serial| *serial > 0)
}

pub(crate) fn is_identifier(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_IDENTIFIER_LEN
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn is_valid_reason(reason: &str) -> bool {
    !reason.trim().is_empty()
        && reason.chars().count() <= MAX_REASON_CHARS
        && !reason.chars().any(char::is_control)
}

fn is_valid_author(author: &str) -> bool {
    !author.is_empty()
        && author.len() <= MAX_AUTHOR_LEN
        && author.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{is_identifier, is_valid_author, is_valid_reason, parse_serial};

    #[test]
    fn serial_subjects_are_canonical_positive_decimals() {
        for (text, expected) in [
            ("1", Some(1)),
            ("42", Some(42)),
            ("9223372036854775807", Some(i64::MAX)),
            ("9223372036854775808", None),
            ("0", None),
            ("042", None),
            ("-1", None),
            ("+1", None),
            (" 1", None),
            ("1e3", None),
            ("", None),
        ] {
            assert_eq!(parse_serial(text), expected, "{text:?}");
        }
    }

    #[test]
    fn identifiers_reasons_and_authors_are_bounded() {
        assert!(is_identifier("67e55044-10b1-426f-9247-bb680e5fe0c8"));
        assert!(is_identifier(&"a".repeat(64)));
        for bad in ["", "a b", "a/b", "a\u{0}", "ä", &"a".repeat(65)] {
            assert!(!is_identifier(bad), "{bad:?}");
        }
        assert!(is_valid_reason("lost laptop"));
        assert!(is_valid_reason(&"ж".repeat(256)));
        for bad in ["", "   ", "line\nbreak", "tab\there", &"x".repeat(257)] {
            assert!(!is_valid_reason(bad), "{bad:?}");
        }
        assert!(is_valid_author("cli:root"));
        assert!(is_valid_author(&"a".repeat(128)));
        for bad in ["", "web user", "cli:\u{7f}", &"a".repeat(129)] {
            assert!(!is_valid_author(bad), "{bad:?}");
        }
    }
}
