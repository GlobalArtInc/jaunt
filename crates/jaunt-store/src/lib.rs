mod api_tokens;
mod audit_events;
mod ca_counters;
mod certificates;
mod enrollments;
mod error;
mod join_tokens;
mod login_requests;
mod nodes;
mod recordings;
mod revocations;
mod sessions;
mod users;
mod web_sessions;

use std::path::Path;
use std::time::Duration;

use sqlx::SqlitePool;
use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

pub use api_tokens::{ApiToken, ApiTokens, NewApiToken, ValidApiToken};
pub use audit_events::{
    AuditCursor, AuditEvents, AuditQuery, AuditRecord, MAX_AUDIT_PAGE, MAX_AUDIT_PAYLOAD_BYTES,
};
pub use ca_counters::{CaCounters, NodeHostCertificate, NodeTrustServed, UnexpiredGroup};
pub use certificates::{Certificate, Certificates, NewCertificate};
pub use enrollments::{
    ApproveEnrollment, ApproveOutcome, Approved, CodeFailure, CreateOutcome, Enrollment,
    EnrollmentLimits, EnrollmentState, Enrollments, NewEnrollment, PurgedEnrollment, RejectOutcome,
};
pub use error::StoreError;
pub use join_tokens::{
    JoinEnrollment, JoinOutcome, JoinToken, JoinTokens, Joined, NameScope, NewJoinToken,
    TokenFailure, TokenRevokeOutcome, Unusable,
};
pub use login_requests::{
    LoginRequest, LoginRequestState, LoginRequests, NewDeviceLoginRequest, NewLoginRequest,
};
pub use nodes::{
    CertificateExpiry, CertificateState, Labels, MAX_NODE_PAGE, NewNodeCertificate, Node,
    NodeCertificate, NodeCertificateKind, NodeCursor, NodeKeys, NodePage, NodeQuery, NodeState,
    Nodes,
};
pub use recordings::{
    MAX_RECORDING_PAGE, Reconciled, Recording, RecordingCursor, RecordingState, Recordings,
    SESSION_ID_LEN, StoredRecording, UploadTarget, is_session_id,
};
pub use revocations::{
    MAX_REVOCATION_PAGE, NewRevocation, Revocation, RevocationCursor, RevocationKind,
    RevocationPage, Revocations, RevokeOutcome, Subjects,
};
pub use sessions::{
    ActivateSession, EndOutcome, EndRejection, EndSession, MAX_SESSION_PAGE, NewSession,
    NodeSessionCounts, OpenSessions, Session, SessionCursor, SessionEndReason, SessionListing,
    SessionPage, SessionQuery, SessionRecording, SessionState, Sessions,
};
pub use users::{NewUser, User, Users};
pub use web_sessions::{NewWebSession, ValidWebSession, WebSession, WebSessions};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

const MAX_CONNECTIONS: u32 = 8;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
}

impl Store {
    pub async fn open(path: &Path) -> Result<Store, StoreError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true)
            .busy_timeout(BUSY_TIMEOUT);
        let pool = SqlitePoolOptions::new()
            .max_connections(MAX_CONNECTIONS)
            .connect_with(options)
            .await?;
        Ok(Store { pool })
    }

    pub async fn migrate(&self) -> Result<(), StoreError> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    pub fn api_tokens(&self) -> ApiTokens {
        ApiTokens::new(self.pool.clone())
    }

    pub fn audit_events(&self) -> AuditEvents {
        AuditEvents::new(self.pool.clone())
    }

    pub fn users(&self) -> Users {
        Users::new(self.pool.clone())
    }

    pub fn login_requests(&self) -> LoginRequests {
        LoginRequests::new(self.pool.clone())
    }

    pub fn ca_counters(&self) -> CaCounters {
        CaCounters::new(self.pool.clone())
    }

    pub fn certificates(&self) -> Certificates {
        Certificates::new(self.pool.clone())
    }

    pub fn nodes(&self) -> Nodes {
        Nodes::new(self.pool.clone())
    }

    pub fn enrollments(&self) -> Enrollments {
        Enrollments::new(self.pool.clone())
    }

    pub fn join_tokens(&self) -> JoinTokens {
        JoinTokens::new(self.pool.clone())
    }

    pub fn recordings(&self) -> Recordings {
        Recordings::new(self.pool.clone())
    }

    pub fn sessions(&self) -> Sessions {
        Sessions::new(self.pool.clone())
    }

    pub fn revocations(&self) -> Revocations {
        Revocations::new(self.pool.clone())
    }

    pub fn web_sessions(&self) -> WebSessions {
        WebSessions::new(self.pool.clone())
    }
}
