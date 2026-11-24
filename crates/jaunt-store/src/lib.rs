mod api_tokens;
mod certificates;
mod error;
mod login_requests;
mod users;

use std::path::Path;
use std::time::Duration;

use sqlx::SqlitePool;
use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

pub use api_tokens::{ApiToken, ApiTokens, NewApiToken, ValidApiToken};
pub use certificates::{Certificate, Certificates, NewCertificate};
pub use error::StoreError;
pub use login_requests::{LoginRequest, LoginRequestState, LoginRequests, NewLoginRequest};
pub use users::{NewUser, User, Users};

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

    pub fn users(&self) -> Users {
        Users::new(self.pool.clone())
    }

    pub fn login_requests(&self) -> LoginRequests {
        LoginRequests::new(self.pool.clone())
    }

    pub fn certificates(&self) -> Certificates {
        Certificates::new(self.pool.clone())
    }
}
