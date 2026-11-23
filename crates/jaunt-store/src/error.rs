#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("corrupt stored value: {0}")]
    Corrupt(String),
}
