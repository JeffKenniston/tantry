use thiserror::Error;

#[derive(Debug, Error)]
pub enum RepoError {
    #[error("Base error: {0}")]
    Base(#[from] base::error::BaseError),
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("Analysis error: {0}")]
    Analysis(String),
}
