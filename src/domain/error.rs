use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Authentication error for `{0}`")]
    AuthenticationError(String),
    #[error("Database error: `{0}`")]
    DatabaseError(#[from] sqlx::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
