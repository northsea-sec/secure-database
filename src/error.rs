use thiserror::Error;

/// Error type returned by the secure database crate.
#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("database connection error: {0}")]
    Connection(String),

    #[error("database query error: {0}")]
    Query(String),

    #[error("migration error: {0}")]
    Migration(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("configuration error: {0}")]
    Configuration(String),

    #[error("io error: {0}")]
    Io(String),

    #[error("integrity violation: {0}")]
    Integrity(String),

    #[error("tee attestation error: {0}")]
    Attestation(String),

    #[error("zero-knowledge error: {0}")]
    ZeroKnowledge(String),

    #[error("unsupported feature: {0}")]
    Unsupported(String),
}

impl From<sqlx::Error> for DatabaseError {
    fn from(err: sqlx::Error) -> Self {
        Self::Query(err.to_string())
    }
}

impl From<std::io::Error> for DatabaseError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

impl From<ring::error::Unspecified> for DatabaseError {
    fn from(_: ring::error::Unspecified) -> Self {
        Self::Encryption("ring::error::Unspecified".into())
    }
}

#[cfg(feature = "zk-halo2")]
impl From<halo2_proofs::plonk::Error> for DatabaseError {
    fn from(err: halo2_proofs::plonk::Error) -> Self {
        Self::ZeroKnowledge(err.to_string())
    }
}
