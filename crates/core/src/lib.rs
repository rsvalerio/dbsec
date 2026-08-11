//! dbsec-core: field-level encryption, pseudonymization and masking primitives
//! for PostgreSQL wire traffic. See plans/PLAN.md for the roadmap.

pub mod blind_index;
pub mod envelope;
pub mod keys;
pub mod mask;
pub mod pgwire;
pub mod transform;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ciphertext envelope is malformed or truncated")]
    Malformed,
    #[error("decryption failed (wrong key or tampered data)")]
    Decrypt,
    #[error("invalid wire message length {0}")]
    BadMessageLength(i32),
    #[error("malformed backend message")]
    MalformedBackend,
    #[error("unknown key: {0}")]
    UnknownKey(String),
    #[error("FPE requires at least {} digits", transform::MIN_FPE_DIGITS)]
    FpeDomain,
    #[error("FPE: {0}")]
    Fpe(String),
    #[error("key source: {0}")]
    KeySource(String),
}
