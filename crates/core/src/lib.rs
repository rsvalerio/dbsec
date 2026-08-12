//! dbsec-core: field-level encryption, pseudonymization and masking primitives
//! for PostgreSQL wire traffic. See plans/PLAN.md for the roadmap.

pub mod blind_index;
pub mod envelope;
pub mod keys;
pub mod mask;
pub mod pgwire;
pub mod transform;

use std::path::PathBuf;

/// Marked `#[non_exhaustive]` so later variants — a keyfile permissions check,
/// a new key backend — stay non-breaking for downstream matches.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("ciphertext envelope is malformed or truncated")]
    Malformed,
    #[error("decryption failed (wrong key or tampered data)")]
    Decrypt,
    #[error("encryption failed")]
    Encrypt,
    /// The active DEK has spent its random-nonce invocation budget and the key
    /// source had no fresh key to roll to (see `envelope::MAX_ENCRYPTIONS_PER_KEY`).
    #[error("key {0} has spent its AES-GCM invocation budget; rotate the active DEK")]
    KeyExhausted(String),
    #[error("invalid wire message length {0}")]
    BadMessageLength(i32),
    #[error("message field does not fit the wire protocol's fixed-width encoding")]
    WireFieldOverflow,
    #[error("malformed backend message")]
    MalformedBackend,
    #[error("unknown key: {0}")]
    UnknownKey(String),
    #[error("FPE requires at least {} digits", transform::MIN_FPE_DIGITS)]
    FpeDomain,
    #[error("FPE transform failed")]
    Fpe(#[from] fpe::ff1::NumeralStringError),
    #[error("reading key file {}", path.display())]
    KeyFileRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("writing key file {}", path.display())]
    KeyFileWrite {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing key file {}", path.display())]
    KeyFileParse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    /// A key backend failure with no typed cause to keep: malformed key
    /// material, or an external KMS whose errors do not cross the crate
    /// boundary. File I/O and parse failures use the `KeyFile*` variants.
    #[error("key source: {0}")]
    KeySource(String),
}
