//! dbsec-core: field-level encryption, pseudonymization and masking primitives
//! for PostgreSQL wire traffic. See plans/PLAN.md for the roadmap.

pub mod blind_index;
pub mod envelope;
pub mod keys;
pub mod mask;
pub mod pgwire;
pub mod sync;
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
    /// A row-bound envelope reached the opener without the row's declared key.
    /// Distinct from [`Self::Decrypt`] on purpose: nothing is wrong with the
    /// ciphertext, the caller simply cannot prove where it belongs, and the two
    /// need different operator responses — this one means the query did not
    /// carry the row key, not that a value was tampered with.
    #[error("row-bound value needs its table's row key, which this result does not carry")]
    RowKeyMissing,
    #[error("encryption failed")]
    Encrypt,
    /// The active DEK has spent its random-nonce invocation budget and the key
    /// source had no fresh key to roll to (see `envelope::MAX_ENCRYPTIONS_PER_KEY`).
    #[error("key {0} has spent its AES-GCM invocation budget; rotate the active DEK")]
    KeyExhausted(String),
    #[error("invalid wire message length {0}")]
    BadMessageLength(i32),
    /// A startup packet whose length prefix exceeds
    /// [`pgwire::MAX_STARTUP_MESSAGE_LEN`]. Distinct from
    /// [`Error::BadMessageLength`] because the length is well-formed — it is
    /// the pre-authentication allocation bound that refuses it.
    #[error("startup message is {len} bytes, over the {max} byte limit")]
    StartupMessageTooLarge { len: usize, max: usize },
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
    /// A key backend failure with no typed cause to keep: key material that is
    /// the wrong length, a lookup that timed out, a backend misconfiguration.
    /// File I/O and parse failures use the `KeyFile*` variants; a failure that
    /// *does* carry a cause uses [`Error::KeyBackend`].
    #[error("key source: {0}")]
    KeySource(String),
    /// A key backend failure that carries its cause: a Vault/OpenBao client
    /// error, or a decode failure on stored key material. The cause is boxed
    /// rather than typed so this crate keeps no dependency on any one backend
    /// (`vaultrs` lives in the proxy), and it is a `#[source]` so
    /// `std::error::Error::source()` reaches the original — an operator can
    /// tell a 403 from a connection refused from a missing KV path (ERR-9).
    #[error("key source: {context}")]
    KeyBackend {
        context: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    /// The OS entropy source refused to produce key material (SEC-10). Rare —
    /// a seccomp filter that blocks `getrandom`, or a sandbox with no
    /// `/dev/urandom` — but the alternative to reporting it is `OsRng`'s own
    /// panic, and a proxy on the data path should fail the operation, not the
    /// process.
    #[error("the OS entropy source failed")]
    Entropy(#[from] rand::Error),
}
