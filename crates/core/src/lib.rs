//! dbsec-core: field-level encryption, pseudonymization and masking for
//! PostgreSQL columns.
//!
//! The crate is deliberately protocol-free: it transforms values, and says
//! nothing about how they reach the database. That is what lets the same
//! primitives serve an application sealing a field before it hands it to its
//! own driver and the `dbsec` proxy sealing the same field mid-flight — both
//! write the identical envelope. The PostgreSQL wire codec the proxy needs
//! lives in `dbsec-pgwire`, and the `i16` format codes stay there with it.
//!
//! It is not I/O-free, and the exception is exactly one type:
//! [`keys::FileKeySource`] reads a TOML keyfile, which is why
//! [`Error::KeyFileRead`], [`Error::KeyFileWrite`] and [`Error::KeyFileParse`]
//! exist and why `toml` is in the dependency graph. That is a dev and test key
//! source; an application shipping its own [`keys::KeySource`] should not have
//! to compile a TOML parser to get an envelope, so the type is to move behind
//! a `keyfile` feature (TASK-0192.06). See plans/PLAN.md for the roadmap.

pub mod blind_index;
pub mod envelope;
pub mod ident;
pub mod keys;
pub mod mask;
pub mod rowkey;
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
    /// A cell-only envelope was found in a column configured as row-bound with
    /// strict binding on. Distinct from both [`Self::Decrypt`] and
    /// [`Self::RowKeyMissing`]: the ciphertext is intact and the row key *was*
    /// supplied — the stored value is simply bound to less than the column's
    /// policy requires, so it can be relocated between rows of that column
    /// undetected. Either it predates the table's `row_key` and needs
    /// re-encrypting, or a write path degraded to a cell-only seal.
    #[error(
        "value is bound to its column only, but this column requires row binding; re-encrypt \
         it, or turn strict_row_binding off for the duration of the migration"
    )]
    RowBindingDowngraded,
    /// A column context or row key too long for the `u32` length prefix the
    /// row-bound (`DBS3`) associated data frames it with. Beyond that the
    /// framing stops being injective — two fields differing by exactly 2^32
    /// bytes would produce the same AAD — which is the whole reason the prefix
    /// exists, so it is refused rather than wrapped. Not reachable through the
    /// proxy's wire limits today; this is the check that says so.
    #[error("{field} is {len} bytes, over the 4 GiB a row-bound envelope's length prefix frames")]
    RowBindingFieldTooLong { field: &'static str, len: usize },
    #[error("encryption failed")]
    Encrypt,
    /// A declared row key could not be canonicalised, so nothing can be bound
    /// to the row it names: the value is NULL, not valid UTF-8, the wrong
    /// width for its type, of a type [`rowkey::supported`] refuses, or carried
    /// under an unknown wire format code. Kept apart from a decryption
    /// failure — the ciphertext is intact, the caller simply cannot say which
    /// row it belongs to.
    #[error("row key cannot be canonicalised: {0}")]
    RowKeyType(String),
    /// The active DEK has spent its random-nonce invocation budget and the key
    /// source had no fresh key to roll to (see `envelope::MAX_ENCRYPTIONS_PER_KEY`).
    #[error("key {0} has spent its AES-GCM invocation budget; rotate the active DEK")]
    KeyExhausted(String),
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
