//! Field-level encryption, pseudonymization and masking for PostgreSQL
//! columns — as a library. The `dbsec` proxy is built on this crate and
//! writes the same bytes, so a table can be shared between an application
//! that links it and clients that go through the proxy.
//!
//! # Threat model, in three sentences
//!
//! The database — its files, its backups, its DBA, a SQL injection that reads
//! a table — sees only ciphertext, pseudonyms and tokens, because keys never
//! reach it. A ciphertext is bound to its column and, opt-in, to its row, so
//! stored bytes moved elsewhere stop authenticating. The application holding
//! the keys is trusted; what it decrypts is its responsibility.
//!
//! # Five minutes
//!
//! Declare a policy, supply keys, and seal / open / search by column name.
//! `keyfile` and `derive` are optional features; this runs with none.
//!
//! ```
//! use std::sync::Arc;
//! use dbsec_core::envelope::{KeyId, RowKey};
//! use dbsec_core::keys::{Key, KeySource};
//! use dbsec_core::policy::{ColumnPolicy, Policy, TablePolicy};
//! use dbsec_core::protector::{Opened, Protector};
//! use dbsec_core::Error;
//!
//! // Your KMS goes here. This one holds a single DEK and one index key.
//! struct StaticKeys;
//! impl KeySource for StaticKeys {
//!     fn active_key(&self) -> Result<(KeyId, Key), Error> { Ok(([1; 16], Key::new([2; 32]))) }
//!     fn key(&self, id: &KeyId) -> Result<Key, Error> {
//!         if *id == [1; 16] { Ok(Key::new([2; 32])) } else { Err(Error::UnknownKey(hex::encode(id))) }
//!     }
//!     fn index_key(&self, _name: &str) -> Result<Key, Error> { Ok(Key::new([3; 32])) }
//! }
//!
//! # fn main() -> Result<(), Error> {
//! let policy = Policy::new(
//!     vec![ColumnPolicy::new("users", "email").searchable(true)],
//!     vec![TablePolicy::new("users", "id")],        // bind values to their row
//! );
//! let p = Protector::new(policy, Arc::new(StaticKeys))?;
//!
//! let row = RowKey::from_i64(42);
//! let stored = p.seal("users.email", b"a@b.io", Some(&row))?;   // -> BYTEA
//! assert_eq!(&stored[32..36], b"DBS3");                          // blind index, then the envelope
//!
//! // WHERE substring(email from 1 for 32) = $1
//! let term = p.search_term("users.email", b"a@b.io")?.unwrap();
//! assert_eq!(&stored[..32], &term[..]);
//!
//! assert_eq!(p.open("users.email", &stored, Some(&row))?, Opened::Value(b"a@b.io".to_vec()));
//! assert!(matches!(p.open("users.email", &stored, Some(&RowKey::from_i64(7))), Err(Error::Decrypt)));
//! # Ok(()) }
//! ```
//!
//! With the `derive` feature the policy lives on the struct instead —
//! `#[derive(Protect)]` generates `User::policy()`, `seal`, `open`,
//! `email_term` and `masked`; see [`record`] and `examples/embedded.rs`.
//!
//! # What is stored
//!
//! | Transform | Stored as | Searchable | Reversible |
//! |---|---|---|---|
//! | `encrypt` | `DBS2` / `DBS3` AES-256-GCM envelope, BYTEA; 32-byte blind index prefix when `searchable` | equality, via the blind index | yes |
//! | `fpe` | FF1 over the digits, same shape as the input, text | equality, deterministic | yes (unless `detokenize = false`) |
//! | `token` | HMAC-SHA-256 hex, text | equality, deterministic | no |
//! | `none` | plaintext | — | mask-only |
//!
//! Envelope versions: `DBS2` binds the cell (`schema.table.column`) into the
//! AAD; `DBS3` binds the row key as well. `DBS1` values still open. See
//! [`envelope`].
//!
//! # What this does not do
//!
//! - **Hide equality.** Blind indexes, FPE and tokens map equal plaintexts to
//!   equal stored bytes by design; frequency analysis works on them. Use plain
//!   `encrypt` for values that must not be correlated.
//! - **Order or prefix search.** Equality only.
//! - **Mask anywhere but where it is called.** A mask is applied by
//!   [`protector::Protector::mask`] or by the proxy; a client that reads the
//!   table directly sees the stored form.
//! - **Manage keys.** [`keys::KeySource`] is the boundary; rotation of the
//!   active DEK is the key source's business, and a deterministic key cannot
//!   rotate without re-encrypting the column.
//! - **Async key fetches.** [`keys::KeySource`] is synchronous; a KMS-backed
//!   implementation should cache so the network is touched only on a cold miss
//!   or a rotation.
//!
//! # Compatibility
//!
//! The stable surface is the **stored format**: the envelope layouts, the AAD
//! construction, the blind-index, FPE and token derivations, and the
//! `schema.table.column` key-naming convention. A change to any of those is a
//! major version, because it strands data at rest. The Rust API follows
//! semver in the usual way; [`Error`] is `#[non_exhaustive]`.
//!
//! # Features
//!
//! - `serde` — `Deserialize` on [`mask::MaskSpec`] and the [`policy`] types.
//! - `keyfile` — [`keys::FileKeySource`], a TOML keyfile for development.
//! - `derive` — `#[derive(Protect)]`.

#![deny(missing_docs)]

pub mod blind_index;
pub mod diag;
pub mod envelope;
pub mod ident;
pub mod keys;
pub mod mask;
pub mod policy;
pub mod protector;
pub mod record;
pub mod rowkey;
pub mod sync;
pub mod transform;

/// `#[derive(Protect)]` — see [`record`] and the `dbsec-derive` docs.
#[cfg(feature = "derive")]
pub use dbsec_derive::Protect;

#[cfg(feature = "keyfile")]
use std::path::PathBuf;

/// Marked `#[non_exhaustive]` so later variants — a keyfile permissions check,
/// a new key backend — stay non-breaking for downstream matches.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The bytes are not an envelope this crate wrote, or are truncated —
    /// also returned when an opened plaintext is not the type the caller
    /// asked for.
    #[error("ciphertext envelope is malformed or truncated")]
    Malformed,
    /// The envelope did not authenticate: wrong key, tampered bytes, or a
    /// value moved to another column or row.
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
    RowBindingFieldTooLong {
        /// Which field: the cell context or the row key.
        field: &'static str,
        /// Its length in bytes.
        len: usize,
    },
    /// AES-GCM refused to seal; not expected in practice.
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
    /// The key source has no key under this id or name.
    #[error("unknown key: {0}")]
    UnknownKey(String),
    /// A secret-bearing file is readable beyond its owner; see
    /// [`keys::check_secret_file_mode`].
    #[error("{0}")]
    SecretFileMode(String),
    /// A column policy that would look like protection while providing none —
    /// see [`policy::Policy::validate`] for the rules. Front ends surface it
    /// as a configuration error.
    #[error("invalid policy: {0}")]
    Policy(String),
    /// A column name the [`protector::Protector`] was not built with. An
    /// error rather than a passthrough: a caller that mistypes a column name
    /// must not end up storing plaintext.
    #[error("no protected column named {0}")]
    UnknownColumn(String),
    /// A column whose table declares a `row_key` was sealed or opened without
    /// one. Refused rather than degraded to a cell-only seal, which is the
    /// relocatable ciphertext `strict_row_binding` exists to catch.
    #[error("column {0} is row-bound; pass the row key")]
    RowKeyRequired(String),
    /// A row key was passed for a column whose table declares none. Refused
    /// because the resulting `DBS3` envelope would bind to a row the proxy
    /// and every other reader of this column never supplies.
    #[error("column {0} declares no row_key, but one was passed")]
    RowKeyNotDeclared(String),
    /// An attempt to open a column whose stored form is irreversible: an HMAC
    /// token, or FPE with `detokenize = false`.
    #[error("column {0} cannot be opened: its stored form is irreversible by policy")]
    NotReadable(String),
    /// [`protector::Opened::into_value`] on a value that carried none of its
    /// column's stored forms — pre-migration plaintext, or a mask-only column.
    #[error("column {0} holds a value in none of its protected forms")]
    Unprotected(String),
    /// Too few digits for FF1 to be safe; see [`transform::MIN_FPE_DIGITS`].
    #[error("FPE requires at least {} digits", transform::MIN_FPE_DIGITS)]
    FpeDomain,
    /// The FF1 implementation refused the input.
    #[error("FPE transform failed")]
    Fpe(#[from] fpe::ff1::NumeralStringError),
    /// The keyfile could not be read (`keyfile` feature).
    #[cfg(feature = "keyfile")]
    #[error("reading key file {}", path.display())]
    KeyFileRead {
        /// The keyfile.
        path: PathBuf,
        /// The I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// The keyfile could not be written (`keyfile` feature).
    #[cfg(feature = "keyfile")]
    #[error("writing key file {}", path.display())]
    KeyFileWrite {
        /// The keyfile.
        path: PathBuf,
        /// The I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// The keyfile is not valid TOML of the expected shape (`keyfile` feature).
    #[cfg(feature = "keyfile")]
    #[error("parsing key file {}", path.display())]
    KeyFileParse {
        /// The keyfile.
        path: PathBuf,
        /// The parse failure.
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
        /// What was being done when the backend failed.
        context: String,
        /// The backend's own error.
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
