//! HashiCorp Vault / OpenBao [`KeySource`](dbsec_core::keys::KeySource) for
//! `dbsec-core`.
//!
//! DEKs use a Transit envelope: [`VaultKeySource::connect`] asks Transit for a
//! fresh data key and stores only the wrapped ciphertext in KV v2 under the
//! random 16-byte key id that gets stamped into ciphertext envelopes.
//! Decrypting an envelope from an older run fetches that id's wrapped blob and
//! unwraps it through Transit — the DEK plaintext never touches Vault storage.
//! Deterministic keys (blind index, FPE, tokens) live one-per-name in KV v2,
//! created with check-and-set so concurrent minters cannot overwrite each
//! other, and a failed read is an error rather than "no key yet". The storage
//! layout, the legacy shared-map migration and the token-lease watch are
//! documented on [`source`].
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use dbsec_vault::{Secret, VaultConfig, VaultKeySource};
//! # async fn run(policy: dbsec_core::policy::Policy) -> Result<(), Box<dyn std::error::Error>> {
//! let config = VaultConfig {
//!     addr: "https://bao.internal:8200".into(),
//!     token: Some(Secret::new("s.xxxx".into())),
//!     ..VaultConfig::default()
//! };
//! let setup = config.resolve()?;                       // address + token checked once
//! let keys = Arc::new(VaultKeySource::connect(&setup).await?);
//! let protector = dbsec_core::protector::Protector::new(policy, keys.clone())?;
//!
//! // Keep a TTL'd token renewed; `shutdown` is any future that resolves to stop.
//! let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
//! tokio::spawn(keys.token_watch(async move { let _ = stop_rx.await; }));
//! # Ok(()) }
//! ```
//!
//! # Runtime
//!
//! `KeySource` is synchronous and the Vault client is not, so a cache miss
//! bridges with `tokio::task::block_in_place`, which needs a **multi-thread**
//! tokio runtime; on a current-thread runtime the lookup fails with an error
//! rather than panicking. Every bridged lookup is bounded by
//! [`VaultConfig::timeout_secs`]. The token watch is a plain future — drive it
//! with whatever spawner the application uses.
//!
//! # What revocation does not do
//!
//! The DEK and index-key caches are grow-only and have no TTL, on purpose (see
//! [`source`]). Revoking the token or rotating a key in Vault does not reach a
//! running process; restart it.

#![deny(missing_docs)]

pub mod source;

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use zeroize::Zeroizing;

pub use source::{VaultKeySource, VaultStore};

/// Errors from configuring and connecting the key source. Key lookups
/// themselves report [`dbsec_core::Error`], as every `KeySource` does.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The `[vault]` configuration is unusable: a bad address, a plaintext
    /// address without `allow_insecure_addr`, no token source or two, a zero
    /// timeout, a token file readable beyond its owner.
    #[error("{0}")]
    Config(String),
    /// The `token_file` could not be read.
    #[error("reading the [vault] token_file {}: {source}", path.display())]
    TokenFile {
        /// The token file.
        path: PathBuf,
        /// The I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// Connecting, minting the DEK or talking to Vault failed.
    #[error(transparent)]
    Key(#[from] dbsec_core::Error),
}

/// A credential held in a buffer that is wiped when it drops and whose
/// [`Debug`] never prints the value.
///
/// A config struct that derives `Debug` eventually gets written into a
/// `tracing` call while chasing a startup failure; the Vault token is the
/// credential that unwraps every DEK and reads every deterministic index key,
/// so it is the value that must survive that without leaking. `expose` is
/// deliberately ugly: it makes every read site greppable.
///
/// Erasure is best-effort at the edges: `serde` materialises the value in its
/// own `String` before this type takes ownership. What this removes is the
/// copies the application itself owns and keeps.
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Takes ownership of a credential.
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// The credential itself, for the one call that has to send it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

/// Where Vault is and how to authenticate; the proxy's `[vault]` section.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    /// e.g. `https://bao.internal:8200`. Validated as a URL with an `https`
    /// scheme by [`VaultConfig::validate_addr`].
    pub addr: String,
    /// Accepts a plaintext `http://` [`Self::addr`]. Development only — see
    /// [`VaultConfig::validate_addr`] for what travels over that channel.
    #[serde(default)]
    pub allow_insecure_addr: bool,
    /// Static token; prefer `token_file` outside of dev.
    pub token: Option<Secret>,
    /// File containing the token (e.g. written by an agent sidecar). Refused
    /// unless readable only by its owner.
    pub token_file: Option<PathBuf>,
    /// KV v2 mount holding wrapped DEKs and index keys.
    #[serde(default = "default_mount")]
    pub mount: String,
    /// Base path within the mount.
    #[serde(default = "default_path")]
    pub path: String,
    /// Transit mount used to wrap/unwrap DEKs.
    #[serde(default = "default_transit_mount")]
    pub transit_mount: String,
    /// Transit key name the DEK envelope is encrypted under.
    #[serde(default = "default_path")]
    pub transit_key: String,
    /// Timeout for each Vault request, and the budget for one key lookup made
    /// from the sync `KeySource` path. Unset, `vaultrs` leaves the HTTP client
    /// with no timeout at all, so a Vault that accepts the connection and then
    /// stops answering would park a runtime worker for the life of the
    /// process.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

impl Default for VaultConfig {
    /// Everything but `addr` and a token source has a usable default.
    fn default() -> Self {
        Self {
            addr: String::new(),
            allow_insecure_addr: false,
            token: None,
            token_file: None,
            mount: default_mount(),
            path: default_path(),
            transit_mount: default_transit_mount(),
            transit_key: default_path(),
            timeout_secs: default_timeout_secs(),
        }
    }
}

fn default_mount() -> String {
    "secret".to_owned()
}

fn default_path() -> String {
    "dbsec".to_owned()
}

fn default_transit_mount() -> String {
    "transit".to_owned()
}

fn default_timeout_secs() -> u64 {
    5
}

/// A [`VaultConfig`] with its token already resolved — the form
/// [`VaultKeySource::connect`] consumes. Produced by [`VaultConfig::resolve`],
/// which proves the token is obtainable *by obtaining it* rather than by
/// resolving a throwaway copy and dropping it.
#[derive(Debug, Clone)]
pub struct VaultSetup {
    /// The validated configuration.
    pub config: VaultConfig,
    /// The token to authenticate with.
    pub token: Secret,
}

impl VaultConfig {
    /// Validates the configuration and resolves the token, once.
    pub fn resolve(&self) -> Result<VaultSetup, Error> {
        if self.timeout_secs == 0 {
            return Err(Error::Config("[vault] timeout_secs must be greater than 0".into()));
        }
        self.validate_addr()?;
        Ok(VaultSetup { config: self.clone(), token: self.resolve_token()? })
    }

    /// Parses [`Self::addr`] and refuses anything that is not a TLS Vault
    /// endpoint.
    ///
    /// Two properties are established here, up front rather than on the
    /// connect path:
    ///
    /// - **It is a URL.** `vaultrs`' `VaultClientSettingsBuilder::address` is
    ///   documented "# Panics" and parses with `Url::parse(..).unwrap()`, so a
    ///   typo in `addr` would otherwise abort the process from inside
    ///   [`VaultKeySource::connect`] instead of being a clean startup error.
    /// - **Its scheme is `https`.** This is the channel that carries the Vault
    ///   token, every DEK in plaintext and every deterministic index key, so
    ///   tolerating a plaintext hop — the one whose compromise yields the
    ///   entire key hierarchy — would be the weakest link deciding the whole.
    ///   A `http://` dev address stays reachable, but only by writing
    ///   `allow_insecure_addr = true`, which is a deliberate act rather than a
    ///   config copied out of an example.
    ///
    /// `addr` is echoed in the refusals: it is an endpoint, and the credential
    /// beside it lives in `token`/`token_file`.
    pub fn validate_addr(&self) -> Result<(), Error> {
        let addr = url::Url::parse(&self.addr).map_err(|e| {
            Error::Config(format!("[vault] addr {:?} is not a URL: {e}", self.addr))
        })?;
        match addr.scheme() {
            "https" => Ok(()),
            "http" if self.allow_insecure_addr => {
                tracing::warn!(
                    addr = self.addr,
                    "[vault] allow_insecure_addr is set: the Vault token, every DEK plaintext \
                     and every deterministic index key cross the network in the clear"
                );
                Ok(())
            }
            "http" => Err(Error::Config(format!(
                "[vault] addr {:?} is plaintext http, which would put the Vault token, every \
                 DEK plaintext and every deterministic index key on the wire in the clear. Use \
                 https, or set allow_insecure_addr = true to accept that in development",
                self.addr
            ))),
            other => Err(Error::Config(format!(
                "[vault] addr {:?} has scheme {other:?}; Vault is reached over https",
                self.addr
            ))),
        }
    }

    /// Resolves the token from whichever of the two sources is configured.
    /// A `token_file` is refused unless readable only by its owner, and read
    /// into a buffer that is wiped on drop.
    pub fn resolve_token(&self) -> Result<Secret, Error> {
        match (&self.token, &self.token_file) {
            (Some(token), None) => Ok(token.clone()),
            (None, Some(path)) => {
                dbsec_core::keys::check_secret_file_mode(path, "the Vault token")
                    .map_err(|e| Error::Config(e.to_string()))?;
                let raw = Zeroizing::new(
                    std::fs::read_to_string(path)
                        .map_err(|source| Error::TokenFile { path: path.clone(), source })?,
                );
                Ok(Secret::new(raw.trim().to_owned()))
            }
            _ => Err(Error::Config("[vault] needs exactly one of token or token_file".into())),
        }
    }
}

/// Kept for callers that hold a `Path` rather than a config: the secret-file
/// check the token file goes through.
pub fn check_token_file(path: &Path) -> Result<(), Error> {
    dbsec_core::keys::check_secret_file_mode(path, "the Vault token")
        .map_err(|e| Error::Config(e.to_string()))
}
