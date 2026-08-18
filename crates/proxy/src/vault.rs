//! OpenBao/Vault `KeySource` (milestone 9).
//!
//! DEKs use a Transit envelope: at startup the proxy asks Transit for a fresh
//! data key and stores only the wrapped ciphertext in KV v2 under the random
//! 16-byte key id that gets stamped into ciphertext envelopes. Decrypting an
//! envelope from an older run fetches that id's wrapped blob and unwraps it
//! through Transit — the DEK plaintext never touches Vault storage. Unwrapped
//! DEKs are cached for the life of the process.
//!
//! # Deterministic index keys
//!
//! Blind-index, FPE and token keys are deterministic: the same key must be
//! used for the whole life of a column, because changing it invalidates every
//! index, pseudonym and token already written. Losing one is unrecoverable
//! without a re-index, so the storage layout is built to make losing one
//! hard:
//!
//! - **One secret per name**, at `{path}/index_keys/{name}`, rather than one
//!   shared map. Minting a key for column B can no longer rewrite column A's,
//!   which is what a read-modify-write over a shared map risks whenever two
//!   proxies — or one proxy at two points in time — touch different columns.
//! - **Created with KV v2 check-and-set** (`cas = 0`, "only if absent"), so
//!   concurrent minters cannot last-write-wins each other. The writer that
//!   loses the race re-reads and adopts the winner's key instead of
//!   overwriting it.
//! - **Versioned inside the record** (`current` plus a `version -> key` map),
//!   so a rotation is at least expressible. The proxy only ever reads
//!   `current`; the re-index that a rotation requires is an operator
//!   procedure, documented in `plans/PLAN.md`.
//! - **A failed read is an error, never "no keys yet"**. Collapsing a 5xx, a
//!   revoked token or a permission denial into an empty map would mint a
//!   fresh key over a perfectly good stored one. Only a genuine 404 means
//!   "not stored yet".
//!
//! Deployments written by an earlier version stored every key in one map at
//! `{path}/index_keys`. That layout is still read: a name found there is
//! migrated into its own versioned secret rather than re-minted. The old copy
//! is left in place — the proxy does not delete key material from a read path
//! — so each migration warns, and retiring the shared map is an operator
//! procedure documented in `plans/PLAN.md`.
//!
//! # Token lease, and what revocation does not do
//!
//! The proxy authenticates once, at startup, with the configured static token.
//! [`token_watch`] then asks Vault about that token once a minute and renews
//! it when the lease runs low, so a TTL'd token — the good practice — can be
//! used without it silently expiring mid-run. When the lease is running out
//! and cannot be extended, the watch says so at WARN on every check rather
//! than waiting for the failure: the key caches would otherwise mask an
//! expired token completely, since everything already cached keeps serving and
//! only the *first cache miss* fails, at ERROR, with nothing pointing at the
//! lease. That masking is exactly what pushes deployments to long-lived or
//! root tokens.
//!
//! **Revoking the token, or rotating a key in Vault, does not reach a running
//! proxy.** The DEK and index-key caches are grow-only and have no TTL: a key
//! resolved once is served from memory for the life of the process, so
//! incident response that revokes or rotates in Vault has no effect until the
//! proxy is restarted. That is deliberate rather than pending — a TTL on these
//! caches would put a Vault round-trip on the relay path at unpredictable
//! moments and make Vault a per-request availability dependency, and it would
//! not help the case it looks like it helps: index keys are deterministic and
//! *must not* change under a running column, and a re-fetched DEK is the same
//! DEK. **Restart the proxy** as part of any Vault-side revocation or
//! rotation; `plans/PLAN.md` carries this in the operator procedures.
//!
//! # Runtime requirements
//!
//! `KeySource` is synchronous and is called from inside the relay loop, so
//! cache misses bridge back into the runtime with
//! [`tokio::task::block_in_place`], which requires a **multi-thread** runtime
//! (`main` builds one). On a current-thread runtime the bridge would panic,
//! so it returns an error instead. Every bridged lookup is bounded by
//! `[vault] timeout_secs`, so a hung Vault parks a worker for at most that
//! long rather than for the life of the process.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use base64::Engine as _;
use dbsec_core::envelope::{KeyId, KEY_ID_LEN};
use dbsec_core::keys::{Key, KeySource};
use dbsec_core::Error as CoreError;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::runtime::RuntimeFlavor;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::error::ClientError;
use zeroize::{Zeroize, Zeroizing};

use crate::config::{VaultConfig, VaultSetup};
use crate::Error;

/// Negative cache for DEK ids Vault has no record of.
///
/// Key: the 16-byte key id read out of a stored envelope. Value: when the
/// miss was observed. Bounded at [`MISSING_DEK_CACHE_MAX`] entries and
/// expired after [`MISSING_DEK_CACHE_TTL`]; invalidation is by TTL only, so a
/// key id provisioned later starts resolving again within one TTL. The id
/// comes out of stored data, so without this a single result set of rows
/// written under a lost DEK issues one Vault roundtrip *per value*
/// (PERF-16, SEC-33). Only "no such secret" is cached — a transport failure
/// or a permission denial is never remembered as an absent key.
const MISSING_DEK_CACHE_TTL: Duration = Duration::from_mins(1);
const MISSING_DEK_CACHE_MAX: usize = 4096;

/// How often [`token_watch`] asks Vault about the token the proxy holds.
///
/// One request a minute against `auth/token/lookup-self` is nothing next to
/// the traffic the proxy already carries, and it bounds how stale the
/// "expiring soon" warning can be.
const TOKEN_CHECK_INTERVAL: Duration = Duration::from_mins(1);

/// A token with less lease than this left is renewed on the next check — or,
/// when it cannot be renewed, warned about on every check until it is.
///
/// Comfortably more than one [`TOKEN_CHECK_INTERVAL`], so a renewal that
/// fails still leaves several attempts (and several warnings) before the lease
/// actually runs out.
const TOKEN_RENEW_THRESHOLD: Duration = Duration::from_mins(10);

/// Wrapped-DEK record stored at `{path}/deks/{key_id_hex}`.
#[derive(Serialize, Deserialize)]
struct WrappedDek {
    wrapped: String,
}

/// Deterministic key for one name, stored at `{path}/index_keys/{name}`.
///
/// `current` names the version new writes use; `versions` carries every
/// version still stored, hex-encoded. Older versions are kept so a rotation
/// leaves a record of what the previous key was — the proxy itself only ever
/// uses `current` (see the module docs).
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct IndexKeyRecord {
    current: u32,
    versions: BTreeMap<u32, String>,
}

/// Hand-written so `versions` cannot be derived into a log line: these are the
/// keys that a leak turns into an offline equality oracle over the column.
impl std::fmt::Debug for IndexKeyRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexKeyRecord")
            .field("current", &self.current)
            .field("versions", &format_args!("<{} redacted>", self.versions.len()))
            .finish()
    }
}

impl IndexKeyRecord {
    /// The first version of a freshly minted key.
    fn first(hex_key: String) -> Self {
        Self { current: 1, versions: BTreeMap::from([(1, hex_key)]) }
    }

    fn current_key(&self) -> Result<Key, CoreError> {
        let hex_key = self.versions.get(&self.current).ok_or_else(|| {
            CoreError::KeySource(format!(
                "stored index key names version {} but does not carry it",
                self.current
            ))
        })?;
        decode_key_hex(hex_key)
    }
}

impl Drop for IndexKeyRecord {
    fn drop(&mut self) {
        for hex_key in self.versions.values_mut() {
            hex_key.zeroize();
        }
    }
}

/// The pre-versioning shared map: `name -> hex key`, every value a live
/// deterministic key.
///
/// A newtype rather than a bare `HashMap<String, String>` for the same reason
/// [`IndexKeyRecord`] is one: the map `vaultrs` deserializes into is a
/// plaintext copy of every legacy index key, and these are the keys that can
/// never be rotated, so it is wiped on drop instead of being freed intact.
/// Serde sees through the newtype, so the stored shape is unchanged.
#[derive(Deserialize)]
pub(crate) struct LegacyIndexKeys(HashMap<String, String>);

impl LegacyIndexKeys {
    fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    /// Wipes every key in the map. Called from [`Drop`]; separate so the wipe
    /// is observable in a test.
    fn wipe(&mut self) {
        for hex_key in self.0.values_mut() {
            hex_key.zeroize();
        }
    }
}

impl Drop for LegacyIndexKeys {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// The Vault operations the key source needs, behind a seam so the key logic
/// — which branch mints, which propagates, which retries — is exercised
/// without a live server. `None` means "no such secret"; every other failure
/// is an `Err`, because the two are not interchangeable for key material.
pub(crate) trait KeyStore: Send + Sync {
    /// Reads the versioned record for `name`.
    fn read_index_key(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Option<IndexKeyRecord>, CoreError>> + Send;

    /// Creates `name`'s record only if it does not exist yet (KV v2
    /// `cas = 0`). `Ok(false)` means another writer created it first.
    fn create_index_key(
        &self,
        name: &str,
        record: &IndexKeyRecord,
    ) -> impl Future<Output = Result<bool, CoreError>> + Send;

    /// Reads the pre-versioning layout: one shared `name -> hex key` map.
    fn read_legacy_index_keys(
        &self,
    ) -> impl Future<Output = Result<Option<LegacyIndexKeys>, CoreError>> + Send;

    /// Fetches and unwraps the DEK stored under `id`.
    fn fetch_dek(&self, id: &KeyId) -> impl Future<Output = Result<Option<Key>, CoreError>> + Send;

    /// What Vault currently says about the token this store authenticates
    /// with (`auth/token/lookup-self`).
    fn token_status(&self) -> impl Future<Output = Result<TokenStatus, CoreError>> + Send;

    /// Extends the token's lease (`auth/token/renew-self`), answering with what
    /// it looks like afterwards.
    fn renew_token(&self) -> impl Future<Output = Result<TokenStatus, CoreError>> + Send;
}

/// What Vault says about the proxy's own token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TokenStatus {
    /// Time left on the lease. Zero means "never expires" — a root token or a
    /// periodic one Vault reports without a TTL.
    pub(crate) ttl: Duration,
    pub(crate) renewable: bool,
}

impl TokenStatus {
    fn never_expires(&self) -> bool {
        self.ttl.is_zero()
    }
}

/// The outcome of one pass of [`token_watch`], so the decision is testable
/// without waiting on a timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenCheck {
    /// Nothing to do: the token never expires, or has plenty of lease left.
    Healthy,
    /// The lease was running down and Vault extended it.
    Renewed,
    /// The lease is running down and cannot be extended — the operator has to
    /// issue a new token and restart.
    Expiring,
    /// Vault could not be asked. Not evidence the token is bad.
    Unknown,
}

/// The live Vault-backed [`KeyStore`].
pub(crate) struct VaultStore {
    client: VaultClient,
    config: VaultConfig,
}

impl VaultStore {
    /// KV paths are built from the configured key name
    /// (`schema.table.column`), so a name carrying a path separator would
    /// address a different secret. Names come from config rather than from
    /// clients, so this guards a surprising configuration, not an attack.
    fn index_key_path(&self, name: &str) -> Result<String, CoreError> {
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            return Err(CoreError::KeySource(format!(
                "index key name {name:?} is not a usable Vault path segment"
            )));
        }
        Ok(format!("{}/index_keys/{}", self.config.path, name))
    }

    fn legacy_index_keys_path(&self) -> String {
        format!("{}/index_keys", self.config.path)
    }
}

impl KeyStore for VaultStore {
    async fn read_index_key(&self, name: &str) -> Result<Option<IndexKeyRecord>, CoreError> {
        let path = self.index_key_path(name)?;
        match vaultrs::kv2::read(&self.client, &self.config.mount, &path).await {
            Ok(record) => Ok(Some(record)),
            Err(e) if is_not_found(&e) => Ok(None),
            Err(e) => Err(backend_error(format!("reading index key {name}"), e)),
        }
    }

    async fn create_index_key(
        &self,
        name: &str,
        record: &IndexKeyRecord,
    ) -> Result<bool, CoreError> {
        let path = self.index_key_path(name)?;
        // cas = 0 is KV v2's "create only if this secret does not exist".
        let options = vaultrs::api::kv2::requests::SetSecretRequestOptions { cas: 0 };
        match vaultrs::kv2::set_with_options(
            &self.client,
            &self.config.mount,
            &path,
            record,
            options,
        )
        .await
        {
            Ok(_) => Ok(true),
            Err(e) if is_cas_conflict(&e) => Ok(false),
            Err(e) => Err(backend_error(format!("storing index key {name}"), e)),
        }
    }

    async fn read_legacy_index_keys(&self) -> Result<Option<LegacyIndexKeys>, CoreError> {
        let path = self.legacy_index_keys_path();
        match vaultrs::kv2::read(&self.client, &self.config.mount, &path).await {
            Ok(keys) => Ok(Some(keys)),
            Err(e) if is_not_found(&e) => Ok(None),
            Err(e) => Err(backend_error(format!("reading {path}"), e)),
        }
    }

    async fn fetch_dek(&self, id: &KeyId) -> Result<Option<Key>, CoreError> {
        let id_hex = hex::encode(id);
        let path = format!("{}/deks/{}", self.config.path, id_hex);
        let record: WrappedDek =
            match vaultrs::kv2::read(&self.client, &self.config.mount, &path).await {
                Ok(record) => record,
                Err(e) if is_not_found(&e) => return Ok(None),
                Err(e) => return Err(backend_error(format!("reading wrapped DEK {id_hex}"), e)),
            };

        let unwrapped = vaultrs::transit::data::decrypt(
            &self.client,
            &self.config.transit_mount,
            &self.config.transit_key,
            &record.wrapped,
            None,
        )
        .await
        .map_err(|e| backend_error(format!("transit unwrap of DEK {id_hex}"), e))?;
        // Moved out of the response struct rather than borrowed, so the base64
        // DEK plaintext is wiped here instead of being freed intact with it.
        let plaintext = Zeroizing::new(unwrapped.plaintext);
        decode_key_b64(&plaintext).map(Some)
    }

    async fn token_status(&self) -> Result<TokenStatus, CoreError> {
        let mut info = vaultrs::token::lookup_self(&self.client)
            .await
            .map_err(|e| backend_error("looking up the vault token".to_owned(), e))?;
        // The response echoes the token itself back. Wiped rather than dropped
        // intact, for the same reason the DEK plaintexts are.
        info.id.zeroize();
        Ok(TokenStatus { ttl: Duration::from_secs(info.ttl), renewable: info.renewable })
    }

    async fn renew_token(&self) -> Result<TokenStatus, CoreError> {
        // No increment: Vault applies the token's own period or its mount's
        // default, which is what the operator configured when issuing it.
        let mut auth = vaultrs::token::renew_self(&self.client, None)
            .await
            .map_err(|e| backend_error("renewing the vault token".to_owned(), e))?;
        auth.client_token.zeroize();
        Ok(TokenStatus { ttl: Duration::from_secs(auth.lease_duration), renewable: auth.renewable })
    }
}

/// A backend failure that keeps its cause reachable through
/// `std::error::Error::source()` (ERR-9): the `vaultrs` error behind a
/// message is what tells a 403 apart from a connection refused, and
/// `format!`ing it into a String destroys that at construction.
fn backend_error(
    context: String,
    source: impl std::error::Error + Send + Sync + 'static,
) -> CoreError {
    CoreError::KeyBackend { context, source: Box::new(source) }
}

/// A missing KV secret, as distinct from every other way a read can fail.
fn is_not_found(e: &ClientError) -> bool {
    matches!(e, ClientError::APIError { code: 404, .. })
}

/// A check-and-set rejection: the secret already exists, so another writer
/// got there first. Vault answers 400 with an explicit message; other 400s
/// (a malformed request, CAS unsupported on the mount) are real errors.
fn is_cas_conflict(e: &ClientError) -> bool {
    match e {
        ClientError::APIError { code: 400, errors } => {
            errors.iter().any(|msg| msg.to_ascii_lowercase().contains("check-and-set"))
        }
        _ => false,
    }
}

pub(crate) struct VaultKeySource<S = VaultStore> {
    store: S,
    handle: tokio::runtime::Handle,
    /// Budget for one key lookup made from the sync relay path, and the
    /// per-request timeout given to the Vault client.
    timeout: Duration,
    active: (KeyId, Key),
    deks: RwLock<HashMap<KeyId, Key>>,
    /// See [`MISSING_DEK_CACHE_TTL`].
    missing_deks: RwLock<HashMap<KeyId, Instant>>,
    index_keys: RwLock<HashMap<String, Key>>,
}

impl VaultKeySource<VaultStore> {
    /// Connects, generates this run's DEK through Transit, and records its
    /// wrapped form in KV. DEKs rotate freely — every startup gets a new one.
    pub(crate) async fn connect(setup: &VaultSetup) -> Result<Self, Error> {
        let config = &setup.config;
        let timeout = Duration::from_secs(config.timeout_secs);
        let settings = VaultClientSettingsBuilder::default()
            .address(&config.addr)
            // Resolved by validation, so no file is read from this async path.
            .token(setup.token.expose())
            // vaultrs 0.7 only calls `reqwest::ClientBuilder::timeout` when
            // this is `Some`, and reqwest's own default is no timeout at all,
            // so leaving it unset means every roundtrip below is unbounded.
            .timeout(Some(timeout))
            .build()
            .map_err(|e| backend_error("building the vault client settings".to_owned(), e))?;
        let client = VaultClient::new(settings)
            .map_err(|e| backend_error("connecting to vault".to_owned(), e))?;

        let datakey = vaultrs::transit::generate::data_key(
            &client,
            &config.transit_mount,
            &config.transit_key,
            vaultrs::api::transit::requests::DataKeyType::Plaintext,
            None,
        )
        .await
        .map_err(|e| backend_error("transit data key".to_owned(), e))?;
        // Transit hands the DEK back base64-encoded in a plain `String`, which
        // is a second plaintext copy of the key. `decode_key_b64` wipes the raw
        // bytes it decodes, so this wipes the encoded form the crate owns —
        // the copy still inside the `vaultrs` response struct is out of reach
        // (documented as a best-effort edge), but this one is not.
        let plaintext = Zeroizing::new(datakey.plaintext.ok_or_else(|| {
            CoreError::KeySource("transit returned no plaintext data key".into())
        })?);
        let key = decode_key_b64(&plaintext)?;

        // The OS entropy source rather than `thread_rng` (SEC-10): this id is
        // stamped into every envelope this run writes, and drawing it from a
        // userspace generator state puts that state — the one that survives
        // `fork()` and that reseeding bugs live in — between the OS and a
        // long-lived value. It is drawn once per process, so it costs nothing.
        let mut key_id = [0u8; KEY_ID_LEN];
        rand::rngs::OsRng.try_fill_bytes(&mut key_id).map_err(CoreError::Entropy)?;
        vaultrs::kv2::set(
            &client,
            &config.mount,
            &format!("{}/deks/{}", config.path, hex::encode(key_id)),
            &WrappedDek { wrapped: datakey.ciphertext },
        )
        .await
        .map_err(|e| backend_error("storing wrapped DEK".to_owned(), e))?;

        Ok(Self::new(VaultStore { client, config: config.clone() }, timeout, (key_id, key)))
    }
}

impl<S: KeyStore> VaultKeySource<S> {
    fn new(store: S, timeout: Duration, active: (KeyId, Key)) -> Self {
        let deks = HashMap::from([(active.0, active.1.clone())]);
        Self {
            store,
            handle: tokio::runtime::Handle::current(),
            timeout,
            active,
            deks: RwLock::new(deks),
            missing_deks: RwLock::new(HashMap::new()),
            index_keys: RwLock::new(HashMap::new()),
        }
    }

    /// Runs one Vault lookup from the sync `KeySource` methods. Only cache
    /// misses come through here — old-DEK unwraps and first-touch index keys.
    ///
    /// The future is bounded by `self.timeout` so a Vault that accepts the
    /// connection and then stops answering parks this worker for a bounded
    /// time rather than for the process's lifetime. `block_in_place` needs a
    /// multi-thread runtime; on a current-thread one it would panic, so that
    /// case is reported as an error instead.
    fn block_on<T>(
        &self,
        what: &str,
        fut: impl Future<Output = Result<T, CoreError>>,
    ) -> Result<T, CoreError> {
        if self.handle.runtime_flavor() == RuntimeFlavor::CurrentThread {
            return Err(CoreError::KeySource(format!(
                "{what}: VaultKeySource needs a multi-thread tokio runtime"
            )));
        }
        tokio::task::block_in_place(|| {
            self.handle.block_on(async {
                match tokio::time::timeout(self.timeout, fut).await {
                    Ok(result) => result,
                    Err(_) => Err(CoreError::KeySource(format!(
                        "{what}: vault did not answer within {:?}",
                        self.timeout
                    ))),
                }
            })
        })
    }

    /// Resolves `name`'s deterministic key, minting one only when Vault
    /// confirms there is none — never because a read failed.
    async fn resolve_index_key(&self, name: &str) -> Result<Key, CoreError> {
        if let Some(record) = self.store.read_index_key(name).await? {
            return record.current_key();
        }
        if let Some(key) = self.adopt_legacy_index_key(name).await? {
            return Ok(key);
        }

        // The OS entropy source rather than `thread_rng` (SEC-10). This is the
        // highest-consequence random draw in the crate: a deterministic index
        // key by design can never rotate, so it has to be right the once.
        let mut fresh = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.try_fill_bytes(fresh.as_mut()).map_err(CoreError::Entropy)?;
        // `as_slice` rather than `*fresh`: dereferencing would copy the key
        // material into a temporary that nothing zeroizes.
        let record = IndexKeyRecord::first(hex::encode(fresh.as_slice()));
        if self.store.create_index_key(name, &record).await? {
            tracing::info!(name, "minted new deterministic index key");
            return Ok(Key::from(fresh));
        }

        // Lost the create race. The winner's key is the one already in use by
        // whoever wrote it, so adopt it rather than overwriting.
        let record = self.store.read_index_key(name).await?.ok_or_else(|| {
            CoreError::KeySource(format!("index key {name} disappeared after a create conflict"))
        })?;
        tracing::info!(name, "another writer minted this index key first; adopting it");
        record.current_key()
    }

    /// Migrates a key stored under the pre-versioning shared-map layout into
    /// its own versioned secret. A conflict on the way in is benign: another
    /// proxy migrated the same material first.
    ///
    /// The copy is deliberately not deleted from the shared map here: deleting
    /// key material as a side effect of a read path is not something a proxy
    /// should do unprompted, and at this point the destination write is not
    /// confirmed durable. The consequence is that the same key lives at two
    /// paths until an operator retires the old one, which is a standing
    /// exposure — so this logs at WARN, naming the migrated key, and
    /// `plans/PLAN.md` carries the cleanup procedure the warning refers to.
    async fn adopt_legacy_index_key(&self, name: &str) -> Result<Option<Key>, CoreError> {
        let Some(legacy) = self.store.read_legacy_index_keys().await? else {
            return Ok(None);
        };
        let Some(hex_key) = legacy.get(name) else {
            return Ok(None);
        };
        let key = decode_key_hex(hex_key)?;
        // `legacy` still holds every other name's key material; it is wiped
        // when it drops at the end of this function.
        let record = IndexKeyRecord::first(hex::encode(key.as_slice()));
        self.store.create_index_key(name, &record).await?;
        tracing::warn!(
            name,
            "migrated index key out of the shared-map layout; the same key material is now \
             stored at both paths — retire the shared map once every name has migrated (see \
             the \"Retiring the shared-map layout\" procedure in plans/PLAN.md)"
        );
        Ok(Some(key))
    }

    /// True when `id` was recently confirmed absent and the record has not
    /// expired yet.
    fn recently_missing(&self, id: &KeyId) -> bool {
        self.missing_deks
            .read()
            .expect("lock")
            .get(id)
            .is_some_and(|seen| seen.elapsed() < MISSING_DEK_CACHE_TTL)
    }

    fn remember_missing(&self, id: &KeyId) {
        let mut missing = self.missing_deks.write().expect("lock");
        missing.retain(|_, seen| seen.elapsed() < MISSING_DEK_CACHE_TTL);
        if missing.len() >= MISSING_DEK_CACHE_MAX {
            missing.clear();
        }
        missing.insert(*id, Instant::now());
    }

    /// One pass of [`token_watch`]: ask Vault about the token, renew it if the
    /// lease is running down, and say so loudly when it cannot be renewed.
    ///
    /// Split out from the loop so the decision — not the timer — is what the
    /// tests exercise.
    async fn check_token(&self) -> TokenCheck {
        let status = match self.store.token_status().await {
            Ok(status) => status,
            Err(e) => {
                // Not evidence of a bad token: Vault may simply be
                // unreachable, and the caches keep serving meanwhile.
                tracing::warn!(error = %e, "could not check the vault token's lease");
                return TokenCheck::Unknown;
            }
        };
        if status.never_expires() || status.ttl > TOKEN_RENEW_THRESHOLD {
            return TokenCheck::Healthy;
        }
        if !status.renewable {
            tracing::warn!(
                ttl_secs = status.ttl.as_secs(),
                "the vault token expires soon and is not renewable; cached keys will keep \
                 serving until the first cache miss, which then fails the session — issue a \
                 fresh token and restart the proxy before then"
            );
            return TokenCheck::Expiring;
        }
        match self.store.renew_token().await {
            Ok(renewed) => {
                tracing::info!(ttl_secs = renewed.ttl.as_secs(), "renewed the vault token");
                TokenCheck::Renewed
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    ttl_secs = status.ttl.as_secs(),
                    "the vault token is near expiry and renewal failed; issue a fresh token \
                     and restart the proxy before the lease runs out"
                );
                TokenCheck::Expiring
            }
        }
    }
}

/// Keeps the proxy's Vault token alive, and makes a token that is running out
/// visible instead of letting the key caches mask it.
///
/// Without this, a TTL'd token — the good practice — expires mid-run and
/// nothing notices: every key already cached keeps working, so traffic looks
/// healthy right up to the first cache miss, which then fails a session at
/// ERROR with no hint that the cause is an expired lease. That failure mode is
/// what pushes deployments towards long-lived or root tokens.
///
/// Runs until `shutdown` flips, mirroring [`crate::resolve::refresh_loop`].
pub(crate) async fn token_watch<S: KeyStore>(
    source: std::sync::Arc<VaultKeySource<S>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            () = tokio::time::sleep(TOKEN_CHECK_INTERVAL) => {}
            _ = shutdown.changed() => return,
        }
        source.check_token().await;
    }
}

impl<S: KeyStore> KeySource for VaultKeySource<S> {
    fn active_key(&self) -> Result<(KeyId, Key), CoreError> {
        Ok((self.active.0, self.active.1.clone()))
    }

    fn key(&self, id: &KeyId) -> Result<Key, CoreError> {
        if let Some(key) = self.deks.read().expect("lock").get(id) {
            return Ok(key.clone());
        }
        if self.recently_missing(id) {
            return Err(CoreError::UnknownKey(hex::encode(id)));
        }
        let Some(key) = self.block_on("fetching DEK", self.store.fetch_dek(id))? else {
            self.remember_missing(id);
            return Err(CoreError::UnknownKey(hex::encode(id)));
        };
        self.deks.write().expect("lock").insert(*id, key.clone());
        Ok(key)
    }

    fn index_key(&self, name: &str) -> Result<Key, CoreError> {
        if let Some(key) = self.index_keys.read().expect("lock").get(name) {
            return Ok(key.clone());
        }
        let key = self.block_on("resolving index key", self.resolve_index_key(name))?;
        self.index_keys.write().expect("lock").insert(name.to_owned(), key.clone());
        Ok(key)
    }
}

/// `CoreError` rather than the proxy's own `Error` so the transit decode
/// failure keeps one shape wherever it is raised — `connect` converts it
/// through `Error::Wire`, and `fetch_dek` propagates it unchanged instead of
/// flattening it back into a String.
fn decode_key_b64(encoded: &str) -> Result<Key, CoreError> {
    let mut raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| backend_error("data key is not valid base64".to_owned(), e))?;
    let result = <[u8; 32]>::try_from(raw.as_slice())
        .map_err(|_| CoreError::KeySource(format!("data key must be 32 bytes, got {}", raw.len())))
        .map(Key::new);
    raw.zeroize();
    result
}

fn decode_key_hex(encoded: &str) -> Result<Key, CoreError> {
    let mut raw = hex::decode(encoded)
        .map_err(|e| backend_error("stored index key is not valid hex".to_owned(), e))?;
    let result = <[u8; 32]>::try_from(raw.as_slice())
        .map(Key::new)
        .map_err(|_| CoreError::KeySource("stored index key must be 32 bytes".into()));
    raw.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const NAME: &str = "public.users.email";
    const STORED: [u8; 32] = [3u8; 32];
    const WINNER: [u8; 32] = [9u8; 32];
    const ACTIVE_ID: KeyId = [1u8; KEY_ID_LEN];
    const OTHER_ID: KeyId = [2u8; KEY_ID_LEN];

    /// How a fake store answers one call.
    #[derive(Default, Clone, Copy, PartialEq, Eq)]
    enum Fault {
        #[default]
        None,
        /// A failure that is *not* "no such secret" — a 5xx, a revoked token,
        /// a permission denial.
        Fails,
        /// Accepts the connection and never answers.
        Hangs,
    }

    #[derive(Default)]
    struct FakeStore {
        records: Mutex<HashMap<String, IndexKeyRecord>>,
        legacy: Mutex<Option<HashMap<String, String>>>,
        deks: Mutex<HashMap<KeyId, Key>>,
        read_index: Fault,
        read_legacy: Fault,
        dek: Fault,
        /// Record another writer wins the create race with, once.
        steal_create_with: Mutex<Option<IndexKeyRecord>>,
        creates: Mutex<u32>,
        dek_reads: Mutex<u32>,
        /// What `lookup-self` answers. `None` makes the lookup itself fail.
        token: Mutex<Option<TokenStatus>>,
        /// What a renewal leaves behind; `None` makes the renewal fail.
        renews_to: Mutex<Option<TokenStatus>>,
        renewals: Mutex<u32>,
    }

    impl FakeStore {
        fn with_record(name: &str, key: [u8; 32]) -> Self {
            let store = Self::default();
            store
                .records
                .lock()
                .expect("lock")
                .insert(name.to_owned(), IndexKeyRecord::first(hex::encode(key)));
            store
        }

        fn stored(&self, name: &str) -> Option<Key> {
            self.records.lock().expect("lock").get(name).map(|r| r.current_key().expect("decodes"))
        }
    }

    impl KeyStore for FakeStore {
        async fn read_index_key(&self, name: &str) -> Result<Option<IndexKeyRecord>, CoreError> {
            match self.read_index {
                Fault::Fails => Err(CoreError::KeySource("vault is unhappy".into())),
                Fault::Hangs => std::future::pending().await,
                Fault::None => Ok(self.records.lock().expect("lock").get(name).cloned()),
            }
        }

        async fn create_index_key(
            &self,
            name: &str,
            record: &IndexKeyRecord,
        ) -> Result<bool, CoreError> {
            *self.creates.lock().expect("lock") += 1;
            let mut records = self.records.lock().expect("lock");
            if let Some(winner) = self.steal_create_with.lock().expect("lock").take() {
                records.insert(name.to_owned(), winner);
                return Ok(false);
            }
            if records.contains_key(name) {
                return Ok(false);
            }
            records.insert(name.to_owned(), record.clone());
            Ok(true)
        }

        async fn read_legacy_index_keys(&self) -> Result<Option<LegacyIndexKeys>, CoreError> {
            match self.read_legacy {
                Fault::Fails => Err(CoreError::KeySource("vault is unhappy".into())),
                Fault::Hangs => std::future::pending().await,
                Fault::None => Ok(self.legacy.lock().expect("lock").clone().map(LegacyIndexKeys)),
            }
        }

        async fn fetch_dek(&self, id: &KeyId) -> Result<Option<Key>, CoreError> {
            *self.dek_reads.lock().expect("lock") += 1;
            match self.dek {
                Fault::Fails => Err(CoreError::KeySource("vault is unhappy".into())),
                Fault::Hangs => std::future::pending().await,
                Fault::None => Ok(self.deks.lock().expect("lock").get(id).cloned()),
            }
        }

        async fn token_status(&self) -> Result<TokenStatus, CoreError> {
            self.token
                .lock()
                .expect("lock")
                .ok_or_else(|| CoreError::KeySource("vault is unhappy".into()))
        }

        async fn renew_token(&self) -> Result<TokenStatus, CoreError> {
            *self.renewals.lock().expect("lock") += 1;
            let renewed = *self.renews_to.lock().expect("lock");
            let renewed =
                renewed.ok_or_else(|| CoreError::KeySource("renewal refused".to_owned()))?;
            *self.token.lock().expect("lock") = Some(renewed);
            Ok(renewed)
        }
    }

    /// A store whose token looks like `ttl` / `renewable` and whose renewals
    /// reset the lease to an hour.
    fn store_with_token(ttl: Duration, renewable: bool) -> FakeStore {
        let store = FakeStore::default();
        *store.token.lock().expect("lock") = Some(TokenStatus { ttl, renewable });
        *store.renews_to.lock().expect("lock") =
            Some(TokenStatus { ttl: Duration::from_secs(3600), renewable });
        store
    }

    fn source<S: KeyStore>(store: S) -> VaultKeySource<S> {
        VaultKeySource::new(store, Duration::from_millis(100), (ACTIVE_ID, Key::new([7u8; 32])))
    }

    #[tokio::test]
    async fn index_key_read_failure_never_mints_over_the_stored_key() {
        let store = FakeStore { read_index: Fault::Fails, ..FakeStore::default() };
        let keys = source(store);

        let error = keys.resolve_index_key(NAME).await.expect_err("read failure must propagate");
        assert!(matches!(error, CoreError::KeySource(_)), "got {error:?}");
        assert_eq!(*keys.store.creates.lock().expect("lock"), 0, "nothing may be written");
    }

    #[tokio::test]
    async fn legacy_read_failure_never_mints_over_the_stored_key() {
        let store = FakeStore { read_legacy: Fault::Fails, ..FakeStore::default() };
        let keys = source(store);

        assert!(keys.resolve_index_key(NAME).await.is_err());
        assert_eq!(*keys.store.creates.lock().expect("lock"), 0, "nothing may be written");
    }

    #[tokio::test]
    async fn absent_index_key_is_minted_and_stored() {
        let keys = source(FakeStore::default());

        let minted = keys.resolve_index_key(NAME).await.expect("mints");
        assert_eq!(*keys.store.stored(NAME).expect("stored"), *minted, "minted key is persisted");
        assert_ne!(*minted, [0u8; 32], "key material is random, not zeroed");
    }

    #[tokio::test]
    async fn stored_index_key_is_reused_rather_than_re_minted() {
        let keys = source(FakeStore::with_record(NAME, STORED));

        assert_eq!(*keys.resolve_index_key(NAME).await.expect("reuses"), STORED);
        assert_eq!(*keys.store.creates.lock().expect("lock"), 0);
    }

    #[tokio::test]
    async fn minting_one_name_leaves_every_other_name_intact() {
        let keys = source(FakeStore::with_record("public.users.ssn", STORED));

        keys.resolve_index_key(NAME).await.expect("mints the new name");

        assert_eq!(
            *keys.store.stored("public.users.ssn").expect("still stored"),
            STORED,
            "the other column's key must survive a mint"
        );
    }

    #[tokio::test]
    async fn losing_the_create_race_adopts_the_winners_key() {
        let store = FakeStore::default();
        *store.steal_create_with.lock().expect("lock") =
            Some(IndexKeyRecord::first(hex::encode(WINNER)));
        let keys = source(store);

        assert_eq!(
            *keys.resolve_index_key(NAME).await.expect("adopts the winner"),
            WINNER,
            "the losing writer must re-read, not overwrite"
        );
        assert_eq!(*keys.store.stored(NAME).expect("stored"), WINNER);
    }

    #[tokio::test]
    async fn shared_map_layout_is_migrated_rather_than_re_minted() {
        let store = FakeStore::default();
        *store.legacy.lock().expect("lock") =
            Some(HashMap::from([(NAME.to_owned(), hex::encode(STORED))]));
        let keys = source(store);

        assert_eq!(*keys.resolve_index_key(NAME).await.expect("adopts"), STORED);
        assert_eq!(
            *keys.store.stored(NAME).expect("migrated"),
            STORED,
            "the legacy key is copied into its own versioned secret"
        );
    }

    /// Collects the level and fields of every event, so a log line an operator
    /// is told to look for is pinned like any other output.
    #[derive(Clone, Default)]
    struct CapturedLogs(std::sync::Arc<Mutex<Vec<(tracing::Level, String)>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CapturedLogs {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Fields(String);
            impl tracing::field::Visit for Fields {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.0.push_str(&format!(" {}={value:?}", field.name()));
                }
            }
            let mut fields = Fields(String::new());
            event.record(&mut fields);
            self.0.lock().expect("lock").push((*event.metadata().level(), fields.0));
        }
    }

    /// The migrated key stays readable at the old path too, so the operator
    /// who has to retire it must be able to see which names moved.
    ///
    /// The capture guard is deliberately held across the `await`: the window
    /// this test must have to itself is exactly the one in which the
    /// subscriber is installed, and the work it is capturing happens inside
    /// it. See [`crate::LOG_CAPTURE`].
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn migrating_out_of_the_shared_map_warns_and_names_the_key() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let _capture = crate::log_capture();
        let store = FakeStore::default();
        *store.legacy.lock().expect("lock") =
            Some(HashMap::from([(NAME.to_owned(), hex::encode(STORED))]));
        let keys = source(store);

        let logs = CapturedLogs::default();
        let guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(logs.clone()));
        keys.resolve_index_key(NAME).await.expect("adopts");
        drop(guard);

        let captured = logs.0.lock().expect("lock");
        let (level, fields) = captured
            .iter()
            .find(|(_, f)| f.contains("shared-map"))
            .unwrap_or_else(|| panic!("the migration must announce itself: {captured:?}"));
        assert_eq!(
            *level,
            tracing::Level::WARN,
            "an unretired duplicate of key material is a warning"
        );
        assert!(fields.contains(NAME), "the migrated name is named: {fields}");
        assert!(fields.contains("PLAN.md"), "and points at the cleanup procedure: {fields}");
    }

    #[test]
    fn record_naming_a_version_it_does_not_carry_is_an_error() {
        let record =
            IndexKeyRecord { current: 2, versions: BTreeMap::from([(1, "ab".to_owned())]) };
        assert!(matches!(record.current_key(), Err(CoreError::KeySource(_))));
    }

    /// The shared map carries the deterministic keys that can never be
    /// rotated, so the copy the proxy owns is wiped rather than freed intact.
    /// `Drop` calls exactly this.
    #[test]
    fn the_legacy_shared_map_is_wiped_rather_than_dropped_intact() {
        let hex_key = hex::encode(STORED);
        let mut legacy = LegacyIndexKeys(HashMap::from([(NAME.to_owned(), hex_key.clone())]));
        assert_eq!(legacy.get(NAME), Some(hex_key.as_str()), "readable before the wipe");

        legacy.wipe();

        assert_eq!(legacy.get(NAME), Some(""), "the key material is gone, not just unreachable");
    }

    #[test]
    fn debugging_a_record_never_prints_key_material() {
        let hex_key = hex::encode(STORED);
        let rendered = format!("{:?}", IndexKeyRecord::first(hex_key.clone()));

        assert!(!rendered.contains(&hex_key), "key material must not reach a log line");
        assert!(rendered.contains("current: 1"), "the version is still legible: {rendered}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn missing_dek_is_negatively_cached() {
        let keys = source(FakeStore::default());

        for _ in 0..3 {
            assert!(matches!(keys.key(&OTHER_ID), Err(CoreError::UnknownKey(_))));
        }
        assert_eq!(
            *keys.store.dek_reads.lock().expect("lock"),
            1,
            "one unopenable column must not issue a Vault read per value"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dek_read_failure_is_not_cached_as_a_missing_key() {
        let store = FakeStore { dek: Fault::Fails, ..FakeStore::default() };
        let keys = source(store);

        assert!(keys.key(&OTHER_ID).is_err());
        assert!(keys.key(&OTHER_ID).is_err());
        assert_eq!(
            *keys.store.dek_reads.lock().expect("lock"),
            2,
            "a transport failure must not be remembered as an absent key"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fetched_dek_is_cached() {
        let store = FakeStore::default();
        store.deks.lock().expect("lock").insert(OTHER_ID, Key::new(STORED));
        let keys = source(store);

        assert_eq!(*keys.key(&OTHER_ID).expect("fetches"), STORED);
        assert_eq!(*keys.key(&OTHER_ID).expect("cached"), STORED);
        assert_eq!(*keys.store.dek_reads.lock().expect("lock"), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_hung_vault_fails_the_lookup_instead_of_parking_the_worker() {
        let store = FakeStore { dek: Fault::Hangs, ..FakeStore::default() };
        let keys = source(store);

        let started = Instant::now();
        let error = keys.key(&OTHER_ID).expect_err("must time out");
        assert!(matches!(error, CoreError::KeySource(_)), "got {error:?}");
        assert!(error.to_string().contains("fetching DEK"), "names the operation: {error}");
        assert!(started.elapsed() < Duration::from_secs(5), "bounded by the configured timeout");
    }

    #[tokio::test]
    async fn a_current_thread_runtime_is_reported_rather_than_panicking() {
        let keys = source(FakeStore::default());

        let error = keys.key(&OTHER_ID).expect_err("cannot block_in_place here");
        assert!(error.to_string().contains("multi-thread"), "got {error}");
    }

    #[tokio::test]
    async fn a_healthy_token_is_left_alone() {
        // Root and periodic tokens report ttl = 0, "never expires".
        let keys = source(store_with_token(Duration::ZERO, false));
        assert_eq!(keys.check_token().await, TokenCheck::Healthy);

        let keys = source(store_with_token(Duration::from_secs(3600), true));
        assert_eq!(keys.check_token().await, TokenCheck::Healthy);
        assert_eq!(*keys.store.renewals.lock().expect("lock"), 0, "nothing to renew");
    }

    #[tokio::test]
    async fn a_token_running_out_of_lease_is_renewed() {
        let keys = source(store_with_token(Duration::from_secs(60), true));

        assert_eq!(keys.check_token().await, TokenCheck::Renewed);
        assert_eq!(*keys.store.renewals.lock().expect("lock"), 1);
        // And the extended lease means the next check has nothing to do.
        assert_eq!(keys.check_token().await, TokenCheck::Healthy);
        assert_eq!(*keys.store.renewals.lock().expect("lock"), 1);
    }

    /// The failure this watch exists for: a lease that cannot be extended must
    /// be surfaced while the caches still make everything look healthy.
    #[tokio::test]
    async fn a_token_that_cannot_be_renewed_is_reported_not_masked() {
        let keys = source(store_with_token(Duration::from_secs(60), false));

        assert_eq!(keys.check_token().await, TokenCheck::Expiring);
        assert_eq!(*keys.store.renewals.lock().expect("lock"), 0, "not renewable, so not tried");

        // A renewable token whose renewal is refused is the same situation.
        let store = store_with_token(Duration::from_secs(60), true);
        *store.renews_to.lock().expect("lock") = None;
        let keys = source(store);
        assert_eq!(keys.check_token().await, TokenCheck::Expiring);
    }

    /// An unreachable Vault says nothing about the token — reporting it as
    /// expiring would cry wolf on every network blip.
    #[tokio::test]
    async fn an_unreachable_vault_is_not_reported_as_an_expiring_token() {
        let keys = source(FakeStore::default());

        assert_eq!(keys.check_token().await, TokenCheck::Unknown);
        assert_eq!(*keys.store.renewals.lock().expect("lock"), 0);
    }

    #[test]
    fn decode_key_hex_accepts_32_bytes_and_rejects_everything_else() {
        assert_eq!(*decode_key_hex(&hex::encode(STORED)).expect("decodes"), STORED);
        assert!(matches!(decode_key_hex("not hex"), Err(CoreError::KeyBackend { .. })));
        assert!(matches!(decode_key_hex(&hex::encode([3u8; 16])), Err(CoreError::KeySource(_))));
        assert!(matches!(decode_key_hex(""), Err(CoreError::KeySource(_))));
    }

    #[test]
    fn decode_key_b64_accepts_32_bytes_and_rejects_everything_else() {
        let engine = base64::engine::general_purpose::STANDARD;
        assert_eq!(*decode_key_b64(&engine.encode(STORED)).expect("decodes"), STORED);
        assert!(matches!(decode_key_b64("not base64!"), Err(CoreError::KeyBackend { .. })));
        assert!(matches!(decode_key_b64(&engine.encode([3u8; 16])), Err(CoreError::KeySource(_))));
        assert!(matches!(decode_key_b64(""), Err(CoreError::KeySource(_))));
    }

    #[test]
    fn a_vault_failure_keeps_its_client_error_reachable() {
        let error = backend_error(
            "reading index key public.users.email".to_owned(),
            ClientError::APIError { code: 403, errors: vec!["permission denied".to_owned()] },
        );

        let source = std::error::Error::source(&error).expect("the cause is reachable");
        assert!(
            source.downcast_ref::<ClientError>().is_some(),
            "the vaultrs error must survive, not be formatted away: {source}"
        );
        assert!(
            error.to_string().contains("reading index key public.users.email"),
            "the proxy's own context stays on the top-level message: {error}"
        );
    }

    #[test]
    fn a_decode_failure_keeps_its_cause_reachable() {
        let hex_error = decode_key_hex("not hex").expect_err("rejects non-hex");
        assert!(std::error::Error::source(&hex_error)
            .and_then(|e| e.downcast_ref::<hex::FromHexError>())
            .is_some());

        let b64_error = decode_key_b64("not base64!").expect_err("rejects non-base64");
        assert!(std::error::Error::source(&b64_error)
            .and_then(|e| e.downcast_ref::<base64::DecodeError>())
            .is_some());
    }

    #[test]
    fn a_missing_secret_is_told_apart_from_every_other_failure() {
        assert!(is_not_found(&ClientError::APIError { code: 404, errors: Vec::new() }));
        assert!(!is_not_found(&ClientError::APIError { code: 403, errors: Vec::new() }));
        assert!(!is_not_found(&ClientError::APIError { code: 500, errors: Vec::new() }));
        assert!(!is_not_found(&ClientError::ResponseEmptyError));
    }

    #[test]
    fn a_cas_conflict_is_told_apart_from_other_bad_requests() {
        assert!(is_cas_conflict(&ClientError::APIError {
            code: 400,
            errors: vec!["check-and-set parameter did not match the current version".to_owned()],
        }));
        assert!(!is_cas_conflict(&ClientError::APIError {
            code: 400,
            errors: vec!["missing client token".to_owned()],
        }));
        assert!(!is_cas_conflict(&ClientError::APIError { code: 404, errors: Vec::new() }));
    }
}
