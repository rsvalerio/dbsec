//! OpenBao/Vault `KeySource` (milestone 9).
//!
//! DEKs use a Transit envelope: at startup the proxy asks Transit for a fresh
//! data key and stores only the wrapped ciphertext in KV v2 under the random
//! 16-byte key id that gets stamped into ciphertext envelopes. Decrypting an
//! envelope from an older run fetches that id's wrapped blob and unwraps it
//! through Transit — the DEK plaintext never touches Vault storage. Unwrapped
//! DEKs are cached for the life of the process.
//!
//! Deterministic keys (blind index, FPE, token HMAC) live in one KV secret as
//! hex and are generated on first use — they can never rotate without
//! breaking determinism, so they are plain stored secrets, not Transit keys.

use std::collections::HashMap;
use std::sync::RwLock;

use base64::Engine as _;
use dbsec_core::envelope::{KeyId, KEY_ID_LEN};
use dbsec_core::keys::{Key, KeySource};
use dbsec_core::Error as CoreError;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use zeroize::Zeroizing;

use crate::config::VaultConfig;
use crate::Error;

/// Wrapped-DEK record stored at `{path}/deks/{key_id_hex}`.
#[derive(Serialize, Deserialize)]
struct WrappedDek {
    wrapped: String,
}

pub struct VaultKeySource {
    client: VaultClient,
    config: VaultConfig,
    handle: tokio::runtime::Handle,
    active: (KeyId, Key),
    deks: RwLock<HashMap<KeyId, Key>>,
    index_keys: RwLock<HashMap<String, Key>>,
}

impl VaultKeySource {
    /// Connects, generates this run's DEK through Transit, and records its
    /// wrapped form in KV. DEKs rotate freely — every startup gets a new one.
    pub async fn connect(config: &VaultConfig) -> Result<Self, Error> {
        let token = config.token()?;
        let settings = VaultClientSettingsBuilder::default()
            .address(&config.addr)
            .token(token.as_str())
            .build()
            .map_err(|e| Error::Vault(e.to_string()))?;
        let client = VaultClient::new(settings).map_err(|e| Error::Vault(e.to_string()))?;

        let datakey = vaultrs::transit::generate::data_key(
            &client,
            &config.transit_mount,
            &config.transit_key,
            vaultrs::api::transit::requests::DataKeyType::Plaintext,
            None,
        )
        .await
        .map_err(|e| Error::Vault(format!("transit data key: {e}")))?;
        let plaintext = datakey
            .plaintext
            .ok_or_else(|| Error::Vault("transit returned no plaintext data key".into()))?;
        let key = decode_key_b64(&plaintext)?;

        let mut key_id = [0u8; KEY_ID_LEN];
        rand::thread_rng().fill_bytes(&mut key_id);
        vaultrs::kv2::set(
            &client,
            &config.mount,
            &format!("{}/deks/{}", config.path, hex::encode(key_id)),
            &WrappedDek { wrapped: datakey.ciphertext },
        )
        .await
        .map_err(|e| Error::Vault(format!("storing wrapped DEK: {e}")))?;

        let mut deks = HashMap::new();
        deks.insert(key_id, key.clone());
        Ok(Self {
            client,
            config: config.clone(),
            handle: tokio::runtime::Handle::current(),
            active: (key_id, key),
            deks: RwLock::new(deks),
            index_keys: RwLock::new(HashMap::new()),
        })
    }

    /// Runs a Vault roundtrip from the sync `KeySource` methods. Only cache
    /// misses come through here — old-DEK unwraps and first-touch index keys.
    fn block_on<T>(
        &self,
        fut: impl std::future::Future<Output = Result<T, CoreError>>,
    ) -> Result<T, CoreError> {
        tokio::task::block_in_place(|| self.handle.block_on(fut))
    }

    async fn fetch_dek(&self, id: &KeyId) -> Result<Key, CoreError> {
        let record: WrappedDek = vaultrs::kv2::read(
            &self.client,
            &self.config.mount,
            &format!("{}/deks/{}", self.config.path, hex::encode(id)),
        )
        .await
        .map_err(|_| CoreError::UnknownKey(hex::encode(id)))?;

        let unwrapped = vaultrs::transit::data::decrypt(
            &self.client,
            &self.config.transit_mount,
            &self.config.transit_key,
            &record.wrapped,
            None,
        )
        .await
        .map_err(|e| CoreError::KeySource(format!("transit unwrap: {e}")))?;
        decode_key_b64(&unwrapped.plaintext).map_err(|e| CoreError::KeySource(e.to_string()))
    }

    async fn fetch_or_create_index_key(&self, name: &str) -> Result<Key, CoreError> {
        let path = format!("{}/index_keys", self.config.path);
        let mut keys: HashMap<String, String> =
            vaultrs::kv2::read(&self.client, &self.config.mount, &path).await.unwrap_or_default();

        if let Some(hex_key) = keys.get(name) {
            return decode_key_hex(hex_key);
        }

        // First use of this name: mint the key and persist it. Two proxies
        // racing here could each mint one and last-write-wins — provision the
        // secret up front if that matters.
        let mut fresh = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(fresh.as_mut());
        keys.insert(name.to_owned(), hex::encode(fresh.as_ref()));
        vaultrs::kv2::set(&self.client, &self.config.mount, &path, &keys)
            .await
            .map_err(|e| CoreError::KeySource(format!("storing index key {name}: {e}")))?;
        tracing::info!(name, "minted new deterministic index key");
        Ok(fresh)
    }
}

impl KeySource for VaultKeySource {
    fn active_key(&self) -> Result<(KeyId, Key), CoreError> {
        Ok((self.active.0, self.active.1.clone()))
    }

    fn key(&self, id: &KeyId) -> Result<Key, CoreError> {
        if let Some(key) = self.deks.read().expect("lock").get(id) {
            return Ok(key.clone());
        }
        let key = self.block_on(self.fetch_dek(id))?;
        self.deks.write().expect("lock").insert(*id, key.clone());
        Ok(key)
    }

    fn index_key(&self, name: &str) -> Result<Key, CoreError> {
        if let Some(key) = self.index_keys.read().expect("lock").get(name) {
            return Ok(key.clone());
        }
        let key = self.block_on(self.fetch_or_create_index_key(name))?;
        self.index_keys.write().expect("lock").insert(name.to_owned(), key.clone());
        Ok(key)
    }
}

fn decode_key_b64(encoded: &str) -> Result<Key, Error> {
    let mut raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| Error::Vault("data key is not valid base64".into()))?;
    let result = <[u8; 32]>::try_from(raw.as_slice())
        .map(Zeroizing::new)
        .map_err(|_| Error::Vault(format!("data key must be 32 bytes, got {}", raw.len())));
    zeroize::Zeroize::zeroize(&mut raw);
    result
}

fn decode_key_hex(encoded: &str) -> Result<Key, CoreError> {
    let mut raw = hex::decode(encoded)
        .map_err(|_| CoreError::KeySource("stored index key is not valid hex".into()))?;
    let result = <[u8; 32]>::try_from(raw.as_slice())
        .map(Zeroizing::new)
        .map_err(|_| CoreError::KeySource("stored index key must be 32 bytes".into()));
    zeroize::Zeroize::zeroize(&mut raw);
    result
}
