//! The dbsec ciphertext envelope:
//!
//! ```text
//! "DBS2" | key_id (16B) | nonce (12B) | AES-256-GCM ciphertext+tag
//! ```
//!
//! Values without a magic prefix are passed through untouched, which allows
//! gradual migration of plaintext columns.
//!
//! # Where a ciphertext is allowed to live
//!
//! The associated data is `key_id || <schema.table.column>` — a
//! [`CellContext`] — not the key id alone. Every encrypted column in a process
//! seals under the same active DEK and therefore stamps the same key id, so a
//! key-id-only binding authenticates a blob *anywhere* that key reaches:
//! someone who can write stored bytes (a DBA, an at-rest compromise, an
//! injected `UPDATE`) could copy one row's `users.ssn` into another row, or
//! swap `ssn` and `credit_card`, and the value would decrypt cleanly with no
//! tamper signal. Binding the column into the AAD makes the ciphertext
//! authenticate only where it was written.
//!
//! The binding is per *column*, not per *cell*: relocating a value between two
//! rows of the same column still authenticates. Cross-column and cross-table
//! relocation are detected; cross-row within one column is not.
//!
//! That gap is a deliberate open decision, not an oversight, and it cannot be
//! closed here. Detecting relocation requires the opener to know where the
//! bytes belong *independently of the bytes themselves*, so any identifier
//! carried inside the envelope is copied along with it and proves nothing —
//! the identity has to be the row's primary key, supplied from outside. Making
//! that key reach both data paths costs a `DBS3` format bump plus deployment
//! rules the proxy cannot impose on its own: client-generated keys on
//! protected tables (a `serial` key does not exist yet when the write path
//! rewrites the statement), single-row `UPDATE`s (one bound parameter cannot
//! become a different ciphertext per target row), and every read projecting
//! its table's key in a type the proxy can canonicalise. `plans/PLAN.md`,
//! "Why the row half is not bound", carries the full analysis and the one
//! viable design.
//!
//! The context is the configured `schema.table.column` string, so **renaming a
//! protected column or table makes every value already stored under the old
//! name unreadable** — the new name is a different AAD, and authentication
//! fails exactly as it would for a relocated value. A rename is therefore a
//! re-encryption, in the same shape as the `DBS1` upgrade below: read under the
//! old name, write back under the new one. `plans/PLAN.md` carries it.
//!
//! # Format versions and migration
//!
//! [`MAGIC_V1`] (`"DBS1"`) is the pre-context format: identical header layout,
//! but only the key id was bound as associated data. It is still opened on
//! read, so an existing deployment keeps working across an upgrade with no
//! migration step; only new writes get [`MAGIC`] (`"DBS2"`). A `DBS1` value
//! remains relocatable — the binding is in the ciphertext's authentication
//! tag, so it cannot be added after the fact — which makes re-encrypting old
//! rows (read through the proxy, write back through it) the migration that
//! actually closes the gap. `plans/PLAN.md` carries the procedure.
//!
//! Rewriting a `DBS2` header to `DBS1` does not downgrade anything: the tag
//! was computed over the context, so the shortened AAD fails authentication.
//!
//! # Key lifetime
//!
//! Nonces are random per invocation, so every DEK has a finite safe lifetime.
//! [`Cipher`] counts its own encryptions against [`MAX_ENCRYPTIONS_PER_KEY`],
//! and [`Ciphers`] — the per-process cache the write path goes through — rolls
//! to a fresh DEK once that budget is spent, or fails closed when the key
//! source has no other key to offer.
//!
//! That budget bounds nonce collisions *within* one generator. It does nothing
//! about two generators emitting the same stream, which is what `fork()` after
//! a DEK is resolved would produce — so **dbsec must not be run under a
//! pre-forking supervisor**. See the comment on the nonce draw in
//! [`Cipher::encrypt`] for what that would cost and what supporting it would
//! take.
//!
//! # What a dropped `Cipher` leaves behind
//!
//! The DEK bytes are `Zeroizing` and the expanded AES round-key schedule inside
//! `Aes256Gcm` is wiped on drop (the workspace enables `aes/zeroize`, and
//! `the_aes_key_schedule_is_wiped_when_a_cipher_drops` below fails if that is
//! ever dropped). One piece of key-derived state is **not** wiped: the GHASH
//! authentication subkey `H = E_K(0^128)`, which `Aes256Gcm` keeps as a
//! `ghash::GHash` for the life of the cipher. When a spent DEK rolls, `H` is
//! freed intact.
//!
//! That is accepted, not overlooked. `H` decrypts nothing, but an attacker who
//! recovered it from a heap disclosure (core dump, swap, cold boot) could
//! forge tags for ciphertexts under that DEK, since the `E_K(J0)` term cancels
//! between two messages sharing a nonce. The reason it stands is that the
//! obvious fix does not work: enabling `zeroize` on `ghash`/`polyval` leaves
//! the persistent copy of `H` untouched on x86 and aarch64, because
//! `polyval`'s autodetect backend stores it in a `union` of `ManuallyDrop`
//! whose destructors never run. The workspace `Cargo.toml` carries the full
//! reasoning next to the `aes` entry, and says what would have to change
//! upstream. The proxy's process hardening (`RLIMIT_CORE = 0`,
//! `PR_SET_DUMPABLE = 0`) is what actually narrows this exposure today.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;

use crate::keys::KeySource;
use crate::sync::Unpoisoned as _;
use crate::Error;

/// Cell-bound envelopes: associated data is the key id *and* the cell context.
/// Written for a column with no configured row key.
pub const MAGIC: &[u8; 4] = b"DBS2";
/// The pre-context envelope version: same header layout, key id alone as
/// associated data. Read-only — nothing writes it any more.
pub const MAGIC_V1: &[u8; 4] = b"DBS1";
/// Row-bound envelopes: associated data is the key id, the cell context *and*
/// the row's declared key, so a ciphertext moved to another row of the same
/// column stops authenticating. Written only for a column whose table declares
/// a `row_key`; see [`RowKey`].
pub const MAGIC_V3: &[u8; 4] = b"DBS3";
pub const KEY_ID_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = MAGIC.len() + KEY_ID_LEN + NONCE_LEN;

pub type KeyId = [u8; KEY_ID_LEN];

/// The cell a ciphertext belongs to — `schema.table.column` — bound into the
/// envelope's associated data so the bytes authenticate only there.
///
/// Not a secret: it is a configured column name, and it is reconstructed on
/// read from which column the value came back in rather than stored in the
/// envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellContext(String);

impl CellContext {
    /// Binds to a qualified column name, `schema.table.column`.
    pub fn new(qualified_column: impl Into<String>) -> Self {
        Self(qualified_column.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The AAD for [`MAGIC`] envelopes. `key_id` is fixed-length and comes
    /// first, so the concatenation cannot be re-split into a different
    /// (key id, context) pair.
    fn aad(&self, key_id: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(key_id.len() + self.0.len());
        aad.extend_from_slice(key_id);
        aad.extend_from_slice(self.0.as_bytes());
        aad
    }

    /// The AAD for [`MAGIC_V3`] envelopes: key id, cell context, and the row's
    /// declared key.
    ///
    /// Every variable-length field is length-prefixed, which the two-field
    /// [`Self::aad`] did not need to be. A third field makes plain
    /// concatenation forgeable: column `users.ssn` with row `42`, and column
    /// `users.ssn4` with row `2`, produce identical bytes — so a value could be
    /// moved between two cells whose names and keys straddle the seam
    /// differently. The row key is very often attacker-chosen (it is their own
    /// row's id), which turns that from a curiosity into a way to defeat
    /// exactly the binding this version adds.
    fn aad_with_row(&self, key_id: &[u8], row: &RowKey) -> Vec<u8> {
        let column = self.0.as_bytes();
        let key = row.as_bytes();
        let mut aad = Vec::with_capacity(key_id.len() + 8 + column.len() + key.len());
        aad.extend_from_slice(key_id);
        aad.extend_from_slice(&(column.len() as u32).to_be_bytes());
        aad.extend_from_slice(column);
        aad.extend_from_slice(&(key.len() as u32).to_be_bytes());
        aad.extend_from_slice(key);
        aad
    }
}

/// The canonical bytes of one row's declared key, as bound into a
/// [`MAGIC_V3`] envelope.
///
/// *Canonical* is the whole difficulty. The same row key reaches the proxy as
/// different bytes depending on the client: `id = 42` arrives as `b"42"` from a
/// text-format client and as four big-endian bytes from a binary one, and both
/// appear in this workspace's own e2e suite. Binding raw wire bytes would mean
/// a row written through one driver could not be read through another, so the
/// proxy canonicalises per type before constructing this (see the proxy's
/// `rowkey` module) and this type is the proof that it did.
///
/// Not a secret: it is a primary key, and it is reconstructed on read from the
/// row the value came back in rather than stored in the envelope. Storing it
/// would defeat the point — an identifier carried inside the ciphertext travels
/// with it and pins nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowKey(Vec<u8>);

impl RowKey {
    pub fn new(canonical: impl Into<Vec<u8>>) -> Self {
        Self(canonical.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Where a value lives: its column, and — when the table declares a row key —
/// which row.
///
/// Carried as one argument rather than two so the version choice stays a single
/// decision: `row: Some(_)` writes [`MAGIC_V3`], `None` writes [`MAGIC`]. A
/// caller cannot accidentally supply a row key that the encryptor then ignores,
/// or omit one the decryptor silently tolerates.
#[derive(Debug, Clone, Copy)]
pub struct Binding<'a> {
    pub context: &'a CellContext,
    pub row: Option<&'a RowKey>,
}

impl<'a> Binding<'a> {
    /// A column with no configured row key: cell-bound only.
    pub fn cell(context: &'a CellContext) -> Self {
        Self { context, row: None }
    }

    /// A column whose table declares a row key.
    pub fn row(context: &'a CellContext, row: &'a RowKey) -> Self {
        Self { context, row: Some(row) }
    }
}

/// How many values one DEK may encrypt under random 96-bit nonces.
///
/// NIST SP 800-38D §8.3 caps a random-IV key at 2^32 invocations, which keeps
/// the nonce-collision probability below 2^-32. A repeated nonce under one key
/// leaks the XOR of two plaintexts and the GHASH authentication subkey — which
/// forges ciphertexts for that key — and the damage is retroactive across every
/// row already stored under it. The proxy encrypts once per protected value
/// rather than once per session, so the limit is reachable: it is enforced
/// (see [`Cipher::encrypt`]), not merely documented.
pub const MAX_ENCRYPTIONS_PER_KEY: u64 = 1 << 32;

/// Returns true if `data` carries a dbsec envelope magic — either version.
pub fn is_enveloped(data: &[u8]) -> bool {
    data.len() > HEADER_LEN
        && (data.starts_with(MAGIC) || data.starts_with(MAGIC_V1) || data.starts_with(MAGIC_V3))
}

/// AES-256-GCM bound to one DEK: the key schedule is built once, and the
/// random-nonce invocation budget is tracked for the life of the instance.
pub struct Cipher {
    gcm: Aes256Gcm,
    /// Encryptions charged against this key so far. Decryption is unlimited —
    /// only encryption draws nonces.
    used: AtomicU64,
    budget: u64,
}

impl Cipher {
    /// A cipher for `key` with the full [`MAX_ENCRYPTIONS_PER_KEY`] budget.
    pub fn new(key: &[u8; 32]) -> Self {
        Self::with_budget(key, MAX_ENCRYPTIONS_PER_KEY)
    }

    /// A cipher with a smaller budget, so tests can reach the boundary without
    /// performing 2^32 encryptions.
    pub fn with_budget(key: &[u8; 32], budget: u64) -> Self {
        Self { gcm: Aes256Gcm::new(key.into()), used: AtomicU64::new(0), budget }
    }

    /// Encryptions still allowed under this key.
    pub fn remaining(&self) -> u64 {
        self.budget.saturating_sub(self.used.load(Ordering::Relaxed))
    }

    /// Encrypts under a fresh random nonce, charging one invocation against
    /// this key's budget. `key_id` is stamped into the header and, together
    /// with `context`, bound as AAD — so a value cannot be replayed under
    /// another key id, nor moved to another column (see the module docs).
    pub fn encrypt(
        &self,
        key_id: &KeyId,
        binding: &Binding<'_>,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if self.used.fetch_add(1, Ordering::Relaxed) >= self.budget {
            return Err(Error::KeyExhausted(hex::encode(key_id)));
        }
        // The one deliberate exception to "cryptographic randomness comes from
        // the OS entropy source" (SEC-10), which `keys::FileKeySource` and the
        // proxy's Vault key source both follow. A GCM nonce is not key
        // material: it is public, it is stored in the clear in the header
        // above, and what it needs is unpredictability and non-repetition, not
        // long-term secrecy. `ThreadRng` gives that — ChaCha12 seeded from the
        // OS and periodically reseeded from it — and it is drawn once per
        // protected value on the data path, where `OsRng`'s `getrandom`
        // syscall would cost several times the AES work it accompanies.
        //
        // Two separate hazards live behind that choice, and only one of them
        // is bounded by MAX_ENCRYPTIONS_PER_KEY:
        //
        // 1. *Birthday collisions* within one generator's stream. That is the
        //    2^-32 bound NIST SP 800-38D §8.3 gives at 2^32 draws, and it is
        //    what the per-key budget enforces.
        // 2. *Two generators emitting the same stream*, which the budget does
        //    nothing about — each process stays comfortably inside it while
        //    colliding nonce-for-nonce with the other. `ThreadRng`'s state is
        //    thread-local userspace state, so `fork()` after a DEK is resolved
        //    hands both children an identical ChaCha12 state and therefore
        //    identical nonces under one key. GCM nonce reuse leaks the XOR of
        //    the two plaintexts and the GHASH subkey, retroactively over every
        //    row stored under that DEK — the worst failure in this file.
        //
        // Hazard 2 is ruled out by the deployment model, not by this code:
        // `main` builds a multi-thread tokio runtime and the proxy never
        // forks, so there is only ever one generator per DEK. **Running dbsec
        // under a pre-forking supervisor that forks workers after startup
        // would break that**, and this comment is the reason it must not be
        // done. Supporting such a model means reseeding after fork (or routing
        // nonces through `OsRng`, which is fork-safe because the kernel holds
        // the state) — a change to make deliberately, not to discover.
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);

        // AES-GCM encryption fails only past the ~64 GiB plaintext limit, and
        // pgwire::MAX_MESSAGE_LEN (1 GiB) already precludes that — so this is a
        // violated internal invariant, not a wrong key or tampering, and must
        // not be reported as Error::Decrypt.
        // The version is the binding's shape, not a separate flag, so a
        // row-bound value can never be written under a cell-only AAD.
        let (magic, aad) = match binding.row {
            Some(row) => (MAGIC_V3, binding.context.aad_with_row(key_id, row)),
            None => (MAGIC, binding.context.aad(key_id)),
        };
        let ciphertext = self
            .gcm
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
            .map_err(|_| Error::Encrypt)?;

        let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        out.extend_from_slice(magic);
        out.extend_from_slice(key_id);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypts an enveloped value read out of `context`'s column. The header's
    /// key id is bound as AAD — and, for [`MAGIC`] envelopes, the context too —
    /// so a value written under a different id, or in a different column, fails
    /// authentication here rather than decrypting into the wrong cell.
    pub fn decrypt(&self, binding: &Binding<'_>, data: &[u8]) -> Result<Vec<u8>, Error> {
        if !is_enveloped(data) {
            return Err(Error::Malformed);
        }
        let id = &data[MAGIC.len()..MAGIC.len() + KEY_ID_LEN];
        let nonce = &data[MAGIC.len() + KEY_ID_LEN..HEADER_LEN];
        // The stored value decides which AAD verifies it, so an older value
        // keeps opening after its table gains a row key. Rewriting a header to
        // an earlier version downgrades nothing: each tag was computed over its
        // own AAD, so relabelling only makes verification fail here.
        //
        // A `DBS3` value with no row key in hand is reported as such rather
        // than as a decryption failure — it is a query that did not project the
        // key, not a tampered value.
        let aad = if data.starts_with(MAGIC_V1) {
            id.to_vec()
        } else if data.starts_with(MAGIC_V3) {
            binding.context.aad_with_row(id, binding.row.ok_or(Error::RowKeyMissing)?)
        } else {
            binding.context.aad(id)
        };
        self.gcm
            .decrypt(Nonce::from_slice(nonce), Payload { msg: &data[HEADER_LEN..], aad: &aad })
            .map_err(|_| Error::Decrypt)
    }
}

/// Per-key [`Cipher`] cache over a [`KeySource`]: each key schedule is built
/// once, and every column encrypting under the active DEK shares one invocation
/// budget for it. Build one per process and share it across transforms —
/// a budget counted per column would let N columns spend N × the limit.
pub struct Ciphers {
    keys: Arc<dyn KeySource>,
    budget: u64,
    /// The DEK new values are sealed under, resolved on first use. Both key
    /// sources fix it at startup, so it is re-resolved only once the budget is
    /// spent (see [`Ciphers::seal`]).
    active: RwLock<Option<(KeyId, Arc<Cipher>)>>,
    /// Read-path ciphers by key id. A key id the key source does not know fails
    /// before it reaches this map, so untrusted stored bytes cannot grow it:
    /// its size is bounded by the number of live DEKs.
    by_id: RwLock<HashMap<KeyId, Arc<Cipher>>>,
}

impl Ciphers {
    pub fn new(keys: Arc<dyn KeySource>) -> Self {
        Self::with_budget(keys, MAX_ENCRYPTIONS_PER_KEY)
    }

    /// A cache with a smaller per-key budget, for tests at the boundary.
    pub fn with_budget(keys: Arc<dyn KeySource>, budget: u64) -> Self {
        Self { keys, budget, active: RwLock::new(None), by_id: RwLock::new(HashMap::new()) }
    }

    /// The key source behind this cache, for the deterministic keys transforms
    /// need alongside their DEK.
    pub fn keys(&self) -> &Arc<dyn KeySource> {
        &self.keys
    }

    /// Seals a value destined for `context`'s column under the active DEK. When
    /// that key's invocation budget is spent the key source is asked for a
    /// fresh one; if it offers the same key id, the write fails closed rather
    /// than reusing an exhausted key.
    pub fn seal(&self, binding: &Binding<'_>, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let (key_id, cipher) = self.active()?;
        match cipher.encrypt(&key_id, binding, plaintext) {
            Err(Error::KeyExhausted(_)) => {
                let (key_id, cipher) = self.roll_active(&key_id)?;
                cipher.encrypt(&key_id, binding, plaintext)
            }
            result => result,
        }
    }

    /// Opens an enveloped value read out of `context`'s column, under the DEK
    /// its header names.
    pub fn open(&self, binding: &Binding<'_>, enveloped: &[u8]) -> Result<Vec<u8>, Error> {
        let id = key_id(enveloped)?;
        self.for_id(&id)?.decrypt(binding, enveloped)
    }

    /// Both caches recover from a poisoned lock rather than panicking on it
    /// ([`crate::sync`]): this one is process-wide, so a panic here would fail
    /// every session from then on, and each critical section is a single slot
    /// or map operation whose value is intact either way.
    fn active(&self) -> Result<(KeyId, Arc<Cipher>), Error> {
        if let Some((id, cipher)) = self.active.read().unpoisoned().as_ref() {
            return Ok((*id, cipher.clone()));
        }
        let (id, key) = self.keys.active_key()?;
        let mut slot = self.active.write().unpoisoned();
        let (id, cipher) =
            slot.get_or_insert_with(|| (id, Arc::new(Cipher::with_budget(&key, self.budget))));
        Ok((*id, cipher.clone()))
    }

    fn roll_active(&self, spent: &KeyId) -> Result<(KeyId, Arc<Cipher>), Error> {
        let (id, key) = self.keys.active_key()?;
        if id == *spent {
            return Err(Error::KeyExhausted(hex::encode(spent)));
        }
        let mut slot = self.active.write().unpoisoned();
        // Another thread may have rolled already; its key is just as fresh.
        if let Some((current, cipher)) = slot.as_ref() {
            if current != spent {
                return Ok((*current, cipher.clone()));
            }
        }
        let cipher = Arc::new(Cipher::with_budget(&key, self.budget));
        *slot = Some((id, cipher.clone()));
        Ok((id, cipher))
    }

    fn for_id(&self, id: &KeyId) -> Result<Arc<Cipher>, Error> {
        if let Some(cipher) = self.by_id.read().unpoisoned().get(id) {
            return Ok(cipher.clone());
        }
        let key = self.keys.key(id)?;
        let cipher = Arc::new(Cipher::with_budget(&key, self.budget));
        Ok(self.by_id.write().unpoisoned().entry(*id).or_insert(cipher).clone())
    }
}

/// Encrypts one value for `context`'s column under `key`, with a fresh random
/// nonce.
///
/// The raw primitive: a cipher built for a single call has no history, so it
/// carries no invocation budget. Production write paths go through
/// [`Ciphers::seal`], which enforces [`MAX_ENCRYPTIONS_PER_KEY`] per DEK.
pub fn encrypt(
    key: &[u8; 32],
    key_id: &KeyId,
    binding: &Binding<'_>,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    Cipher::new(key).encrypt(key_id, binding, plaintext)
}

/// Extracts the key id from an enveloped value so the caller can look up the key.
pub fn key_id(data: &[u8]) -> Result<KeyId, Error> {
    if !is_enveloped(data) {
        return Err(Error::Malformed);
    }
    let mut id = [0u8; KEY_ID_LEN];
    id.copy_from_slice(&data[MAGIC.len()..MAGIC.len() + KEY_ID_LEN]);
    Ok(id)
}

/// Decrypts one enveloped value from `context`'s column under `key`.
/// [`Ciphers::open`] is the cached equivalent for values arriving in bulk.
pub fn decrypt(key: &[u8; 32], binding: &Binding<'_>, data: &[u8]) -> Result<Vec<u8>, Error> {
    Cipher::new(key).decrypt(binding, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Key;
    use std::sync::atomic::AtomicU8;

    const KEY: [u8; 32] = [7u8; 32];
    const KEY_ID: KeyId = [1u8; KEY_ID_LEN];

    fn ssn() -> CellContext {
        CellContext::new("public.users.ssn")
    }

    fn credit_card() -> CellContext {
        CellContext::new("public.users.credit_card")
    }

    /// Builds a pre-context `DBS1` envelope the way the previous format did:
    /// key id alone as associated data. Tests read the legacy path with it;
    /// nothing in the crate writes this shape any more.
    fn encrypt_v1(key: &[u8; 32], key_id: &KeyId, plaintext: &[u8]) -> Vec<u8> {
        let gcm = Aes256Gcm::new(key.into());
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ciphertext = gcm
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: key_id })
            .expect("encrypts");
        let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        out.extend_from_slice(MAGIC_V1);
        out.extend_from_slice(key_id);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// A key source stuck on one DEK: it can never roll.
    struct OneKey;

    impl KeySource for OneKey {
        fn active_key(&self) -> Result<(KeyId, Key), Error> {
            Ok((KEY_ID, Key::new(KEY)))
        }
        fn key(&self, id: &KeyId) -> Result<Key, Error> {
            if id == &KEY_ID {
                Ok(Key::new(KEY))
            } else {
                Err(Error::UnknownKey(hex::encode(id)))
            }
        }
        fn index_key(&self, name: &str) -> Result<Key, Error> {
            Err(Error::UnknownKey(name.to_owned()))
        }
    }

    /// A key source that mints a new DEK every time it is asked for the active
    /// one — the rotating counterpart of `OneKey`.
    #[derive(Default)]
    struct RollingKeys {
        next: AtomicU8,
    }

    impl KeySource for RollingKeys {
        fn active_key(&self) -> Result<(KeyId, Key), Error> {
            let n = self.next.fetch_add(1, Ordering::Relaxed);
            Ok(([n; KEY_ID_LEN], Key::new([n; 32])))
        }
        fn key(&self, id: &KeyId) -> Result<Key, Error> {
            Ok(Key::new([id[0]; 32]))
        }
        fn index_key(&self, name: &str) -> Result<Key, Error> {
            Err(Error::UnknownKey(name.to_owned()))
        }
    }

    #[test]
    fn roundtrip() {
        let ct = encrypt(&KEY, &KEY_ID, &Binding::cell(&ssn()), b"secret").unwrap();
        assert!(is_enveloped(&ct));
        assert!(ct.starts_with(MAGIC), "new writes carry the current version");
        assert_eq!(key_id(&ct).unwrap(), KEY_ID);
        assert_eq!(decrypt(&KEY, &Binding::cell(&ssn()), &ct).unwrap(), b"secret");
    }

    fn row(id: &str) -> RowKey {
        RowKey::new(id.as_bytes())
    }

    /// The finding this version exists for: the same column, a different row.
    #[test]
    fn a_value_never_opens_in_another_row() {
        let ct = encrypt(&KEY, &KEY_ID, &Binding::row(&ssn(), &row("42")), b"secret").unwrap();
        assert!(ct.starts_with(MAGIC_V3), "a row-bound write carries DBS3");
        assert_eq!(decrypt(&KEY, &Binding::row(&ssn(), &row("42")), &ct).unwrap(), b"secret");
        assert!(
            matches!(decrypt(&KEY, &Binding::row(&ssn(), &row("43")), &ct), Err(Error::Decrypt)),
            "a ciphertext pasted into another row must not authenticate"
        );
    }

    /// A row-bound value reaching the opener with no key is a query that did
    /// not project it, not a tampered value, and the two want different
    /// operator responses.
    #[test]
    fn a_row_bound_value_without_its_key_is_reported_as_such() {
        let ct = encrypt(&KEY, &KEY_ID, &Binding::row(&ssn(), &row("42")), b"secret").unwrap();
        assert!(matches!(decrypt(&KEY, &Binding::cell(&ssn()), &ct), Err(Error::RowKeyMissing)));
    }

    /// Length-prefixing the AAD's variable fields is load-bearing, not tidiness.
    /// Concatenated, `column="a.b.c" + row="42"` and `column="a.b.c4" + row="2"`
    /// are the same bytes — and the row key is usually the attacker's own row
    /// id, so they could pick one that straddles the seam and move a value into
    /// a cell it was never written for.
    #[test]
    fn the_aad_cannot_be_re_split_between_column_and_row() {
        let short = CellContext::new("a.b.c");
        let long = CellContext::new("a.b.c4");
        let ct = encrypt(&KEY, &KEY_ID, &Binding::row(&short, &row("42")), b"secret").unwrap();
        assert!(
            matches!(decrypt(&KEY, &Binding::row(&long, &row("2")), &ct), Err(Error::Decrypt)),
            "column and row must not be re-splittable across the seam"
        );
    }

    /// Older values keep opening after a table gains a row key, and relabelling
    /// a header to an earlier version downgrades nothing — each tag was
    /// computed over its own AAD.
    #[test]
    fn versions_do_not_downgrade_into_each_other() {
        let bound = encrypt(&KEY, &KEY_ID, &Binding::row(&ssn(), &row("42")), b"secret").unwrap();
        let cell = encrypt(&KEY, &KEY_ID, &Binding::cell(&ssn()), b"secret").unwrap();
        assert_eq!(decrypt(&KEY, &Binding::cell(&ssn()), &cell).unwrap(), b"secret");

        let mut downgraded = bound.clone();
        downgraded[..MAGIC.len()].copy_from_slice(MAGIC);
        assert!(matches!(decrypt(&KEY, &Binding::cell(&ssn()), &downgraded), Err(Error::Decrypt)));

        let mut upgraded = cell.clone();
        upgraded[..MAGIC.len()].copy_from_slice(MAGIC_V3);
        assert!(matches!(
            decrypt(&KEY, &Binding::row(&ssn(), &row("42")), &upgraded),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn tampering_is_detected() {
        let mut ct = encrypt(&KEY, &KEY_ID, &Binding::cell(&ssn()), b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xff;
        assert!(matches!(decrypt(&KEY, &Binding::cell(&ssn()), &ct), Err(Error::Decrypt)));
    }

    #[test]
    fn wrong_key_fails() {
        let ct = encrypt(&KEY, &KEY_ID, &Binding::cell(&ssn()), b"secret").unwrap();
        assert!(matches!(decrypt(&[8u8; 32], &Binding::cell(&ssn()), &ct), Err(Error::Decrypt)));
    }

    #[test]
    fn plaintext_passes_through_detection() {
        assert!(!is_enveloped(b"just a plain value"));
        assert!(matches!(decrypt(&KEY, &Binding::cell(&ssn()), b"plain"), Err(Error::Malformed)));
    }

    /// The relocation attack the context binding exists to stop: stored bytes
    /// copied into another column of the same row, under the very same DEK.
    #[test]
    fn a_ciphertext_moved_to_another_column_fails_authentication() {
        let stored = encrypt(&KEY, &KEY_ID, &Binding::cell(&ssn()), b"078-05-1120").unwrap();

        assert!(
            matches!(decrypt(&KEY, &Binding::cell(&credit_card()), &stored), Err(Error::Decrypt)),
            "the same key must not open an ssn blob pasted into credit_card"
        );
        assert!(
            matches!(
                decrypt(&KEY, &Binding::cell(&CellContext::new("public.audit.ssn")), &stored),
                Err(Error::Decrypt)
            ),
            "nor the same column name in another table"
        );
        assert_eq!(decrypt(&KEY, &Binding::cell(&ssn()), &stored).unwrap(), b"078-05-1120");
    }

    /// Cross-column relocation is caught through the cached path too, not only
    /// through the raw primitive.
    #[test]
    fn ciphers_reject_a_value_opened_under_another_column() {
        let ciphers = Ciphers::new(Arc::new(OneKey));
        let stored = ciphers.seal(&Binding::cell(&ssn()), b"078-05-1120").unwrap();

        assert!(matches!(
            ciphers.open(&Binding::cell(&credit_card()), &stored),
            Err(Error::Decrypt)
        ));
        assert_eq!(ciphers.open(&Binding::cell(&ssn()), &stored).unwrap(), b"078-05-1120");
    }

    /// Rows written before the context binding keep opening, so an upgrade
    /// needs no migration step to stay readable.
    #[test]
    fn legacy_envelopes_still_open_under_any_context() {
        let legacy = encrypt_v1(&KEY, &KEY_ID, b"secret");

        assert!(is_enveloped(&legacy));
        assert_eq!(key_id(&legacy).unwrap(), KEY_ID);
        assert_eq!(decrypt(&KEY, &Binding::cell(&ssn()), &legacy).unwrap(), b"secret");
        // Which is exactly the exposure re-encryption closes: the old format
        // binds no column, so it opens wherever the DEK reaches.
        assert_eq!(decrypt(&KEY, &Binding::cell(&credit_card()), &legacy).unwrap(), b"secret");
    }

    /// Relabelling a current envelope as the pre-context version does not strip
    /// its binding — the tag was computed over the longer associated data.
    #[test]
    fn downgrading_the_header_to_the_legacy_version_fails() {
        let mut stored = encrypt(&KEY, &KEY_ID, &Binding::cell(&ssn()), b"secret").unwrap();
        stored[..MAGIC.len()].copy_from_slice(MAGIC_V1);

        assert!(matches!(decrypt(&KEY, &Binding::cell(&ssn()), &stored), Err(Error::Decrypt)));
        assert!(matches!(
            decrypt(&KEY, &Binding::cell(&credit_card()), &stored),
            Err(Error::Decrypt)
        ));
    }

    /// The DEK bytes are `Zeroizing`, but `Aes256Gcm::new` expands them into a
    /// round-key schedule in an allocation of its own — and the original key is
    /// recoverable from that schedule. When a spent DEK rolls, the old
    /// [`Cipher`] drops and the schedule would otherwise be freed intact.
    ///
    /// `aes`'s `zeroize` feature (enabled in the workspace manifest) is what
    /// wipes it. `aes-gcm` has no feature of its own for this and builds its
    /// cipher out of `aes` — `Aes256Gcm` is `AesGcm<Aes256, U12>` and holds
    /// exactly the type asserted on below — so the assertion stops compiling
    /// if the feature is ever dropped.
    #[test]
    fn the_aes_key_schedule_is_wiped_when_a_cipher_drops() {
        fn assert_wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_wiped_on_drop::<aes::Aes256>();

        // And the schedule is inside the value that drops: rolling to a fresh
        // key replaces the whole `Cipher`, so nothing outlives the drop.
        let ciphers = Ciphers::with_budget(Arc::new(RollingKeys::default()), 1);
        let first = key_id(&ciphers.seal(&Binding::cell(&ssn()), b"one").unwrap()).unwrap();
        let second = key_id(&ciphers.seal(&Binding::cell(&ssn()), b"two").unwrap()).unwrap();
        assert_ne!(first, second, "the spent cipher was dropped, not reused");
    }

    #[test]
    fn invocation_budget_is_spent_exactly_once_per_encryption() {
        let cipher = Cipher::with_budget(&KEY, 2);
        assert_eq!(cipher.remaining(), 2);
        let ct = cipher.encrypt(&KEY_ID, &Binding::cell(&ssn()), b"one").unwrap();
        assert_eq!(cipher.remaining(), 1);
        cipher.encrypt(&KEY_ID, &Binding::cell(&ssn()), b"two").unwrap();
        assert_eq!(cipher.remaining(), 0);

        // At the boundary the key is retired rather than reused.
        assert!(matches!(
            cipher.encrypt(&KEY_ID, &Binding::cell(&ssn()), b"three"),
            Err(Error::KeyExhausted(_))
        ));
        assert!(matches!(
            cipher.encrypt(&KEY_ID, &Binding::cell(&ssn()), b"four"),
            Err(Error::KeyExhausted(_))
        ));
        // Reading is not rationed: only encryption draws nonces.
        assert_eq!(cipher.decrypt(&Binding::cell(&ssn()), &ct).unwrap(), b"one");
    }

    #[test]
    fn spent_budget_rolls_to_a_fresh_dek() {
        let ciphers = Ciphers::with_budget(Arc::new(RollingKeys::default()), 1);
        let first = ciphers.seal(&Binding::cell(&ssn()), b"one").unwrap();
        let second = ciphers.seal(&Binding::cell(&ssn()), b"two").unwrap();
        assert_ne!(key_id(&first).unwrap(), key_id(&second).unwrap());
        assert_eq!(ciphers.open(&Binding::cell(&ssn()), &first).unwrap(), b"one");
        assert_eq!(ciphers.open(&Binding::cell(&ssn()), &second).unwrap(), b"two");
    }

    #[test]
    fn spent_budget_fails_closed_when_the_key_source_cannot_roll() {
        let ciphers = Ciphers::with_budget(Arc::new(OneKey), 1);
        ciphers.seal(&Binding::cell(&ssn()), b"one").unwrap();
        assert!(matches!(
            ciphers.seal(&Binding::cell(&ssn()), b"two"),
            Err(Error::KeyExhausted(_))
        ));
    }

    #[test]
    fn ciphers_open_rejects_unknown_key_ids() {
        let ciphers = Ciphers::new(Arc::new(OneKey));
        let foreign = encrypt(&KEY, &[9u8; KEY_ID_LEN], &Binding::cell(&ssn()), b"secret").unwrap();
        assert!(matches!(
            ciphers.open(&Binding::cell(&ssn()), &foreign),
            Err(Error::UnknownKey(_))
        ));
        assert!(matches!(ciphers.open(&Binding::cell(&ssn()), b"plain"), Err(Error::Malformed)));
    }

    #[test]
    fn ciphers_reuse_one_instance_per_key_id() {
        let ciphers = Ciphers::new(Arc::new(OneKey));
        let sealed = ciphers.seal(&Binding::cell(&ssn()), b"secret").unwrap();
        assert_eq!(ciphers.open(&Binding::cell(&ssn()), &sealed).unwrap(), b"secret");
        assert_eq!(ciphers.open(&Binding::cell(&ssn()), &sealed).unwrap(), b"secret");
        assert_eq!(ciphers.by_id.read().unpoisoned().len(), 1);
    }

    /// `Ciphers` is process-wide, so panicking on a poisoned lock would fail
    /// every session from then on rather than the one that tripped it. Both
    /// caches recover instead ([`crate::sync`]), and what they hand back is
    /// what the panicking thread left — a single slot or map operation that
    /// cannot be half-applied.
    #[test]
    fn a_poisoned_cache_keeps_serving() {
        let ciphers = Arc::new(Ciphers::new(Arc::new(OneKey)));
        let sealed = ciphers.seal(&Binding::cell(&ssn()), b"secret").unwrap();
        // Populates `by_id` too, so both locks are holding real state.
        assert_eq!(ciphers.open(&Binding::cell(&ssn()), &sealed).unwrap(), b"secret");

        let poisoner = Arc::clone(&ciphers);
        let panicked = std::thread::spawn(move || {
            let _active = poisoner.active.write().unpoisoned();
            let _by_id = poisoner.by_id.write().unpoisoned();
            panic!("a session task panicked while holding the cache locks");
        })
        .join();
        assert!(panicked.is_err(), "the helper thread has to have panicked");
        assert!(ciphers.active.is_poisoned() && ciphers.by_id.is_poisoned());

        // Every path a live session takes still works.
        assert_eq!(ciphers.open(&Binding::cell(&ssn()), &sealed).unwrap(), b"secret");
        let again = ciphers.seal(&Binding::cell(&ssn()), b"another").unwrap();
        assert_eq!(ciphers.open(&Binding::cell(&ssn()), &again).unwrap(), b"another");
    }
}
