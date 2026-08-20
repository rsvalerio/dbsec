//! Key material access. Transforms obtain keys through [`KeySource`]; an
//! application supplies its own implementation over its KMS (the `dbsec`
//! proxy's Vault/OpenBao source is one), and [`FileKeySource`] — behind the
//! `keyfile` feature — exists for development and tests.

#[cfg(feature = "keyfile")]
use std::collections::HashMap;
use std::path::Path;

#[cfg(feature = "keyfile")]
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::envelope::KeyId;
#[cfg(feature = "keyfile")]
use crate::envelope::KEY_ID_LEN;
use crate::Error;

/// 32 bytes of live key material: a DEK, or one of the deterministic index
/// keys.
///
/// A newtype over `Zeroizing<[u8; 32]>` rather than an alias for it, purely so
/// it cannot be printed. `Zeroizing` derives `Debug`, so with an alias a stray
/// `?key` in a `tracing` call — or a `#[derive(Debug)]` on any struct that
/// happens to hold one — compiles silently and writes raw key bytes into a log.
/// No production site does that today; this is what makes it impossible to
/// start. The rest of the crate's secret-bearing types (`Secret`,
/// `IndexKeyRecord`, `TlsContext`) already hand-write a redacting `Debug`, and
/// this is the same treatment for the one type that was missing it.
///
/// [`Deref`](std::ops::Deref) gives back the bytes, so the key is as usable as
/// the alias was — the redaction covers formatting, not access.
#[derive(Clone)]
pub struct Key(Zeroizing<[u8; 32]>);

impl Key {
    /// Wraps 32 bytes of key material; they are wiped when the `Key` drops.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// Redacted rather than derived: see [`Key`].
impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

impl std::ops::Deref for Key {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &*self.0
    }
}

impl From<Zeroizing<[u8; 32]>> for Key {
    fn from(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }
}

/// Where keys come from: the active DEK for new envelopes, any DEK by id for
/// stored ones, and the named deterministic keys.
///
/// Synchronous by design — see the crate docs. An implementation that reaches
/// a KMS over the network should cache, so that only a cold miss or a rotation
/// touches the wire.
pub trait KeySource: Send + Sync {
    /// The DEK new envelopes are encrypted under, with the id stamped into them.
    fn active_key(&self) -> Result<(KeyId, Key), Error>;
    /// The DEK for a given envelope key id (decrypt path).
    fn key(&self, id: &KeyId) -> Result<Key, Error>;
    /// A named deterministic key (blind index, FPE, HMAC tokens). These never
    /// rotate freely — rotating one breaks determinism (see plans/PLAN.md).
    fn index_key(&self, name: &str) -> Result<Key, Error>;
}

/// Refuses a secret-bearing file that anyone but its owner can read.
///
/// Mode `0600` or tighter, on unix. Group-readable is not a safe exception: a
/// process that reads its own key at startup shares it with nobody, and a
/// group-readable copy hands every local member the ability to impersonate it.
/// A deployment that must share a key should give the other service its own
/// `0600` copy.
///
/// A file that cannot be stat'ed is left alone: the read that follows reports
/// the real I/O error with its path, which is a better message than anything
/// this check could invent for a path that may not exist yet. `holds` names
/// the credential in the refusal ("every master key", "the Vault token") so
/// the message says why the file is a secret.
///
/// Non-unix targets have no `st_mode` to inspect, so the check is a documented
/// no-op there; secret-file permissions are the deployment's responsibility.
pub fn check_secret_file_mode(path: &Path, holds: &str) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let Ok(metadata) = std::fs::metadata(path) else {
            return Ok(());
        };
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(Error::SecretFileMode(format!(
                "{} is readable beyond its owner (mode {:04o}); it holds {holds} — chmod 600 {}",
                path.display(),
                mode & 0o7777,
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = (path, holds);
    Ok(())
}

/// Dev/test key source backed by a flat TOML file (`keyfile` feature):
///
/// ```toml
/// active = "00112233445566778899aabbccddeeff"
///
/// [keys]
/// 00112233445566778899aabbccddeeff = "<64 hex chars>"
///
/// [index_keys]
/// email = "<64 hex chars>"
/// ```
#[cfg(feature = "keyfile")]
pub struct FileKeySource {
    active: KeyId,
    keys: HashMap<KeyId, Key>,
    index_keys: HashMap<String, Key>,
}

/// The parsed keyfile. Every value in `keys` and `index_keys` is 64 hex
/// characters of live key material in its own heap allocation, so the struct
/// wipes them in [`Drop`] rather than letting them be freed intact — the
/// `Zeroizing<[u8; 32]>` on the decoded copy buys little while two plaintext
/// copies of every key outlive it.
///
/// Erasure is best-effort by construction: `toml` builds its own intermediate
/// buffers while parsing, and this crate can neither name nor reach them. The
/// goal is to remove the copies it does own.
#[cfg(feature = "keyfile")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    /// A key *id*, not key material — left in the clear so it can still be
    /// named in an error message.
    active: String,
    keys: HashMap<String, String>,
    #[serde(default)]
    index_keys: HashMap<String, String>,
}

#[cfg(feature = "keyfile")]
impl Drop for KeyFile {
    fn drop(&mut self) {
        for hex_key in self.keys.values_mut().chain(self.index_keys.values_mut()) {
            hex_key.zeroize();
        }
    }
}

#[cfg(feature = "keyfile")]
impl FileKeySource {
    /// Reads and validates a keyfile. The caller is responsible for the
    /// file's permissions; the proxy refuses one that is not mode 0600.
    pub fn load(path: &Path) -> Result<Self, Error> {
        // The whole file is every DEK and every deterministic index key in
        // plaintext hex, so it is held in a buffer that is wiped when it
        // drops rather than in a bare `String`.
        let raw = Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|source| Error::KeyFileRead { path: path.to_path_buf(), source })?,
        );
        let parsed: KeyFile = toml::from_str(&raw)
            .map_err(|source| Error::KeyFileParse { path: path.to_path_buf(), source })?;

        let mut keys = HashMap::new();
        for (id_hex, key_hex) in &parsed.keys {
            keys.insert(decode::<KEY_ID_LEN>(id_hex, "key id")?, decode_key(key_hex)?);
        }
        let mut index_keys = HashMap::new();
        for (name, key_hex) in &parsed.index_keys {
            index_keys.insert(name.clone(), decode_key(key_hex)?);
        }
        let active = decode::<KEY_ID_LEN>(&parsed.active, "active key id")?;
        if !keys.contains_key(&active) {
            return Err(Error::KeySource(format!(
                "active key id {} not present in [keys]",
                parsed.active
            )));
        }
        Ok(Self { active, keys, index_keys })
    }

    /// Writes a fresh keyfile with one active DEK (mode 0600 on unix).
    /// Fails if `path` already exists — never overwrites key material.
    pub fn generate(path: &Path) -> Result<(), Error> {
        use rand::RngCore;
        // The OS entropy source rather than `thread_rng` (SEC-10): this is the
        // master key for everything the product protects, and `ThreadRng`
        // would interpose a userspace generator state — the state that
        // survives `fork()` and that reseeding bugs live in — between the OS
        // and a long-lived key. `try_fill_bytes` rather than `fill_bytes` so a
        // refusing entropy source is an error, not a panic.
        let mut id = [0u8; KEY_ID_LEN];
        rand::rngs::OsRng.try_fill_bytes(&mut id)?;
        let mut key = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.try_fill_bytes(key.as_mut())?;

        // Appended into one pre-sized zeroizing buffer. `hex::encode` would
        // return the key as a plain `String` that nothing wipes, and a
        // `format!` that outgrows its buffer leaves what it already wrote in a
        // freed allocation. The capacity below is exact, so no reallocation
        // happens mid-build either.
        const TEMPLATE: &str = "active = \"\"\n\n[keys]\n = \"\"\n";
        let mut contents =
            Zeroizing::new(String::with_capacity(TEMPLATE.len() + KEY_ID_LEN * 4 + 64));
        contents.push_str("active = \"");
        push_hex(&mut contents, &id);
        contents.push_str("\"\n\n[keys]\n");
        push_hex(&mut contents, &id);
        contents.push_str(" = \"");
        push_hex(&mut contents, key.as_ref());
        contents.push_str("\"\n");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options
            .open(path)
            .map_err(|source| Error::KeyFileWrite { path: path.to_path_buf(), source })?;
        std::io::Write::write_all(&mut file, contents.as_bytes())
            .map_err(|source| Error::KeyFileWrite { path: path.to_path_buf(), source })?;
        Ok(())
    }
}

#[cfg(feature = "keyfile")]
impl KeySource for FileKeySource {
    fn active_key(&self) -> Result<(KeyId, Key), Error> {
        Ok((self.active, self.keys[&self.active].clone()))
    }

    fn key(&self, id: &KeyId) -> Result<Key, Error> {
        self.keys.get(id).cloned().ok_or_else(|| Error::UnknownKey(hex::encode(id)))
    }

    fn index_key(&self, name: &str) -> Result<Key, Error> {
        self.index_keys.get(name).cloned().ok_or_else(|| Error::UnknownKey(name.to_owned()))
    }
}

#[cfg(feature = "keyfile")]
fn decode<const N: usize>(hex_str: &str, what: &str) -> Result<[u8; N], Error> {
    let mut raw =
        hex::decode(hex_str).map_err(|_| Error::KeySource(format!("{what} is not valid hex")))?;
    let result = <[u8; N]>::try_from(raw.as_slice())
        .map_err(|_| Error::KeySource(format!("{what} must be {N} bytes ({} hex chars)", N * 2)));
    raw.zeroize();
    result
}

#[cfg(feature = "keyfile")]
fn decode_key(hex_str: &str) -> Result<Key, Error> {
    decode::<32>(hex_str, "key").map(Key::new)
}

/// Appends `bytes` as lowercase hex straight into `out`. `hex::encode` would
/// hand back key material in a fresh `String` that nothing wipes; this writes
/// it into the caller's zeroizing buffer instead.
#[cfg(feature = "keyfile")]
fn push_hex(out: &mut String, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for &byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
}

#[cfg(all(test, feature = "keyfile"))]
mod tests {
    use super::*;

    const KEYFILE: &str = "\
active = \"00112233445566778899aabbccddeeff\"

[keys]
00112233445566778899aabbccddeeff = \"0707070707070707070707070707070707070707070707070707070707070707\"

[index_keys]
email = \"0303030303030303030303030303030303030303030303030303030303030303\"
";

    fn write_keyfile(contents: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("keys.toml"), contents).unwrap();
        dir
    }

    /// A stray `?key` in a `tracing` call must not be able to write key bytes
    /// into a log line. `Zeroizing` derives `Debug`, so before the newtype this
    /// compiled and printed all 32 bytes.
    #[test]
    fn debugging_a_key_never_prints_its_bytes() {
        let key = Key::new([7u8; 32]);
        let rendered = format!("{key:?}");

        assert!(!rendered.contains('7'), "key material must not reach a log line: {rendered}");
        assert!(rendered.contains("redacted"), "and the redaction is legible: {rendered}");
        // The bytes are still reachable — the redaction is on formatting only.
        assert_eq!(*key, [7u8; 32]);
    }

    /// The other half: a struct that holds a `Key` can derive `Debug` — the
    /// thing that silently leaks with a `Zeroizing` alias — without exposing
    /// anything.
    #[test]
    fn a_struct_holding_a_key_can_derive_debug_safely() {
        #[derive(Debug)]
        struct Holder {
            name: &'static str,
            key: Key,
        }

        let holder = Holder { name: "public.users.email", key: Key::new([9u8; 32]) };
        let rendered = format!("{holder:?}");

        assert!(rendered.contains(holder.name), "non-secret fields still print");
        assert!(!rendered.contains('9'), "the key does not: {rendered}");
        assert_eq!(*holder.key, [9u8; 32], "and the field is still usable");
    }

    #[test]
    fn loads_and_serves_keys() {
        let dir = write_keyfile(KEYFILE);
        let source = FileKeySource::load(&dir.path().join("keys.toml")).unwrap();

        let (id, key) = source.active_key().unwrap();
        assert_eq!(hex::encode(id), "00112233445566778899aabbccddeeff");
        assert_eq!(*key, [7u8; 32]);
        assert_eq!(*source.key(&id).unwrap(), [7u8; 32]);
        assert_eq!(*source.index_key("email").unwrap(), [3u8; 32]);

        assert!(matches!(source.key(&[9u8; KEY_ID_LEN]), Err(Error::UnknownKey(_))));
        assert!(matches!(source.index_key("ssn"), Err(Error::UnknownKey(_))));
    }

    #[test]
    fn rejects_active_id_missing_from_keys() {
        let dir = write_keyfile(
            "active = \"ffffffffffffffffffffffffffffffff\"\n\n[keys]\n00112233445566778899aabbccddeeff = \"0707070707070707070707070707070707070707070707070707070707070707\"\n",
        );
        assert!(matches!(
            FileKeySource::load(&dir.path().join("keys.toml")),
            Err(Error::KeySource(_))
        ));
    }

    #[test]
    fn rejects_wrong_length_key_material() {
        let dir = write_keyfile("active = \"0011\"\n\n[keys]\n0011 = \"0707\"\n");
        assert!(matches!(
            FileKeySource::load(&dir.path().join("keys.toml")),
            Err(Error::KeySource(_))
        ));
    }

    #[test]
    fn missing_keyfile_keeps_the_io_error_as_a_cause() {
        let dir = tempfile::tempdir().unwrap();
        let Err(err) = FileKeySource::load(&dir.path().join("absent.toml")) else {
            panic!("loading a missing keyfile must fail");
        };
        let Error::KeyFileRead { path, source } = &err else {
            panic!("expected KeyFileRead, got {err:?}");
        };
        // The operator needs "missing" told apart from "unreadable".
        assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
        assert!(path.ends_with("absent.toml"));
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn malformed_keyfile_keeps_the_toml_error_as_a_cause() {
        let dir = write_keyfile("active = \n");
        let Err(err) = FileKeySource::load(&dir.path().join("keys.toml")) else {
            panic!("loading a malformed keyfile must fail");
        };
        let Error::KeyFileParse { source, .. } = &err else {
            panic!("expected KeyFileParse, got {err:?}");
        };
        // toml's span survives, so a caller can point at the offending line.
        assert!(source.span().is_some());
        assert!(std::error::Error::source(&err).is_some());
    }

    /// `generate` hand-rolls hex so key material never lands in an
    /// intermediate `String`; this pins it against the crate everyone else
    /// uses.
    #[test]
    fn push_hex_matches_hex_encode() {
        let mut out = String::new();
        push_hex(&mut out, &[0x00, 0x0f, 0xa5, 0xff]);
        assert_eq!(out, hex::encode([0x00, 0x0f, 0xa5, 0xffu8]));

        let mut empty = String::new();
        push_hex(&mut empty, &[]);
        assert!(empty.is_empty());
    }

    /// The buffer `generate` writes into is sized up front so it cannot
    /// reallocate mid-build and strand a partial copy of the key in a freed
    /// allocation.
    #[test]
    fn generated_keyfile_fits_the_buffer_it_was_written_into() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.toml");
        FileKeySource::generate(&path).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        const TEMPLATE: &str = "active = \"\"\n\n[keys]\n = \"\"\n";
        assert_eq!(written.len(), TEMPLATE.len() + KEY_ID_LEN * 4 + 64);
    }

    #[test]
    fn generate_produces_loadable_keyfile_without_overwriting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.toml");
        FileKeySource::generate(&path).unwrap();
        let source = FileKeySource::load(&path).unwrap();
        let (id, key) = source.active_key().unwrap();
        assert_eq!(*source.key(&id).unwrap(), *key);

        assert!(FileKeySource::generate(&path).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
