//! Key material access. Transforms obtain keys through `KeySource`; the
//! Vault/OpenBao implementation arrives in milestone 9. `FileKeySource`
//! exists for development and tests.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use crate::envelope::{KeyId, KEY_ID_LEN};
use crate::Error;

pub type Key = Zeroizing<[u8; 32]>;

pub trait KeySource: Send + Sync {
    /// The DEK new envelopes are encrypted under, with the id stamped into them.
    fn active_key(&self) -> Result<(KeyId, Key), Error>;
    /// The DEK for a given envelope key id (decrypt path).
    fn key(&self, id: &KeyId) -> Result<Key, Error>;
    /// A named deterministic key (blind index, FPE, HMAC tokens). These never
    /// rotate freely — rotating one breaks determinism (see plans/PLAN.md).
    fn index_key(&self, name: &str) -> Result<Key, Error>;
}

/// Dev/test key source backed by a flat TOML file:
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
pub struct FileKeySource {
    active: KeyId,
    keys: HashMap<KeyId, Key>,
    index_keys: HashMap<String, Key>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    active: String,
    keys: HashMap<String, String>,
    #[serde(default)]
    index_keys: HashMap<String, String>,
}

impl FileKeySource {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::KeySource(format!("reading {}: {e}", path.display())))?;
        let parsed: KeyFile = toml::from_str(&raw)
            .map_err(|e| Error::KeySource(format!("parsing {}: {e}", path.display())))?;

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
        let mut id = [0u8; KEY_ID_LEN];
        rand::thread_rng().fill_bytes(&mut id);
        let mut key = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(key.as_mut());

        let contents = Zeroizing::new(format!(
            "active = \"{id}\"\n\n[keys]\n{id} = \"{key}\"\n",
            id = hex::encode(id),
            key = hex::encode(key.as_ref()),
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options
            .open(path)
            .map_err(|e| Error::KeySource(format!("creating {}: {e}", path.display())))?;
        std::io::Write::write_all(&mut file, contents.as_bytes())
            .map_err(|e| Error::KeySource(format!("writing {}: {e}", path.display())))?;
        Ok(())
    }
}

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

fn decode<const N: usize>(hex_str: &str, what: &str) -> Result<[u8; N], Error> {
    let mut raw =
        hex::decode(hex_str).map_err(|_| Error::KeySource(format!("{what} is not valid hex")))?;
    let result = <[u8; N]>::try_from(raw.as_slice())
        .map_err(|_| Error::KeySource(format!("{what} must be {N} bytes ({} hex chars)", N * 2)));
    raw.zeroize();
    result
}

fn decode_key(hex_str: &str) -> Result<Key, Error> {
    decode::<32>(hex_str, "key").map(Zeroizing::new)
}

#[cfg(test)]
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
