//! Flat TOML configuration: addresses, optional TLS for each hop, the keyfile,
//! `[[column]]` entries naming the protected columns, and `on_unprotected`,
//! the switch that decides what happens when a statement cannot be protected.
//!
//! # Operating assumptions this file encodes
//!
//! - **`search_path`.** A `[[column]]` table without a schema means `public`,
//!   and the write path resolves unqualified SQL names the same way. A session
//!   that points `search_path` somewhere else breaks that equivalence in both
//!   directions — an unqualified write can miss the catalog (plaintext at
//!   rest) or match the wrong table (sealed for a table the read path never
//!   resolves). The proxy therefore watches the startup packet and `SET
//!   search_path` for changes, and stops resolving unqualified names once the
//!   default no longer holds; `on_unprotected` decides whether that is a
//!   warning or a refusal. Schema-qualifying either the config or the SQL
//!   sidesteps the question entirely.
//! - **`COPY`.** A `COPY ... FROM` payload arrives as a `CopyData` stream the
//!   proxy does not parse, so a bulk load into a protected table stores
//!   plaintext; `COPY ... TO` bypasses the read path, so a masked column
//!   leaves as its unmasked stored value. Both are `on_unprotected` sites.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Error;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address the proxy listens on for client connections.
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Address of the real PostgreSQL server.
    #[serde(default = "default_upstream")]
    pub upstream: String,
    /// TOML keyfile for `FileKeySource` (see `dbsec_core::keys`). Columns
    /// require either this or `[vault]`.
    pub keys_file: Option<PathBuf>,
    /// OpenBao/Vault key source (Transit-wrapped DEKs + KV index keys).
    pub vault: Option<VaultConfig>,
    /// DSN for the startup control connection that resolves configured
    /// columns to table OID + attnum. Required when any `[[column]]` is
    /// configured, e.g. `postgres://dbsec:secret@127.0.0.1:5432/app`.
    pub control_dsn: Option<String>,
    /// Deadline for the client-controlled startup phase: the first read, the
    /// downstream TLS handshake, the upstream connection, and forwarding the
    /// startup message. A client that stalls any of them is dropped here
    /// rather than holding a task and two sockets indefinitely.
    #[serde(default = "default_startup_timeout_secs")]
    pub startup_timeout_secs: u64,
    /// Maximum number of concurrent client sessions. Connections arriving
    /// while the limit is reached are refused immediately; the default keeps
    /// worst-case descriptor use (two sockets per session plus one upstream
    /// backend connection) well inside a 1024 `ulimit -n`.
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    #[serde(default)]
    pub tls: TlsSection,
    /// What to do with a statement the proxy cannot protect — see
    /// [`OnUnprotected`].
    #[serde(default)]
    pub on_unprotected: OnUnprotected,
    #[serde(default, rename = "column")]
    pub columns: Vec<ColumnConfig>,
}

/// What the proxy does when a statement touches a protected column but the
/// rewrite cannot cover it: an `INSERT` whose values are not literals, a
/// `COPY`, an upsert branch, SQL that does not parse, a session whose
/// `search_path` no longer makes the catalog's schema the right answer.
///
/// The default is [`OnUnprotected::Warn`], which is fail-*open*: the statement
/// runs and the plaintext lands in the column. It is the default only because
/// the alternative refuses statements that work today — including SQL that
/// sqlparser cannot parse but PostgreSQL can, whether or not it touches a
/// protected table. A deployment that needs the "a protected column is never
/// at rest in plaintext" invariant actually enforced sets
/// `on_unprotected = "reject"` and treats the warnings it sees first as the
/// list of statements to fix.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnUnprotected {
    /// Log `tracing::warn!` and relay the statement unchanged.
    #[default]
    Warn,
    /// Refuse the statement with a PostgreSQL ErrorResponse. Nothing reaches
    /// the server and the session stays usable.
    Reject,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColumnConfig {
    /// Table name, optionally schema-qualified; bare names mean `public`.
    pub table: String,
    /// Column name within the table.
    pub column: String,
    #[serde(default)]
    pub transform: TransformKind,
    /// Searchable columns carry a blind index before the envelope (stripped
    /// on read; equality rewrite arrives with the searchable milestone).
    /// Only valid with `transform = "encrypt"`.
    #[serde(default)]
    pub searchable: bool,
    /// Whether FPE values are detokenized on the read path. Only meaningful
    /// for `transform = "fpe"`; tokens are irreversible, envelopes always
    /// decrypt.
    #[serde(default = "default_true")]
    pub detokenize: bool,
    /// Read-path mask applied after decryption/detokenization, e.g.
    /// `mask = { keep_last = 4 }`.
    pub mask: Option<dbsec_core::mask::MaskSpec>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransformKind {
    /// AES-256-GCM envelope, stored as BYTEA.
    #[default]
    Encrypt,
    /// FF1 format-preserving encryption over decimal digits, stored in the
    /// column's original text shape.
    Fpe,
    /// Irreversible deterministic HMAC token (hex), stored as text.
    Token,
    /// No crypto — writes pass through untouched. Only valid together with
    /// `mask`, for columns that should be masked but stay plaintext at rest.
    None,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    /// e.g. `https://bao.internal:8200`.
    pub addr: String,
    /// Static token; prefer `token_file` outside of dev.
    pub token: Option<String>,
    /// File containing the token (e.g. written by an agent sidecar).
    pub token_file: Option<PathBuf>,
    /// KV v2 mount holding wrapped DEKs and index keys.
    #[serde(default = "default_vault_mount")]
    pub mount: String,
    /// Base path within the mount.
    #[serde(default = "default_vault_path")]
    pub path: String,
    /// Transit mount used to wrap/unwrap DEKs.
    #[serde(default = "default_transit_mount")]
    pub transit_mount: String,
    /// Transit key name the DEK envelope is encrypted under.
    #[serde(default = "default_vault_path")]
    pub transit_key: String,
    /// Timeout for each Vault request, and the budget for one key lookup made
    /// from the relay path. Unset, `vaultrs` leaves the HTTP client with no
    /// timeout at all, so a Vault that accepts the connection and then stops
    /// answering would park a runtime worker for the life of the process.
    #[serde(default = "default_vault_timeout_secs")]
    pub timeout_secs: u64,
}

impl VaultConfig {
    pub fn token(&self) -> Result<String, Error> {
        match (&self.token, &self.token_file) {
            (Some(token), None) => Ok(token.clone()),
            (None, Some(path)) => Ok(std::fs::read_to_string(path)
                .map_err(|e| Error::Vault(format!("reading {}: {e}", path.display())))?
                .trim()
                .to_owned()),
            _ => {
                Err(Error::InvalidConfig("[vault] needs exactly one of token or token_file".into()))
            }
        }
    }
}

fn default_vault_mount() -> String {
    "secret".to_owned()
}

fn default_vault_path() -> String {
    "dbsec".to_owned()
}

fn default_transit_mount() -> String {
    "transit".to_owned()
}

fn default_vault_timeout_secs() -> u64 {
    5
}

impl ColumnConfig {
    /// `(schema, table)` with the `public` default applied.
    pub fn schema_and_table(&self) -> (&str, &str) {
        match self.table.split_once('.') {
            Some((schema, table)) => (schema, table),
            None => ("public", &self.table),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSection {
    /// Client-facing TLS. When set, plaintext clients are rejected.
    pub downstream: Option<DownstreamTls>,
    /// TLS to the real server, verify-full. When set, an upstream that
    /// refuses TLS is an error.
    pub upstream: Option<UpstreamTls>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownstreamTls {
    /// PEM certificate chain presented to clients.
    pub cert: PathBuf,
    /// PEM private key for the certificate.
    pub key: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamTls {
    /// PEM CA bundle the server certificate must chain to.
    pub ca: PathBuf,
    /// Name to verify the server certificate against; defaults to the host
    /// part of `upstream`.
    pub hostname: Option<String>,
}

fn default_listen() -> String {
    "127.0.0.1:6432".to_owned()
}

fn default_upstream() -> String {
    "127.0.0.1:5432".to_owned()
}

fn default_startup_timeout_secs() -> u64 {
    30
}

fn default_max_sessions() -> usize {
    256
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            upstream: default_upstream(),
            keys_file: None,
            vault: None,
            control_dsn: None,
            startup_timeout_secs: default_startup_timeout_secs(),
            max_sessions: default_max_sessions(),
            tls: TlsSection::default(),
            on_unprotected: OnUnprotected::default(),
            columns: Vec::new(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let raw = std::fs::read_to_string(path)
            .map_err(|source| Error::ConfigRead { path: path.to_owned(), source })?;
        let config: Self = toml::from_str(&raw)
            .map_err(|source| Error::ConfigParse { path: path.to_owned(), source })?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.startup_timeout_secs == 0 {
            return Err(Error::InvalidConfig("startup_timeout_secs must be greater than 0".into()));
        }
        if self.max_sessions == 0 {
            return Err(Error::InvalidConfig("max_sessions must be greater than 0".into()));
        }
        if !self.columns.is_empty() {
            match (&self.keys_file, &self.vault) {
                (Some(_), None) | (None, Some(_)) => {}
                (None, None) => {
                    return Err(Error::InvalidConfig(
                        "[[column]] entries require keys_file or [vault]".into(),
                    ))
                }
                (Some(_), Some(_)) => {
                    return Err(Error::InvalidConfig(
                        "keys_file and [vault] are mutually exclusive".into(),
                    ))
                }
            }
            if self.control_dsn.is_none() {
                return Err(Error::InvalidConfig("[[column]] entries require control_dsn".into()));
            }
        }
        if let Some(vault) = &self.vault {
            vault.token()?;
            if vault.timeout_secs == 0 {
                return Err(Error::InvalidConfig(
                    "[vault] timeout_secs must be greater than 0".into(),
                ));
            }
        }
        let mut seen = std::collections::HashSet::new();
        for column in &self.columns {
            let (schema, table) = column.schema_and_table();
            let name = format!("{schema}.{table}.{}", column.column);
            if !seen.insert(name.clone()) {
                return Err(Error::InvalidConfig(format!("duplicate [[column]] entry for {name}")));
            }
            if column.searchable && column.transform != TransformKind::Encrypt {
                return Err(Error::InvalidConfig(format!(
                    "{name}: searchable requires transform = \"encrypt\""
                )));
            }
            if !column.detokenize && column.transform != TransformKind::Fpe {
                return Err(Error::InvalidConfig(format!(
                    "{name}: detokenize = false is only meaningful for transform = \"fpe\""
                )));
            }
            if column.transform == TransformKind::None && column.mask.is_none() {
                return Err(Error::InvalidConfig(format!(
                    "{name}: transform = \"none\" does nothing without a mask"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_apply_to_empty_config() {
        let cfg: Config = toml::from_str("").unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:6432");
        assert_eq!(cfg.upstream, "127.0.0.1:5432");
        assert_eq!(cfg.startup_timeout_secs, 30);
        assert_eq!(cfg.max_sessions, 256);
        cfg.validate().unwrap();
    }

    #[test]
    fn limits_parse_and_reject_zero() {
        let cfg: Config = toml::from_str("startup_timeout_secs = 5\nmax_sessions = 8\n").unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.startup_timeout_secs, 5);
        assert_eq!(cfg.max_sessions, 8);

        let no_startup: Config = toml::from_str("startup_timeout_secs = 0").unwrap();
        assert!(matches!(no_startup.validate(), Err(Error::InvalidConfig(_))));
        let no_sessions: Config = toml::from_str("max_sessions = 0").unwrap();
        assert!(matches!(no_sessions.validate(), Err(Error::InvalidConfig(_))));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        assert!(toml::from_str::<Config>("listne = \"oops\"").is_err());
    }

    #[test]
    fn on_unprotected_defaults_to_warn_and_parses_reject() {
        let cfg: Config = toml::from_str("").unwrap();
        assert_eq!(cfg.on_unprotected, OnUnprotected::Warn);
        let strict: Config = toml::from_str("on_unprotected = \"reject\"").unwrap();
        assert_eq!(strict.on_unprotected, OnUnprotected::Reject);
        assert!(toml::from_str::<Config>("on_unprotected = \"nonsense\"").is_err());
    }

    #[test]
    fn columns_parse_and_validate() {
        let cfg: Config = toml::from_str(
            "keys_file = \"keys.toml\"\ncontrol_dsn = \"postgres://x\"\n\n[[column]]\ntable = \"users\"\ncolumn = \"email\"\nsearchable = true\n\n[[column]]\ntable = \"billing.cards\"\ncolumn = \"pan\"\n",
        )
        .unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.columns.len(), 2);
        assert_eq!(cfg.columns[0].schema_and_table(), ("public", "users"));
        assert!(cfg.columns[0].searchable);
        assert_eq!(cfg.columns[1].schema_and_table(), ("billing", "cards"));

        let no_keys: Config = toml::from_str(
            "control_dsn = \"postgres://x\"\n\n[[column]]\ntable = \"users\"\ncolumn = \"email\"\n",
        )
        .unwrap();
        assert!(matches!(no_keys.validate(), Err(Error::InvalidConfig(_))));

        let dup: Config = toml::from_str(
            "keys_file = \"k\"\ncontrol_dsn = \"d\"\n\n[[column]]\ntable = \"public.users\"\ncolumn = \"email\"\n\n[[column]]\ntable = \"users\"\ncolumn = \"email\"\n",
        )
        .unwrap();
        assert!(matches!(dup.validate(), Err(Error::InvalidConfig(_))));
    }

    #[test]
    fn transform_kinds_parse_and_validate() {
        let cfg: Config = toml::from_str(
            "keys_file = \"k\"\ncontrol_dsn = \"d\"\n\n[[column]]\ntable = \"cards\"\ncolumn = \"pan\"\ntransform = \"fpe\"\ndetokenize = false\n\n[[column]]\ntable = \"users\"\ncolumn = \"ssn\"\ntransform = \"token\"\n",
        )
        .unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.columns[0].transform, TransformKind::Fpe);
        assert!(!cfg.columns[0].detokenize);
        assert_eq!(cfg.columns[1].transform, TransformKind::Token);
        assert!(cfg.columns[1].detokenize);

        let searchable_fpe: Config = toml::from_str(
            "keys_file = \"k\"\ncontrol_dsn = \"d\"\n\n[[column]]\ntable = \"cards\"\ncolumn = \"pan\"\ntransform = \"fpe\"\nsearchable = true\n",
        )
        .unwrap();
        assert!(matches!(searchable_fpe.validate(), Err(Error::InvalidConfig(_))));

        let no_detok_encrypt: Config = toml::from_str(
            "keys_file = \"k\"\ncontrol_dsn = \"d\"\n\n[[column]]\ntable = \"users\"\ncolumn = \"email\"\ndetokenize = false\n",
        )
        .unwrap();
        assert!(matches!(no_detok_encrypt.validate(), Err(Error::InvalidConfig(_))));
    }

    #[test]
    fn vault_section_parses_and_is_exclusive_with_keys_file() {
        let cfg: Config = toml::from_str(
            "control_dsn = \"d\"\n\n[vault]\naddr = \"http://127.0.0.1:8200\"\ntoken = \"root\"\n\n[[column]]\ntable = \"users\"\ncolumn = \"email\"\n",
        )
        .unwrap();
        cfg.validate().unwrap();
        let vault = cfg.vault.as_ref().unwrap();
        assert_eq!(vault.mount, "secret");
        assert_eq!(vault.path, "dbsec");
        assert_eq!(vault.transit_mount, "transit");
        assert_eq!(vault.token().unwrap(), "root");
        assert_eq!(vault.timeout_secs, 5, "every Vault call is bounded by default");

        let zero_timeout: Config = toml::from_str(
            "control_dsn = \"d\"\n\n[vault]\naddr = \"a\"\ntoken = \"t\"\ntimeout_secs = 0\n\n[[column]]\ntable = \"users\"\ncolumn = \"email\"\n",
        )
        .unwrap();
        assert!(
            matches!(zero_timeout.validate(), Err(Error::InvalidConfig(_))),
            "a zero timeout would expire instantly, not disable the bound"
        );

        let both: Config = toml::from_str(
            "keys_file = \"k\"\ncontrol_dsn = \"d\"\n\n[vault]\naddr = \"a\"\ntoken = \"t\"\n\n[[column]]\ntable = \"users\"\ncolumn = \"email\"\n",
        )
        .unwrap();
        assert!(matches!(both.validate(), Err(Error::InvalidConfig(_))));

        let no_token: Config = toml::from_str("[vault]\naddr = \"a\"\n").unwrap();
        assert!(matches!(no_token.validate(), Err(Error::InvalidConfig(_))));
    }

    #[test]
    fn tls_sections_parse() {
        let cfg: Config = toml::from_str(
            "[tls.downstream]\ncert = \"c.pem\"\nkey = \"k.pem\"\n\n[tls.upstream]\nca = \"ca.pem\"\n",
        )
        .unwrap();
        assert!(cfg.tls.downstream.is_some());
        let up = cfg.tls.upstream.unwrap();
        assert_eq!(up.ca.to_str().unwrap(), "ca.pem");
        assert!(up.hostname.is_none());
    }
}
