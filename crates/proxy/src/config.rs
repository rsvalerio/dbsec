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

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::Error;

/// What a redacted secret renders as, in both [`Secret`] and [`Dsn`].
const REDACTED: &str = "<redacted>";

/// A configured credential, held in a buffer that is wiped when it drops and
/// whose [`Debug`] never prints the value.
///
/// [`Config`] derives `Debug`, and the reason to derive it is that somebody
/// eventually writes `?config` into a `tracing` call while chasing a startup
/// failure. The Vault token is the credential that unwraps every DEK and reads
/// every deterministic index key, so it is the one value in the config that
/// must survive that without leaking. `expose` is deliberately ugly: it makes
/// every read site greppable.
///
/// Erasure is best-effort at the edges. `serde` materialises the token in its
/// own `String` before this type can take ownership of it, and `toml` keeps
/// intermediate buffers of the whole config text — neither is reachable from
/// here. What this removes is the copies the proxy itself owns and keeps.
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
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
        f.write_str(REDACTED)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

/// A PostgreSQL connection string, printed with its password masked.
///
/// Unlike [`Secret`] the whole value is not sensitive: the scheme, user, host,
/// port and database name are exactly what an operator needs when the control
/// connection fails at boot, which is the most failure-prone step there is.
/// Only the password is hidden, so a `?config` stays useful.
#[derive(Clone, Deserialize)]
pub struct Dsn(String);

impl Dsn {
    /// Configuration builds these through `serde`; only tests need to name one
    /// directly, so the constructor does not exist outside them.
    #[cfg(test)]
    pub fn new(raw: String) -> Self {
        Self(raw)
    }

    /// The connection string as `tokio_postgres` needs it.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The connection string with any password replaced by [`REDACTED`].
    ///
    /// A value that is not a connection string at all is never echoed: it
    /// cannot connect either, so there is nothing to lose by hiding it, and
    /// masking a shape this function does not recognise is guesswork.
    pub fn redacted(&self) -> String {
        if self.0.parse::<tokio_postgres::Config>().is_err() {
            return format!("<unparseable control_dsn {REDACTED}>");
        }
        redact_dsn(&self.0)
    }
}

impl fmt::Debug for Dsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.redacted(), f)
    }
}

/// Masked, like [`Debug`] — so `%dsn` in a `tracing` call is safe too. The raw
/// string is reachable only through [`Dsn::as_str`].
impl fmt::Display for Dsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.redacted())
    }
}

/// Masks the password out of a connection string in either shape
/// `tokio_postgres` accepts: the URL form (`postgres://user:pw@host/db`) and
/// the libpq keyword/value form (`host=... password=...`). Everything else is
/// preserved verbatim, because everything else is diagnostics.
fn redact_dsn(dsn: &str) -> String {
    let mut out = String::with_capacity(dsn.len());
    let rest = match dsn.split_once("://") {
        Some((scheme, rest)) => {
            out.push_str(scheme);
            out.push_str("://");
            // Userinfo ends at the last `@` before the path or query starts.
            let authority = rest.find(['/', '?']).unwrap_or(rest.len());
            match rest[..authority].rfind('@') {
                Some(at) => {
                    let (userinfo, from_at) = rest.split_at(at);
                    match userinfo.split_once(':') {
                        Some((user, _)) => {
                            out.push_str(user);
                            out.push(':');
                            out.push_str(REDACTED);
                        }
                        None => out.push_str(userinfo),
                    }
                    from_at
                }
                None => rest,
            }
        }
        None => dsn,
    };
    mask_password_parameters(rest, &mut out);
    out
}

/// Masks `password=<value>` wherever it appears as a parameter — a libpq
/// keyword or a URL query parameter — leaving every other parameter legible.
///
/// Values may be single-quoted with backslash escapes (libpq's grammar), so a
/// password containing a space cannot be masked by splitting on whitespace
/// alone. Only ASCII bytes are ever compared, so this never cuts a multi-byte
/// character in half.
fn mask_password_parameters(input: &str, out: &mut String) {
    const DELIMITERS: [u8; 6] = *b" \t&?/@";
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if DELIMITERS.contains(&bytes[i]) {
            out.push(char::from(bytes[i]));
            i += 1;
            continue;
        }
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' && !DELIMITERS.contains(&bytes[i]) {
            i += 1;
        }
        let key = &input[key_start..i];
        out.push_str(key);
        if i >= bytes.len() || bytes[i] != b'=' {
            continue;
        }
        out.push('=');
        i += 1;
        let value_start = i;
        if bytes.get(i) == Some(&b'\'') {
            i += 1;
            while i < bytes.len() {
                match bytes[i] {
                    b'\\' => i += 2,
                    b'\'' => {
                        i += 1;
                        break;
                    }
                    _ => i += 1,
                }
            }
            i = i.min(bytes.len());
        } else {
            while i < bytes.len() && !matches!(bytes[i], b' ' | b'\t' | b'&') {
                i += 1;
            }
        }
        if key.eq_ignore_ascii_case("password") {
            out.push_str(REDACTED);
        } else {
            out.push_str(&input[value_start..i]);
        }
    }
}

/// Refuses a secret file that anyone but its owner can read.
///
/// `keys_file` is every master key in plaintext hex, `[vault] token_file`
/// is the credential that unwraps them, and `[tls.downstream] key` is the
/// private key the proxy authenticates itself with — so a `0644` on any of
/// them defeats the product outright, and `0644` is what `cp`, a Docker
/// `COPY`, an editor that recreates the file on save, or a config-management
/// template with no explicit mode all produce silently. `ssh` refuses a
/// private key on the same grounds (SEC-29). Refusing rather than warning is
/// deliberate: a startup warning scrolls past, and the failure mode this
/// prevents is permanent.
///
/// The TLS key gets the same refusal as the other two rather than a warning,
/// even though a service group sharing a key is a real deployment shape. The
/// group-readable case is not a safe exception here: this proxy is a single
/// process that reads the key itself at startup, so nothing else in the group
/// needs it, and a group-readable copy hands every local member the ability
/// to impersonate the proxy to its clients and to decrypt any captured
/// session that did not negotiate forward secrecy. A deployment that must
/// share the key with another service should give that service its own
/// `0600` copy — or, if the sharing is genuinely required, say so in config
/// rather than have the proxy infer consent from a permission bit.
///
/// A file that cannot be stat'ed is left alone. The read that follows reports
/// the real I/O error with its path (ERR-13), which is a better message than
/// anything this check could invent for a path that may not exist yet.
#[cfg(unix)]
fn check_secret_file_mode(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt as _;

    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(());
    };
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(Error::InvalidConfig(format!(
            "{} is readable beyond its owner (mode {:04o}); it holds secret material — chmod 600 {}",
            path.display(),
            mode & 0o7777,
            path.display()
        )));
    }
    Ok(())
}

/// Non-unix targets have no `st_mode` to inspect and no equivalent this crate
/// can check portably, so the check is a documented no-op there rather than a
/// build failure. Secret-file permissions on those platforms are the
/// deployment's responsibility.
#[cfg(not(unix))]
fn check_secret_file_mode(_path: &Path) -> Result<(), Error> {
    Ok(())
}

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
    /// configured, e.g. `postgres://dbsec:secret@127.0.0.1:5432/app`. Carries
    /// a password, so it is a [`Dsn`] rather than a `String`: see that type.
    pub control_dsn: Option<Dsn>,
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
    /// How often the `[[column]]` list is re-resolved to `(table oid, attnum)`
    /// against the live catalog. The read path matches on those, the write
    /// path matches on names, so a migration that recreates a table or a
    /// column desynchronises them until the next resolution — writes keep
    /// being encrypted while reads relay stored values. `0` disables the
    /// timer and leaves only the on-demand re-resolution a session triggers
    /// when it sees a result column it cannot explain.
    #[serde(default = "default_column_refresh_secs")]
    pub column_refresh_secs: u64,
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
    pub token: Option<Secret>,
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
    /// Resolves the token from whichever of the two sources is configured.
    ///
    /// Called once, by [`Config::validate`], and the result is carried in the
    /// [`VaultSetup`] validation hands out — so `token_file` is read exactly
    /// once per startup, and the async connect path neither re-reads it nor
    /// performs blocking file I/O on the runtime (CONC-5).
    fn resolve_token(&self) -> Result<Secret, Error> {
        match (&self.token, &self.token_file) {
            (Some(token), None) => Ok(token.clone()),
            (None, Some(path)) => {
                check_secret_file_mode(path)?;
                // The file contents are the token: read into a buffer that is
                // wiped on drop, and hand the trimmed copy straight to
                // `Secret`, which is wiped in turn.
                let raw = Zeroizing::new(
                    std::fs::read_to_string(path)
                        .map_err(|e| Error::Vault(format!("reading {}: {e}", path.display())))?,
                );
                Ok(Secret::new(raw.trim().to_owned()))
            }
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

/// Five minutes: short enough that a migration is picked up well inside a
/// deploy window, long enough that the control connection is idle in every
/// steady state. The on-demand trigger is what actually bounds the exposure;
/// this is the backstop for a migration nobody reads across.
fn default_column_refresh_secs() -> u64 {
    300
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
            column_refresh_secs: default_column_refresh_secs(),
            tls: TlsSection::default(),
            on_unprotected: OnUnprotected::default(),
            columns: Vec::new(),
        }
    }
}

/// The key source protected columns are opened with. Validation resolves the
/// `keys_file`/`[vault]` pair into exactly one of these once, so no later
/// stage has to restate the invariant with a panic (ERR-11).
#[derive(Debug, Clone)]
pub enum KeySourceConfig {
    /// TOML keyfile for `dbsec_core::keys::FileKeySource`.
    File(PathBuf),
    /// OpenBao/Vault Transit + KV. Boxed: a resolved Vault setup is eight
    /// fields where a keyfile is one path, and this enum is matched once at
    /// startup rather than moved around.
    Vault(Box<VaultSetup>),
}

/// A `[vault]` section with its token already resolved — the form the connect
/// path consumes. Validation proves the token is obtainable *by obtaining it*,
/// rather than by resolving a throwaway copy and dropping it (SEC-5).
#[derive(Debug, Clone)]
pub struct VaultSetup {
    pub config: VaultConfig,
    pub token: Secret,
}

/// What the protected-column path needs, proved present by validation:
/// exactly one key source and a control DSN. Constructed only by
/// [`Config::validated`], and only when at least one `[[column]]` is
/// configured — a config with no columns cannot produce one, so the proxy's
/// plain-relay mode never reaches this state at all.
#[derive(Debug)]
pub struct ProtectedConfig {
    pub keys: KeySourceConfig,
    pub control_dsn: Dsn,
}

/// A [`Config`] that has passed [`Config::validate`], carrying what
/// validation proved rather than expecting the use site to re-derive it.
#[derive(Debug)]
pub struct ValidatedConfig {
    pub config: Config,
    /// `None` when no `[[column]]` is configured: the proxy is then a plain
    /// relay and needs neither keys nor a control connection.
    pub protected: Option<ProtectedConfig>,
}

impl Config {
    pub fn load(path: &Path) -> Result<ValidatedConfig, Error> {
        // A config with an inline `[vault] token` holds a credential, so the
        // file's text is wiped when it drops rather than left in the heap for
        // the life of the process. Same best-effort caveat as [`Secret`]:
        // `toml`'s own intermediate buffers are outside this crate's reach.
        let raw = Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|source| Error::ConfigRead { path: path.to_owned(), source })?,
        );
        let config: Self = toml::from_str(&raw)
            .map_err(|source| Error::ConfigParse { path: path.to_owned(), source })?;
        config.validated()
    }

    /// Validates and hands back the resolved form. The only way to obtain a
    /// [`ValidatedConfig`], including for a programmatically built config.
    pub fn validated(self) -> Result<ValidatedConfig, Error> {
        let protected = self.validate()?;
        Ok(ValidatedConfig { config: self, protected })
    }

    /// Checks every config invariant and returns the resolved protected-column
    /// setup, `None` when no `[[column]]` is configured.
    fn validate(&self) -> Result<Option<ProtectedConfig>, Error> {
        if self.startup_timeout_secs == 0 {
            return Err(Error::InvalidConfig("startup_timeout_secs must be greater than 0".into()));
        }
        if self.max_sessions == 0 {
            return Err(Error::InvalidConfig("max_sessions must be greater than 0".into()));
        }
        // Checked whether or not any `[[column]]` is configured: the proxy
        // presents this key to every client even in plain-relay mode, so it is
        // a secret on the same footing as `keys_file` (SEC-29). The cert beside
        // it is public and is deliberately not checked.
        if let Some(downstream) = &self.tls.downstream {
            check_secret_file_mode(&downstream.key)?;
        }
        // Resolved before the `[[column]]` branch below, and only here: a
        // `[vault]` section is validated whether or not a column uses it, and
        // resolving once means `token_file` is read exactly once per startup
        // rather than once to prove it is readable and again to connect.
        let vault = match &self.vault {
            None => None,
            Some(vault) => {
                if vault.timeout_secs == 0 {
                    return Err(Error::InvalidConfig(
                        "[vault] timeout_secs must be greater than 0".into(),
                    ));
                }
                Some(VaultSetup { config: vault.clone(), token: vault.resolve_token()? })
            }
        };
        let protected = if self.columns.is_empty() {
            None
        } else {
            let keys = match (&self.keys_file, vault) {
                (Some(keys_file), None) => {
                    check_secret_file_mode(keys_file)?;
                    KeySourceConfig::File(keys_file.clone())
                }
                (None, Some(setup)) => KeySourceConfig::Vault(Box::new(setup)),
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
            };
            let control_dsn = self.control_dsn.clone().ok_or_else(|| {
                Error::InvalidConfig("[[column]] entries require control_dsn".into())
            })?;
            Some(ProtectedConfig { keys, control_dsn })
        };
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
        Ok(protected)
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
        assert_eq!(vault.resolve_token().unwrap().expose(), "root");
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

    /// The whole reason `Config` may be `Debug`-formatted at all.
    #[test]
    fn debugging_the_config_never_prints_the_vault_token() {
        let cfg: Config = toml::from_str(
            "control_dsn = \"postgres://dbsec:hunter2@db.internal:5433/app\"\n\n\
             [vault]\naddr = \"https://bao.internal:8200\"\ntoken = \"s3cr3t-token\"\n\n\
             [[column]]\ntable = \"users\"\ncolumn = \"email\"\n",
        )
        .unwrap();

        let vault = format!("{:?}", cfg.vault.as_ref().unwrap());
        assert!(!vault.contains("s3cr3t-token"), "VaultConfig leaked the token: {vault}");

        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("s3cr3t-token"), "Config leaked the token: {rendered}");
        assert!(!rendered.contains("hunter2"), "Config leaked the DSN password: {rendered}");
        // The resolved form is what the connect path is handed, so it has to
        // hold the same line.
        let validated = cfg.validated().unwrap();
        let resolved = format!("{:?}", validated.protected.as_ref().unwrap());
        assert!(!resolved.contains("s3cr3t-token"), "ProtectedConfig leaked the token: {resolved}");
        assert!(!resolved.contains("hunter2"), "ProtectedConfig leaked the password: {resolved}");
    }

    /// A DSN is a mixed value: the password is the only part worth hiding, and
    /// hiding the rest would cost the operator the startup diagnostic.
    #[test]
    fn debugging_a_dsn_masks_the_password_and_keeps_the_endpoint() {
        let url = Dsn::new("postgres://dbsec:hunter2@db.internal:5433/app?sslmode=require".into());
        let rendered = format!("{url:?}");
        assert!(!rendered.contains("hunter2"), "password survived: {rendered}");
        for legible in ["dbsec", "db.internal", "5433", "app", "sslmode=require"] {
            assert!(rendered.contains(legible), "{legible} must stay legible: {rendered}");
        }

        let keyword_value =
            Dsn::new("host=db.internal port=5433 dbname=app user=dbsec password=hunter2".into());
        let rendered = format!("{keyword_value:?}");
        assert!(!rendered.contains("hunter2"), "password survived: {rendered}");
        for legible in ["host=db.internal", "port=5433", "dbname=app", "user=dbsec"] {
            assert!(rendered.contains(legible), "{legible} must stay legible: {rendered}");
        }

        // libpq quotes a value containing a space, so masking cannot be a
        // matter of splitting on whitespace.
        let quoted = Dsn::new("host=db.internal password='hunter 2' dbname=app".into());
        let rendered = format!("{quoted:?}");
        assert!(!rendered.contains("hunter"), "quoted password survived: {rendered}");
        assert!(rendered.contains("dbname=app"), "masking ate the rest: {rendered}");

        // A password in a URL query string rather than the userinfo.
        let query = Dsn::new("postgres://dbsec@db.internal:5433/app?password=hunter2".into());
        assert!(!format!("{query:?}").contains("hunter2"));

        // Not a connection string at all: nothing here is known to be safe.
        let junk = Dsn::new("this is not a dsn".into());
        assert!(!format!("{junk:?}").contains("not a dsn"));

        // Display carries the same guarantee, so `%dsn` is safe in a log line.
        assert!(!format!("{url}").contains("hunter2"));
    }

    #[cfg(unix)]
    fn write_mode(dir: &Path, name: &str, contents: &str, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    /// SEC-29. `0644` on a keyfile is what `cp`, a Docker `COPY` or an editor
    /// that recreates the file on save all produce, and it defeats the product
    /// outright.
    #[cfg(unix)]
    #[test]
    fn secret_files_must_be_readable_only_by_their_owner() {
        let dir = tempfile::tempdir().unwrap();
        let config_for = |path: &Path| {
            format!(
                "control_dsn = \"postgres://x\"\nkeys_file = {path:?}\n\n\
                 [[column]]\ntable = \"users\"\ncolumn = \"email\"\n"
            )
        };

        let tight = write_mode(dir.path(), "tight.toml", "active = \"00\"\n", 0o600);
        toml::from_str::<Config>(&config_for(&tight)).unwrap().validate().unwrap();

        let loose = write_mode(dir.path(), "loose.toml", "active = \"00\"\n", 0o644);
        let Err(err) = toml::from_str::<Config>(&config_for(&loose)).unwrap().validate() else {
            panic!("a world-readable keyfile must not be accepted");
        };
        assert!(matches!(err, Error::InvalidConfig(_)), "got {err:?}");
        assert!(err.to_string().contains("0644"), "the mode must be named: {err}");

        // The same rule for the Vault token file, which is the credential that
        // unwraps everything the keyfile would have held.
        let token = write_mode(dir.path(), "token", "s3cr3t\n", 0o640);
        let cfg: Config =
            toml::from_str(&format!("[vault]\naddr = \"a\"\ntoken_file = {token:?}\n")).unwrap();
        assert!(matches!(cfg.validate(), Err(Error::InvalidConfig(_))));
    }

    /// SEC-29 for the third secret in the config. A group-readable key is
    /// refused just like a world-readable one: the proxy is the only reader,
    /// so a service group sharing it buys nothing and lets every local member
    /// impersonate the proxy to its clients.
    #[cfg(unix)]
    #[test]
    fn the_downstream_tls_key_must_be_readable_only_by_its_owner() {
        let dir = tempfile::tempdir().unwrap();
        let cert = write_mode(dir.path(), "cert.pem", "cert\n", 0o644);
        let config_for = |key: &Path| format!("[tls.downstream]\ncert = {cert:?}\nkey = {key:?}\n");

        // Checked with no `[[column]]` configured: the key is presented to
        // clients in plain-relay mode too. This case also pins that the
        // certificate beside it is public — it is `0644` above and validation
        // still succeeds.
        let tight = write_mode(dir.path(), "tight.pem", "key\n", 0o600);
        toml::from_str::<Config>(&config_for(&tight)).unwrap().validate().unwrap();

        for (name, mode) in [("group.pem", 0o640), ("world.pem", 0o644)] {
            let loose = write_mode(dir.path(), name, "key\n", mode);
            let Err(err) = toml::from_str::<Config>(&config_for(&loose)).unwrap().validate() else {
                panic!("a {mode:04o} TLS key must not be accepted");
            };
            assert!(matches!(err, Error::InvalidConfig(_)), "got {err:?}");
            assert!(
                err.to_string().contains(&format!("{mode:04o}")),
                "the mode must be named: {err}"
            );
        }
    }

    /// TASK-0019: the token file is read once per startup, not once to prove
    /// it is readable and again to connect.
    #[cfg(unix)]
    #[test]
    fn the_token_file_is_read_once_and_carried() {
        let dir = tempfile::tempdir().unwrap();
        let token = write_mode(dir.path(), "token", "  s3cr3t\n", 0o600);
        let cfg: Config = toml::from_str(&format!(
            "control_dsn = \"postgres://x\"\n\n[vault]\naddr = \"a\"\ntoken_file = {token:?}\n\n\
             [[column]]\ntable = \"users\"\ncolumn = \"email\"\n"
        ))
        .unwrap();

        let validated = cfg.validated().unwrap();
        let KeySourceConfig::Vault(setup) = &validated.protected.as_ref().unwrap().keys else {
            panic!("a [vault] section must resolve to a Vault key source");
        };
        assert_eq!(setup.token.expose(), "s3cr3t", "the token is trimmed and carried");

        // Nothing reads the file again, so removing it changes nothing.
        std::fs::remove_file(&token).unwrap();
        assert_eq!(setup.token.expose(), "s3cr3t");
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
