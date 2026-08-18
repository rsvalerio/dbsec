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
//!   resolves). The proxy therefore watches the startup packet and every
//!   spelling that moves the setting — `SET search_path`, `SET SCHEMA`,
//!   `set_config('search_path', …)` — and stops resolving unqualified names
//!   once the default no longer holds; `on_unprotected` decides whether that
//!   is a warning or a refusal. Schema-qualifying either the config or the SQL
//!   sidesteps the question entirely.
//! - **`standard_conforming_strings`.** With it on — the default, and the only
//!   value the proxy assumes — a backslash in an ordinary string literal is
//!   just a backslash, which is what makes the client's `'\x…'` and the
//!   proxy's parser agree on the bytes a BYTEA literal denotes. A session that
//!   turns it off is an `on_unprotected` site: sealed values go out in a form
//!   that does not depend on the setting, but the *client's* literals are then
//!   read one way by the server and another by the proxy.
//! - **Identifier folding.** A `[[column]]` name is the name the catalog
//!   holds. The write path folds a SQL identifier the way PostgreSQL does
//!   before comparing it (see [`fold_identifier`]), so a configured name that
//!   is not itself in folded form only ever matches a double-quoted SQL
//!   reference, and one longer than [`MAX_IDENTIFIER_BYTES`] matches nothing
//!   at all — which validation refuses rather than leaving to be discovered at
//!   the first unprotected write.
//! - **`COPY`.** A `COPY ... FROM` payload arrives as a `CopyData` stream the
//!   proxy does not parse, so a bulk load into a protected table stores
//!   plaintext; `COPY ... TO` bypasses the read path, so a masked column
//!   leaves as its unmasked stored value. Both are `on_unprotected` sites, and
//!   so is the query form `COPY (SELECT ...) TO STDOUT`, which is flagged
//!   whenever its query reads a protected table — its rows leave as `CopyData`
//!   too, so the read path never sees them.
//! - **The function-call fast path.** `FunctionCall`/`FunctionCallResponse`
//!   invokes a function by OID with no SQL and no `RowDescription`, so its
//!   answer carries no column identity: a function that reads a protected
//!   column returns the stored form, and a mask-only column's plaintext. It is
//!   an `on_unprotected` site too — relayed with one warning per session under
//!   `warn`, refused under `reject`. Drivers reach it only through libpq's
//!   large-object API.

use std::borrow::Cow;
use std::fmt;
use std::ops::Range;
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

    /// Whether this DSN carries a password, in either accepted shape.
    ///
    /// Decided by `tokio_postgres`' own parser rather than by re-scanning the
    /// string, so it cannot disagree with what the control connection will
    /// actually send. A value that does not parse answers `true`: it is not a
    /// connection string this proxy understands, so what is in it is unknown,
    /// and the only use of this answer is deciding whether the file holding it
    /// has to be owner-only.
    pub fn carries_password(&self) -> bool {
        match self.0.parse::<tokio_postgres::Config>() {
            Ok(dsn) => dsn.get_password().is_some(),
            Err(_) => true,
        }
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
///
/// `holds` names the credential in the refusal, because the file this is
/// applied to is not always obviously a secret: the config file itself gets
/// the same check once it carries an inline `[vault] token` or a
/// password-bearing `control_dsn`, and "dbsec.toml is readable beyond its
/// owner" without saying *why* reads as a bug rather than as the thing to fix.
#[cfg(unix)]
fn check_secret_file_mode(path: &Path, holds: &str) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt as _;

    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(());
    };
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(Error::InvalidConfig(format!(
            "{} is readable beyond its owner (mode {:04o}); it holds {holds} — chmod 600 {}",
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
fn check_secret_file_mode(_path: &Path, _holds: &str) -> Result<(), Error> {
    Ok(())
}

/// Key-name fragments whose value is, or may contain, a credential.
///
/// Used only by [`describe_parse_error`], which is asking about text that did
/// *not* parse and so has to guess — deliberately over-broadly. `keys_file`
/// matches on `key` though it holds a path rather than a secret; withholding
/// one parse message too many costs a diagnostic, and the alternative costs a
/// credential. [`Config::inline_secret`] answers the same question exactly,
/// because by then the config has parsed.
const SECRET_KEY_MARKERS: [&str; 5] = ["token", "password", "secret", "dsn", "key"];

/// Renders a `toml` parse failure *without* the offending source line.
///
/// `toml::de::Error`'s own `Display` quotes the input around the failure, so
/// `error!("{e}")` on a config with a lost closing quote on `token = "…"`
/// prints the Vault token — the credential that unwraps every DEK — into
/// stderr and every log pipeline collecting it. [`Secret`] and [`Dsn`] cannot
/// help: they only ever hold values that parsed.
///
/// What survives is `message()` (the parser's own words, with no input in
/// them) plus the position, which is what an operator needs to find the line.
/// The message is withheld too when the parser pointed at a line that
/// configures a credential, since serde's message for a *type* mismatch quotes
/// the offending value ("invalid type: integer 1234, expected a string") and
/// on those lines that value is the secret.
fn describe_parse_error(err: &toml::de::Error, raw: &str) -> String {
    let Some(span) = err.span() else {
        // No position: the failure is about the document as a whole (a
        // missing table, a duplicated key reported without a span), so there
        // is no source text behind it to quote.
        return err.message().to_owned();
    };
    let (line, column) = position(raw, span.start);
    if spans_a_secret_line(raw, &span) {
        return format!(
            "invalid TOML at line {line}, column {column}; the parser's message is withheld \
             because that line configures a credential"
        );
    }
    format!("{} (at line {line}, column {column})", err.message())
}

/// One-based line and byte-column of `offset`. Counted over bytes so a span
/// landing inside a multi-byte character cannot panic.
fn position(raw: &str, offset: usize) -> (usize, usize) {
    let head = &raw.as_bytes()[..offset.min(raw.len())];
    let line = head.iter().filter(|byte| **byte == b'\n').count() + 1;
    let column =
        head.iter().rposition(|byte| *byte == b'\n').map_or(head.len(), |i| head.len() - i - 1) + 1;
    (line, column)
}

/// Whether any line the span touches assigns a [`SECRET_KEY_MARKERS`] key.
fn spans_a_secret_line(raw: &str, span: &Range<usize>) -> bool {
    let bytes = raw.as_bytes();
    // Widened to whole lines in both directions: a span may start mid-value,
    // and a value the parser could not terminate runs past the line it began
    // on. Both ends land on a `\n` or on an end of input, so slicing `raw`
    // with them cannot split a character.
    let start = bytes[..span.start.min(bytes.len())]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |i| i + 1);
    let from = span.end.min(bytes.len());
    let end =
        bytes[from..].iter().position(|byte| *byte == b'\n').map_or(bytes.len(), |i| from + i);
    raw[start..end].lines().any(assigns_a_secret)
}

/// Whether a config line is `<key> = …` for a key that names a credential.
fn assigns_a_secret(line: &str) -> bool {
    let Some((key, _)) = line.split_once('=') else {
        return false;
    };
    let key = key.trim().trim_matches('"').to_ascii_lowercase();
    SECRET_KEY_MARKERS.iter().any(|marker| key.contains(marker))
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
    /// Largest single protected column value the read path will decrypt, mask
    /// and re-encode. A value over it is refused with an ErrorResponse and the
    /// session ends, because the alternative is handing the client the column's
    /// stored form.
    ///
    /// The bound exists because opening one value costs several times its own
    /// size in transient memory — the hex-decoded stored form, the plaintext,
    /// the masked copy, the hex re-encode — so an unbounded value near the
    /// 1 GiB frame limit drives peak resident memory to several GiB per session
    /// (SEC-33). The default is generous for field-level encryption; a
    /// deployment that encrypts a column holding documents, images or large
    /// JSONB raises it and accepts that cost, rather than meeting a hard read
    /// refusal naming a limit it cannot change.
    #[serde(default = "default_max_protected_value_bytes")]
    pub max_protected_value_bytes: usize,
    #[serde(default)]
    pub tls: TlsSection,
    /// What to do with a statement the proxy cannot protect — see
    /// [`OnUnprotected`].
    #[serde(default)]
    pub on_unprotected: OnUnprotected,
    #[serde(default, rename = "column")]
    pub columns: Vec<ColumnConfig>,
    /// Per-table row binding: `[[table]] table = "users", row_key = "id"`.
    /// Optional and opt-in — a table with no entry keeps cell-only binding and
    /// its stored values are untouched.
    #[serde(default, rename = "table")]
    pub tables: Vec<TableConfig>,
}

/// One table's declared row key, which binds each encrypted value to the row it
/// was written in (see `dbsec_core::envelope::RowKey`).
///
/// Opt-in per table because it is not free: the proxy must be able to name the
/// row at both ends, so a protected table with a row key accepts only
/// client-supplied key values, only single-row updates of its protected
/// columns, and only reads that project the key. Those are refusals, not silent
/// degradations — see `README.md`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TableConfig {
    /// Table name, optionally schema-qualified; bare names mean `public`.
    pub table: String,
    /// The column whose value names a row. Must be unique per row — a primary
    /// key, or a column with a unique constraint. The proxy cannot verify that
    /// and does not try: a non-unique choice silently weakens the binding to
    /// "some row in this group", which is why this is documented as the
    /// operator's assertion.
    pub row_key: String,
}

impl TableConfig {
    /// Splits `schema.table`, defaulting the schema to `public`.
    pub fn schema_and_table(&self) -> (&str, &str) {
        match self.table.split_once('.') {
            Some((schema, table)) => (schema, table),
            None => ("public", &self.table),
        }
    }
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
///
/// It governs the read path's one fail-closed reading too — a result column
/// named like a protected column that the resolved map does not cover
/// ([`crate::rows`]) — rather than that having a switch of its own. Both paths
/// are asking the same question about the same columns, and a deployment that
/// is strict about writing plaintext but lax about handing back stored bytes
/// enforces neither half of the invariant. Both paths answer a refusal with the
/// same ErrorResponse, but only the write path's is statement-level: a refused
/// write is withheld before the backend sees it, while a refused read is the
/// result of a statement that already ran, so the session ends to stop the rest
/// of the batch committing behind it (see [`crate::rows`]).
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
    /// e.g. `https://bao.internal:8200`. Validated as a URL with an `https`
    /// scheme by [`VaultConfig::validate_addr`].
    pub addr: String,
    /// Accepts a plaintext `http://` [`Self::addr`]. Development only — see
    /// [`VaultConfig::validate_addr`] for what travels over that channel.
    #[serde(default)]
    pub allow_insecure_addr: bool,
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
    /// Parses [`Self::addr`] and refuses anything that is not a TLS Vault
    /// endpoint.
    ///
    /// Two properties are established here, both at startup rather than on the
    /// connect path:
    ///
    /// - **It is a URL.** `vaultrs`' `VaultClientSettingsBuilder::address` is
    ///   documented "# Panics" and parses with `Url::parse(..).unwrap()`, so a
    ///   typo in `addr` would otherwise abort the process from inside
    ///   `VaultKeySource::connect` instead of joining every neighbouring
    ///   misconfiguration as a clean startup error (ERR-11).
    /// - **Its scheme is `https`.** This is the channel that carries the Vault
    ///   token, every DEK in plaintext and every deterministic index key. The
    ///   proxy hard-refuses a plaintext peer on both pgwire hops once TLS is
    ///   configured, so tolerating a fully plaintext KMS hop — the one whose
    ///   compromise yields the entire key hierarchy — would be the weakest
    ///   link deciding the whole (SEC-31). A `http://` dev address stays
    ///   reachable, but only by writing `allow_insecure_addr = true`, which is
    ///   a deliberate act rather than a config copied out of an example.
    ///
    /// `addr` is echoed in the refusals: unlike `control_dsn` it is an
    /// endpoint, and the credential beside it lives in `token`/`token_file`.
    fn validate_addr(&self) -> Result<(), Error> {
        let addr = url::Url::parse(&self.addr).map_err(|e| {
            Error::InvalidConfig(format!("[vault] addr {:?} is not a URL: {e}", self.addr))
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
            "http" => Err(Error::InvalidConfig(format!(
                "[vault] addr {:?} is plaintext http, which would put the Vault token, every \
                 DEK plaintext and every deterministic index key on the wire in the clear. Use \
                 https, or set allow_insecure_addr = true to accept that in development",
                self.addr
            ))),
            other => Err(Error::InvalidConfig(format!(
                "[vault] addr {:?} has scheme {other:?}; Vault is reached over https",
                self.addr
            ))),
        }
    }

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
                check_secret_file_mode(path, "the Vault token")?;
                // The file contents are the token: read into a buffer that is
                // wiped on drop, and hand the trimmed copy straight to
                // `Secret`, which is wiped in turn.
                let raw = Zeroizing::new(
                    std::fs::read_to_string(path)
                        .map_err(|source| Error::VaultToken { path: path.clone(), source })?,
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

/// PostgreSQL's `NAMEDATALEN - 1`: the most bytes of an identifier the server
/// keeps. Anything longer is truncated on the way into the catalog, and every
/// later reference to the long name resolves to the truncated one.
pub const MAX_IDENTIFIER_BYTES: usize = 63;

/// Folds a SQL identifier the way PostgreSQL does, so that a name written in a
/// query and the same name written in a `[[column]]` entry compare equal.
///
/// Both halves of this are places where Rust's own string handling would give
/// a different answer than the server, and a mismatch here is not a parse
/// error: it makes a protected column look unprotected, and the write path
/// relays the plaintext.
///
/// - An *unquoted* identifier is downcased **ASCII-only**. `str::to_lowercase`
///   applies full Unicode case folding — `Ä` to `ä`, the Kelvin sign `K`
///   (U+212A) to `k` — while PostgreSQL under a UTF-8 server encoding leaves
///   every multibyte character exactly as written. A quoted identifier is not
///   folded at all.
/// - Every identifier, quoted or not, is clipped to
///   [`MAX_IDENTIFIER_BYTES`] on a character boundary (the server's
///   `pg_mbcliplen`).
///
/// The write path calls this on identifiers it reads out of SQL and
/// [`Config::validate`] calls it on the configured names, so the two cannot
/// drift apart.
pub fn fold_identifier(value: &str, quoted: bool) -> Cow<'_, str> {
    let clipped = truncate_identifier(value);
    if quoted || !clipped.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Cow::Borrowed(clipped);
    }
    Cow::Owned(clipped.to_ascii_lowercase())
}

/// Clips an identifier to the bytes PostgreSQL keeps, never splitting a
/// character.
fn truncate_identifier(value: &str) -> &str {
    if value.len() <= MAX_IDENTIFIER_BYTES {
        return value;
    }
    let mut end = MAX_IDENTIFIER_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
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

/// 16 MiB — the read path's own default, kept where its rationale is
/// ([`crate::rows::DEFAULT_MAX_PROTECTED_VALUE_LEN`]) rather than restated
/// here, so the two cannot drift.
fn default_max_protected_value_bytes() -> usize {
    crate::rows::DEFAULT_MAX_PROTECTED_VALUE_LEN
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
            max_protected_value_bytes: default_max_protected_value_bytes(),
            tls: TlsSection::default(),
            on_unprotected: OnUnprotected::default(),
            columns: Vec::new(),
            tables: Vec::new(),
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
        let config: Self = toml::from_str(&raw).map_err(|source| Error::ConfigParse {
            path: path.to_owned(),
            reason: describe_parse_error(&source, &raw),
        })?;
        // The config file joins the keyfile, the token file and the TLS key as
        // a secret file the moment it carries one of those credentials inline
        // (SEC-29). Checked here rather than in `validate` because it is a
        // property of the file this config was read from, and a config built
        // programmatically — in a test, or by a future embedder — has no file
        // behind it to check.
        if let Some(holds) = config.inline_secret() {
            check_secret_file_mode(path, holds)?;
        }
        config.validated()
    }

    /// What credential this config carries in the file itself, if any.
    ///
    /// `token_file` is deliberately not one: that path is checked on its own
    /// (`VaultConfig::resolve_token`), and naming a file is not holding its
    /// contents.
    fn inline_secret(&self) -> Option<&'static str> {
        if self.vault.as_ref().is_some_and(|vault| vault.token.is_some()) {
            return Some("an inline [vault] token");
        }
        if self.control_dsn.as_ref().is_some_and(Dsn::carries_password) {
            return Some("a control_dsn password");
        }
        None
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
        // A ceiling of 0 would refuse every protected read, and one above the
        // frame limit could never be reached — a value cannot outgrow the
        // DataRow carrying it — so both are configuration mistakes rather than
        // choices, and both are worth saying so at load time (ERR-11).
        let max_frame = dbsec_core::pgwire::MAX_MESSAGE_LEN;
        if self.max_protected_value_bytes == 0 || self.max_protected_value_bytes > max_frame {
            return Err(Error::InvalidConfig(format!(
                "max_protected_value_bytes must be between 1 and {max_frame} (the frame limit)"
            )));
        }
        // Checked whether or not any `[[column]]` is configured: the proxy
        // presents this key to every client even in plain-relay mode, so it is
        // a secret on the same footing as `keys_file` (SEC-29). The cert beside
        // it is public and is deliberately not checked.
        if let Some(downstream) = &self.tls.downstream {
            check_secret_file_mode(&downstream.key, "the proxy's TLS private key")?;
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
                vault.validate_addr()?;
                Some(VaultSetup { config: vault.clone(), token: vault.resolve_token()? })
            }
        };
        let protected = if self.columns.is_empty() {
            None
        } else {
            let keys = match (&self.keys_file, vault) {
                (Some(keys_file), None) => {
                    check_secret_file_mode(keys_file, "every master key")?;
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
            if self.tls.upstream.is_some() {
                check_control_dsn_is_not_downgradeable(&control_dsn)?;
            }
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
            check_identifiers(&name, schema, table, &column.column)?;
        }
        self.validate_row_keys()?;
        Ok(protected)
    }

    /// Checks every `[[table]]` row-key declaration against the columns it
    /// would bind.
    ///
    /// Three of these refuse a configuration that would *look* like row
    /// binding while providing none of it, which is the failure worth being
    /// loud about: an operator who declares a row key believes cross-row
    /// relocation is detected, and a silent no-op leaves them believing it.
    fn validate_row_keys(&self) -> Result<(), Error> {
        let mut seen = std::collections::HashSet::new();
        for entry in &self.tables {
            let (schema, table) = entry.schema_and_table();
            let qualified = format!("{schema}.{table}");
            if !seen.insert(qualified.clone()) {
                return Err(Error::InvalidConfig(format!(
                    "duplicate [[table]] entry for {qualified}"
                )));
            }
            check_identifiers(&qualified, schema, table, &entry.row_key)?;

            let columns: Vec<&ColumnConfig> = self
                .columns
                .iter()
                .filter(|column| column.schema_and_table() == (schema, table))
                .collect();
            if columns.is_empty() {
                return Err(Error::InvalidConfig(format!(
                    "[[table]] {qualified} declares row_key = \"{}\" but the table has no \
                     [[column]] entries, so there is nothing to bind",
                    entry.row_key
                )));
            }
            // Only authenticated encryption has associated data to bind a row
            // into. FPE and tokenization map a plaintext to the same stored
            // bytes in every row — that determinism is what makes them
            // searchable and joinable — so a copy between rows of such a column
            // is indistinguishable from a legitimate write, whatever is
            // configured here.
            if !columns.iter().any(|column| column.transform == TransformKind::Encrypt) {
                return Err(Error::InvalidConfig(format!(
                    "[[table]] {qualified} declares row_key = \"{}\", but none of its columns \
                     use transform = \"encrypt\"; fpe and token values are identical in every \
                     row by design, so a row key would bind nothing",
                    entry.row_key
                )));
            }
            // The key column may itself be protected — but then reading it
            // back to verify a sibling would require opening a value that is
            // bound to the key being recovered.
            if columns.iter().any(|column| {
                column.column == entry.row_key && column.transform != TransformKind::None
            }) {
                return Err(Error::InvalidConfig(format!(
                    "[[table]] {qualified} declares row_key = \"{}\", which is itself a \
                     transformed [[column]]; the row key must be readable to verify the row it \
                     names",
                    entry.row_key
                )));
            }
        }
        Ok(())
    }
}

/// Refuses a `control_dsn` that would accept a plaintext session while
/// `[tls.upstream]` is configured.
///
/// The data hop sends SSLRequest itself and hard-fails on anything but `S`
/// ([`crate::session`]), so it cannot be downgraded. The control hop hands the
/// DSN to `tokio_postgres`, whose default `sslmode` is `prefer`: a server —
/// or an active MITM stripping the TLS offer — that answers `N` gets a
/// plaintext session instead, with no error. That session carries the control
/// user's password and performs the catalog resolution that decides which
/// columns are protected, so it is the *more* sensitive of the two hops, and
/// leaving it downgradeable while the data hop is not enforces neither half of
/// the invariant (SEC-31).
///
/// Refused rather than rewritten: the DSN arrives in either of the two shapes
/// `tokio_postgres` accepts, and editing a connection string carrying a
/// password is a worse trade than telling the operator exactly what to add.
///
/// Only the two modes that permit a plaintext fallback are rejected, so a
/// future `tokio_postgres` mode at least as strict as `require` is accepted
/// rather than refused by a stale allow-list (the enum is `#[non_exhaustive]`).
fn check_control_dsn_is_not_downgradeable(dsn: &Dsn) -> Result<(), Error> {
    use tokio_postgres::config::SslMode;

    // The parse error is not echoed: it quotes the offending part of the
    // connection string, which is where the password lives (SEC-21).
    let parsed = dsn.as_str().parse::<tokio_postgres::Config>().map_err(|_| {
        Error::InvalidConfig(
            "control_dsn is not a PostgreSQL connection string in either the URL or the \
             keyword/value form"
                .into(),
        )
    })?;
    // Named with the `sslmode=` spelling the operator would have written, so
    // the refusal quotes their own config back at them.
    let downgradeable = match parsed.get_ssl_mode() {
        SslMode::Disable => "disable",
        SslMode::Prefer => "prefer",
        _ => return Ok(()),
    };
    Err(Error::InvalidConfig(format!(
        "[tls.upstream] is configured but control_dsn has sslmode={downgradeable} — that lets \
         the control connection fall back to plaintext when the server, or a MITM stripping the \
         TLS offer, answers N to its SSLRequest, and that connection carries the control user's \
         password and resolves which columns are protected. Add sslmode=require to control_dsn"
    )))
}

/// Checks one `[[column]]` entry's three names against what PostgreSQL can
/// actually hold, so a name the catalog could never match is caught here
/// rather than turning into a write the proxy quietly treats as unprotected.
///
/// A name longer than [`MAX_IDENTIFIER_BYTES`] is an error: the server
/// truncates on the way in, so no catalog row carries the name as written and
/// the entry can only ever fail to resolve. A name that is not already in
/// PostgreSQL's folded form is a warning rather than an error, because it is
/// legitimate — a column created as `"Email"` really is stored with the
/// capital — but it is far more often a config typo, and the consequence is
/// worth spelling out: only a *double-quoted* SQL reference will match it.
fn check_identifiers(name: &str, schema: &str, table: &str, column: &str) -> Result<(), Error> {
    for (kind, ident) in [("schema", schema), ("table", table), ("column", column)] {
        if ident.len() > MAX_IDENTIFIER_BYTES {
            return Err(Error::InvalidConfig(format!(
                "{name}: {kind} name is {} bytes, and PostgreSQL truncates identifiers to \
                 {MAX_IDENTIFIER_BYTES}, so no table or column can carry it",
                ident.len()
            )));
        }
        if fold_identifier(ident, false) != ident {
            tracing::warn!(
                kind,
                ident,
                "configured identifier is not in the form PostgreSQL folds an unquoted name to; \
                 only a double-quoted SQL reference will match it"
            );
        }
    }
    Ok(())
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
        assert_eq!(cfg.max_protected_value_bytes, crate::rows::DEFAULT_MAX_PROTECTED_VALUE_LEN);
        cfg.validate().unwrap();
    }

    /// The read path's per-value ceiling is the operator's to set, so it needs
    /// a load-time answer for the two settings that could never work: one that
    /// refuses every protected read, and one no DataRow could ever reach.
    #[test]
    fn the_protected_value_ceiling_parses_and_is_bounded() {
        let cfg: Config = toml::from_str("max_protected_value_bytes = 67108864").unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.max_protected_value_bytes, 64 * 1024 * 1024);

        for invalid in ["0".to_owned(), (dbsec_core::pgwire::MAX_MESSAGE_LEN + 1).to_string()] {
            let cfg: Config =
                toml::from_str(&format!("max_protected_value_bytes = {invalid}")).unwrap();
            assert!(
                matches!(cfg.validate(), Err(Error::InvalidConfig(_))),
                "max_protected_value_bytes = {invalid} must be refused"
            );
        }
    }

    /// A row key is opt-in and does not disturb anything else.
    #[test]
    fn a_row_key_parses_and_defaults_its_schema() {
        let cfg: Config = toml::from_str(
            "keys_file = \"k.toml\"\ncontrol_dsn = \"postgres://u@h/d\"\n\
             [[column]]\ntable = \"users\"\ncolumn = \"ssn\"\ntransform = \"encrypt\"\n\
             [[table]]\ntable = \"users\"\nrow_key = \"id\"\n",
        )
        .expect("parses");
        assert_eq!(cfg.tables.len(), 1);
        assert_eq!(cfg.tables[0].schema_and_table(), ("public", "users"));
        assert_eq!(cfg.tables[0].row_key, "id");
    }

    /// Every one of these would leave an operator believing cross-row
    /// relocation is detected when it is not, which is worse than not offering
    /// the setting.
    #[test]
    fn a_row_key_that_would_bind_nothing_is_refused() {
        let base = "keys_file = \"k.toml\"\ncontrol_dsn = \"postgres://u@h/d\"\n";
        for (name, columns, tables) in [
            (
                "no columns on the table",
                "[[column]]\ntable = \"other\"\ncolumn = \"ssn\"\ntransform = \"encrypt\"\n",
                "[[table]]\ntable = \"users\"\nrow_key = \"id\"\n",
            ),
            (
                "deterministic transforms only",
                "[[column]]\ntable = \"users\"\ncolumn = \"pan\"\ntransform = \"fpe\"\n",
                "[[table]]\ntable = \"users\"\nrow_key = \"id\"\n",
            ),
            (
                "the row key is itself protected",
                "[[column]]\ntable = \"users\"\ncolumn = \"ssn\"\ntransform = \"encrypt\"\n\
                 [[column]]\ntable = \"users\"\ncolumn = \"id\"\ntransform = \"encrypt\"\n",
                "[[table]]\ntable = \"users\"\nrow_key = \"id\"\n",
            ),
            (
                "duplicate declarations",
                "[[column]]\ntable = \"users\"\ncolumn = \"ssn\"\ntransform = \"encrypt\"\n",
                "[[table]]\ntable = \"users\"\nrow_key = \"id\"\n\
                 [[table]]\ntable = \"public.users\"\nrow_key = \"id\"\n",
            ),
        ] {
            let cfg: Config = toml::from_str(&format!("{base}{columns}{tables}")).expect("parses");
            assert!(
                matches!(cfg.validate(), Err(Error::InvalidConfig(_))),
                "{name}: must be refused"
            );
        }
    }

    /// A table whose encrypt column sits beside deterministic ones is fine —
    /// the encrypt column is bound, the others are documented as not.
    #[test]
    fn a_row_key_is_accepted_when_any_column_can_bind_it() {
        let cfg: Config = toml::from_str(
            "keys_file = \"k.toml\"\ncontrol_dsn = \"postgres://u@h/d\"\n\
             [[column]]\ntable = \"users\"\ncolumn = \"pan\"\ntransform = \"fpe\"\n\
             [[column]]\ntable = \"users\"\ncolumn = \"ssn\"\ntransform = \"encrypt\"\n\
             [[table]]\ntable = \"users\"\nrow_key = \"id\"\n",
        )
        .expect("parses");
        cfg.validate().expect("accepted");
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

    /// A name PostgreSQL would have truncated cannot name anything in the
    /// catalog, so the entry can only ever fail to resolve — caught here
    /// rather than at the first write it silently fails to protect.
    #[test]
    fn over_long_identifiers_are_rejected() {
        let long = "e".repeat(MAX_IDENTIFIER_BYTES + 1);
        for entry in [
            format!("table = \"{long}\"\ncolumn = \"email\"\n"),
            format!("table = \"users\"\ncolumn = \"{long}\"\n"),
            format!("table = \"{long}.users\"\ncolumn = \"email\"\n"),
        ] {
            let cfg: Config = toml::from_str(&format!(
                "keys_file = \"k\"\ncontrol_dsn = \"d\"\n\n[[column]]\n{entry}"
            ))
            .unwrap();
            let err = cfg.validate().expect_err(&entry);
            assert!(matches!(err, Error::InvalidConfig(_)), "got {err:?}");
        }

        // Exactly at the limit is a name the server can hold.
        let at_limit = "e".repeat(MAX_IDENTIFIER_BYTES);
        let cfg: Config = toml::from_str(&format!(
            "keys_file = \"k\"\ncontrol_dsn = \"d\"\n\n[[column]]\ntable = \"users\"\ncolumn = \"{at_limit}\"\n"
        ))
        .unwrap();
        cfg.validate().unwrap();
    }

    /// A mixed-case or non-ASCII name is legitimate — the column really can
    /// have been created quoted — so it warns rather than failing, and
    /// validation still succeeds.
    #[test]
    fn names_outside_the_folded_form_still_validate() {
        let cfg: Config = toml::from_str(
            "keys_file = \"k\"\ncontrol_dsn = \"d\"\n\n[[column]]\ntable = \"Users\"\ncolumn = \"Ämail\"\n",
        )
        .unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn identifiers_fold_the_way_postgres_folds_them() {
        // ASCII-only downcase: `str::to_lowercase` would map `Ä` to `ä` and
        // the Kelvin sign to `k`, where the server leaves both alone.
        assert_eq!(fold_identifier("EMail", false), "email");
        assert_eq!(fold_identifier("ÄMAIL", false), "Ämail");
        assert_eq!(fold_identifier("\u{212a}elvin", false), "\u{212a}elvin");
        // A quoted identifier is not folded at all.
        assert_eq!(fold_identifier("EMail", true), "EMail");
        // Both are clipped to what the catalog holds, on a character boundary.
        let long = "é".repeat(MAX_IDENTIFIER_BYTES);
        let folded = fold_identifier(&long, false);
        assert_eq!(folded, "é".repeat(MAX_IDENTIFIER_BYTES / 2));
        assert!(folded.len() <= MAX_IDENTIFIER_BYTES);
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
            "control_dsn = \"d\"\n\n[vault]\naddr = \"https://bao.internal:8200\"\ntoken = \"root\"\n\n[[column]]\ntable = \"users\"\ncolumn = \"email\"\n",
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
            "control_dsn = \"d\"\n\n[vault]\naddr = \"https://bao.internal:8200\"\ntoken = \"t\"\ntimeout_secs = 0\n\n[[column]]\ntable = \"users\"\ncolumn = \"email\"\n",
        )
        .unwrap();
        assert!(
            matches!(zero_timeout.validate(), Err(Error::InvalidConfig(_))),
            "a zero timeout would expire instantly, not disable the bound"
        );

        let both: Config = toml::from_str(
            "keys_file = \"k\"\ncontrol_dsn = \"d\"\n\n[vault]\naddr = \"https://bao.internal:8200\"\ntoken = \"t\"\n\n[[column]]\ntable = \"users\"\ncolumn = \"email\"\n",
        )
        .unwrap();
        assert!(matches!(both.validate(), Err(Error::InvalidConfig(_))));

        let no_token: Config =
            toml::from_str("[vault]\naddr = \"https://bao.internal:8200\"\n").unwrap();
        assert!(matches!(no_token.validate(), Err(Error::InvalidConfig(_))));
    }

    /// A `[vault]` section with `addr` set to `value`, and no column — the
    /// section is validated whether or not anything uses it.
    fn vault_addr_config(value: &str) -> Config {
        toml::from_str(&format!("[vault]\naddr = {value:?}\ntoken = \"t\"\n"))
            .expect("test config parses")
    }

    /// The KMS hop carries the Vault token, every DEK plaintext and every
    /// deterministic index key. A config copied out of a dev example must not
    /// put that on the wire in the clear just because nobody edited one line.
    #[test]
    fn a_plaintext_vault_addr_is_refused_unless_it_is_opted_into() {
        let plaintext = vault_addr_config("http://127.0.0.1:8200");
        let Err(err) = plaintext.validate() else {
            panic!("a plaintext Vault address must not pass validation");
        };
        assert!(matches!(err, Error::InvalidConfig(_)), "got {err}");
        assert!(
            err.to_string().contains("allow_insecure_addr"),
            "the refusal names the opt-in that would accept it: {err}"
        );

        let opted_in: Config = toml::from_str(
            "[vault]\naddr = \"http://127.0.0.1:8200\"\ntoken = \"t\"\nallow_insecure_addr = true\n",
        )
        .expect("test config parses");
        opted_in.validate().expect("an explicit dev opt-in is honoured");

        vault_addr_config("https://bao.internal:8200").validate().expect("https is the norm");
    }

    /// `vaultrs`' address setter is documented "# Panics" and unwraps a
    /// `Url::parse`, so a typo that reaches it aborts the process from inside
    /// the async connect path instead of failing at startup like every
    /// neighbouring misconfiguration.
    #[test]
    fn a_malformed_vault_addr_is_a_startup_error() {
        for addr in ["a", "https://[", "", "bao.internal:8200"] {
            let Err(err) = vault_addr_config(addr).validate() else {
                panic!("{addr:?} is not a Vault address and must not validate");
            };
            assert!(matches!(err, Error::InvalidConfig(_)), "{addr:?} gave {err}");
        }

        let Err(err) = vault_addr_config("file:///etc/passwd").validate() else {
            panic!("only http(s) reaches a Vault server");
        };
        assert!(err.to_string().contains("https"), "the refusal names what is expected: {err}");
    }

    /// The data hop sends its own SSLRequest and hard-fails on anything but
    /// `S`; the control hop lets the DSN decide, and `tokio_postgres` defaults
    /// to `sslmode=prefer`. Leaving the more sensitive of the two hops
    /// downgradeable while the other is not enforces neither half.
    #[test]
    fn a_downgradeable_control_dsn_is_refused_once_upstream_tls_is_configured() {
        let config = |dsn: &str, tls: &str| -> Config {
            toml::from_str(&format!(
                "control_dsn = {dsn:?}\nkeys_file = \"k\"\n{tls}\n\
                 [[column]]\ntable = \"users\"\ncolumn = \"email\"\n"
            ))
            .expect("test config parses")
        };
        let upstream_tls = "[tls.upstream]\nca = \"ca.pem\"\n\n";

        for dsn in [
            // `prefer`, by omission and by name.
            "postgres://dbsec:hunter2@db.internal:5433/app",
            "postgres://dbsec:hunter2@db.internal:5433/app?sslmode=prefer",
            "host=db.internal password=hunter2 sslmode=disable",
        ] {
            let Err(err) = config(dsn, upstream_tls).validate() else {
                panic!("{dsn} accepts a plaintext control session and must be refused");
            };
            assert!(matches!(err, Error::InvalidConfig(_)), "got {err}");
            assert!(
                err.to_string().contains("sslmode=require"),
                "the refusal names the fix: {err}"
            );
            assert!(!err.to_string().contains("hunter2"), "the password must not surface: {err}");
        }

        config("postgres://dbsec@db.internal:5433/app?sslmode=require", upstream_tls)
            .validate()
            .expect("sslmode=require cannot fall back to plaintext");
        config("host=db.internal password=hunter2 sslmode=require", upstream_tls)
            .validate()
            .expect("the keyword/value form is checked the same way as the URL form");

        // Without `[tls.upstream]` the operator has asked for no TLS on the
        // data hop either; the control hop is not held to a bar the rest of
        // the deployment does not meet.
        config("postgres://dbsec@db.internal:5433/app", "")
            .validate()
            .expect("plaintext upstream leaves the control hop alone");
    }

    /// A `control_dsn` that `tokio_postgres` cannot parse never connects
    /// either, so it is a config error — and the diagnosis must not quote the
    /// part of the string the password lives in.
    #[test]
    fn an_unparseable_control_dsn_is_refused_without_being_echoed() {
        let cfg: Config = toml::from_str(
            "control_dsn = \"host=db.internal password='unterminated\"\nkeys_file = \"k\"\n\n\
             [tls.upstream]\nca = \"ca.pem\"\n\n\
             [[column]]\ntable = \"users\"\ncolumn = \"email\"\n",
        )
        .expect("test config parses");

        let Err(err) = cfg.validate() else { panic!("an unparseable control_dsn must be refused") };
        assert!(matches!(err, Error::InvalidConfig(_)), "got {err}");
        assert!(!err.to_string().contains("unterminated"), "the DSN must not be echoed: {err}");
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
        let cfg: Config = toml::from_str(&format!(
            "[vault]\naddr = \"https://bao.internal:8200\"\ntoken_file = {token:?}\n"
        ))
        .unwrap();
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
            "control_dsn = \"postgres://x\"\n\n[vault]\naddr = \"https://bao.internal:8200\"\ntoken_file = {token:?}\n\n\
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

    /// The parse error an operator meets most often is a lost quote, and the
    /// line it lands on is as likely as not the one holding the Vault token or
    /// the DSN password. `toml`'s own `Display` quotes that line back; nothing
    /// this crate renders may.
    #[cfg(unix)]
    #[test]
    fn a_parse_failure_never_echoes_the_line_it_failed_on() {
        let dir = tempfile::tempdir().unwrap();
        let cases = [
            // A lost closing quote on the token: the classic fat-finger.
            ("token.toml", "[vault]\naddr = \"a\"\ntoken = \"s3cr3t-token\n", "s3cr3t-token"),
            // A value serde rejects by *type*, whose message quotes it.
            ("typed.toml", "[vault]\naddr = \"a\"\ntoken = 31337\n", "31337"),
            // The other credential in the file.
            (
                "dsn.toml",
                "control_dsn = \"postgres://dbsec:hunter2@db/app\"\nmax_sessions = \n",
                "hunter2",
            ),
        ];

        for (name, text, secret) in cases {
            let path = write_mode(dir.path(), name, text, 0o600);
            let Err(err) = Config::load(&path) else {
                panic!("{name} must not parse");
            };
            assert!(matches!(err, Error::ConfigParse { .. }), "{name}: got {err:?}");
            let rendered = format!("{err}");
            assert!(!rendered.contains(secret), "{name} leaked {secret}: {rendered}");
            assert!(!format!("{err:?}").contains(secret), "{name} leaked via Debug: {err:?}");
            assert!(
                std::error::Error::source(&err).is_none(),
                "{name}: keeping the toml error as a source would print the snippet back"
            );
            assert!(rendered.contains("line"), "{name} must still say where: {rendered}");
        }
    }

    /// A parse failure that touches nothing sensitive keeps the parser's own
    /// words — withholding every message would trade one leak for a config
    /// nobody can debug.
    #[cfg(unix)]
    #[test]
    fn a_parse_failure_on_an_ordinary_line_keeps_its_message() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_mode(dir.path(), "typo.toml", "listne = \"oops\"\n", 0o600);

        let Err(err) = Config::load(&path) else {
            panic!("an unknown field must not parse");
        };
        let rendered = format!("{err}");
        assert!(rendered.contains("unknown field"), "{rendered}");
        assert!(rendered.contains("line 1"), "{rendered}");
    }

    /// SEC-29 for the config file itself: it is a secret file whenever it
    /// carries the credential inline, and `0644` on it hands every local user
    /// the token that unwraps every DEK.
    #[cfg(unix)]
    #[test]
    fn a_config_holding_an_inline_secret_must_be_readable_only_by_its_owner() {
        let dir = tempfile::tempdir().unwrap();
        let inline_token = "[vault]\naddr = \"https://bao.internal:8200\"\ntoken = \"s3cr3t\"\n";

        let tight = write_mode(dir.path(), "tight.toml", inline_token, 0o600);
        Config::load(&tight).unwrap();

        for (name, mode) in [("group.toml", 0o640), ("world.toml", 0o644)] {
            let loose = write_mode(dir.path(), name, inline_token, mode);
            let Err(err) = Config::load(&loose) else {
                panic!("a {mode:04o} config holding an inline token must not be accepted");
            };
            assert!(matches!(err, Error::InvalidConfig(_)), "got {err:?}");
            assert!(err.to_string().contains(&format!("{mode:04o}")), "name the mode: {err}");
            assert!(err.to_string().contains("[vault] token"), "name the credential: {err}");
        }

        // A password in the control DSN is the same credential class.
        let dsn = write_mode(
            dir.path(),
            "dsn.toml",
            "control_dsn = \"postgres://dbsec:hunter2@db.internal/app\"\n",
            0o644,
        );
        let Err(err) = Config::load(&dsn) else {
            panic!("a world-readable config holding a DSN password must not be accepted");
        };
        assert!(err.to_string().contains("control_dsn password"), "{err}");
        assert!(!err.to_string().contains("hunter2"), "the refusal itself must not leak it: {err}");
    }

    /// The other half: a config that holds no credential is an ordinary file
    /// and keeps working at the mode a checkout or a config-management run
    /// gives it.
    #[cfg(unix)]
    #[test]
    fn a_config_with_no_inline_secret_is_unaffected_by_its_mode() {
        let dir = tempfile::tempdir().unwrap();
        let token_file = write_mode(dir.path(), "token", "s3cr3t\n", 0o600);
        let text = format!(
            "listen = \"127.0.0.1:6432\"\ncontrol_dsn = \"postgres://dbsec@db.internal/app\"\n\n\
             [vault]\naddr = \"https://bao.internal:8200\"\ntoken_file = {token_file:?}\n"
        );

        let world_readable = write_mode(dir.path(), "public.toml", &text, 0o644);
        Config::load(&world_readable).unwrap();
    }

    /// ERR-9/ERR-13: a `token_file` that cannot be read names the path and
    /// keeps the `io::Error` as a source, so "no such file" is told apart from
    /// "permission denied" without the operator guessing.
    #[test]
    fn an_unreadable_token_file_names_the_path_and_keeps_its_cause() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("absent-token");
        let cfg: Config = toml::from_str(&format!(
            "control_dsn = \"postgres://x\"\n\n[vault]\n\
             addr = \"https://bao.internal:8200\"\ntoken_file = {absent:?}\n"
        ))
        .unwrap();

        let err = cfg.validated().expect_err("a token file that is not there cannot resolve");
        let Error::VaultToken { path, source } = &err else {
            panic!("expected a token-file read error, got: {err}");
        };
        assert_eq!(path, &absent);
        assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
        assert!(err.to_string().contains(&absent.display().to_string()), "{err}");
        assert!(
            std::error::Error::source(&err).is_some(),
            "the io::Error stays reachable through the chain"
        );
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
