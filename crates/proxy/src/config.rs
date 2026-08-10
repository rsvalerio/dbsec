//! Flat TOML configuration: addresses, optional TLS for each hop, the keyfile,
//! and `[[column]]` entries naming the protected columns.

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
    /// TOML keyfile for `FileKeySource` (see `dbsec_core::keys`). Required
    /// when any `[[column]]` is configured.
    pub keys_file: Option<PathBuf>,
    /// DSN for the startup control connection that resolves configured
    /// columns to table OID + attnum. Required when any `[[column]]` is
    /// configured, e.g. `postgres://dbsec:secret@127.0.0.1:5432/app`.
    pub control_dsn: Option<String>,
    #[serde(default)]
    pub tls: TlsSection,
    #[serde(default, rename = "column")]
    pub columns: Vec<ColumnConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColumnConfig {
    /// Table name, optionally schema-qualified; bare names mean `public`.
    pub table: String,
    /// Column name within the table.
    pub column: String,
    /// Searchable columns carry a blind index before the envelope (stripped
    /// on read; equality rewrite arrives with the searchable milestone).
    #[serde(default)]
    pub searchable: bool,
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

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            upstream: default_upstream(),
            keys_file: None,
            control_dsn: None,
            tls: TlsSection::default(),
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
        if !self.columns.is_empty() {
            if self.keys_file.is_none() {
                return Err(Error::InvalidConfig("[[column]] entries require keys_file".into()));
            }
            if self.control_dsn.is_none() {
                return Err(Error::InvalidConfig("[[column]] entries require control_dsn".into()));
            }
        }
        let mut seen = std::collections::HashSet::new();
        for column in &self.columns {
            let (schema, table) = column.schema_and_table();
            if !seen.insert((schema.to_owned(), table.to_owned(), column.column.clone())) {
                return Err(Error::InvalidConfig(format!(
                    "duplicate [[column]] entry for {schema}.{table}.{}",
                    column.column
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
    }

    #[test]
    fn unknown_fields_are_rejected() {
        assert!(toml::from_str::<Config>("listne = \"oops\"").is_err());
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
