//! TLS for both hops (milestone 3), each independently optional.
//!
//! Downstream: when `[tls.downstream]` is configured the proxy answers `S` to
//! SSLRequest and rejects clients that try to proceed in plaintext. Upstream:
//! when `[tls.upstream]` is configured the proxy sends SSLRequest and requires
//! a verified TLS connection (verify-full: CA and hostname).

use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::config::Config;
use crate::Error;

/// Per-process TLS state, built once at startup from the config.
pub struct TlsContext {
    pub acceptor: Option<TlsAcceptor>,
    pub connector: Option<(TlsConnector, ServerName<'static>)>,
    /// The upstream client config, kept for the control connection.
    pub upstream_client: Option<Arc<ClientConfig>>,
}

/// Installs the process-wide rustls crypto provider, and reports which one is
/// actually in force.
///
/// The dependency graph enables both `aws-lc-rs` (our rustls) and `ring`
/// (vaultrs via reqwest), so rustls cannot pick a default automatically and
/// whichever crate installs first wins. That provider decides the cipher
/// suites, key exchange groups and signature algorithms for *both* TLS hops,
/// so "whoever got there first" is not an acceptable answer: when a default
/// is already installed and its negotiation policy differs from the one this
/// build intends, startup fails with that difference spelled out rather than
/// running TLS on a policy nobody chose (SEC-8).
pub fn install_crypto_provider() -> Result<(), Error> {
    static OUTCOME: OnceLock<Result<(), String>> = OnceLock::new();
    OUTCOME
        .get_or_init(|| {
            let intended = rustls::crypto::aws_lc_rs::default_provider();
            let intended_policy = ProviderPolicy::of(&intended);
            if intended.install_default().is_ok() {
                return Ok(());
            }
            // The install lost a race. Its error carries the provider that was
            // *rejected* — ours — so the one actually in force has to be read
            // back from rustls rather than taken from the error.
            match CryptoProvider::get_default() {
                Some(in_force) => check_installed(in_force, &intended_policy),
                None => Err("rustls refused the crypto provider install but reports no default \
                             provider in force"
                    .to_owned()),
            }
        })
        .clone()
        .map_err(Error::TlsConfig)
}

/// Accepts an already-installed provider only when it negotiates exactly what
/// the intended one would.
fn check_installed(in_force: &CryptoProvider, intended: &ProviderPolicy) -> Result<(), String> {
    let in_force = ProviderPolicy::of(in_force);
    if in_force == *intended {
        tracing::debug!("rustls crypto provider was already installed with the intended policy");
        return Ok(());
    }
    Err(format!(
        "a foreign rustls crypto provider is already installed process-wide: in force {in_force}; \
         intended (aws-lc-rs) {intended}"
    ))
}

/// What a `CryptoProvider` will actually negotiate. Providers carry no name,
/// so they are compared — and reported — by the policy they implement, which
/// is the part that matters to a TLS peer.
#[derive(Debug, PartialEq, Eq)]
struct ProviderPolicy {
    suites: Vec<String>,
    kx_groups: Vec<String>,
}

impl ProviderPolicy {
    fn of(provider: &CryptoProvider) -> Self {
        Self {
            suites: provider.cipher_suites.iter().map(|s| format!("{:?}", s.suite())).collect(),
            kx_groups: provider.kx_groups.iter().map(|g| format!("{:?}", g.name())).collect(),
        }
    }
}

impl std::fmt::Display for ProviderPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cipher suites {:?}, key exchange groups {:?}", self.suites, self.kx_groups)
    }
}

impl TlsContext {
    pub fn from_config(config: &Config) -> Result<Self, Error> {
        install_crypto_provider()?;
        let acceptor = match &config.tls.downstream {
            Some(down) => {
                let certs = load_certs(&down.cert)?;
                let key = load_key(&down.key)?;
                let server_config = ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .map_err(|e| Error::TlsConfig(format!("downstream cert/key: {e}")))?;
                Some(TlsAcceptor::from(Arc::new(server_config)))
            }
            None => None,
        };

        let (connector, upstream_client) = match &config.tls.upstream {
            Some(up) => {
                let mut roots = RootCertStore::empty();
                for cert in load_certs(&up.ca)? {
                    roots.add(cert).map_err(|e| {
                        Error::TlsConfig(format!("upstream ca {}: {e}", up.ca.display()))
                    })?;
                }
                let client_config = Arc::new(
                    ClientConfig::builder().with_root_certificates(roots).with_no_client_auth(),
                );
                let hostname = match &up.hostname {
                    Some(name) => name.clone(),
                    None => upstream_host(&config.upstream).to_owned(),
                };
                let name = ServerName::try_from(hostname.clone()).map_err(|_| {
                    Error::TlsConfig(format!("invalid upstream hostname {hostname}"))
                })?;
                (Some((TlsConnector::from(client_config.clone()), name)), Some(client_config))
            }
            None => (None, None),
        };

        Ok(Self { acceptor, connector, upstream_client })
    }
}

/// The host part of `host:port` (a trailing `:port` is stripped; IPv6
/// brackets are removed).
fn upstream_host(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        return rest.split_once(']').map_or(rest, |(host, _)| host);
    }
    match addr.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => addr,
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, Error> {
    let certs: Result<Vec<_>, _> = CertificateDer::pem_file_iter(path)
        .map_err(|e| Error::TlsConfig(format!("opening {}: {e}", path.display())))?
        .collect();
    let certs = certs.map_err(|e| Error::TlsConfig(format!("reading {}: {e}", path.display())))?;
    if certs.is_empty() {
        return Err(Error::TlsConfig(format!("{} contains no certificates", path.display())));
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, Error> {
    PrivateKeyDer::from_pem_file(path)
        .map_err(|e| Error::TlsConfig(format!("reading {}: {e}", path.display())))
}

/// A stream that may or may not have been upgraded to TLS. Fixes the stream
/// type for the relay loops regardless of negotiation outcome.
pub enum MaybeTls<S> {
    Plain(S),
    /// Downstream hop: we are the TLS server.
    Server(Box<tokio_rustls::server::TlsStream<S>>),
    /// Upstream hop: we are the TLS client.
    Client(Box<tokio_rustls::client::TlsStream<S>>),
}

impl<S> MaybeTls<S> {
    pub fn is_plain(&self) -> bool {
        matches!(self, MaybeTls::Plain(_))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for MaybeTls<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTls::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTls::Server(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            MaybeTls::Client(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for MaybeTls<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MaybeTls::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTls::Server(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            MaybeTls::Client(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTls::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeTls::Server(s) => Pin::new(s.as_mut()).poll_flush(cx),
            MaybeTls::Client(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTls::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTls::Server(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            MaybeTls::Client(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::config::{DownstreamTls, TlsSection, UpstreamTls};

    use super::*;

    #[test]
    fn upstream_host_strips_port_and_brackets() {
        assert_eq!(upstream_host("db.example.com:5432"), "db.example.com");
        assert_eq!(upstream_host("db.example.com"), "db.example.com");
        assert_eq!(upstream_host("127.0.0.1:5432"), "127.0.0.1");
        assert_eq!(upstream_host("[::1]:5432"), "::1");
    }

    /// A self-signed pair, used both as a leaf and (self-signed) as its own CA.
    fn cert_pair() -> (String, String) {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        (generated.cert.pem(), generated.key_pair.serialize_pem())
    }

    fn write(dir: &tempfile::TempDir, name: &str, contents: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn message(err: &Error) -> String {
        match err {
            Error::TlsConfig(message) => message.clone(),
            other => panic!("expected a TlsConfig error, got {other}"),
        }
    }

    /// The message from a `from_config` that had to fail. Spelled out rather
    /// than `unwrap_err`, which would need `TlsContext: Debug` — and a
    /// `TlsContext` holds key material, so it deliberately has no `Debug`.
    fn config_error(result: Result<TlsContext, Error>) -> String {
        match result {
            Ok(_) => panic!("expected TlsContext::from_config to fail"),
            Err(err) => message(&err),
        }
    }

    fn downstream_config(cert: PathBuf, key: PathBuf) -> Config {
        Config {
            tls: TlsSection { downstream: Some(DownstreamTls { cert, key }), upstream: None },
            ..Config::default()
        }
    }

    fn upstream_config(ca: PathBuf, hostname: Option<String>, upstream: &str) -> Config {
        Config {
            upstream: upstream.to_owned(),
            tls: TlsSection { downstream: None, upstream: Some(UpstreamTls { ca, hostname }) },
            ..Config::default()
        }
    }

    #[test]
    fn load_certs_names_the_path_it_could_not_read() {
        let dir = tempfile::tempdir().unwrap();

        let absent = dir.path().join("absent.pem");
        let err = message(&load_certs(&absent).unwrap_err());
        assert!(err.contains(&absent.display().to_string()), "{err}");

        // A section that opens and never closes. (A body of non-base64 text
        // is *not* the case to use here: the PEM reader skips characters it
        // cannot decode and yields a short, garbage certificate rather than an
        // error — which rustls then rejects further down, at `with_single_cert`
        // or `RootCertStore::add`.)
        let truncated = write(&dir, "truncated.pem", "-----BEGIN CERTIFICATE-----\nMIIBkTCB+w==\n");
        let err = message(&load_certs(&truncated).unwrap_err());
        assert!(err.contains(&truncated.display().to_string()), "{err}");
    }

    /// The arm that exists to turn a silent success — an empty root store, or
    /// a server config with no chain — into a refusal to start.
    #[test]
    fn load_certs_rejects_a_pem_file_holding_no_certificates() {
        let dir = tempfile::tempdir().unwrap();
        let (_, key) = cert_pair();
        let key_only = write(&dir, "key-only.pem", &key);
        let err = message(&load_certs(&key_only).unwrap_err());
        assert!(err.contains(&key_only.display().to_string()), "{err}");
        assert!(err.contains("no certificates"), "{err}");
    }

    #[test]
    fn load_key_names_the_path_it_could_not_read() {
        let dir = tempfile::tempdir().unwrap();

        let absent = dir.path().join("absent.key");
        let err = message(&load_key(&absent).unwrap_err());
        assert!(err.contains(&absent.display().to_string()), "{err}");

        let garbage = write(&dir, "garbage.key", "this is not a private key\n");
        let err = message(&load_key(&garbage).unwrap_err());
        assert!(err.contains(&garbage.display().to_string()), "{err}");
    }

    #[test]
    fn from_config_rejects_a_cert_that_does_not_match_its_key() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, _) = cert_pair();
        let (_, other_key_pem) = cert_pair();
        let cert = write(&dir, "cert.pem", &cert_pem);
        let key = write(&dir, "other.key", &other_key_pem);

        let err = config_error(TlsContext::from_config(&downstream_config(cert, key)));
        assert!(err.contains("downstream cert/key"), "{err}");
    }

    #[test]
    fn from_config_reports_a_missing_downstream_cert() {
        let dir = tempfile::tempdir().unwrap();
        let (_, key_pem) = cert_pair();
        let cert = dir.path().join("absent.pem");
        let key = write(&dir, "key.pem", &key_pem);

        let err = config_error(TlsContext::from_config(&downstream_config(cert.clone(), key)));
        assert!(err.contains(&cert.display().to_string()), "{err}");
    }

    #[test]
    fn from_config_rejects_an_empty_upstream_ca_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let ca = write(&dir, "ca.pem", "# no PEM blocks here\n");

        let err = config_error(TlsContext::from_config(&upstream_config(
            ca.clone(),
            None,
            "db.example.com:5432",
        )));
        assert!(err.contains(&ca.display().to_string()), "{err}");
        assert!(err.contains("no certificates"), "{err}");
    }

    #[test]
    fn from_config_rejects_an_invalid_upstream_hostname() {
        let dir = tempfile::tempdir().unwrap();
        let (ca_pem, _) = cert_pair();
        let ca = write(&dir, "ca.pem", &ca_pem);

        let config = upstream_config(ca, Some("not a hostname".to_owned()), "db.example.com:5432");
        let err = config_error(TlsContext::from_config(&config));
        assert!(err.contains("invalid upstream hostname"), "{err}");
        assert!(err.contains("not a hostname"), "{err}");
    }

    /// `[tls.upstream]` without `hostname` verifies against the host part of
    /// `upstream` — the default an operator relies on when the two agree.
    #[test]
    fn the_upstream_hostname_defaults_to_the_upstream_host() {
        let dir = tempfile::tempdir().unwrap();
        let (ca_pem, _) = cert_pair();
        let ca = write(&dir, "ca.pem", &ca_pem);

        let context =
            TlsContext::from_config(&upstream_config(ca.clone(), None, "db.example.com:5432"))
                .unwrap();
        let (_, name) = context.connector.expect("upstream TLS is configured");
        assert_eq!(name.to_str(), "db.example.com");

        // An explicit hostname still wins over the derived one.
        let context = TlsContext::from_config(&upstream_config(
            ca,
            Some("other.example.com".to_owned()),
            "db.example.com:5432",
        ))
        .unwrap();
        let (_, name) = context.connector.expect("upstream TLS is configured");
        assert_eq!(name.to_str(), "other.example.com");
    }

    /// The point of SEC-8: the provider in force is compared, not assumed, and
    /// a policy that differs from the intended one is reported rather than
    /// silently accepted.
    #[test]
    fn a_foreign_installed_provider_is_reported() {
        install_crypto_provider().expect("this process installs its own provider");
        // Repeat calls report the same outcome instead of re-racing.
        install_crypto_provider().unwrap();

        let intended = ProviderPolicy::of(&rustls::crypto::aws_lc_rs::default_provider());
        let in_force = CryptoProvider::get_default().expect("the install above put one in force");
        assert!(
            check_installed(in_force, &intended).is_ok(),
            "the provider in force is the intended one"
        );

        // A provider negotiating something else is refused, naming both sides.
        let mut narrowed = rustls::crypto::aws_lc_rs::default_provider();
        narrowed.cipher_suites.truncate(1);
        let narrowed_policy = ProviderPolicy::of(&narrowed);
        assert_ne!(narrowed_policy, intended);
        let err = check_installed(&narrowed, &intended)
            .expect_err("a provider with a different policy must be reported");
        assert!(err.contains("cipher suites"), "{err}");

        // The API `install_crypto_provider` hinges on: a losing install hands
        // back the provider it *rejected*, not the one in force — which is why
        // the check reads `get_default()` instead of trusting the error.
        let rejected = narrowed.install_default().expect_err("a default is already installed");
        assert_eq!(ProviderPolicy::of(&rejected), narrowed_policy);
    }
}
