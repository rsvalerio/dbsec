//! TLS for both hops (milestone 3), each independently optional.
//!
//! Downstream: when `[tls.downstream]` is configured the proxy answers `S` to
//! SSLRequest and rejects clients that try to proceed in plaintext. Upstream:
//! when `[tls.upstream]` is configured the proxy sends SSLRequest and requires
//! a verified TLS connection (verify-full: CA and hostname).

use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

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

impl TlsContext {
    pub fn from_config(config: &Config) -> Result<Self, Error> {
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
    use super::*;

    #[test]
    fn upstream_host_strips_port_and_brackets() {
        assert_eq!(upstream_host("db.example.com:5432"), "db.example.com");
        assert_eq!(upstream_host("db.example.com"), "db.example.com");
        assert_eq!(upstream_host("127.0.0.1:5432"), "127.0.0.1");
        assert_eq!(upstream_host("[::1]:5432"), "::1");
    }
}
