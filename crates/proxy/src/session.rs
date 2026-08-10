//! One client connection: startup negotiation (including TLS on either hop),
//! then a frame-aware relay in each direction. The upstream→client relay
//! runs the row decryptor; client→upstream is still untouched until the
//! encrypt milestone.

use std::sync::Arc;
use std::time::Duration;

use dbsec_core::pgwire::{self, Startup};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::encrypt::{QueryRewriter, WriteCatalog};
use crate::rows::RowContext;
use crate::tls::{MaybeTls, TlsContext};
use crate::Error;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Everything a session needs beyond its socket.
pub struct SessionContext {
    pub upstream_addr: String,
    pub tls: TlsContext,
    pub rows: Option<Arc<RowContext>>,
    pub writes: Option<Arc<WriteCatalog>>,
}

pub async fn run(client: TcpStream, ctx: &SessionContext) -> Result<(), Error> {
    let (upstream_addr, tls) = (ctx.upstream_addr.as_str(), &ctx.tls);
    let mut client = MaybeTls::Plain(client);

    // Startup phase: answer SSLRequest/GSSENCRequest locally, upgrade to TLS
    // when configured, and only then forward the real startup message.
    let startup = loop {
        let Some(msg) = read_startup_message(&mut client).await? else {
            return Ok(()); // client connected and left (health check)
        };
        let mut code = [0u8; 4];
        code.copy_from_slice(&msg[4..8]);
        match pgwire::startup_kind(i32::from_be_bytes(code)) {
            Startup::Tls => match (&tls.acceptor, client) {
                (Some(acceptor), MaybeTls::Plain(mut sock)) => {
                    sock.write_all(b"S").await?;
                    client = MaybeTls::Server(Box::new(acceptor.accept(sock).await?));
                }
                // Second SSLRequest, or SSLRequest without TLS configured.
                (_, mut other) => {
                    other.write_all(b"N").await?;
                    client = other;
                }
            },
            Startup::GssEnc => client.write_all(b"N").await?,
            Startup::Cancel | Startup::Protocol(_) => {
                if tls.acceptor.is_some() && client.is_plain() {
                    return Err(Error::PlaintextRejected);
                }
                break msg;
            }
        }
    };

    let upstream_tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(upstream_addr))
        .await
        .map_err(|_| Error::ConnectTimeout { addr: upstream_addr.to_owned() })??;
    let mut upstream = match &tls.connector {
        Some((connector, name)) => {
            let sock = request_upstream_tls(upstream_tcp, upstream_addr).await?;
            MaybeTls::Client(Box::new(connector.connect(name.clone(), sock).await?))
        }
        None => MaybeTls::Plain(upstream_tcp),
    };
    upstream.write_all(&startup).await?;

    let mut decryptor = ctx.rows.as_ref().map(|rows| rows.decryptor());
    let mut rewriter = ctx.writes.as_ref().map(|writes| QueryRewriter::new(writes.clone()));
    let (client_r, client_w) = tokio::io::split(client);
    let (upstream_r, upstream_w) = tokio::io::split(upstream);
    tokio::try_join!(
        relay(client_r, upstream_w, "client->upstream", move |msg_type, body| {
            match &mut rewriter {
                Some(rewriter) => rewriter.on_frame(msg_type, body),
                None => Ok(None),
            }
        }),
        relay(upstream_r, client_w, "upstream->client", move |msg_type, body| {
            match &mut decryptor {
                Some(decryptor) => decryptor.on_frame(msg_type, body),
                None => Ok(None),
            }
        }),
    )?;
    Ok(())
}

/// Sends SSLRequest upstream and requires the `S` answer; a server that
/// refuses TLS fails the session (verify-full, no downgrade).
async fn request_upstream_tls(mut sock: TcpStream, addr: &str) -> Result<TcpStream, Error> {
    let mut request = 8i32.to_be_bytes().to_vec();
    request.extend_from_slice(&pgwire::SSL_REQUEST.to_be_bytes());
    sock.write_all(&request).await?;
    let mut answer = [0u8; 1];
    sock.read_exact(&mut answer).await?;
    if &answer != b"S" {
        return Err(Error::UpstreamTlsRefused { addr: addr.to_owned() });
    }
    Ok(sock)
}

/// Reads one startup-phase message (which has no type byte). Returns the full
/// message including its length field, or `None` on a clean pre-startup EOF.
async fn read_startup_message<S>(stream: &mut S) -> Result<Option<Vec<u8>>, Error>
where
    S: AsyncRead + Unpin,
{
    let mut len_field = [0u8; 4];
    match stream.read_exact(&mut len_field).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let body_len = pgwire::startup_body_len(len_field)?;
    let mut msg = vec![0u8; 4 + body_len];
    msg[..4].copy_from_slice(&len_field);
    stream.read_exact(&mut msg[4..]).await?;
    Ok(Some(msg))
}

/// Copies framed messages from `reader` to `writer` until EOF at a frame
/// boundary, passing each frame through `transform` (which returns a
/// replacement body, or `None` to relay untouched). EOF mid-frame is an
/// error; frames with invalid lengths or failing transforms abort the
/// session rather than desyncing the relay or leaking ciphertext.
async fn relay<R, W, T>(
    mut reader: R,
    mut writer: W,
    direction: &str,
    mut transform: T,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    T: FnMut(u8, &[u8]) -> Result<Option<Vec<u8>>, Error>,
{
    let mut header = [0u8; pgwire::FRAME_HEADER_LEN];
    let mut body = Vec::new();
    loop {
        match reader.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                writer.shutdown().await.ok();
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
        let (msg_type, body_len) = pgwire::frame_body_len(&header).map_err(|e| {
            tracing::warn!(direction, error = %e, "aborting desynced relay");
            e
        })?;
        body.resize(body_len, 0);
        reader.read_exact(&mut body).await?;
        tracing::trace!(direction, msg_type = %(msg_type as char), body_len, "relayed frame");
        match transform(msg_type, &body).map_err(|e| {
            tracing::error!(direction, msg_type = %(msg_type as char), error = %e, "transform failed; closing session");
            e
        })? {
            Some(new_body) => {
                let mut new_header = [msg_type; pgwire::FRAME_HEADER_LEN];
                new_header[1..].copy_from_slice(&(4 + new_body.len() as i32).to_be_bytes());
                writer.write_all(&new_header).await?;
                writer.write_all(&new_body).await?;
            }
            None => {
                writer.write_all(&header).await?;
                writer.write_all(&body).await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn frame(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![msg_type];
        out.extend_from_slice(&(4 + body.len() as i32).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn ssl_request() -> Vec<u8> {
        let mut msg = 8i32.to_be_bytes().to_vec();
        msg.extend_from_slice(&pgwire::SSL_REQUEST.to_be_bytes());
        msg
    }

    fn startup_v3() -> Vec<u8> {
        let params = b"user\0test\0\0";
        let mut msg = ((8 + params.len()) as i32).to_be_bytes().to_vec();
        msg.extend_from_slice(&pgwire::PROTOCOL_V3.to_be_bytes());
        msg.extend_from_slice(params);
        msg
    }

    fn plain_ctx(upstream_addr: &str) -> SessionContext {
        SessionContext {
            upstream_addr: upstream_addr.to_owned(),
            tls: TlsContext::from_config(&Config::default()).unwrap(),
            rows: None,
            writes: None,
        }
    }

    /// Self-signed cert for `localhost`, written as PEM files.
    fn test_cert(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        (cert_path, key_path)
    }

    /// Fake plaintext upstream: reads the startup message, answers with an
    /// `R` frame, echoes the startup back through the task handle.
    async fn spawn_fake_upstream() -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut len_field = [0u8; 4];
            sock.read_exact(&mut len_field).await.unwrap();
            let mut startup = vec![0u8; i32::from_be_bytes(len_field) as usize];
            startup[..4].copy_from_slice(&len_field);
            sock.read_exact(&mut startup[4..]).await.unwrap();
            sock.write_all(&frame(b'R', &0i32.to_be_bytes())).await.unwrap();
            sock.shutdown().await.unwrap();
            startup
        });
        (addr, task)
    }

    #[tokio::test]
    async fn relay_rewrites_transformed_frames_and_lengths() {
        let mut input = frame(b'D', b"old");
        input.extend_from_slice(&frame(b'Z', b"I"));
        let mut output = Vec::new();
        relay(input.as_slice(), &mut output, "test", |msg_type, body| {
            assert!(matches!(msg_type, b'D' | b'Z'));
            Ok((msg_type == b'D' && body == b"old").then(|| b"rewritten".to_vec()))
        })
        .await
        .unwrap();

        let mut expected = frame(b'D', b"rewritten");
        expected.extend_from_slice(&frame(b'Z', b"I"));
        assert_eq!(output, expected);
    }

    #[tokio::test]
    async fn relay_fails_closed_on_transform_error() {
        let input = frame(b'D', b"boom");
        let mut output = Vec::new();
        let result = relay(input.as_slice(), &mut output, "test", |_, _| {
            Err(Error::Wire(dbsec_core::Error::Decrypt))
        })
        .await;
        assert!(result.is_err());
        assert!(output.is_empty());
    }

    #[tokio::test]
    async fn session_negotiates_ssl_refusal_and_relays() {
        let (upstream_addr, upstream_task) = spawn_fake_upstream().await;

        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let session = tokio::spawn(async move {
            let (sock, _) = proxy.accept().await.unwrap();
            run(sock, &plain_ctx(&upstream_addr)).await
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(&ssl_request()).await.unwrap();
        let mut answer = [0u8; 1];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"N");

        let startup = startup_v3();
        client.write_all(&startup).await.unwrap();

        let mut auth = vec![0u8; 9];
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, frame(b'R', &0i32.to_be_bytes()));

        assert_eq!(upstream_task.await.unwrap(), startup);
        client.shutdown().await.unwrap();
        session.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn downstream_tls_handshakes_and_rejects_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) = test_cert(dir.path());
        let (upstream_addr, upstream_task) = spawn_fake_upstream().await;

        let config: Config = toml::from_str(&format!(
            "[tls.downstream]\ncert = {:?}\nkey = {:?}\n",
            cert_path, key_path
        ))
        .unwrap();
        let first_ctx = SessionContext {
            upstream_addr: "127.0.0.1:1".to_owned(),
            tls: TlsContext::from_config(&config).unwrap(),
            rows: None,
            writes: None,
        };
        let second_ctx = SessionContext {
            upstream_addr,
            tls: TlsContext::from_config(&config).unwrap(),
            rows: None,
            writes: None,
        };

        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let sessions = tokio::spawn(async move {
            // First connection: plaintext startup → rejected.
            let (sock, _) = proxy.accept().await.unwrap();
            let plaintext_result = run(sock, &first_ctx).await;
            // Second connection: TLS handshake, then relayed startup.
            let (sock, _) = proxy.accept().await.unwrap();
            let tls_result = run(sock, &second_ctx).await;
            (plaintext_result, tls_result)
        });

        // Plaintext client is refused before anything reaches an upstream.
        let mut plain = TcpStream::connect(proxy_addr).await.unwrap();
        plain.write_all(&startup_v3()).await.unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(plain.read(&mut buf).await.unwrap(), 0);
        drop(plain);

        // TLS client: SSLRequest → 'S' → handshake → startup relayed.
        use rustls::pki_types::pem::PemObject;
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls::pki_types::CertificateDer::pem_file_iter(&cert_path).unwrap() {
            roots.add(cert.unwrap()).unwrap();
        }
        let client_config = std::sync::Arc::new(
            rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth(),
        );
        let mut sock = TcpStream::connect(proxy_addr).await.unwrap();
        sock.write_all(&ssl_request()).await.unwrap();
        let mut answer = [0u8; 1];
        sock.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"S");
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut client = connector.connect(name, sock).await.unwrap();

        let startup = startup_v3();
        client.write_all(&startup).await.unwrap();
        let mut auth = vec![0u8; 9];
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, frame(b'R', &0i32.to_be_bytes()));

        assert_eq!(upstream_task.await.unwrap(), startup);
        client.shutdown().await.unwrap();
        let (plaintext_result, tls_result) = sessions.await.unwrap();
        assert!(matches!(plaintext_result, Err(Error::PlaintextRejected)));
        tls_result.unwrap();
    }

    #[tokio::test]
    async fn upstream_tls_negotiates_and_refusal_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) = test_cert(dir.path());

        // Fake TLS upstream: answers 'S', handshakes, reads startup, replies.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap().to_string();
        use rustls::pki_types::pem::PemObject;
        let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_file_iter(&cert_path)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let key = rustls::pki_types::PrivateKeyDer::from_pem_file(&key_path).unwrap();
        let upstream_task = tokio::spawn(async move {
            let server_config = std::sync::Arc::new(
                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .unwrap(),
            );
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 8];
            sock.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[4..], pgwire::SSL_REQUEST.to_be_bytes());
            sock.write_all(b"S").await.unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let mut tls_sock = acceptor.accept(sock).await.unwrap();
            let mut len_field = [0u8; 4];
            tls_sock.read_exact(&mut len_field).await.unwrap();
            let mut startup = vec![0u8; i32::from_be_bytes(len_field) as usize];
            startup[..4].copy_from_slice(&len_field);
            tls_sock.read_exact(&mut startup[4..]).await.unwrap();
            tls_sock.write_all(&frame(b'R', &0i32.to_be_bytes())).await.unwrap();
            tls_sock.shutdown().await.unwrap();
            startup
        });

        let config: Config = toml::from_str(&format!(
            "upstream = \"{upstream_addr}\"\n\n[tls.upstream]\nca = {cert_path:?}\nhostname = \"localhost\"\n",
        ))
        .unwrap();
        let ctx = SessionContext {
            upstream_addr: config.upstream.clone(),
            tls: TlsContext::from_config(&config).unwrap(),
            rows: None,
            writes: None,
        };

        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let session = tokio::spawn(async move {
            let (sock, _) = proxy.accept().await.unwrap();
            run(sock, &ctx).await
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let startup = startup_v3();
        client.write_all(&startup).await.unwrap();
        let mut auth = vec![0u8; 9];
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, frame(b'R', &0i32.to_be_bytes()));
        assert_eq!(upstream_task.await.unwrap(), startup);
        client.shutdown().await.unwrap();
        session.await.unwrap().unwrap();

        // An upstream that answers 'N' fails the session (no downgrade).
        let refusing = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let refusing_addr = refusing.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut sock, _) = refusing.accept().await.unwrap();
            let mut request = [0u8; 8];
            sock.read_exact(&mut request).await.unwrap();
            sock.write_all(b"N").await.unwrap();
        });
        let config: Config = toml::from_str(&format!(
            "upstream = \"{refusing_addr}\"\n\n[tls.upstream]\nca = {cert_path:?}\nhostname = \"localhost\"\n",
        ))
        .unwrap();
        let ctx = SessionContext {
            upstream_addr: config.upstream.clone(),
            tls: TlsContext::from_config(&config).unwrap(),
            rows: None,
            writes: None,
        };
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let session = tokio::spawn(async move {
            let (sock, _) = proxy.accept().await.unwrap();
            run(sock, &ctx).await
        });
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(&startup_v3()).await.unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(client.read(&mut buf).await.unwrap(), 0);
        assert!(matches!(session.await.unwrap(), Err(Error::UpstreamTlsRefused { .. })));
    }
}
