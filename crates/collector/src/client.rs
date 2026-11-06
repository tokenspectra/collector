//! The Collector's outbound HTTP/1.1 client: one POST per connection, plain
//! or over TLS, with a deadline it keeps asking about. The shipper
//! ([`crate::ship`]) and the Fleet channel ([`crate::fleet`]) both use it.
//!
//! An [`Endpoint`] is built by scheme: [`Endpoint::tls`] takes only
//! `https://`, [`Endpoint::plain`] only `http://`. Plain is for development;
//! `--dev-plain-http` is what lets the command line reach it.
//!
//! TLS is 1.3 only. The client's key stays behind [`KeyProvider`]: rustls
//! asks it for signatures and never holds the key itself.
//!
//! A response is read to the end of the connection, as `Connection: close`
//! asks, and its body is taken as sent: chunked replies aren't decoded.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use std::sync::mpsc::RecvTimeoutError;

use rustls::client::ResolvesClientCert;
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, SignatureAlgorithm, SignatureScheme, StreamOwned,
};

use crate::sign::KeyProvider;

/// The longest a request waits on the socket before its deadline is asked
/// about again.
pub const SLICE: Duration = Duration::from_millis(50);

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("URL {0:?}: expected {1}://host[:port]/path")]
    Url(String, &'static str),
    #[error("TLS: {0}")]
    Tls(String),
    /// Worth retrying: the far end is down, busy or out of time.
    #[error("{0}")]
    Unavailable(String),
    #[error("{0}")]
    Io(#[from] io::Error),
}

/// Where a request goes.
#[derive(Clone, Debug)]
pub struct Endpoint {
    host: String,
    port: u16,
    path: String,
    /// `None` is plain `http://`.
    tls: Option<Arc<ClientConfig>>,
}

impl PartialEq for Endpoint {
    fn eq(&self, other: &Self) -> bool {
        (&self.host, self.port, &self.path, self.tls.is_some())
            == (&other.host, other.port, &other.path, other.tls.is_some())
    }
}

impl Eq for Endpoint {}

impl Endpoint {
    /// Parses `http://host[:port][/path]`. For development only.
    pub fn plain(url: &str) -> Result<Self, ClientError> {
        let (host, port, path) = parse(url, "http", 80)?;
        Ok(Endpoint {
            host,
            port,
            path,
            tls: None,
        })
    }

    /// Parses `https://host[:port][/path]`, to be reached with `tls`.
    pub fn tls(url: &str, tls: Arc<ClientConfig>) -> Result<Self, ClientError> {
        let (host, port, path) = parse(url, "https", 443)?;
        Ok(Endpoint {
            host,
            port,
            path,
            tls: Some(tls),
        })
    }

    /// `host:port`, for messages.
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// POSTs `body` to the endpoint's path plus `suffix` and returns the
    /// status and at most `limit` bytes of the response. Gives up once
    /// `until()` has passed; it is asked again at least every [`SLICE`]
    /// while the address is looked up, the connection made, the request
    /// written and the response awaited, so a deadline that moves closer
    /// cuts the request short at any of them.
    pub fn post(
        &self,
        suffix: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        limit: usize,
        until: &mut dyn FnMut() -> Instant,
    ) -> Result<(u16, Vec<u8>), ClientError> {
        let unavailable = |e: io::Error| ClientError::Unavailable(format!("{}: {e}", self.authority()));
        let mut left = || match until().checked_duration_since(Instant::now()) {
            Some(d) if !d.is_zero() => Ok(d),
            _ => Err(ClientError::Unavailable(format!(
                "{}: timed out",
                self.authority()
            ))),
        };
        let tcp = self.connect(&mut left)?;
        let mut conn = match &self.tls {
            None => Conn::Plain(tcp),
            Some(cfg) => {
                let name = ServerName::try_from(self.host.clone())
                    .map_err(|e| ClientError::Tls(format!("{}: {e}", self.host)))?;
                let tls =
                    ClientConnection::new(cfg.clone(), name).map_err(|e| ClientError::Tls(e.to_string()))?;
                Conn::Tls(Box::new(StreamOwned::new(tls, tcp)))
            }
        };
        let host = if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            self.authority()
        };
        let mut head = format!("POST {}{suffix} HTTP/1.1\r\nHost: {host}\r\n", self.path);
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        ));
        for mut part in [head.as_bytes(), body] {
            while !part.is_empty() {
                conn.set_timeout(left()?.min(SLICE)).map_err(unavailable)?;
                match conn.write(part) {
                    Ok(0) => return Err(unavailable(io::ErrorKind::WriteZero.into())),
                    Ok(n) => part = &part[n..],
                    Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(unavailable(e)),
                }
            }
        }
        let mut resp = Vec::new();
        let mut buf = [0u8; 4096];
        while resp.len() < limit {
            conn.set_timeout(left()?.min(SLICE)).map_err(unavailable)?;
            match conn.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => resp.extend_from_slice(&buf[..n]),
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                // A TLS peer that closes without close_notify: fine if
                // the whole response is here, a cut one otherwise.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && whole(&resp) => break,
                Err(e) => return Err(unavailable(e)),
            }
        }
        let status = resp
            .split(|&b| b == b'\n')
            .next()
            .and_then(|l| std::str::from_utf8(l).ok())
            .and_then(|l| l.split(' ').nth(1))
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| ClientError::Unavailable("no HTTP status in the response".into()))?;
        let body = head_end(&resp).map_or(&[][..], |i| &resp[i..]).to_vec();
        Ok((status, body))
    }

    /// Looks up the host and connects to it on a helper thread, waiting on
    /// it in [`SLICE`]s so that `left()` running out is noticed. A thread
    /// given up on finishes on its own: its connect is bounded by the time
    /// left when it started, its lookup only by the resolver.
    fn connect(
        &self,
        left: &mut dyn FnMut() -> Result<Duration, ClientError>,
    ) -> Result<TcpStream, ClientError> {
        let (host, port, budget) = (self.host.clone(), self.port, left()?);
        let (tx, rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("client-connect".into())
            .spawn(move || {
                let conn = (host.as_str(), port)
                    .to_socket_addrs()
                    .and_then(|mut addrs| {
                        addrs
                            .next()
                            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address"))
                    })
                    .and_then(|addr| TcpStream::connect_timeout(&addr, budget));
                let _ = tx.send(conn);
            })?;
        loop {
            match rx.recv_timeout(left()?.min(SLICE)) {
                Ok(conn) => {
                    return conn.map_err(|e| ClientError::Unavailable(format!("{}: {e}", self.authority())))
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(ClientError::Io(io::Error::other("connect thread panicked")))
                }
            }
        }
    }
}

fn parse(url: &str, scheme: &'static str, default_port: u16) -> Result<(String, u16, String), ClientError> {
    let bad = || ClientError::Url(url.to_string(), scheme);
    let rest = url
        .strip_prefix(scheme)
        .and_then(|r| r.strip_prefix("://"))
        .ok_or_else(bad)?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.strip_prefix('[') {
        // An IPv6 literal: `[::1]` or `[::1]:8080`.
        Some(v6) => {
            let (h, rest) = v6.split_once(']').ok_or_else(bad)?;
            match rest {
                "" => (h, default_port),
                p => (
                    h,
                    p.strip_prefix(':').and_then(|p| p.parse().ok()).ok_or_else(bad)?,
                ),
            }
        }
        None => match authority.split_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().map_err(|_| bad())?),
            None => (authority, default_port),
        },
    };
    if host.is_empty() || path.chars().any(|c| c.is_ascii_control() || c == ' ') {
        return Err(bad());
    }
    Ok((host.to_string(), port, path.to_string()))
}

/// Where the body of `resp` starts.
fn head_end(resp: &[u8]) -> Option<usize> {
    resp.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Whether `resp` holds as many body bytes as its `Content-Length` says.
fn whole(resp: &[u8]) -> bool {
    let Some(start) = head_end(resp) else {
        return false;
    };
    let head = String::from_utf8_lossy(&resp[..start]);
    head.lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .is_some_and(|len| resp.len() - start >= len)
}

enum Conn {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Conn {
    /// Both ways: a TLS read can write, and a TLS write can read.
    fn set_timeout(&self, d: Duration) -> io::Result<()> {
        let sock = match self {
            Conn::Plain(s) => s,
            Conn::Tls(s) => s.get_ref(),
        };
        sock.set_read_timeout(Some(d))?;
        sock.set_write_timeout(Some(d))
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(buf),
            Conn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(buf),
            Conn::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

/// The CA certificates in the PEM file at `path`.
pub fn read_roots(path: &Path) -> Result<RootCertStore, ClientError> {
    let bad = |e: &dyn std::fmt::Display| ClientError::Tls(format!("{}: {e}", path.display()));
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(path).map_err(|e| bad(&e))? {
        roots.add(cert.map_err(|e| bad(&e))?).map_err(|e| bad(&e))?;
    }
    if roots.is_empty() {
        return Err(bad(&"no certificates"));
    }
    Ok(roots)
}

/// A TLS 1.3 client that trusts `roots` and, with `identity`, proves itself
/// with that certificate chain and the Ed25519 key behind the provider.
pub fn client_config(
    roots: RootCertStore,
    identity: Option<(Vec<CertificateDer<'static>>, Arc<dyn KeyProvider>)>,
) -> Result<Arc<ClientConfig>, ClientError> {
    let tls = |e: rustls::Error| ClientError::Tls(e.to_string());
    let builder = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls)?
        .with_root_certificates(roots);
    Ok(Arc::new(match identity {
        None => builder.with_no_client_auth(),
        Some((chain, key)) => {
            let key: Arc<dyn SigningKey> = Arc::new(TlsKey(key));
            builder.with_client_cert_resolver(Arc::new(Identity(Arc::new(CertifiedKey::new(chain, key)))))
        }
    }))
}

/// Always the one certificate.
#[derive(Debug)]
struct Identity(Arc<CertifiedKey>);

impl ResolvesClientCert for Identity {
    fn resolve(&self, _hints: &[&[u8]], schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        schemes
            .contains(&SignatureScheme::ED25519)
            .then(|| self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// A [`KeyProvider`] as rustls sees it.
#[derive(Clone)]
struct TlsKey(Arc<dyn KeyProvider>);

impl std::fmt::Debug for TlsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TlsKey")
    }
}

impl SigningKey for TlsKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ED25519)
            .then(|| Box::new(self.clone()) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

impl Signer for TlsKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.0
            .sign(message)
            .map(|s| s.to_vec())
            .map_err(|e| rustls::Error::General(e.to_string()))
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_constructor_takes_its_own_scheme_only() {
        let i = Endpoint::plain("http://127.0.0.1:8080/ingest/windows").unwrap();
        assert_eq!(
            (i.host.as_str(), i.port, i.path.as_str()),
            ("127.0.0.1", 8080, "/ingest/windows")
        );
        let i = Endpoint::plain("http://cp.local").unwrap();
        assert_eq!((i.host.as_str(), i.port, i.path.as_str()), ("cp.local", 80, "/"));
        let i = Endpoint::plain("http://[::1]:9/x").unwrap();
        assert_eq!((i.host.as_str(), i.port), ("::1", 9));
        assert!(Endpoint::plain("https://cp.local/").is_err());
        assert!(Endpoint::plain("http://:80/").is_err());
        assert!(Endpoint::plain("http://h:x/").is_err());
        assert!(Endpoint::plain("http://h/a b").is_err());

        let tls = client_config(RootCertStore::empty(), None).unwrap();
        let i = Endpoint::tls("https://cp.local/in", tls.clone()).unwrap();
        assert_eq!((i.port, i.path.as_str()), (443, "/in"));
        assert!(Endpoint::tls("http://cp.local/", tls).is_err());
    }

    #[test]
    fn a_response_is_whole_when_its_length_says_so() {
        assert!(whole(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"));
        assert!(whole(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"));
        assert!(!whole(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok"));
        assert!(!whole(b"HTTP/1.1 200 OK\r\n\r\nok"));
        assert!(!whole(b"HTTP/1.1 200"));
    }
}
