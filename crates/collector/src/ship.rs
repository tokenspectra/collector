//! The shipper (spec §11): POSTs each window manifest in the log
//! ([`crate::manifest::LOG`]) to the control plane's ingest.
//!
//! The log is the source of truth; the shipper only reads it. How far it
//! has shipped is a byte offset into the log, kept in [`CURSOR`] beside it
//! and replaced atomically after each accepted line. A run that stops
//! mid-way, or an ingest that is down, leaves the rest for the next pass,
//! the next run, or `collector ship`. A line is sent at least once; the
//! ingest deduplicates by Collector and window.
//!
//! Each line is one request:
//!
//! ```text
//! POST <path> HTTP/1.1
//! Content-Type: application/json
//! Idempotency-Key: <collector>/<window_start_ns>
//!
//! <the manifest line>
//! ```
//!
//! Any 2xx is accepted: the first copy of a window, or a repeat of the same
//! bytes. 408, 429 and 5xx, and a failed connection, are retried later.
//! Any other status, such as 409 for a window the ingest already holds
//! with other bytes, stops the shipper: retrying cannot fix it.
//!
//! v1 speaks plain `http://` only, like the Tap (spec "Settled" 6).
//!
//! [`CURSOR`] is the shipper's own state, not an output of the run: two
//! runs over the same capture write the same log whether or not they ship.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError, TryRecvError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::manifest::LOG;

/// How far the log has been shipped: a byte offset, in decimal.
pub const CURSOR: &str = "manifests.shipped";

#[derive(Debug, thiserror::Error)]
pub enum ShipError {
    #[error("ingest URL {0:?}: only http://host[:port]/path is supported")]
    Url(String),
    #[error("{0}")]
    Io(#[from] io::Error),
    /// Worth retrying: the ingest is down or busy.
    #[error("ingest unavailable: {0}")]
    Unavailable(String),
    /// Not worth retrying.
    #[error("ingest refused window {key}: HTTP {status}: {body}")]
    Refused { key: String, status: u16, body: String },
    #[error("{LOG} line at byte {0} is not a manifest")]
    BadLine(u64),
}

impl ShipError {
    fn retryable(&self) -> bool {
        matches!(self, ShipError::Unavailable(_))
    }
}

/// Where the ingest is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ingest {
    host: String,
    port: u16,
    path: String,
}

impl Ingest {
    /// Parses `http://host[:port][/path]`.
    pub fn parse(url: &str) -> Result<Self, ShipError> {
        let bad = || ShipError::Url(url.to_string());
        let rest = url.strip_prefix("http://").ok_or_else(bad)?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = match authority.strip_prefix('[') {
            // An IPv6 literal: `[::1]` or `[::1]:8080`.
            Some(v6) => {
                let (h, rest) = v6.split_once(']').ok_or_else(bad)?;
                match rest {
                    "" => (h, 80),
                    p => (
                        h,
                        p.strip_prefix(':').and_then(|p| p.parse().ok()).ok_or_else(bad)?,
                    ),
                }
            }
            None => match authority.split_once(':') {
                Some((h, p)) => (h, p.parse::<u16>().map_err(|_| bad())?),
                None => (authority, 80),
            },
        };
        if host.is_empty() || path.chars().any(|c| c.is_ascii_control() || c == ' ') {
            return Err(bad());
        }
        Ok(Ingest {
            host: host.to_string(),
            port,
            path: path.to_string(),
        })
    }

    /// POSTs one manifest line; returns the HTTP status. Gives up once
    /// `until()` has passed; it is asked again at least every [`SLICE`]
    /// while the address is looked up, the connection made, the request
    /// written and the response awaited, so a deadline that moves closer
    /// cuts the request short at any of them.
    fn post(
        &self,
        key: &str,
        body: &[u8],
        until: &mut dyn FnMut() -> Instant,
    ) -> Result<(u16, String), ShipError> {
        let unavailable = |e: io::Error| ShipError::Unavailable(format!("{}:{}: {e}", self.host, self.port));
        let mut left = || match until().checked_duration_since(Instant::now()) {
            Some(d) if !d.is_zero() => Ok(d),
            _ => Err(ShipError::Unavailable(format!(
                "{}:{}: timed out",
                self.host, self.port
            ))),
        };
        let mut conn = self.connect(&mut left)?;
        let host = if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        };
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nIdempotency-Key: {key}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.path,
            body.len()
        );
        for mut part in [head.as_bytes(), body] {
            while !part.is_empty() {
                conn.set_write_timeout(Some(left()?.min(SLICE)))
                    .map_err(unavailable)?;
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
        while resp.len() < 64 << 10 {
            conn.set_read_timeout(Some(left()?.min(SLICE)))
                .map_err(unavailable)?;
            match conn.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => resp.extend_from_slice(&buf[..n]),
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(unavailable(e)),
            }
        }
        let text = String::from_utf8_lossy(&resp);
        let status = text
            .lines()
            .next()
            .and_then(|l| l.split(' ').nth(1))
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| ShipError::Unavailable("no HTTP status in the response".into()))?;
        let body = text.split_once("\r\n\r\n").map_or("", |(_, b)| b).trim();
        Ok((status, body.chars().take(200).collect()))
    }

    /// Looks up the ingest and connects to it on a helper thread, waiting
    /// on it in [`SLICE`]s so that `left()` running out is noticed. A
    /// thread given up on finishes on its own: its connect is bounded by
    /// the time left when it started, its lookup only by the resolver.
    fn connect(&self, left: &mut dyn FnMut() -> Result<Duration, ShipError>) -> Result<TcpStream, ShipError> {
        let (host, port, budget) = (self.host.clone(), self.port, left()?);
        let (tx, rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("shipper-connect".into())
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
                    return conn
                        .map_err(|e| ShipError::Unavailable(format!("{}:{}: {e}", self.host, self.port)))
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(ShipError::Io(io::Error::other("shipper connect thread panicked")))
                }
            }
        }
    }
}

/// What one pass shipped.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Shipped {
    /// Lines the ingest accepted in this pass.
    pub sent: u64,
    /// Complete lines still unshipped after it.
    pub pending: u64,
}

fn read_cursor(out: &Path) -> io::Result<u64> {
    match std::fs::read_to_string(out.join(CURSOR)) {
        Ok(s) => Ok(s.trim().parse().unwrap_or(0)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
}

fn write_cursor(out: &Path, offset: u64) -> io::Result<()> {
    let tmp = out.join(format!("{CURSOR}.tmp"));
    std::fs::write(&tmp, format!("{offset}\n"))?;
    std::fs::rename(tmp, out.join(CURSOR))
}

/// The dedup key of a manifest line: `<collector>/<window_start_ns>`.
fn dedup_key(line: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(line).ok()?;
    Some(format!(
        "{}/{}",
        v["collector"].as_str()?,
        v["window_start_ns"].as_u64()?
    ))
}

/// Ships every complete line of the log in `out` past the cursor, in order,
/// and stops at the first failure. The cursor advances past each line the
/// ingest accepts.
pub fn ship_pending(out: &Path, ingest: &Ingest, timeout: Duration) -> Result<Shipped, ShipError> {
    ship_within(out, ingest, timeout, &mut || None)
}

/// [`ship_pending`], stopping at the deadline `shutdown()` returns once it
/// has one. It is asked before each line and at least every [`SLICE`]
/// during each request, and bounds each request's timeout. Lines left when
/// it passes stay pending.
fn ship_within(
    out: &Path,
    ingest: &Ingest,
    timeout: Duration,
    shutdown: &mut dyn FnMut() -> Option<Instant>,
) -> Result<Shipped, ShipError> {
    let mut shipped = Shipped::default();
    let file = match File::open(out.join(LOG)) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(shipped),
        Err(e) => return Err(e.into()),
    };
    let len = file.metadata()?.len();
    let mut offset = read_cursor(out)?;
    if offset > len {
        warn!(
            cursor = offset,
            log_len = len,
            "{CURSOR} is past the end of {LOG}; shipping it all again"
        );
        offset = 0;
    }
    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::Start(offset))?;
    let mut line = Vec::new();
    let mut result = Ok(());
    let mut out_of_time = false;
    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 || line.last() != Some(&b'\n') {
            break; // the end, or a line still being written
        }
        if result.is_err() || out_of_time || shutdown().is_some_and(|d| Instant::now() >= d) {
            out_of_time |= result.is_ok();
            shipped.pending += 1;
            continue;
        }
        let body = &line[..line.len() - 1];
        let request = Instant::now() + timeout;
        let sent = match dedup_key(body) {
            None => Err(ShipError::BadLine(offset)),
            Some(key) => ingest
                .post(&key, body, &mut || shutdown().map_or(request, |d| d.min(request)))
                .and_then(|(status, text)| match status {
                    200..=299 => {
                        debug!(window = %key, status, "manifest shipped");
                        Ok(())
                    }
                    408 | 429 | 500..=599 => Err(ShipError::Unavailable(format!("HTTP {status}: {text}"))),
                    _ => Err(ShipError::Refused {
                        key,
                        status,
                        body: text,
                    }),
                }),
        };
        match sent {
            Ok(()) => {
                offset += n as u64;
                write_cursor(out, offset)?;
                shipped.sent += 1;
            }
            Err(e) => {
                shipped.pending += 1;
                result = Err(e);
            }
        }
    }
    result.map(|()| shipped)
}

/// A shipper thread: tails the log in `out` and ships new lines as they
/// are appended, retrying with backoff while the ingest is unavailable.
pub struct Shipper {
    stop: mpsc::Sender<Instant>,
    thread: JoinHandle<Result<Shipped, ShipError>>,
}

impl Shipper {
    pub fn spawn(out: PathBuf, ingest: Ingest, poll: Duration) -> io::Result<Self> {
        let (stop, stopped) = mpsc::channel::<Instant>();
        let thread = std::thread::Builder::new()
            .name("shipper".into())
            .spawn(move || run(&out, &ingest, poll, &stopped))?;
        Ok(Shipper { stop, thread })
    }

    /// Ships what is left within `wait`, retrying while the ingest is
    /// unavailable, and returns the totals. Returns within `wait` (plus
    /// [`SLICE`]) however slow the ingest is; lines still pending stay in
    /// the log for later.
    pub fn finish(self, wait: Duration) -> Result<Shipped, ShipError> {
        let _ = self.stop.send(Instant::now() + wait);
        self.thread
            .join()
            .unwrap_or_else(|_| Err(ShipError::Io(io::Error::other("shipper thread panicked"))))
    }
}

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// The longest a request waits on the socket before the shutdown deadline
/// is checked again.
const SLICE: Duration = Duration::from_millis(50);

fn run(
    out: &Path,
    ingest: &Ingest,
    poll: Duration,
    stopped: &mpsc::Receiver<Instant>,
) -> Result<Shipped, ShipError> {
    let mut total = Shipped::default();
    let mut backoff = poll;
    let mut deadline: Option<Instant> = None;
    loop {
        // A shutdown request is taken up between lines and mid-request, not
        // only between passes.
        let pass = ship_within(out, ingest, TIMEOUT, &mut || {
            if deadline.is_none() {
                match stopped.try_recv() {
                    Ok(d) => deadline = Some(d),
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => deadline = Some(Instant::now()),
                }
            }
            deadline
        });
        let wait = match pass {
            Ok(s) => {
                total.sent += s.sent;
                total.pending = s.pending;
                backoff = poll;
                if deadline.is_some() {
                    return Ok(total);
                }
                poll
            }
            Err(e) if e.retryable() => {
                let first = backoff == poll;
                backoff = (backoff * 2).min(MAX_BACKOFF);
                if deadline.is_some_and(|d| Instant::now() + backoff >= d) {
                    return Err(e);
                }
                if first {
                    warn!(error = %e, "manifests not shipped yet; retrying");
                }
                total.pending = pending_lines(out).unwrap_or(total.pending);
                backoff
            }
            Err(e) => {
                tracing::error!(error = %e, "shipper stopped");
                return Err(e);
            }
        };
        if deadline.is_none() {
            match stopped.recv_timeout(wait) {
                Ok(d) => deadline = Some(d),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => deadline = Some(Instant::now()),
            }
        } else {
            std::thread::sleep(wait);
        }
    }
}

/// Complete lines past the cursor.
pub fn pending_lines(out: &Path) -> io::Result<u64> {
    let mut file = match File::open(out.join(LOG)) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let offset = read_cursor(out)?.min(file.metadata()?.len());
    file.seek(SeekFrom::Start(offset))?;
    let mut reader = BufReader::with_capacity(64 << 10, file);
    let mut n = 0;
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            return Ok(n);
        }
        n += buf.iter().filter(|&&b| b == b'\n').count() as u64;
        let len = buf.len();
        reader.consume(len);
    }
}

/// Logs the outcome of a run's shipping.
pub fn log_outcome(res: &Result<Shipped, ShipError>, out: &Path) {
    match res {
        Ok(s) if s.pending == 0 => info!(sent = s.sent, "manifests shipped"),
        Ok(s) => {
            warn!(sent = s.sent, pending = s.pending, out = %out.display(), "manifests left in the log; ship them with `collector ship`")
        }
        Err(e) => {
            let pending = pending_lines(out).unwrap_or(0);
            warn!(error = %e, pending, out = %out.display(), "manifests left in the log; ship them with `collector ship`");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_urls_only() {
        let i = Ingest::parse("http://127.0.0.1:8080/ingest/windows").unwrap();
        assert_eq!(
            (i.host.as_str(), i.port, i.path.as_str()),
            ("127.0.0.1", 8080, "/ingest/windows")
        );
        let i = Ingest::parse("http://cp.local").unwrap();
        assert_eq!((i.host.as_str(), i.port, i.path.as_str()), ("cp.local", 80, "/"));
        let i = Ingest::parse("http://[::1]:9/x").unwrap();
        assert_eq!((i.host.as_str(), i.port), ("::1", 9));
        assert!(Ingest::parse("https://cp.local/").is_err());
        assert!(Ingest::parse("http://:80/").is_err());
        assert!(Ingest::parse("http://h:x/").is_err());
        assert!(Ingest::parse("http://h/a b").is_err());
    }

    #[test]
    fn dedup_key_is_collector_and_window() {
        assert_eq!(
            dedup_key(br#"{"site":"s","collector":"c","window_start_ns":7}"#).as_deref(),
            Some("c/7")
        );
        assert_eq!(dedup_key(b"{}"), None);
    }

    #[test]
    fn an_unreachable_ingest_leaves_lines_pending() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(LOG),
            "{\"collector\":\"c\",\"window_start_ns\":0}\n{\"collector\":\"c\",\"window_start_ns\":1}\n{\"coll",
        )
        .unwrap();
        // Bound and dropped: nothing listens there.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let ingest = Ingest::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let err = ship_pending(dir.path(), &ingest, Duration::from_secs(1)).unwrap_err();
        assert!(err.retryable(), "{err}");
        assert_eq!(pending_lines(dir.path()).unwrap(), 2);
        assert_eq!(read_cursor(dir.path()).unwrap(), 0);
    }

    /// A log of `n` manifest lines in a fresh directory.
    fn log_of(n: u64) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let text: String = (0..n)
            .map(|w| format!("{{\"collector\":\"c\",\"window_start_ns\":{w}}}\n"))
            .collect();
        std::fs::write(dir.path().join(LOG), text).unwrap();
        dir
    }

    /// An ingest that reads each request, waits `delay`, then accepts it
    /// with 200. `None` never answers.
    fn slow_ingest(delay: Option<Duration>) -> Ingest {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for conn in listener.incoming() {
                let mut conn = conn.unwrap();
                let mut req = Vec::new();
                let mut buf = [0u8; 4096];
                // Head, then a body of Content-Length bytes.
                while !String::from_utf8_lossy(&req)
                    .split_once("\r\n\r\n")
                    .is_some_and(|(head, body)| {
                        head.lines()
                            .find_map(|l| l.strip_prefix("Content-Length: "))
                            .is_some_and(|n| body.len() >= n.parse().unwrap())
                    })
                {
                    let n = conn.read(&mut buf).unwrap();
                    req.extend_from_slice(&buf[..n]);
                }
                match delay {
                    Some(d) => {
                        std::thread::sleep(d);
                        let _ = conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                    }
                    None => held.push(conn),
                }
            }
        });
        Ingest::parse(&format!("http://127.0.0.1:{port}/")).unwrap()
    }

    #[test]
    fn a_hung_ingest_does_not_hold_shutdown() {
        let dir = log_of(3);
        let shipper =
            Shipper::spawn(dir.path().to_owned(), slow_ingest(None), Duration::from_secs(1)).unwrap();
        std::thread::sleep(Duration::from_millis(100)); // the first POST is waiting
        let t0 = Instant::now();
        let res = shipper.finish(Duration::from_millis(300));
        let took = t0.elapsed();
        // Bounded by the budget, not by the 10 s request timeout.
        assert!(took < Duration::from_secs(1), "finish took {took:?}");
        assert!(res.unwrap_err().retryable());
        assert_eq!(pending_lines(dir.path()).unwrap(), 3);
        assert_eq!(read_cursor(dir.path()).unwrap(), 0);
    }

    #[test]
    fn a_slow_ingest_stops_at_the_budget_and_keeps_the_rest() {
        let dir = log_of(20);
        let shipper = Shipper::spawn(
            dir.path().to_owned(),
            slow_ingest(Some(Duration::from_millis(100))),
            Duration::from_secs(1),
        )
        .unwrap();
        let t0 = Instant::now();
        let res = shipper.finish(Duration::from_millis(450));
        let took = t0.elapsed();
        assert!(took < Duration::from_millis(1200), "finish took {took:?}");
        // Some lines went, the rest are still pending past the cursor.
        let pending = pending_lines(dir.path()).unwrap();
        assert!((1..20).contains(&pending), "{pending} pending");
        if let Ok(s) = res {
            assert_eq!((s.sent, s.pending), (20 - pending, pending));
        }

        // A later pass ships exactly what was left.
        let ingest = slow_ingest(Some(Duration::ZERO));
        let s = ship_pending(dir.path(), &ingest, Duration::from_secs(5)).unwrap();
        assert_eq!((s.sent, s.pending), (pending, 0));
    }

    #[test]
    fn a_zero_budget_starts_no_request() {
        let dir = log_of(2);
        let shipper =
            Shipper::spawn(dir.path().to_owned(), slow_ingest(None), Duration::from_secs(1)).unwrap();
        let s = shipper.finish(Duration::ZERO);
        // The first POST may have begun before the stop; it is cut short.
        assert!(s.map_or_else(|e| e.retryable(), |s| s.pending == 2));
        assert_eq!(pending_lines(dir.path()).unwrap(), 2);
    }

    #[test]
    fn a_stop_during_a_blocked_upload_returns_within_budget() {
        // One manifest far larger than the loopback socket buffers, to an
        // ingest that accepts the connection but never reads it: the upload
        // blocks part-way.
        let dir = tempfile::tempdir().unwrap();
        let pad = "x".repeat(32 << 20);
        std::fs::write(
            dir.path().join(LOG),
            format!("{{\"collector\":\"c\",\"window_start_ns\":0,\"pad\":\"{pad}\"}}\n"),
        )
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (accepted, connected) = mpsc::channel();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for conn in listener.incoming() {
                held.push(conn);
                let _ = accepted.send(());
            }
        });
        let ingest = Ingest::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let shipper = Shipper::spawn(dir.path().to_owned(), ingest, Duration::from_secs(1)).unwrap();
        connected.recv_timeout(Duration::from_secs(10)).unwrap();
        std::thread::sleep(Duration::from_millis(200)); // the upload is stuck
        let t0 = Instant::now();
        let res = shipper.finish(Duration::from_millis(100));
        let took = t0.elapsed();
        assert!(took < Duration::from_millis(400), "finish took {took:?}");
        assert!(res.unwrap_err().retryable());
        assert_eq!(pending_lines(dir.path()).unwrap(), 1);
        assert_eq!(read_cursor(dir.path()).unwrap(), 0);
    }
}
