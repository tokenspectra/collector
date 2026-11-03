//! The spool (TS-38, spec §8): with a remote store, objects are written
//! to a local directory first, and an [`Uploader`] copies them out.
//!
//! The [`crate::store::StoreSink`] writes every object into the spool, a
//! [`LocalFileSystem`] that syncs each put, exactly as it writes the local
//! store; a window's manifest is committed once its objects are there. The
//! spool stays inside the protected boundary: nothing leaves it except
//! through the uploader. An object-store outage then delays evidence
//! instead of ending the run.
//!
//! The uploader takes objects in the order they were spooled. Each is put
//! write-once to the remote store (`PutMode::Create`); one already there
//! with the same bytes counts as uploaded, one with other bytes stops the
//! uploader and fails the run, as a conflicting put does without a spool.
//! An uploaded object is removed from the spool. Any other error is retried
//! after a pause, doubling up to [`MAX_PAUSE`], for as long as it takes.
//!
//! **Backpressure.** The spool holds at most `max_bytes`. A put that would
//! pass it waits until uploads make room, so a long outage holds the run
//! back instead of filling the disk. One object bigger than the whole
//! spool still goes in once the spool is empty.
//!
//! A run ends by giving the uploader a deadline ([`Uploader::finish`]).
//! What is still spooled then stays on disk; the next run, or
//! `collector upload`, sends it first.

use std::collections::{HashSet, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use object_store::local::LocalFileSystem;
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload};
use tracing::{debug, warn};

use crate::stats::{add, Registry};
use crate::store::{block_on, local, StoreError};

/// The longest pause between attempts at an object the store refuses.
pub const MAX_PAUSE: Duration = Duration::from_secs(30);
const FIRST_PAUSE: Duration = Duration::from_millis(250);

#[derive(Default)]
struct State {
    /// Spooled objects not uploaded yet, oldest first: key and length.
    queue: VecDeque<(String, u64)>,
    queued: HashSet<String>,
    bytes: u64,
    peak: u64,
    /// Why the uploader stopped for good.
    failed: Option<String>,
    /// Set by [`Uploader::finish`]: stop once the queue is empty or the
    /// deadline has passed.
    deadline: Option<Instant>,
}

/// The spool directory and what in it is waiting for the uploader.
pub struct Spool {
    dir: PathBuf,
    store: Arc<LocalFileSystem>,
    max_bytes: u64,
    state: Mutex<State>,
    changed: Condvar,
    reg: Option<Arc<Registry>>,
}

impl Spool {
    /// Opens the spool at `dir`, creating it if missing. Objects a past run
    /// left behind are queued first, by key.
    pub fn open(dir: &Path, max_bytes: u64, reg: Option<Arc<Registry>>) -> Result<Arc<Self>, StoreError> {
        std::fs::create_dir_all(dir)?;
        let mut left = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d)? {
                let e = e?;
                let p = e.path();
                if e.file_type()?.is_dir() {
                    stack.push(p);
                    continue;
                }
                // `LocalFileSystem` stages a put as `{key}#{n}` and renames
                // it; one left by a crash never became an object.
                let rel = p.strip_prefix(dir).expect("under the spool");
                let Some(key) = rel.to_str().filter(|k| !k.contains('#')) else {
                    continue;
                };
                left.push((key.replace(std::path::MAIN_SEPARATOR, "/"), e.metadata()?.len()));
            }
        }
        left.sort();
        let spool = Spool {
            dir: dir.to_path_buf(),
            store: Arc::new(local(dir)?),
            max_bytes,
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            reg,
        };
        {
            let mut st = spool.lock();
            for (key, len) in left {
                spool.enqueue(&mut st, key, len);
            }
        }
        Ok(Arc::new(spool))
    }

    /// The spool as an object store, for the [`crate::store::StoreSink`].
    pub fn store(&self) -> Arc<dyn ObjectStore> {
        self.store.clone()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn enqueue(&self, st: &mut State, key: String, len: u64) {
        if st.queued.insert(key.clone()) {
            st.queue.push_back((key, len));
            st.bytes += len;
            st.peak = st.peak.max(st.bytes);
            self.gauges(st);
        }
    }

    fn gauges(&self, st: &State) {
        if let Some(r) = &self.reg {
            r.set_spool(st.queue.len() as u64, st.bytes);
        }
    }

    /// Waits until `len` more bytes fit, or the spool is empty. Fails once
    /// the uploader has stopped for good: nothing would make room.
    pub fn wait_for_room(&self, len: u64) -> Result<(), StoreError> {
        let mut st = self.lock();
        let mut waited = false;
        loop {
            if let Some(why) = &st.failed {
                return Err(StoreError::Upload(why.clone()));
            }
            if st.bytes == 0 || st.bytes + len <= self.max_bytes {
                return Ok(());
            }
            if !waited {
                waited = true;
                warn!(
                    spooled_bytes = st.bytes,
                    max_bytes = self.max_bytes,
                    "spool full: waiting for uploads"
                );
            }
            st = self.changed.wait(st).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// Queues an object just written to the spool.
    pub fn added(&self, key: &str, len: u64) {
        let mut st = self.lock();
        self.enqueue(&mut st, key.to_string(), len);
        self.changed.notify_all();
    }

    /// Objects and bytes waiting.
    pub fn pending(&self) -> (u64, u64) {
        let st = self.lock();
        (st.queue.len() as u64, st.bytes)
    }

    /// The most bytes the spool has held at once.
    pub fn peak_bytes(&self) -> u64 {
        self.lock().peak
    }
}

/// What an uploader did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Uploaded {
    pub objects: u64,
    pub bytes: u64,
    /// Objects and bytes still in the spool when it stopped.
    pub left: u64,
    pub left_bytes: u64,
}

/// Copies spooled objects to the remote store, on a thread of its own.
pub struct Uploader {
    spool: Arc<Spool>,
    thread: JoinHandle<Uploaded>,
}

enum Outcome {
    Done(u64),
    /// Worth another try later.
    Retry(String),
    Fatal(String),
}

impl Uploader {
    pub fn spawn(spool: Arc<Spool>, remote: Arc<dyn ObjectStore>) -> io::Result<Self> {
        let s = spool.clone();
        let thread = std::thread::Builder::new()
            .name("uploader".into())
            .spawn(move || run(&s, remote.as_ref()))?;
        Ok(Uploader { spool, thread })
    }

    /// Lets the uploader go on for at most `wait`, then stops it; a request
    /// in flight then still runs to its end, at most
    /// [`crate::store::REQUEST_RETRY`] plus the transfer. Fails if an
    /// object conflicted with the store.
    pub fn finish(self, wait: Duration) -> Result<Uploaded, StoreError> {
        {
            let mut st = self.spool.lock();
            st.deadline = Some(Instant::now() + wait);
            self.spool.changed.notify_all();
        }
        let done = self
            .thread
            .join()
            .map_err(|_| StoreError::Upload("the uploader panicked".into()))?;
        match self.spool.lock().failed.clone() {
            Some(why) => Err(StoreError::Upload(why)),
            None => Ok(done),
        }
    }
}

fn run(spool: &Spool, remote: &dyn ObjectStore) -> Uploaded {
    let mut done = Uploaded::default();
    let mut pause = FIRST_PAUSE;
    loop {
        let (key, len) = {
            let mut st = spool.lock();
            loop {
                let past = st.deadline.is_some_and(|d| Instant::now() >= d);
                if st.failed.is_some() || past || (st.deadline.is_some() && st.queue.is_empty()) {
                    done.left = st.queue.len() as u64;
                    done.left_bytes = st.bytes;
                    return done;
                }
                if let Some(next) = st.queue.front() {
                    break next.clone();
                }
                st = spool.changed.wait(st).unwrap_or_else(|e| e.into_inner());
            }
        };
        match upload(spool, remote, &key) {
            Outcome::Done(stored) => {
                if let Err(e) = std::fs::remove_file(spool.dir.join(&key)) {
                    if e.kind() != io::ErrorKind::NotFound {
                        warn!(key, error = %e, "uploaded, but could not remove it from the spool");
                    }
                }
                let mut st = spool.lock();
                st.queue.pop_front();
                st.queued.remove(&key);
                st.bytes -= len;
                spool.gauges(&st);
                spool.changed.notify_all();
                done.objects += 1;
                done.bytes += stored;
                pause = FIRST_PAUSE;
            }
            Outcome::Retry(why) => {
                if let Some(r) = &spool.reg {
                    add(&r.upload_retries, 1);
                }
                warn!(key, error = %why, retry_in_ms = pause.as_millis() as u64, "upload failed");
                let st = spool.lock();
                // Sleeps through the pause unless `finish` wakes it.
                let until = Instant::now() + pause;
                let deadline = st.deadline.map_or(until, |d| d.min(until));
                let wait = deadline.saturating_duration_since(Instant::now());
                drop(spool.changed.wait_timeout(st, wait));
                pause = (pause * 2).min(MAX_PAUSE);
            }
            Outcome::Fatal(why) => {
                warn!(key, error = %why, "upload stopped");
                let mut st = spool.lock();
                st.failed = Some(why);
                spool.changed.notify_all();
            }
        }
    }
}

/// Puts one spooled object to the remote store, once.
fn upload(spool: &Spool, remote: &dyn ObjectStore, key: &str) -> Outcome {
    let bytes = match std::fs::read(spool.dir.join(key)) {
        Ok(b) => b,
        // Gone already: another uploader sent it.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Outcome::Done(0),
        Err(e) => return Outcome::Fatal(format!("{key}: reading the spool: {e}")),
    };
    // TS-47 encrypts each object to the auditor here, between the spool
    // and the store.
    let path = ObjectPath::from(key);
    let len = bytes.len() as u64;
    let opts = PutOptions {
        mode: PutMode::Create,
        ..PutOptions::default()
    };
    match block_on(remote.put_opts(&path, PutPayload::from(bytes.clone()), opts)) {
        Ok(_) => {
            if let Some(r) = &spool.reg {
                add(&r.uploads, 1);
                add(&r.upload_bytes, len);
            }
            debug!(key, bytes = len, "uploaded");
            Outcome::Done(len)
        }
        Err(object_store::Error::AlreadyExists { .. }) => {
            match block_on(async { remote.get(&path).await?.bytes().await }) {
                Ok(existing) if existing[..] == bytes[..] => {
                    if let Some(r) = &spool.reg {
                        add(&r.uploads_existing, 1);
                    }
                    Outcome::Done(0)
                }
                Ok(_) => Outcome::Fatal(StoreError::Conflict(key.to_string()).to_string()),
                Err(e) => Outcome::Retry(e.to_string()),
            }
        }
        Err(e) => Outcome::Retry(e.to_string()),
    }
}
