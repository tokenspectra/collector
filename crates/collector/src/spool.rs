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
//! **Backpressure.** The spool holds at most `max_bytes`. A put reserves
//! its bytes first ([`Spool::reserve`]), waiting until uploads make room,
//! so a long outage holds the run back instead of filling the disk. One
//! object bigger than the whole spool still goes in once the spool is
//! empty. An object's bytes count until its file is gone: an upload whose
//! file cannot be removed keeps its room, and the removal is retried.
//! [`Spool::stop`] ends the wait: a stopping run must not hang on a full
//! spool (see `crate::store`).
//!
//! **One owner.** A spool is opened by one process at a time: [`LOCK`] in
//! it is locked while it is open, and a second open fails.
//!
//! A run ends by giving the uploader a deadline ([`Uploader::finish`]).
//! What is still spooled then stays on disk; the next run, or
//! `collector upload`, sends it first.

use std::collections::{HashSet, VecDeque};
use std::fs::File;
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

/// The spool's lock file; never uploaded.
pub const LOCK: &str = ".lock";

/// The longest pause between attempts at an object the store refuses.
pub const MAX_PAUSE: Duration = Duration::from_secs(30);
const FIRST_PAUSE: Duration = Duration::from_millis(250);

#[derive(Default)]
struct State {
    /// Spooled objects not uploaded yet, oldest first: key and length.
    queue: VecDeque<(String, u64)>,
    queued: HashSet<String>,
    /// Bytes on disk: queued objects, and uploaded ones not removed yet.
    bytes: u64,
    /// Bytes reserved by puts in progress.
    reserved: u64,
    peak: u64,
    /// No more waiting for room ([`Spool::stop`]).
    stopped: bool,
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
    /// Held, locked, while the spool is open.
    _lock: File,
}

/// Room for one object, reserved in the spool until it is
/// [`Reservation::commit`]ted or dropped.
pub struct Reservation<'a> {
    spool: &'a Spool,
    len: u64,
}

impl Reservation<'_> {
    /// Queues the object, now written and synced under `key`.
    pub fn commit(self, key: &str) {
        let spool = self.spool;
        let mut st = spool.lock();
        st.reserved -= self.len;
        spool.enqueue(&mut st, key.to_string(), self.len);
        std::mem::forget(self);
        spool.changed.notify_all();
    }
}

impl Drop for Reservation<'_> {
    /// The put failed: its room is free again.
    fn drop(&mut self) {
        let mut st = self.spool.lock();
        st.reserved -= self.len;
        self.spool.changed.notify_all();
    }
}

impl Spool {
    /// Opens the spool at `dir`, creating it if missing. Objects a past run
    /// left behind are queued first, by key.
    pub fn open(dir: &Path, max_bytes: u64, reg: Option<Arc<Registry>>) -> Result<Arc<Self>, StoreError> {
        std::fs::create_dir_all(dir)?;
        let lock = File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join(LOCK))?;
        if let Err(e) = lock.try_lock() {
            return Err(StoreError::Upload(format!(
                "spool {} is in use by another process ({e})",
                dir.display()
            )));
        }
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
                let Some(key) = rel.to_str().filter(|k| !k.contains('#') && *k != LOCK) else {
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
            _lock: lock,
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

    /// Queues `key`, unless it is queued already: then its file is the
    /// one already counted.
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

    /// Reserves room for an object of `len` bytes, waiting until it fits
    /// or nothing else is spooled or reserved. Fails once the uploader has
    /// stopped for good (nothing would make room), or once the spool is
    /// [`Spool::stop`]ped while it is full.
    pub fn reserve(&self, len: u64) -> Result<Reservation<'_>, StoreError> {
        let mut st = self.lock();
        let mut waited = false;
        loop {
            if let Some(why) = &st.failed {
                return Err(StoreError::Upload(why.clone()));
            }
            let used = st.bytes + st.reserved;
            if used == 0 || used + len <= self.max_bytes {
                st.reserved += len;
                st.peak = st.peak.max(st.bytes + st.reserved);
                return Ok(Reservation { spool: self, len });
            }
            if st.stopped {
                return Err(StoreError::Stopped(used));
            }
            if !waited {
                waited = true;
                warn!(
                    spooled_bytes = used,
                    max_bytes = self.max_bytes,
                    "spool full: waiting for uploads"
                );
            }
            st = self.changed.wait(st).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// Stops waiting for room: from now on a put that does not fit fails
    /// instead. For a run that is stopping while the store is down.
    pub fn stop(&self) {
        self.lock().stopped = true;
        self.changed.notify_all();
    }

    /// Objects and bytes waiting.
    pub fn pending(&self) -> (u64, u64) {
        let st = self.lock();
        (st.queue.len() as u64, st.bytes)
    }

    /// The most bytes the spool has held, or had reserved, at once.
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
    // The object at the front once the store holds it: what is left is
    // removing its file.
    let mut uploaded: Option<(String, u64)> = None;
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
        let outcome = match &uploaded {
            Some((k, stored)) if *k == key => Outcome::Done(*stored),
            _ => upload(spool, remote, &key),
        };
        let outcome = match outcome {
            Outcome::Done(stored) => match std::fs::remove_file(spool.dir.join(&key)) {
                Ok(()) => Outcome::Done(stored),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Outcome::Done(stored),
                // Its bytes stay counted until the file is gone.
                Err(e) => {
                    uploaded = Some((key.clone(), stored));
                    Outcome::Retry(format!("uploaded, but could not remove it from the spool: {e}"))
                }
            },
            o => o,
        };
        match outcome {
            Outcome::Done(stored) => {
                uploaded = None;
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

#[cfg(test)]
mod tests {
    use std::sync::Barrier;

    use object_store::memory::InMemory;

    use super::*;

    /// Writes `key` the way the store sink does: room, synced put, queue.
    fn put(spool: &Spool, key: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let room = spool.reserve(bytes.len() as u64)?;
        let path = ObjectPath::from(key);
        block_on(spool.store().put(&path, PutPayload::from(bytes.to_vec())))?;
        room.commit(key);
        Ok(())
    }

    /// Two writers racing for the last room: one gets it, the other waits
    /// for an upload, and the cap holds throughout.
    #[test]
    fn concurrent_writers_never_pass_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path(), 10, None).unwrap();
        let start = Arc::new(Barrier::new(2));
        let writers: Vec<_> = ["a", "b"]
            .into_iter()
            .map(|key| {
                let (spool, start) = (spool.clone(), start.clone());
                std::thread::spawn(move || {
                    start.wait();
                    put(&spool, key, &[0; 8])
                })
            })
            .collect();
        // The winner's synced put can be slow on a loaded runner: wait for it,
        // then give the loser time to (wrongly) pass the cap.
        let finished = || writers.iter().filter(|w| w.is_finished()).count();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while finished() == 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(finished(), 1);
        assert_eq!(spool.pending(), (1, 8));

        let remote = Arc::new(InMemory::new());
        let uploader = Uploader::spawn(spool.clone(), remote.clone()).unwrap();
        for w in writers {
            w.join().unwrap().unwrap();
        }
        let done = uploader.finish(Duration::from_secs(10)).unwrap();
        assert_eq!((done.objects, done.left), (2, 0));
        assert!(spool.peak_bytes() <= 10, "peak {}", spool.peak_bytes());
        assert_eq!(spool.pending(), (0, 0));
    }

    /// A failed put frees the room it reserved.
    #[test]
    fn a_failed_put_frees_its_room() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path(), 10, None).unwrap();
        drop(spool.reserve(8).unwrap());
        put(&spool, "a", &[0; 10]).unwrap();
        assert_eq!(spool.pending(), (1, 10));
    }

    #[test]
    fn a_spool_has_one_owner() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path(), 10, None).unwrap();
        let err = Spool::open(dir.path(), 10, None).err().unwrap().to_string();
        assert!(err.contains("in use by another process"), "{err}");
        drop(spool);
        Spool::open(dir.path(), 10, None).unwrap();
    }

    /// A writer waiting for room fails once the spool is stopped.
    #[test]
    fn stop_ends_the_wait_for_room() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path(), 10, None).unwrap();
        put(&spool, "a", &[0; 8]).unwrap();
        let waiting = {
            let spool = spool.clone();
            std::thread::spawn(move || put(&spool, "b", &[0; 8]))
        };
        std::thread::sleep(Duration::from_millis(200));
        assert!(!waiting.is_finished());
        spool.stop();
        let err = waiting.join().unwrap().unwrap_err();
        assert!(matches!(err, StoreError::Stopped(8)), "{err}");
        // What fits still goes in.
        put(&spool, "c", &[0; 2]).unwrap();
        assert_eq!(spool.pending(), (2, 10));
    }

    /// An uploaded object whose file cannot be removed keeps its bytes
    /// counted, and the removal is retried.
    #[cfg(unix)]
    #[test]
    fn a_file_that_cannot_be_removed_keeps_its_room() {
        use std::os::unix::fs::PermissionsExt;

        // SAFETY: plain geteuid(2).
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipped: root removes files from read-only directories");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let objects = dir.path().join("objects");
        let mode = |m| std::fs::set_permissions(&objects, std::fs::Permissions::from_mode(m)).unwrap();
        let spool = Spool::open(dir.path(), 10, None).unwrap();
        put(&spool, "objects/a", &[1; 8]).unwrap();
        mode(0o555);

        let remote = Arc::new(InMemory::new());
        let done = Uploader::spawn(spool.clone(), remote.clone())
            .unwrap()
            .finish(Duration::from_secs(1))
            .unwrap();
        assert_eq!((done.objects, done.left, done.left_bytes), (0, 1, 8));
        assert_eq!(spool.pending(), (1, 8));
        assert!(objects.join("a").exists());
        let stored = block_on(async { remote.get(&ObjectPath::from("objects/a")).await?.bytes().await });
        assert_eq!(&stored.unwrap()[..], &[1; 8], "uploaded all the same");
        spool.stop();
        assert!(spool.reserve(8).is_err(), "no room is handed out twice");

        mode(0o755);
        drop(spool);
        let spool = Spool::open(dir.path(), 10, None).unwrap();
        let done = Uploader::spawn(spool.clone(), remote)
            .unwrap()
            .finish(Duration::from_secs(10))
            .unwrap();
        assert_eq!((done.objects, done.left), (1, 0));
        assert!(!objects.join("a").exists());
        assert_eq!(spool.pending(), (0, 0));
    }
}
