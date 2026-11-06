//! The S3 backend end to end (TS-38, spec §8), against a real
//! S3-compatible store: the objects are the local store's, byte for byte,
//! every one reads back and verifies, a re-run leaves them alone, an object
//! with other bytes is never overwritten, and split chunks join. Through
//! the spool: an outage during a run delays the objects without ending
//! the run, and a full spool holds the run back until uploads make room.
//! A proxy that can be switched off stands in for the outage.
//!
//! Needs `TS_S3_TEST_URL=s3://bucket[/prefix]` and the `AWS_*` variables
//! [`collector::store::open`] reads; each test writes under a prefix of its
//! own. Without them the tests pass without running, except under CI,
//! where they fail. CI runs them against VersityGW.

#[path = "support/collect.rs"]
mod collect;
#[path = "support/fixtures.rs"]
mod fixtures;

use std::collections::BTreeMap;
use std::io;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use collector::output::JsonlSink;
use collector::spool::{Spool, Uploader};
use collector::stats::Registry;
use collector::store::{fetch_blob, fetch_chunk, BlobKind, BlobRecord, StoreConfig, StoreSink};
use collector::{mh, AssemblerConfig, CapturedPacket, DecoderConfig, FileSource, PacketSource, SourceError};

use futures::TryStreamExt;
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as ObjectPath;
use object_store::prefix::PrefixStore;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload, RetryConfig};
use serde_json::Value;

use collect::{fixture_paths, run_into, run_stored, WINDOW_NS};
use fixtures::cases;

/// A fresh `s3://` URL under a prefix of its own, or `None` when no S3
/// store is configured.
fn s3_url(test: &str) -> Option<String> {
    let Ok(base) = std::env::var("TS_S3_TEST_URL") else {
        assert!(std::env::var_os("CI").is_none(), "CI must set TS_S3_TEST_URL");
        eprintln!("{test}: TS_S3_TEST_URL is not set; skipped");
        return None;
    };
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    Some(format!("{}/{test}-{nanos}", base.trim_end_matches('/')))
}

/// A fresh, empty store under its own prefix.
fn s3(test: &str) -> Option<Arc<dyn ObjectStore>> {
    Some(collector::store::open(&s3_url(test)?, None).expect("S3 store"))
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Every object in `store`, by key.
fn objects(store: &dyn ObjectStore) -> BTreeMap<String, Vec<u8>> {
    rt().block_on(async {
        let metas: Vec<_> = store.list(None).try_collect().await.unwrap();
        let mut out = BTreeMap::new();
        for m in metas {
            let bytes = store.get(&m.location).await.unwrap().bytes().await.unwrap();
            out.insert(m.location.to_string(), bytes.to_vec());
        }
        out
    })
}

/// The objects in a spool directory: its files but the lock.
fn spooled(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = tree(dir);
    files.remove(collector::spool::LOCK);
    files
}

/// Every file under `dir`, by relative path.
fn tree(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let rel = p.strip_prefix(dir).unwrap().to_string_lossy().into_owned();
                out.insert(rel, std::fs::read(&p).unwrap());
            }
        }
    }
    out
}

fn rows(out: &Path, table: &str) -> Vec<Value> {
    std::fs::read_to_string(out.join(format!("{table}.jsonl")))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn blobs(out: &Path) -> Vec<BlobRecord> {
    rows(out, "blobs")
        .into_iter()
        .map(|r| BlobRecord {
            hash: r["hash"].as_str().unwrap().into(),
            kind: if r["kind"] == "body" {
                BlobKind::Body
            } else {
                BlobKind::Workunit
            },
            workunit_id: r["workunit_id"].as_str().map(Into::into),
            window_start_ns: r["window_start_ns"].as_u64().unwrap(),
            pack: r["pack"].as_str().unwrap().into(),
            offset: r["offset"].as_u64().unwrap(),
            len: r["len"].as_u64().unwrap(),
            raw_len: r["raw_len"].as_u64().unwrap(),
        })
        .collect()
}

fn run_s3(
    names: &[&str],
    out: &Path,
    store: &Arc<dyn ObjectStore>,
    cfg: StoreConfig,
    reg: Option<Arc<Registry>>,
) -> Result<(), collector::store::StoreError> {
    run_into(
        &mut FileSource::new(fixture_paths(names)),
        out,
        store.clone(),
        DecoderConfig::default(),
        cfg,
        reg,
    )
    .map(drop)
}

#[test]
fn s3_holds_the_local_stores_objects_and_they_verify() {
    for (case, files) in cases() {
        let Some(store) = s3(&format!("same-{case}")) else {
            return;
        };
        let names: Vec<&str> = files.iter().map(String::as_str).collect();
        let (local, remote) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        run_stored(
            &mut FileSource::new(fixture_paths(&names)),
            local.path(),
            DecoderConfig::default(),
            StoreConfig::new(WINDOW_NS),
            None,
        );
        run_s3(&names, remote.path(), &store, StoreConfig::new(WINDOW_NS), None).unwrap();

        assert_eq!(
            objects(store.as_ref()),
            tree(&local.path().join("store")),
            "{case}"
        );
        for c in rows(remote.path(), "chunks") {
            let key = c["key"].as_str().unwrap();
            let bytes = fetch_chunk(store.as_ref(), key, c["parts"].as_u64().unwrap()).unwrap();
            assert_eq!(mh::of(&bytes), c["chunk_hash"], "{case}");
        }
        let blobs = blobs(remote.path());
        for b in &blobs {
            let bytes = fetch_blob(store.as_ref(), &blobs, &b.hash).unwrap();
            assert!(bytes.is_some(), "{case}: {}", b.hash);
        }
    }
}

#[test]
fn s3_rewrites_are_idempotent_and_never_overwrite() {
    let Some(store) = s3("rewrite") else { return };
    let names = ["openai_h1_json.pcapng"];
    let out = tempfile::tempdir().unwrap();
    run_s3(&names, out.path(), &store, StoreConfig::new(WINDOW_NS), None).unwrap();
    let first = objects(store.as_ref());

    // Every object is already there with the same bytes.
    let reg = Registry::new();
    run_s3(
        &names,
        out.path(),
        &store,
        StoreConfig::new(WINDOW_NS),
        Some(reg.clone()),
    )
    .unwrap();
    let s = reg.snapshot();
    assert_eq!(s.store_objects, [0, 0, 0]);
    assert_eq!(s.store_existing, first.len() as u64);
    assert_eq!(objects(store.as_ref()), first);

    // A pack with other bytes fails the run and stays as it is: the put
    // carried `If-None-Match: *`.
    let pack = first.keys().find(|k| k.ends_with(".pack")).unwrap();
    rt().block_on(store.put(
        &ObjectPath::from(pack.as_str()),
        PutPayload::from_static(b"tampered"),
    ))
    .unwrap();
    let err = run_s3(&names, out.path(), &store, StoreConfig::new(WINDOW_NS), None)
        .unwrap_err()
        .to_string();
    assert!(err.contains("already exists with different bytes"), "{err}");
    assert_eq!(objects(store.as_ref())[pack], b"tampered");
}

#[test]
fn s3_split_chunks_join() {
    let Some(store) = s3("parts") else { return };
    let out = tempfile::tempdir().unwrap();
    let cfg = StoreConfig {
        part_bytes: 256,
        ..StoreConfig::new(WINDOW_NS)
    };
    run_s3(&["anthropic_h1_json.pcapng"], out.path(), &store, cfg, None).unwrap();
    let all = objects(store.as_ref());
    for c in rows(out.path(), "chunks") {
        let (key, parts) = (c["key"].as_str().unwrap(), c["parts"].as_u64().unwrap());
        assert!(parts > 1);
        assert!(!all.contains_key(key));
        assert!((0..parts).all(|i| all[&format!("{key}-part{i}")].len() <= 256));
        let bytes = fetch_chunk(store.as_ref(), key, parts).unwrap();
        assert_eq!(mh::of(&bytes), c["chunk_hash"]);
    }
}

type Store = Arc<dyn ObjectStore>;

/// Forwards TCP to the S3 endpoint while up. Switched down, it closes every
/// open connection and refuses new ones: the store is unreachable.
struct Proxy {
    url: String,
    up: Arc<AtomicBool>,
    open: Arc<Mutex<Vec<TcpStream>>>,
}

impl Proxy {
    fn start(target: &str) -> Proxy {
        let target = target
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (up, open) = (Arc::new(AtomicBool::new(true)), Arc::new(Mutex::new(Vec::new())));
        let (up2, open2) = (up.clone(), open.clone());
        std::thread::spawn(move || {
            for client in listener.incoming() {
                let Ok(client) = client else { continue };
                if !up2.load(Ordering::SeqCst) {
                    drop(client);
                    continue;
                }
                let Ok(server) = TcpStream::connect(&target) else {
                    continue;
                };
                let mut open = open2.lock().unwrap();
                open.push(client.try_clone().unwrap());
                open.push(server.try_clone().unwrap());
                for (mut from, mut to) in [
                    (client.try_clone().unwrap(), server.try_clone().unwrap()),
                    (server, client),
                ] {
                    std::thread::spawn(move || {
                        let _ = io::copy(&mut from, &mut to);
                        let _ = to.shutdown(Shutdown::Write);
                    });
                }
            }
        });
        Proxy { url, up, open }
    }

    fn set_up(&self, up: bool) {
        self.up.store(up, Ordering::SeqCst);
        if !up {
            for s in self.open.lock().unwrap().drain(..) {
                let _ = s.shutdown(Shutdown::Both);
            }
        }
    }
}

/// A fresh prefix of the test store, reached through a [`Proxy`] (down to
/// start with) and directly, or `None` when no S3 store is configured.
fn s3_behind_proxy(test: &str) -> Option<(Proxy, Store, Store)> {
    let url = s3_url(test)?;
    let direct = collector::store::open(&url, None).expect("S3 store");
    let (bucket, prefix) = url["s3://".len()..].split_once('/').unwrap();
    let endpoint = std::env::var("AWS_ENDPOINT").expect("the proxy needs AWS_ENDPOINT");
    let proxy = Proxy::start(&endpoint);
    proxy.set_up(false);
    // Fails fast while the proxy is down; the uploader does the retrying.
    let retry = RetryConfig {
        max_retries: 1,
        retry_timeout: Duration::from_secs(2),
        ..RetryConfig::default()
    };
    let s3 = AmazonS3Builder::from_env()
        .with_bucket_name(bucket)
        .with_endpoint(&proxy.url)
        .with_retry(retry)
        .build()
        .unwrap();
    let through: Store = Arc::new(PrefixStore::new(s3, ObjectPath::from(prefix)));
    Some((proxy, through, direct))
}

/// Runs `names` with its tables in `out` and its objects in `spool`.
fn run_spooled(
    names: &[&str],
    out: &Path,
    spool: Arc<Spool>,
    reg: Arc<Registry>,
) -> Result<(), collector::store::StoreError> {
    run_spooled_from(&mut FileSource::new(fixture_paths(names)), out, spool, reg)
}

fn run_spooled_from(
    source: &mut dyn PacketSource,
    out: &Path,
    spool: Arc<Spool>,
    reg: Arc<Registry>,
) -> Result<(), collector::store::StoreError> {
    let mut sink = JsonlSink::create(out, collect::test_key()).unwrap();
    let mut stored = StoreSink::spooled(&mut sink, spool, StoreConfig::new(WINDOW_NS), Some(reg));
    collector::run::run(
        source,
        WINDOW_NS,
        AssemblerConfig::default(),
        DecoderConfig::default(),
        &mut stored,
    )
    .unwrap();
    let res = stored.finish().map(drop);
    sink.finish().unwrap();
    res
}

/// The local store's objects for `names`: what the remote store must end
/// up holding.
fn local_objects(names: &[&str]) -> BTreeMap<String, Vec<u8>> {
    let dir = tempfile::tempdir().unwrap();
    run_stored(
        &mut FileSource::new(fixture_paths(names)),
        dir.path(),
        DecoderConfig::default(),
        StoreConfig::new(WINDOW_NS),
        None,
    );
    tree(&dir.path().join("store"))
}

const SPAN: [&str; 2] = ["span_windows-1.pcapng", "span_windows-2.pcapng"];

/// The store is down for the whole run: the run still ends, its manifests
/// committed and its objects in the spool. They stay there past the
/// uploader's deadline, and the next uploader, once the store is back,
/// sends them all.
#[test]
fn an_outage_delays_the_objects_without_ending_the_run() {
    let Some((proxy, through, direct)) = s3_behind_proxy("outage") else {
        return;
    };
    let want = local_objects(&SPAN);
    let (out, spool_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let reg = Registry::new();
    let spool = Spool::open(spool_dir.path(), u64::MAX, Some(reg.clone())).unwrap();
    let uploader = Uploader::spawn(spool.clone(), through.clone()).unwrap();
    run_spooled(&SPAN, out.path(), spool.clone(), reg.clone()).unwrap();

    let manifests = std::fs::read_to_string(out.path().join(collector::manifest::LOG)).unwrap();
    assert!(manifests.lines().count() > 1, "every window is sealed");
    let done = uploader.finish(Duration::from_secs(1)).unwrap();
    assert_eq!((done.objects, done.left), (0, want.len() as u64));
    assert!(reg.snapshot().upload_retries > 0);
    assert!(objects(direct.as_ref()).is_empty());
    assert_eq!(spooled(spool_dir.path()), want, "the spool holds every object");

    // The next run (or `collector upload`) finds them on disk, once this
    // one has let go of the spool.
    drop(spool);
    proxy.set_up(true);
    let spool = Spool::open(spool_dir.path(), u64::MAX, None).unwrap();
    assert_eq!(spool.pending().0, want.len() as u64);
    let done = Uploader::spawn(spool, through)
        .unwrap()
        .finish(Duration::from_secs(60))
        .unwrap();
    assert_eq!((done.objects, done.left), (want.len() as u64, 0));
    assert_eq!(objects(direct.as_ref()), want);
    assert!(
        spooled(spool_dir.path()).is_empty(),
        "uploaded objects leave the spool"
    );
}

/// A spool smaller than the run's objects, with the store down: the run
/// waits once the spool is full, and goes on when the store comes back.
#[test]
fn a_full_spool_holds_the_run_back() {
    let Some((proxy, through, direct)) = s3_behind_proxy("full") else {
        return;
    };
    let want = local_objects(&SPAN);
    let biggest = want.values().map(Vec::len).max().unwrap() as u64;
    let total: u64 = want.values().map(|v| v.len() as u64).sum();
    let max = biggest.max(total / 3);
    assert!(total > max, "the run does not fit in the spool");

    let (out, spool_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let reg = Registry::new();
    let spool = Spool::open(spool_dir.path(), max, Some(reg.clone())).unwrap();
    let uploader = Uploader::spawn(spool.clone(), through).unwrap();
    let run = {
        let (spool, reg, out) = (spool.clone(), reg.clone(), out.path().to_path_buf());
        std::thread::spawn(move || run_spooled(&SPAN, &out, spool, reg))
    };
    std::thread::sleep(Duration::from_secs(2));
    assert!(!run.is_finished(), "the run waits for room");
    let (_, held) = spool.pending();
    assert!(held <= max && held > 0, "{held} bytes held, {max} allowed");
    assert_eq!(reg.snapshot().spool_bytes, held);
    assert!(objects(direct.as_ref()).is_empty());

    proxy.set_up(true);
    run.join().unwrap().unwrap();
    let done = uploader.finish(Duration::from_secs(60)).unwrap();
    assert_eq!((done.objects, done.left), (want.len() as u64, 0));
    assert!(spool.peak_bytes() <= max);
    assert_eq!(objects(direct.as_ref()), want);
    assert_eq!(reg.snapshot().spool_bytes, 0);
}

/// Stands in for the dumpcap ring: hands out its files' packets, then
/// waits for more input until it is stopped, as `RingSource` waits for
/// dumpcap's next file until dumpcap exits.
struct Live {
    files: FileSource,
    stopped: Arc<AtomicBool>,
}

impl PacketSource for Live {
    fn next(&mut self) -> Option<Result<CapturedPacket, SourceError>> {
        if let Some(p) = self.files.next() {
            return Some(p);
        }
        while !self.stopped.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }
}

/// A live run held back by a full spool while the store is down still
/// stops when asked: the wait for room ends, the run reports it, and the
/// uploader gets its deadline. Windows not sealed are still in the input:
/// running it again once the store is back fills the store completely.
#[test]
fn a_stop_ends_a_live_run_held_back_by_a_full_spool() {
    let Some((proxy, through, direct)) = s3_behind_proxy("stop") else {
        return;
    };
    let want = local_objects(&SPAN);
    let total: u64 = want.values().map(|v| v.len() as u64).sum();
    let max = want.values().map(Vec::len).max().unwrap() as u64;
    assert!(total > max);

    let (out, spool_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let reg = Registry::new();
    let spool = Spool::open(spool_dir.path(), max, Some(reg.clone())).unwrap();
    let uploader = Uploader::spawn(spool.clone(), through.clone()).unwrap();
    let stopped = Arc::new(AtomicBool::new(false));
    let run = {
        let (spool, reg, out) = (spool.clone(), reg.clone(), out.path().to_path_buf());
        let mut live = Live {
            files: FileSource::new(fixture_paths(&SPAN)),
            stopped: stopped.clone(),
        };
        std::thread::spawn(move || run_spooled_from(&mut live, &out, spool, reg))
    };
    std::thread::sleep(Duration::from_secs(2));
    assert!(!run.is_finished(), "held back by the full spool");

    // What the stop signal does in `ring`: dumpcap ends, the spool stops
    // waiting.
    let asked = std::time::Instant::now();
    stopped.store(true, Ordering::SeqCst);
    spool.stop();
    let err = run.join().unwrap().unwrap_err().to_string();
    assert!(err.contains("stopped with the spool full"), "{err}");
    let done = uploader.finish(Duration::from_secs(1)).unwrap();
    assert!(asked.elapsed() < Duration::from_secs(10), "{:?}", asked.elapsed());
    assert!(done.left > 0 && done.left_bytes <= max);
    assert!(spool.peak_bytes() <= max);
    drop(spool);

    // Run the input again with the store back: everything arrives.
    proxy.set_up(true);
    let again = tempfile::tempdir().unwrap();
    let spool = Spool::open(spool_dir.path(), u64::MAX, None).unwrap();
    let uploader = Uploader::spawn(spool.clone(), through).unwrap();
    run_spooled(&SPAN, again.path(), spool, Registry::new()).unwrap();
    let done = uploader.finish(Duration::from_secs(60)).unwrap();
    assert_eq!(done.left, 0);
    assert_eq!(objects(direct.as_ref()), want);
}
