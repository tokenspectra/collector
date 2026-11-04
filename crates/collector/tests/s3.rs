//! The S3 backend end to end (TS-38, spec §8), against a real
//! S3-compatible store: the objects are the local store's, byte for byte,
//! every one reads back and verifies, a re-run leaves them alone, an object
//! with other bytes is never overwritten, and split chunks join.
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
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use collector::stats::Registry;
use collector::store::{fetch_blob, fetch_chunk, BlobKind, BlobRecord, StoreConfig};
use collector::{mh, DecoderConfig, FileSource};
use futures::TryStreamExt;
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};
use serde_json::Value;

use collect::{fixture_paths, run_into, run_stored, WINDOW_NS};
use fixtures::cases;

/// A fresh, empty store under its own prefix, or `None` when no S3 store
/// is configured.
fn s3(test: &str) -> Option<Arc<dyn ObjectStore>> {
    let Ok(base) = std::env::var("TS_S3_TEST_URL") else {
        assert!(std::env::var_os("CI").is_none(), "CI must set TS_S3_TEST_URL");
        eprintln!("{test}: TS_S3_TEST_URL is not set; skipped");
        return None;
    };
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let url = format!("{}/{test}-{nanos}", base.trim_end_matches('/'));
    Some(collector::store::open(&url, None).expect("S3 store"))
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
