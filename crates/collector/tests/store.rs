//! Hashing, the Capture Rate cut and the object store (TS-26, spec §6–8):
//! every stored body, record and chunk can be fetched by hash and verifies,
//! the Slice hash chain matches its definition, Parquet holds the same rows
//! as the local tables, and the store is deterministic.

#[path = "support/collect.rs"]
mod collect;
#[path = "support/fixtures.rs"]
mod fixtures;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use collector::capture::CaptureConfig;
use collector::chunk::merkle_root;
use collector::flow::Dir;
use collector::stats::Registry;
use collector::store::{fetch_blob, fetch_chunk, BlobKind, BlobRecord, StoreConfig};
use collector::{mh, DecoderConfig, FileSource};
use object_store::local::LocalFileSystem;
use parquet::file::reader::{FileReader, SerializedFileReader};
use serde_json::Value;

use collect::{collect_files, fixture_paths, run_stored, WINDOW_NS};
use fixtures::cases;

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

fn run_case(names: &[&str], out: &Path, store_cfg: StoreConfig) {
    run_stored(
        &mut FileSource::new(fixture_paths(names)),
        out,
        DecoderConfig::default(),
        store_cfg,
        None,
    );
}

fn local(out: &Path) -> LocalFileSystem {
    LocalFileSystem::new_with_prefix(out.join("store")).unwrap()
}

/// Packets of a stored pcapng: (captured bytes, original length).
fn pcapng_packets(bytes: &[u8]) -> Vec<(Vec<u8>, u32)> {
    let mut r = pcap_file::pcapng::PcapNgReader::new(bytes).unwrap();
    let mut out = Vec::new();
    while let Some(block) = r.next_block() {
        if let pcap_file::pcapng::Block::EnhancedPacket(p) = block.unwrap() {
            out.push((p.data.to_vec(), p.original_len));
        }
    }
    out
}

#[test]
fn every_body_record_and_chunk_is_fetched_by_hash_and_verifies() {
    for (case, files) in cases() {
        let names: Vec<&str> = files.iter().map(String::as_str).collect();
        let dir = tempfile::tempdir().unwrap();
        run_case(&names, dir.path(), StoreConfig::new(WINDOW_NS));
        let store = local(dir.path());
        let blobs = blobs(dir.path());

        // Every body hash in the http table, every Workunit record.
        for row in rows(dir.path(), "http") {
            for m in ["request", "response"] {
                if let Some(h) = row[m]["body_hash"].as_str() {
                    let body = fetch_blob(&store, &blobs, h).unwrap();
                    assert!(body.is_some(), "{case}: body {h} not in the store");
                }
            }
        }
        let workunits = std::fs::read_to_string(dir.path().join("workunits.jsonl")).unwrap();
        for line in workunits.lines() {
            let got = fetch_blob(&store, &blobs, &mh::of(line.as_bytes())).unwrap();
            assert_eq!(got.as_deref(), Some(line.as_bytes()), "{case}: workunit record");
        }
        for b in &blobs {
            assert!(fetch_blob(&store, &blobs, &b.hash).unwrap().is_some(), "{case}");
        }

        // Every chunk: its name verifies, and its packets are the packets
        // table's, in full (the default Capture Rate keeps everything).
        let packets = rows(dir.path(), "packets");
        let chunks = rows(dir.path(), "chunks");
        assert!(!chunks.is_empty(), "{case}");
        let mut seen = 0;
        for c in &chunks {
            let bytes = fetch_chunk(&store, c["key"].as_str().unwrap()).unwrap();
            assert_eq!(mh::of(&bytes), c["chunk_hash"], "{case}");
            let mine: Vec<&Value> = packets
                .iter()
                .filter(|p| p["link"] == c["link"] && p["window_start_ns"] == c["window_start_ns"])
                .collect();
            let stored = pcapng_packets(&bytes);
            assert_eq!(stored.len(), mine.len(), "{case}");
            assert_eq!(c["packets"].as_u64(), Some(mine.len() as u64), "{case}");
            for ((data, orig_len), p) in stored.iter().zip(&mine) {
                assert_eq!(mh::of(data), p["hash"], "{case}");
                assert_eq!(u64::from(*orig_len), p["orig_len"].as_u64().unwrap(), "{case}");
            }
            let hashes: Vec<blake3::Hash> = mine
                .iter()
                .map(|p| mh::parse(p["hash"].as_str().unwrap()).unwrap())
                .collect();
            assert_eq!(
                mh::name(&merkle_root(&hashes).unwrap()),
                c["merkle_root"],
                "{case}"
            );
            seen += mine.len();
        }
        assert_eq!(seen, packets.len(), "{case}: every packet is in a chunk");

        // A corrupted pack fails the read instead of returning bad bytes.
        if let Some(b) = blobs.first() {
            let path = dir.path().join("store").join(&b.pack);
            let mut pack = std::fs::read(&path).unwrap();
            let mut frame = zstd::bulk::decompress(
                &pack[b.offset as usize..(b.offset + b.len) as usize],
                b.raw_len as usize,
            )
            .unwrap();
            if let Some(x) = frame.first_mut() {
                *x ^= 1;
                let bad = zstd::bulk::compress(&frame, 3).unwrap();
                pack.splice(
                    b.offset as usize..(b.offset + b.len) as usize,
                    bad.iter().copied(),
                );
                let mut moved = b.clone();
                moved.len = bad.len() as u64;
                std::fs::write(&path, &pack).unwrap();
                assert!(
                    fetch_blob(&local(dir.path()), &[moved], &b.hash).is_err(),
                    "{case}"
                );
            }
        }
    }
}

#[test]
fn slice_hashes_follow_the_chain() {
    // Fixtures without gaps, so a Slice's bytes are its stream range.
    for names in [
        &["span_windows-1.pcapng", "span_windows-2.pcapng"][..],
        &["openai_h2c_sse.pcapng"],
    ] {
        let c = collect_files(names);
        assert!(c.flows.len() > 1 || names.len() == 1);
        let mut prev: BTreeMap<(String, Dir), blake3::Hash> = BTreeMap::new();
        for f in &c.flows {
            let s = &f.slice;
            for (dir, stats) in [(Dir::Orig, &s.orig_stats), (Dir::Resp, &s.resp_stats)] {
                assert_eq!(stats.gap_bytes, 0);
                let p = *prev
                    .entry((s.flow.to_string(), dir))
                    .or_insert_with(|| collector::assembler::genesis(&s.flow, s.first_ts_ns));
                let stream = c
                    .streams
                    .get(&(s.flow.to_string(), dir))
                    .cloned()
                    .unwrap_or_default();
                let (a, b) = (
                    stats.stream_start.unwrap_or(0) as usize,
                    stats.stream_end.unwrap_or(0) as usize,
                );
                let mut h = blake3::Hasher::new();
                h.update(p.as_bytes());
                h.update(s.flow.as_str().as_bytes());
                h.update(&[0, dir.idx() as u8]);
                h.update(&stream[a..b]);
                let want = h.finalize();
                assert_eq!(
                    stats.slice_hash.as_deref(),
                    Some(mh::name(&want).as_str()),
                    "{} {dir:?}",
                    s.flow
                );
                prev.insert((s.flow.to_string(), dir), want);
            }
        }
    }
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

#[test]
fn the_store_is_deterministic_and_rewrites_are_idempotent() {
    for (case, files) in cases() {
        let names: Vec<&str> = files.iter().map(String::as_str).collect();
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        run_case(&names, a.path(), StoreConfig::new(WINDOW_NS));
        run_case(&names, b.path(), StoreConfig::new(WINDOW_NS));
        let first = tree(&a.path().join("store"));
        assert_eq!(first, tree(&b.path().join("store")), "{case}");

        // Running again into the same store finds every object already
        // there with the same bytes.
        let reg = Registry::new();
        run_stored(
            &mut FileSource::new(fixture_paths(&names)),
            a.path(),
            DecoderConfig::default(),
            StoreConfig::new(WINDOW_NS),
            Some(reg.clone()),
        );
        let s = reg.snapshot();
        assert_eq!(s.store_objects, [0, 0, 0], "{case}");
        assert_eq!(s.store_existing, first.len() as u64, "{case}");
        assert_eq!(first, tree(&a.path().join("store")), "{case}");
    }
}

#[test]
fn an_object_with_other_bytes_is_never_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    run_case(
        &["openai_h1_json.pcapng"],
        dir.path(),
        StoreConfig::new(WINDOW_NS),
    );
    let pack = tree(&dir.path().join("store"))
        .into_keys()
        .find(|k| k.ends_with(".pack"))
        .unwrap();
    std::fs::write(dir.path().join("store").join(&pack), b"tampered").unwrap();
    let store = Arc::new(local(dir.path()));
    let mut sink = collector::output::JsonlSink::create(dir.path()).unwrap();
    let mut stored = collector::store::StoreSink::new(&mut sink, store, StoreConfig::new(WINDOW_NS), None);
    collector::run::run(
        &mut FileSource::new(fixture_paths(&["openai_h1_json.pcapng"])),
        WINDOW_NS,
        collector::AssemblerConfig::default(),
        DecoderConfig::default(),
        &mut stored,
    )
    .unwrap();
    let err = stored.finish().unwrap_err().to_string();
    assert!(err.contains("already exists with different bytes"), "{err}");
    assert_eq!(
        std::fs::read(dir.path().join("store").join(&pack)).unwrap(),
        b"tampered"
    );
}

#[test]
fn capture_rate_truncates_workunits_it_does_not_keep() {
    let names = ["openai_h1_sse.pcapng", "openai_h1_json.pcapng"];
    let (full, cut) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    run_case(&names[..1], full.path(), StoreConfig::new(WINDOW_NS));
    let mut cfg = StoreConfig::new(WINDOW_NS);
    cfg.capture = CaptureConfig {
        rate: 0.0,
        key: Some([3; 32]),
        ..CaptureConfig::default()
    };
    let reg = Registry::new();
    run_stored(
        &mut FileSource::new(fixture_paths(&names[..1])),
        cut.path(),
        DecoderConfig::default(),
        cfg,
        Some(reg.clone()),
    );
    // Hashes and every other table stay the same; only the chunk changes.
    for t in [
        "packets",
        "segments",
        "events",
        "flows",
        "http",
        "workunits",
        "blobs",
    ] {
        assert_eq!(rows(full.path(), t), rows(cut.path(), t), "{t}");
    }
    let (cf, cc) = (&rows(full.path(), "chunks")[0], &rows(cut.path(), "chunks")[0]);
    assert_eq!(cf["merkle_root"], cc["merkle_root"]);
    assert_ne!(cf["chunk_hash"], cc["chunk_hash"]);
    assert!(cc["truncated_packets"].as_u64().unwrap() > 0);

    // Exactly the packets carrying Workunit bytes are cut, to 128 bytes,
    // with their original length kept.
    let flows_wu: BTreeSet<String> = rows(cut.path(), "http")
        .iter()
        .filter(|r| r["bucket"] == "workunit")
        .map(|r| r["flow"].as_str().unwrap().to_string())
        .collect();
    let bytes = fetch_chunk(&local(cut.path()), cc["key"].as_str().unwrap()).unwrap();
    let packets = rows(cut.path(), "packets");
    let mut truncated = 0;
    for ((data, orig_len), p) in pcapng_packets(&bytes).iter().zip(&packets) {
        let cap = p["cap_len"].as_u64().unwrap() as usize;
        assert_eq!(u64::from(*orig_len), p["orig_len"].as_u64().unwrap());
        let payload = p["payload_len"].as_u64().unwrap_or(0);
        let workunit = payload > 0 && flows_wu.contains(p["flow"].as_str().unwrap_or(""));
        if workunit && cap > 128 {
            assert_eq!(data.len(), 128, "{p}");
            truncated += 1;
        } else {
            assert_eq!(mh::of(data), p["hash"], "kept in full: {p}");
        }
    }
    assert_eq!(cc["truncated_packets"].as_u64(), Some(truncated));

    let s = reg.snapshot();
    assert_eq!(s.capture_packets[1], truncated);
    assert_eq!(s.capture_packets[0] + s.capture_packets[1], packets.len() as u64);
    assert_eq!(s.capture_kept_bytes, cc["kept_bytes"].as_u64().unwrap());
    assert_eq!(s.capture_truncated_bytes, cc["truncated_bytes"].as_u64().unwrap());
    assert_eq!(s.store_objects[0], 1);
    assert_eq!(s.store_objects[1], 1);
    assert_eq!(s.store_objects[2], 8);
}

#[test]
fn alarm_flows_are_kept_up_to_the_cap() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = StoreConfig::new(WINDOW_NS);
    cfg.capture.alarm_cap_bytes = 100;
    // The fixture's packets are small: cut to their headers.
    cfg.capture.truncate_to = 54;
    run_case(&["tls_plaintext.pcapng"], dir.path(), cfg);
    let c = &rows(dir.path(), "chunks")[0];
    assert!(c["truncated_packets"].as_u64().unwrap() > 0, "{c}");
    let dir = tempfile::tempdir().unwrap();
    run_case(&["tls_plaintext.pcapng"], dir.path(), StoreConfig::new(WINDOW_NS));
    assert_eq!(rows(dir.path(), "chunks")[0]["truncated_packets"], 0);
}

/// Anomalies arrive before their packet's record; those packets still stay
/// whole when everything else is cut.
#[test]
fn anomaly_packets_are_kept_whole() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = StoreConfig::new(WINDOW_NS);
    cfg.capture.alarm_cap_bytes = 0;
    cfg.capture.truncate_to = 54;
    run_case(&["retransmit_differs.pcapng"], dir.path(), cfg);
    let packets = rows(dir.path(), "packets");
    let mut stored = BTreeMap::new();
    for c in rows(dir.path(), "chunks") {
        let bytes = fetch_chunk(&local(dir.path()), c["key"].as_str().unwrap()).unwrap();
        let in_chunk = packets
            .iter()
            .filter(|p| p["window_start_ns"] == c["window_start_ns"] && p["link"] == c["link"]);
        for (p, (data, _)) in in_chunk.zip(pcapng_packets(&bytes)) {
            stored.insert(
                (p["window_start_ns"].as_u64(), p["index"].as_u64()),
                (p.clone(), data),
            );
        }
    }
    let flagged: Vec<_> = rows(dir.path(), "events")
        .into_iter()
        .filter(|e| e["kind"] == "retransmit_differs")
        .map(|e| (e["window_start_ns"].as_u64(), e["index"].as_u64()))
        .collect();
    assert_eq!(flagged.len(), 2);
    for at in &flagged {
        let (p, data) = &stored[at];
        assert!(p["cap_len"].as_u64().unwrap() > 54, "{p}");
        assert_eq!(mh::of(data), p["hash"], "kept whole: {p}");
    }
    assert!(
        stored
            .iter()
            .any(|(at, (p, data))| !flagged.contains(at)
                && data.len() < p["cap_len"].as_u64().unwrap() as usize),
        "the other payload packets are cut"
    );
}

#[test]
fn parquet_index_holds_the_same_rows_as_the_tables() {
    for (case, files) in cases() {
        let names: Vec<&str> = files.iter().map(String::as_str).collect();
        let dir = tempfile::tempdir().unwrap();
        run_case(&names, dir.path(), StoreConfig::new(WINDOW_NS));
        let files = tree(&dir.path().join("store"));
        for table in collector::index::TABLES {
            let jsonl = rows(dir.path(), table);
            for r in &jsonl {
                let missing = collector::index::uncovered(table, r);
                assert!(missing.is_empty(), "{case}/{table}: no column for {missing:?}");
            }
            let mut n = 0;
            for (path, bytes) in files
                .iter()
                .filter(|(p, _)| p.ends_with(&format!("/{table}.parquet")))
            {
                assert!(path.starts_with("index/local/local/"), "{path}");
                let r = SerializedFileReader::new(bytes::Bytes::from(bytes.clone())).unwrap();
                n += r.metadata().file_metadata().num_rows() as usize;
            }
            assert_eq!(n, jsonl.len(), "{case}/{table}");
        }
    }
}
