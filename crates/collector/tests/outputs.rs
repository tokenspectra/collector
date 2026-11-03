//! Outputs and end-to-end acceptance (TS-27, spec §11–12) over the whole
//! golden set, all four Wire Protocols included: every window's manifest
//! names objects that exist and sums to the tables, the shipper delivers
//! each window to the ingest once and a re-run only repeats it, and two
//! runs give byte-identical output directories, store and log included.

#[path = "support/collect.rs"]
mod collect;
#[path = "support/fixtures.rs"]
mod fixtures;
#[path = "support/ingest.rs"]
mod ingest;

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use collector::capture::CaptureConfig;
use collector::manifest::LOG;
use collector::ship::{pending_lines, ship_pending, Ingest, ShipError, CURSOR};
use collector::store::StoreConfig;
use collector::{DecoderConfig, FileSource};
use parquet::file::reader::{FileReader, SerializedFileReader};
use serde_json::Value;

use collect::{fixture_paths, run_stored, run_to_dir, WINDOW_NS};
use fixtures::{cases, CAPTURED};
use ingest::MockIngest;

const TIMEOUT: Duration = Duration::from_secs(5);

fn lines(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn run_case(names: &[String], out: &Path, store_cfg: StoreConfig) {
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    run_stored(
        &mut FileSource::new(fixture_paths(&names)),
        out,
        DecoderConfig::default(),
        store_cfg,
        None,
    );
}

fn store_cfg(collector: &str) -> StoreConfig {
    let mut cfg = StoreConfig::new(WINDOW_NS);
    cfg.collector = collector.into();
    cfg
}

/// Every file under `dir` by relative path, symlinks followed.
fn tree(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            let rel = p.strip_prefix(dir).unwrap().to_string_lossy().into_owned();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.insert(rel, std::fs::read(&p).unwrap());
            }
        }
    }
    out
}

#[test]
fn the_golden_set_covers_every_wire_protocol() {
    for protocol in ["openai", "openai_responses", "anthropic", "ollama"] {
        let out = tempfile::tempdir().unwrap();
        let names: Vec<String> = CAPTURED.iter().map(|c| format!("{c}.pcapng")).collect();
        let found = names.iter().any(|n| {
            run_case(std::slice::from_ref(n), out.path(), store_cfg(n));
            lines(&out.path().join("workunits.jsonl"))
                .iter()
                .any(|w| w["protocol"] == protocol)
        });
        assert!(found, "no golden case decodes {protocol}");
    }
}

#[test]
fn manifests_name_every_object_and_sum_to_the_tables() {
    for (case, files) in cases() {
        let out = tempfile::tempdir().unwrap();
        run_case(&files, out.path(), store_cfg(&case));
        let store = out.path().join("store");
        let manifests = lines(&out.path().join(LOG));
        assert!(!manifests.is_empty(), "{case}: no manifest");

        // One manifest per sealed window, in order, each window once.
        let windows: Vec<u64> = manifests
            .iter()
            .map(|m| m["window_start_ns"].as_u64().unwrap())
            .collect();
        assert!(windows.windows(2).all(|w| w[0] < w[1]), "{case}: {windows:?}");
        let index_dirs = tree(&store)
            .keys()
            .filter(|k| k.starts_with("index/") && k.ends_with("/packets.parquet"))
            .count();
        assert_eq!(manifests.len(), index_dirs, "{case}");

        let mut chunks = Vec::new();
        let mut totals: BTreeMap<String, u64> = BTreeMap::new();
        for m in &manifests {
            assert_eq!(m["collector"], case.as_str());
            assert_eq!(m["window_ns"], WINDOW_NS);
            for c in m["chunks"].as_array().unwrap() {
                let key = c["key"].as_str().unwrap();
                collector::store::fetch_chunk(
                    &object_store::local::LocalFileSystem::new_with_prefix(&store).unwrap(),
                    key,
                )
                .unwrap_or_else(|e| panic!("{case}: {key}: {e}"));
                chunks.push(c.clone());
            }
            let links: Vec<&Value> = m["chunks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| &c["link"])
                .collect();
            assert_eq!(m["links"].as_array().unwrap().iter().collect::<Vec<_>>(), links);
            if let Some(pack) = m["pack"].as_str() {
                assert!(store.join(pack).is_file(), "{case}: {pack}");
            }
            for f in m["index"].as_array().unwrap() {
                let key = f["key"].as_str().unwrap();
                let file = std::fs::File::open(store.join(key)).unwrap();
                let rows = SerializedFileReader::new(file)
                    .unwrap()
                    .metadata()
                    .file_metadata()
                    .num_rows();
                assert_eq!(f["rows"].as_u64(), Some(rows as u64), "{case}: {key}");
            }
            for (k, v) in m["totals"].as_object().unwrap() {
                *totals.entry(k.clone()).or_default() += v.as_u64().unwrap();
            }
        }
        // The chunks named are the chunks written.
        assert_eq!(chunks, lines(&out.path().join("chunks.jsonl")), "{case}");

        // Totals over every window add up to the tables.
        let count = |t: &str| lines(&out.path().join(format!("{t}.jsonl"))).len() as u64;
        let packets = lines(&out.path().join("packets.jsonl"));
        let expect = [
            ("packets", packets.len() as u64),
            (
                "bytes",
                packets.iter().map(|p| p["orig_len"].as_u64().unwrap()).sum(),
            ),
            (
                "kept_bytes",
                chunks.iter().map(|c| c["kept_bytes"].as_u64().unwrap()).sum(),
            ),
            (
                "truncated_bytes",
                chunks
                    .iter()
                    .map(|c| c["truncated_bytes"].as_u64().unwrap())
                    .sum(),
            ),
            ("flows", count("flows")),
            ("exchanges", count("http")),
            ("workunits", count("workunits")),
            ("events", count("events")),
            ("blobs", count("blobs")),
        ];
        for (k, v) in expect {
            assert_eq!(totals.get(k).copied(), Some(v), "{case}: totals.{k}");
        }
    }
}

#[test]
fn every_window_is_shipped_once_and_a_rerun_only_repeats_it() {
    let ingest = MockIngest::start();
    let url = Ingest::parse(&ingest.url).unwrap();
    let mut windows = 0;
    for (case, files) in cases() {
        let out = tempfile::tempdir().unwrap();
        run_case(&files, out.path(), store_cfg(&case));
        let n = lines(&out.path().join(LOG)).len() as u64;
        let s = ship_pending(out.path(), &url, TIMEOUT).unwrap();
        assert_eq!((s.sent, s.pending), (n, Some(0)), "{case}");
        let log_len = std::fs::metadata(out.path().join(LOG)).unwrap().len();
        let cursor = std::fs::read_to_string(out.path().join(CURSOR)).unwrap();
        assert_eq!(cursor.trim(), log_len.to_string(), "{case}");
        // Nothing new: nothing sent.
        assert_eq!(ship_pending(out.path(), &url, TIMEOUT).unwrap().sent, 0);
        windows += n;
    }
    let (held, accepted, duplicates, conflicts) = ingest.snapshot();
    assert_eq!(
        (held.len() as u64, accepted, duplicates, conflicts),
        (windows, windows, 0, 0)
    );

    // A second run of every case, into new directories, sends the same
    // manifests again; the ingest keeps one of each.
    for (case, files) in cases() {
        let out = tempfile::tempdir().unwrap();
        run_case(&files, out.path(), store_cfg(&case));
        ship_pending(out.path(), &url, TIMEOUT).unwrap();
    }
    let (again, accepted, duplicates, conflicts) = ingest.snapshot();
    assert_eq!(again, held);
    assert_eq!((accepted, duplicates, conflicts), (windows, windows, 0));
}

#[test]
fn a_window_with_other_bytes_is_refused_and_stays_in_the_log() {
    let ingest = MockIngest::start();
    let url = Ingest::parse(&ingest.url).unwrap();
    let files = vec!["openai_h1_sse.pcapng".to_string()];
    let first = tempfile::tempdir().unwrap();
    run_case(&files, first.path(), store_cfg("c1"));
    ship_pending(first.path(), &url, TIMEOUT).unwrap();

    // Same Collector and window, other bytes: a Capture Rate of 0 truncates
    // every Workunit's packets, so the chunk hashes differ.
    let mut cfg = store_cfg("c1");
    cfg.capture = CaptureConfig {
        rate: 0.0,
        key: Some([7; 32]),
        ..CaptureConfig::default()
    };
    let second = tempfile::tempdir().unwrap();
    run_case(&files, second.path(), cfg);
    let err = ship_pending(second.path(), &url, TIMEOUT).unwrap_err();
    assert!(matches!(err, ShipError::Refused { status: 409, .. }), "{err}");
    assert!(!second.path().join(CURSOR).exists());
    assert_eq!(
        pending_lines(second.path()).unwrap(),
        lines(&second.path().join(LOG)).len() as u64
    );
    assert_eq!(ingest.snapshot().3, 1);
}

#[test]
fn shipping_resumes_where_it_stopped() {
    let out = tempfile::tempdir().unwrap();
    run_case(
        &["span_windows-1.pcapng".into(), "span_windows-2.pcapng".into()],
        out.path(),
        store_cfg("c1"),
    );
    let n = lines(&out.path().join(LOG)).len() as u64;
    assert!(n >= 2, "{n} windows");
    // The ingest is down: nothing moves.
    let down = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let down = Ingest::parse(&format!("http://{down}/ingest/windows")).unwrap();
    assert!(ship_pending(out.path(), &down, TIMEOUT).is_err());
    assert_eq!(pending_lines(out.path()).unwrap(), n);

    // Half shipped by an earlier pass, the rest now.
    let ingest = MockIngest::start();
    let url = Ingest::parse(&ingest.url).unwrap();
    let log = std::fs::read(out.path().join(LOG)).unwrap();
    let first_line = log.iter().position(|&b| b == b'\n').unwrap() + 1;
    std::fs::write(out.path().join(CURSOR), format!("{first_line}\n")).unwrap();
    let s = ship_pending(out.path(), &url, TIMEOUT).unwrap();
    assert_eq!((s.sent, s.pending), (n - 1, Some(0)));
    assert_eq!(ingest.snapshot().0.len() as u64, n - 1);
}

/// Spec §12.2, end to end: two runs over the same files give byte-identical
/// output directories, the object store, bodies, `by-exchange/` and the
/// manifest log included.
#[test]
fn two_runs_give_byte_identical_output_directories() {
    for (case, files) in cases() {
        let names: Vec<&str> = files.iter().map(String::as_str).collect();
        let a = run_to_dir(&mut FileSource::new(fixture_paths(&names)));
        let b = run_to_dir(&mut FileSource::new(fixture_paths(&names)));
        let (ta, tb) = (tree(a.path()), tree(b.path()));
        assert!(
            ta.contains_key(LOG) && ta.keys().any(|k| k.starts_with("store/index/")),
            "{case}"
        );
        assert_eq!(
            ta.keys().collect::<Vec<_>>(),
            tb.keys().collect::<Vec<_>>(),
            "{case}"
        );
        for (k, v) in &ta {
            assert!(tb[k] == *v, "{case}: {k} differs");
        }
    }
}

/// The CLI ships each window as it is sealed, and a second run into the same
/// directory appends the same manifests, which the ingest takes as repeats.
#[test]
fn the_cli_ships_to_the_ingest() {
    let ingest = MockIngest::start();
    let out = tempfile::tempdir().unwrap();
    let files: Vec<String> = [
        "openai_h2c_sse",
        "anthropic_h1_sse",
        "ollama_native",
        "openai_responses_h1_sse",
    ]
    .iter()
    .map(|c| format!("{c}.pcapng"))
    .collect();
    let run = || {
        let status = Command::new(env!("CARGO_BIN_EXE_collector"))
            .args([
                "-q",
                "--ingest",
                &ingest.url,
                "--collector-id",
                "cli",
                "files",
                "-w",
                "1",
                "-o",
            ])
            .arg(out.path())
            .args(fixture_paths(
                &files.iter().map(String::as_str).collect::<Vec<_>>(),
            ))
            .status()
            .unwrap();
        assert!(status.success());
    };
    run();
    let n = lines(&out.path().join(LOG)).len() as u64;
    assert!(n > 0);
    assert_eq!(pending_lines(out.path()).unwrap(), 0);
    let (held, accepted, ..) = ingest.snapshot();
    assert_eq!((held.len() as u64, accepted), (n, n));
    assert!(held.keys().all(|k| k.starts_with("cli/")));

    run();
    assert_eq!(lines(&out.path().join(LOG)).len() as u64, 2 * n);
    assert_eq!(pending_lines(out.path()).unwrap(), 0);
    let (again, accepted, duplicates, conflicts) = ingest.snapshot();
    assert_eq!((again, accepted, duplicates, conflicts), (held, n, n, 0));
}
