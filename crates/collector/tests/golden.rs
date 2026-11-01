//! Golden `.pcapng` fixtures with expected outputs (TS-24 acceptance).
//!
//! Expected tables live in `tests/golden/<case>/`. After an intended change
//! in output, regenerate them with `UPDATE_GOLDEN=1 cargo test -p collector
//! --test golden` and review the diff.

#[path = "support/collect.rs"]
mod collect;
#[path = "support/fixtures.rs"]
mod fixtures;

use std::io::Cursor;
use std::path::Path;

use collector::assembler::EventKind;
use collector::flow::Dir;
use collector::{FileSource, RingSource};

use collect::{collect_files, fixture_dir, fixture_paths, tables};

const DUMPCAP_KEEPALIVE: &[&str] = &[
    "dumpcap_keepalive-1.pcapng",
    "dumpcap_keepalive-2.pcapng",
    "dumpcap_keepalive-3.pcapng",
    "dumpcap_keepalive-4.pcapng",
    "dumpcap_keepalive-5.pcapng",
];

/// (case name, files in read order).
fn cases() -> Vec<(String, Vec<String>)> {
    let mut cases: Vec<(String, Vec<String>)> = fixtures::all()
        .into_iter()
        .map(|fx| {
            (
                fx.name.to_string(),
                fx.files.iter().map(|(n, _)| n.to_string()).collect(),
            )
        })
        .collect();
    cases.push((
        "dumpcap_keepalive".into(),
        DUMPCAP_KEEPALIVE.iter().map(|s| s.to_string()).collect(),
    ));
    cases
}

fn first_diff(expected: &[u8], actual: &[u8]) -> String {
    let e = String::from_utf8_lossy(expected);
    let a = String::from_utf8_lossy(actual);
    for (i, (x, y)) in e.lines().zip(a.lines()).enumerate() {
        if x != y {
            return format!("line {}:\n  expected: {x}\n  actual:   {y}", i + 1);
        }
    }
    format!(
        "{} expected lines, {} actual",
        e.lines().count(),
        a.lines().count()
    )
}

#[test]
fn golden_outputs() {
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();
    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    let mut failures = Vec::new();
    for (case, files) in cases() {
        let names: Vec<&str> = files.iter().map(String::as_str).collect();
        let dir = golden.join(&case);
        for (table, actual) in tables(&mut FileSource::new(fixture_paths(&names))) {
            let path = dir.join(&table);
            if update {
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(&path, &actual).unwrap();
                continue;
            }
            let expected = std::fs::read(&path).unwrap_or_default();
            if expected != actual {
                failures.push(format!("{case}/{table}: {}", first_diff(&expected, &actual)));
            }
        }
    }
    assert!(failures.is_empty(), "golden mismatches:\n{}", failures.join("\n"));
}

#[test]
fn two_runs_are_byte_identical() {
    for (case, files) in cases() {
        let names: Vec<&str> = files.iter().map(String::as_str).collect();
        let a = tables(&mut FileSource::new(fixture_paths(&names)));
        let b = tables(&mut FileSource::new(fixture_paths(&names)));
        assert_eq!(a, b, "{case}");
    }
}

#[test]
fn fixtures_are_current() {
    for fx in fixtures::all() {
        for (name, frames) in &fx.files {
            let committed = std::fs::read(fixture_dir().join(name)).unwrap();
            assert!(
                committed == fixtures::pcapng(frames),
                "{name} is stale: run `cargo run -p collector --example gen_fixtures`"
            );
        }
    }
}

/// `RingSource` hands each closed file to `FileSource`; over the same files
/// it must give the same output as `FileSource` over the list.
#[test]
fn ring_handoff_equals_file_source() {
    for (case, files) in cases() {
        let names: Vec<&str> = files.iter().map(String::as_str).collect();
        let paths = fixture_paths(&names);
        let listing: String = paths.iter().map(|p| format!("{}\n", p.display())).collect();
        let mut ring = RingSource::from_names(Cursor::new(listing));
        let from_ring = tables(&mut ring);
        assert_eq!(ring.files(), paths.as_slice());
        let from_files = tables(&mut FileSource::new(paths));
        assert_eq!(from_ring, from_files, "{case}");
    }
}

/// The spawn path, with a stand-in for dumpcap that prints closed file
/// names the way `-b printname:stdout` does and records its arguments.
#[cfg(unix)]
#[test]
fn ring_spawns_dumpcap_and_reads_printed_names() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let paths = fixture_paths(&["span_windows-1.pcapng", "span_windows-2.pcapng"]);
    let args_file = tmp.path().join("args");
    let script = tmp.path().join("fake-dumpcap");
    let mut body = format!("#!/bin/sh\necho \"$@\" > '{}'\n", args_file.display());
    for p in &paths {
        body.push_str(&format!("echo '{}'\n", p.display()));
    }
    std::fs::write(&script, body).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut cfg = collector::RingConfig::new("tap0", 1, tmp.path());
    cfg.dumpcap = script;
    let mut ring = RingSource::spawn(&cfg).unwrap();
    let from_ring = tables(&mut ring);
    let from_files = tables(&mut FileSource::new(paths));
    assert_eq!(from_ring, from_files);

    let args = std::fs::read_to_string(args_file).unwrap();
    assert!(args.contains("-b interval:1 -b printname:stdout"), "{args}");
    assert!(!args.contains("files:"), "{args}");
}

const FLOW: &str = "tap0|tcp|10.0.0.1:40000|10.0.0.2:8000|0";

#[test]
fn span_windows_carries_flow_across_files_and_windows() {
    let c = collect_files(&["span_windows-1.pcapng", "span_windows-2.pcapng"]);
    assert_eq!(
        c.stream(FLOW, Dir::Orig),
        String::from_utf8_lossy(fixtures::HTTP_REQUEST)
    );
    let response = [fixtures::HTTP_RESPONSE_1, fixtures::HTTP_RESPONSE_2].concat();
    assert_eq!(c.stream(FLOW, Dir::Resp), String::from_utf8_lossy(&response));

    // One Flow, two Slices; the response stream is split at the window edge.
    assert_eq!(c.slices.len(), 2);
    assert!(c.slices.iter().all(|s| s.flow.as_str() == FLOW));
    let r1 = fixtures::HTTP_RESPONSE_1.len() as u64;
    assert_eq!(c.slices[0].resp_stats.stream_start, Some(0));
    assert_eq!(c.slices[0].resp_stats.stream_end, Some(r1));
    assert_eq!(c.slices[1].resp_stats.stream_start, Some(r1));
    assert_eq!(
        c.slices[1].resp_stats.stream_end,
        Some(r1 + fixtures::HTTP_RESPONSE_2.len() as u64)
    );
    assert!(!c.slices[0].ended && c.slices[1].ended);
    assert!(c.events.is_empty());

    // The second response segment is packet 0 of the second window's chunk.
    let seg = c
        .segments
        .iter()
        .find(|s| s.dir == Dir::Resp && s.stream_off == r1)
        .unwrap();
    assert_eq!(
        (seg.window_start_ns, seg.index, seg.pkt_off),
        (fixtures::T0 + fixtures::SEC, 0, 54)
    );
}

#[test]
fn mid_stream_start_is_accepted_and_marked() {
    let c = collect_files(&["mid_stream.pcapng"]);
    let s = &c.slices[0];
    assert!(s.mid_stream_start);
    assert!(!s.syn && !s.syn_ack);
    // Without a handshake, the first sender is the originator.
    assert_eq!(s.orig.to_string(), "10.0.0.2:8000");
    let body = [fixtures::MID_1, fixtures::MID_2].concat();
    assert_eq!(c.stream(FLOW, Dir::Orig), String::from_utf8_lossy(&body));
    let kinds: Vec<EventKind> = c.events.iter().map(|e| e.kind).collect();
    assert_eq!(kinds, [EventKind::BeforeStreamStart]);
    assert_eq!(c.events[0].len, 4);
    // The rest of that packet repeats bytes already delivered, unchanged.
    assert_eq!(s.orig_stats.retransmit_bytes, fixtures::MID_1.len() as u64);
    assert_eq!(s.orig_stats.retransmit_diff_bytes, 0);
}

#[test]
fn lost_segment_becomes_a_gap_across_sequence_wraparound() {
    let c = collect_files(&["lost_segment.pcapng"]);
    let a = fixtures::LOST_A.len() as u64;
    let b = fixtures::LOST_B.len() as u64;
    let gaps: Vec<_> = c.events.iter().filter(|e| e.kind.is_gap()).collect();
    assert_eq!(gaps.len(), 1);
    assert_eq!(
        (gaps[0].kind, gaps[0].stream_off, gaps[0].len),
        (EventKind::GapLost, Some(a), b)
    );
    let expected = format!(
        "{}{}{}",
        String::from_utf8_lossy(fixtures::LOST_A),
        "~".repeat(b as usize),
        String::from_utf8_lossy(fixtures::LOST_C)
    );
    assert_eq!(c.stream(FLOW, Dir::Orig), expected);
    assert_eq!(c.slices[0].orig_stats.gap_bytes, b);
}

#[test]
fn retransmit_with_different_bytes_is_flagged() {
    let c = collect_files(&["retransmit_differs.pcapng"]);
    // First copy wins.
    assert_eq!(c.stream(FLOW, Dir::Orig), "hello world\nsecond line third line\n");
    let diffs: Vec<(Option<u64>, u64)> = c
        .events
        .iter()
        .filter(|e| e.kind == EventKind::RetransmitDiffers)
        .map(|e| (e.stream_off, e.len))
        .collect();
    // "world" vs "WORLD" after delivery; "third" vs "thirD" while pending.
    assert_eq!(diffs, [(Some(6), 5), (Some(28), 1)]);
    let s = &c.slices[0].orig_stats;
    assert_eq!(s.retransmit_bytes, 12 + 12 + 11);
    assert_eq!(s.retransmit_diff_bytes, 6);
}

#[test]
fn udp_datagrams_and_idle_generation() {
    let c = collect_files(&["udp.pcapng"]);
    let ids: Vec<&str> = c.slices.iter().map(|s| s.flow.as_str()).collect();
    assert_eq!(
        ids,
        [
            "tap0|udp|10.0.0.1:5353|10.0.0.53:53|0",
            "tap0|udp|10.0.0.1:5353|10.0.0.53:53|1"
        ]
    );
    let first = &c.slices[0];
    assert_eq!(first.orig_stats.datagrams, 1);
    assert_eq!(first.resp_stats.datagrams, 2);
    // The truncated answer kept 8 of its 45 payload bytes.
    assert_eq!(first.resp_stats.gap_bytes, 37);
    assert_eq!(first.orig_stats.stream_start, None);
    assert!(c.segments.is_empty());
    assert_eq!(c.packets.iter().filter(|p| p.note == Some("not_ip")).count(), 1);
}

#[test]
fn non_http_tcp_and_tuple_reuse() {
    let c = collect_files(&["non_http_tcp.pcapng"]);
    let g0 = "tap0|tcp|10.0.0.1:40000|10.0.0.2:6379|0";
    let g1 = "tap0|tcp|10.0.0.1:40000|10.0.0.2:6379|1";
    assert_eq!(
        c.stream(g0, Dir::Orig),
        String::from_utf8_lossy(fixtures::REDIS_PING)
    );
    assert_eq!(
        c.stream(g0, Dir::Resp),
        String::from_utf8_lossy(fixtures::REDIS_PONG)
    );
    // The new SYN starts generation 1; its SET was cut to 20 bytes.
    let set = c.stream(g1, Dir::Orig);
    assert_eq!(set.len(), 59);
    assert!(set.starts_with("*3\r\n$3\r\nSET\r\n$1\r\nk\r\n") && set.ends_with(&"~".repeat(39)));
    let truncated: Vec<_> = c
        .events
        .iter()
        .filter(|e| e.kind == EventKind::GapTruncated)
        .collect();
    assert_eq!(truncated.len(), 1);
    assert_eq!(truncated[0].index, Some(11));
    assert!(c.slices[0].fin_orig && c.slices[0].fin_resp);
    assert!(c.slices[1].rst);
}

#[test]
fn dumpcap_keepalive_flow_spans_ring_files() {
    let c = collect_files(DUMPCAP_KEEPALIVE);
    let flows: std::collections::BTreeSet<&str> = c.slices.iter().map(|s| s.flow.as_str()).collect();
    assert_eq!(flows.len(), 1, "one keep-alive Flow");
    assert!(c.slices.len() >= 2, "it spans windows");
    assert!(
        c.slices.iter().all(|s| s.mid_stream_start),
        "its SYN predates the capture"
    );
    assert!(c.events.is_empty());
    let flow = *flows.iter().next().unwrap();
    let requests = c.stream(flow, Dir::Orig);
    let responses = c.stream(flow, Dir::Resp);
    assert_eq!(requests.matches("GET /health.json HTTP/1.1\r\n").count(), 6);
    assert_eq!(responses.matches("HTTP/1.1 200 OK\r\n").count(), 6);
}
