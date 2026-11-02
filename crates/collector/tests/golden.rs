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
use collector::decode::{Bucket, Buckets, HttpVersion, Verdict};
use collector::flow::Dir;
use collector::{FileSource, RingSource};

use collect::{collect_files, fixture_dir, fixture_paths, run_to_dir, tables, tables_and_bodies};
use fixtures::{cases, DUMPCAP_KEEPALIVE};

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

/// Every stream byte of every Flow, direction and Slice is in exactly one
/// bucket: the buckets sum to the Slice's stream range (TCP) or payload
/// (UDP), and the `gap` bucket matches the gaps Flow assembly counted.
#[test]
fn buckets_sum_to_flow_bytes_in_every_fixture() {
    for (case, files) in cases() {
        let names: Vec<&str> = files.iter().map(String::as_str).collect();
        let c = collect_files(&names);
        assert!(!c.flows.is_empty(), "{case}");
        for f in &c.flows {
            for (stats, bytes) in [
                (&f.slice.orig_stats, &f.orig_bytes),
                (&f.slice.resp_stats, &f.resp_bytes),
            ] {
                let total = match (stats.stream_start, stats.stream_end) {
                    (Some(s), Some(e)) => e - s,
                    _ => stats.payload_bytes,
                };
                assert_eq!(bytes.total(), total, "{case} {} {bytes:?}", f.slice.flow);
                assert_eq!(bytes.gap, stats.gap_bytes, "{case} {}", f.slice.flow);
            }
        }
        // Rows stay in window order per Flow, one per Slice.
        assert_eq!(c.flows.len(), c.slices.len());
    }
}

fn bytes_where(c: &collect::Collected, pick: impl Fn(&Buckets) -> u64) -> u64 {
    c.flows
        .iter()
        .map(|f| pick(&f.orig_bytes) + pick(&f.resp_bytes))
        .sum()
}

#[test]
fn openai_json_over_http1_and_h2c() {
    for (name, http) in [
        ("openai_h1_json", HttpVersion::Http1),
        ("openai_h2c_json", HttpVersion::Http2),
    ] {
        let c = collect_files(&[&format!("{name}.pcapng")]);
        let verdict = if http == HttpVersion::Http1 {
            Verdict::Http1
        } else {
            Verdict::Http2
        };
        assert!(c.flows.iter().all(|f| f.verdict == Some(verdict)), "{name}");
        assert_eq!(
            bytes_where(&c, |b| b.unexplained + b.gap + b.http_other),
            0,
            "{name}"
        );
        let eps: Vec<&str> = c.workunits.iter().map(|w| w.endpoint).collect();
        assert_eq!(eps, ["/v1/chat/completions", "/v1/completions"], "{name}");
        for w in &c.workunits {
            assert_eq!(w.http, http);
            assert!(w.complete && !w.stream && w.status == 200, "{name}");
            assert_eq!(w.model.as_deref(), Some("mock-model"));
            assert!(w.sse_events.is_none() && w.usage.is_some());
            assert!(w.completed_ts_ns.unwrap() > w.received_ts_ns);
        }
        assert_eq!(c.workunits[0].seed, Some(serde_json::json!(7)));
        assert_eq!(c.workunits[0].response_id.as_deref(), Some("chatcmpl-mock-0001"));
        assert_eq!(c.workunits[0].finish_reason[0].finish_reason, "stop");
        assert_eq!(c.workunits[1].finish_reason[0].finish_reason, "length");
    }
}

#[test]
fn openai_sse_over_http1_chunked_and_h2c() {
    for name in ["openai_h1_sse", "openai_h2c_sse"] {
        let c = collect_files(&[&format!("{name}.pcapng")]);
        assert_eq!(c.workunits.len(), 2, "{name}");
        let chat = &c.workunits[0];
        assert!(
            chat.stream && chat.complete && chat.sse_done == Some(true),
            "{name}"
        );
        // Role, four tokens, finish, usage, [DONE].
        let events = chat.sse_events.as_ref().unwrap();
        assert_eq!(events.len(), 8, "{name}");
        assert_eq!(events.iter().map(|e| e.len).sum::<u64>(), chat.response_body_len);
        assert!(
            events.windows(2).all(|w| w[0].ts_ns < w[1].ts_ns),
            "events arrive over time"
        );
        assert_eq!(chat.usage.as_ref().unwrap()["completion_tokens"], 4);
        assert_eq!(chat.finish_reason[0].finish_reason, "stop");
        assert_eq!(c.workunits[1].sse_events.as_ref().unwrap().len(), 5);
        assert_eq!(
            bytes_where(&c, |b| b.unexplained + b.gap + b.http_other),
            0,
            "{name}"
        );
        // Chunk-size lines (HTTP/1.1) or frame headers (h2c) are framing.
        assert!(bytes_where(&c, |b| b.framing) > 0);
    }
}

/// The same bodies sent over HTTP/1.1 and h2c hash the same: body hashes
/// cover the bytes, not the framing around them.
#[test]
fn body_hashes_do_not_depend_on_framing() {
    let hashes = |name: &str| -> Vec<(Option<String>, Option<String>)> {
        collect_files(&[&format!("{name}.pcapng")])
            .workunits
            .iter()
            .map(|w| (w.request_body_hash.clone(), w.response_body_hash.clone()))
            .collect()
    };
    assert_eq!(hashes("openai_h1_json"), hashes("openai_h2c_json"));
    assert_eq!(hashes("openai_h1_sse"), hashes("openai_h2c_sse"));
    let h = hashes("openai_h1_json");
    assert!(h
        .iter()
        .all(|(a, b)| a.as_ref().unwrap().starts_with("f1e20") && b.is_some()));
}

#[test]
fn health_models_and_bad_json_are_http_other() {
    let c = collect_files(&["http_other_h1.pcapng"]);
    assert!(c.workunits.is_empty());
    let got: Vec<(&str, u16, Bucket)> = c
        .exchanges
        .iter()
        .map(|e| {
            let req = e.request.as_ref().unwrap();
            (
                req.target.as_deref().unwrap(),
                e.response.as_ref().unwrap().status.unwrap(),
                e.bucket,
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            ("/health", 200, Bucket::HttpOther),
            ("/v1/models", 200, Bucket::HttpOther),
            ("/v1/chat/completions", 400, Bucket::HttpOther),
        ]
    );
    assert_eq!(bytes_where(&c, |b| b.http_other), bytes_where(&c, Buckets::total));
}

#[test]
fn http1_edge_cases() {
    let c = collect_files(&["http1_edge.pcapng"]);
    // Window 0 holds only the streaming request; it waits for the JSON error
    // response in window 1 and is then a Workunit.
    assert_eq!(c.flows.len(), 2);
    assert_eq!(c.flows[0].orig_bytes.workunit, fixtures::EDGE_A_REQ.len() as u64);
    assert_eq!(c.workunits.len(), 1);
    let w = &c.workunits[0];
    assert!(w.stream && w.status == 400 && w.response_content_type.as_deref() == Some("application/json"));
    let buckets: Vec<Bucket> = c.exchanges.iter().map(|e| e.bucket).collect();
    assert_eq!(buckets, [Bucket::Workunit, Bucket::HttpOther, Bucket::HttpOther]);
    // The pipelined pair is matched in order.
    let targets: Vec<&str> = c
        .exchanges
        .iter()
        .map(|e| e.request.as_ref().unwrap().target.as_deref().unwrap())
        .collect();
    assert_eq!(targets, ["/v1/chat/completions", "/v1/completions", "/metrics"]);
    // The lost segment inside chunk data is a gap; parsing stays in sync.
    let metrics = c.exchanges[2].response.as_ref().unwrap();
    assert_eq!(
        (
            metrics.body_len,
            metrics.body_gap_bytes,
            metrics.body_hash.as_deref()
        ),
        (20, 10, None)
    );
    let r = &c.flows[1].resp_bytes;
    assert_eq!((r.gap, r.framing, r.unexplained), (10, 4 + 2 + 3 + 2, 0));
    assert!(c
        .flows
        .iter()
        .all(|f| f.orig_desync.is_none() && f.resp_desync.is_none()));
}

#[test]
fn tls_and_grpc_flows_are_unexplained() {
    let c = collect_files(&["tls_plaintext.pcapng"]);
    assert_eq!(c.flows[0].verdict, Some(Verdict::Tls));
    assert_eq!(
        bytes_where(&c, |b| b.unexplained),
        (fixtures::TLS_CLIENT_HELLO.len() + fixtures::TLS_SERVER_HELLO.len() + fixtures::TLS_APP_DATA.len())
            as u64
    );
    assert!(c.exchanges.is_empty());

    let c = collect_files(&["grpc_h2c.pcapng"]);
    assert_eq!(c.flows[0].verdict, Some(Verdict::Grpc));
    assert_eq!(
        bytes_where(&c, |b| b.unexplained),
        bytes_where(&c, Buckets::total)
    );
    assert_eq!(c.exchanges.len(), 1);
    assert_eq!(c.exchanges[0].bucket, Bucket::Unexplained);
}

#[test]
fn stage_one_fixtures_get_verdicts() {
    let verdicts = |names: &[&str]| -> Vec<Option<Verdict>> {
        collect_files(names).flows.iter().map(|f| f.verdict).collect()
    };
    assert_eq!(verdicts(&["udp.pcapng"]), [Some(Verdict::Opaque); 2]);
    assert_eq!(verdicts(&["non_http_tcp.pcapng"]), [Some(Verdict::Opaque); 2]);
    // An SSE response caught mid-stream does not start with a status line.
    assert_eq!(verdicts(&["mid_stream.pcapng"]), [Some(Verdict::Opaque)]);
    // A keep-alive Flow caught mid-stream that starts on a request line.
    assert!(verdicts(DUMPCAP_KEEPALIVE)
        .iter()
        .all(|v| *v == Some(Verdict::Http1)));
    // The lost segment is in the request head: the rest of it is unexplained.
    let c = collect_files(&["lost_segment.pcapng"]);
    assert_eq!(c.flows[0].orig_desync, Some("gap"));
    assert_eq!(
        c.flows[0].orig_bytes.unexplained,
        (fixtures::LOST_A.len() + fixtures::LOST_C.len()) as u64
    );
}

/// Packets held in memory.
struct Packets(std::vec::IntoIter<collector::CapturedPacket>);

impl collector::PacketSource for Packets {
    fn next(&mut self) -> Option<Result<collector::CapturedPacket, collector::SourceError>> {
        self.0.next().map(Ok)
    }
}

/// The parsers read adversarial bytes. Corrupt payload bytes of every
/// fixture (seeded, so failures reproduce) and check that decoding never
/// panics and still puts every byte in exactly one bucket.
#[test]
fn corrupted_payloads_never_break_accounting() {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut rand = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for (case, files) in cases() {
        let names: Vec<&str> = files.iter().map(String::as_str).collect();
        let mut src = FileSource::new(fixture_paths(&names));
        let mut clean = Vec::new();
        while let Some(p) = collector::PacketSource::next(&mut src) {
            clean.push(p.unwrap());
        }
        for round in 0..40 {
            let mut pkts = clean.clone();
            for p in &mut pkts {
                // Leave Ethernet, IPv4 and TCP headers alone so Flows still form.
                if p.data.len() > 66 && rand() % 3 == 0 {
                    for _ in 0..1 + rand() % 4 {
                        let i = 66 + (rand() as usize) % (p.data.len() - 66);
                        p.data[i] = match round % 3 {
                            0 => rand() as u8,
                            1 => p.data[i] ^ 0x20,
                            _ => b"\r\n:0 \x00\xff"[(rand() % 7) as usize],
                        };
                    }
                }
            }
            let mut sink = collect::Collected::default();
            collector::run::run(
                &mut Packets(pkts.into_iter()),
                collect::WINDOW_NS,
                collector::AssemblerConfig::default(),
                collector::DecoderConfig::default(),
                &mut sink,
            )
            .unwrap();
            // Every kept body still matches its name.
            for (b3, body) in &sink.bodies {
                assert_eq!(*b3, collector::mh::of(body), "{case} round {round}");
            }
            for f in &sink.flows {
                for (stats, bytes) in [
                    (&f.slice.orig_stats, &f.orig_bytes),
                    (&f.slice.resp_stats, &f.resp_bytes),
                ] {
                    let total = match (stats.stream_start, stats.stream_end) {
                        (Some(s), Some(e)) => e - s,
                        _ => stats.payload_bytes,
                    };
                    assert_eq!(bytes.total(), total, "{case} round {round}");
                }
            }
        }
    }
}

/// Every body with a `body_hash` in the `http` table is kept under
/// `bodies/{multihash}`, and the file hashes to its name. `--no-bodies` keeps
/// none and leaves every table unchanged.
#[test]
fn bodies_are_kept_by_hash_unless_opted_out() {
    let mut kept_any = false;
    for (case, files) in cases() {
        let names: Vec<&str> = files.iter().map(String::as_str).collect();
        let (tables, bodies) = tables_and_bodies(&mut FileSource::new(fixture_paths(&names)), true);
        let http = &tables.iter().find(|(n, _)| n == "http.jsonl").unwrap().1;
        let mut want = std::collections::BTreeSet::new();
        for line in http.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
            let row: serde_json::Value = serde_json::from_slice(line).unwrap();
            for m in ["request", "response"] {
                if let Some(b3) = row[m]["body_hash"].as_str() {
                    want.insert(b3.to_string());
                }
            }
        }
        let got: std::collections::BTreeSet<String> = bodies.iter().map(|(n, _)| n.clone()).collect();
        assert_eq!(got, want, "{case}");
        for (name, body) in &bodies {
            assert_eq!(*name, collector::mh::of(body), "{case}");
        }
        kept_any |= bodies.iter().any(|(_, b)| !b.is_empty());

        let (without, none) = tables_and_bodies(&mut FileSource::new(fixture_paths(&names)), false);
        assert!(none.is_empty(), "{case}");
        assert_eq!(without, tables, "{case}");
    }
    assert!(kept_any);
}

#[test]
fn workunit_bodies_are_readable_by_hash() {
    let c = collect_files(&["openai_h1_sse.pcapng"]);
    let w = &c.workunits[0];
    let req = &c.bodies[w.request_body_hash.as_ref().unwrap()];
    assert!(req.starts_with(b"{") && req.len() as u64 == w.request_body_len);
    // One blob per SSE response, chunked encoding removed.
    let resp = &c.bodies[w.response_body_hash.as_ref().unwrap()];
    assert!(resp.starts_with(b"data: {") && resp.ends_with(b"data: [DONE]\n\n"));
    // The /metrics body with a lost segment has no hash and is not kept.
    let c = collect_files(&["http1_edge.pcapng"]);
    assert!(!c.bodies.values().any(|b| b.starts_with(fixtures::EDGE_C_CHUNK)));
}

/// Every `by-exchange/` link resolves to a body in `bodies/` whose hash is
/// its name (spec §12, locally). SSE Workunits get a merged view, the same
/// over HTTP/1.1 and h2c and across runs.
#[test]
fn by_exchange_links_resolve_and_sse_is_merged() {
    let mut links = 0;
    for (case, files) in cases() {
        let names: Vec<&str> = files.iter().map(String::as_str).collect();
        let out = run_to_dir(&mut FileSource::new(fixture_paths(&names)));
        let root = out.path().join(collector::views::BY_EXCHANGE);
        let Ok(flows) = std::fs::read_dir(&root) else {
            continue;
        };
        for flow in flows {
            for f in std::fs::read_dir(flow.unwrap().path()).unwrap() {
                let path = f.unwrap().path();
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                if name.ends_with(".merged.json") {
                    continue;
                }
                let target = std::fs::read_link(&path).unwrap();
                assert!(target.starts_with("../../bodies"), "{case} {name}");
                let hash = target.file_name().unwrap().to_string_lossy().into_owned();
                let body = std::fs::read(&path).expect("link resolves");
                assert_eq!(collector::mh::of(&body), hash, "{case} {name}");
                links += 1;
            }
        }
    }
    assert!(links > 0);

    let merged = |name: &str| -> Vec<serde_json::Value> {
        let out = run_to_dir(&mut FileSource::new(fixture_paths(&[&format!("{name}.pcapng")])));
        let mut files: Vec<_> = walk(&out.path().join(collector::views::BY_EXCHANGE))
            .into_iter()
            .filter(|p| p.to_string_lossy().ends_with(".merged.json"))
            .collect();
        files.sort();
        files
            .iter()
            .map(|p| serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap())
            .collect()
    };
    let h1 = merged("openai_h1_sse");
    assert_eq!(h1.len(), 2);
    assert_eq!(h1[0]["object"], "chat.completion");
    assert_eq!(h1[0]["choices"][0]["message"]["content"], "Hello, world!");
    assert_eq!(h1[0]["choices"][0]["finish_reason"], "stop");
    assert_eq!(h1[0]["usage"]["completion_tokens"], 4);
    assert_eq!(h1[0]["incomplete"], false);
    assert_eq!(h1[1]["object"], "text_completion");
    assert_eq!(h1[1]["choices"][0]["text"], "Hello, world!");
    assert_eq!(h1, merged("openai_h2c_sse"));
    assert_eq!(h1, merged("openai_h1_sse"));
    // JSON Workunits have no merged view.
    assert!(merged("openai_h1_json").is_empty());
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).into_iter().flatten() {
        let p = e.unwrap().path();
        if p.is_dir() && !p.is_symlink() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}
