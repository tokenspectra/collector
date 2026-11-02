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

use collect::{collect_files, fixture_dir, fixture_paths, run_to_dir, tables, tables_and_bodies, Files};
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
            assert_eq!(
                (w.protocol, w.output_tokens, &w.extra),
                ("openai", Some(4), &None)
            );
        }
        assert_eq!(c.workunits[0].input_tokens, Some(9));
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

fn responses_extra(w: &collector::decode::WorkunitRecord, key: &str) -> serde_json::Value {
    w.extra.as_ref().unwrap()[key].clone()
}

#[test]
fn openai_responses_json_over_http1_and_h2c() {
    for (name, http) in [
        ("openai_responses_h1_json", HttpVersion::Http1),
        ("openai_responses_h2c_json", HttpVersion::Http2),
    ] {
        let c = collect_files(&[&format!("{name}.pcapng")]);
        assert_eq!(
            bytes_where(&c, |b| b.unexplained + b.gap + b.http_other),
            0,
            "{name}"
        );
        assert_eq!(c.workunits.len(), 2, "{name}");
        for w in &c.workunits {
            assert_eq!(
                (w.protocol, w.endpoint, w.http),
                ("openai_responses", "/v1/responses", http)
            );
            assert!(w.complete && !w.stream && w.status == 200, "{name}");
            assert_eq!(w.outcome(), collector::stats::Outcome::Ok, "{name}");
            assert_eq!(w.model.as_deref(), Some("mock-model"));
            assert_eq!(w.response_id.as_deref(), Some("resp_mock_0001"));
            assert!(w.sse_events.is_none() && w.seed.is_none());
            assert_eq!(w.input_tokens, Some(9));
        }
        let (full, cut) = (&c.workunits[0], &c.workunits[1]);
        assert_eq!(full.output_tokens, Some(4));
        assert_eq!(full.finish_reason[0].finish_reason, "completed");
        assert_eq!(responses_extra(full, "status"), "completed");
        assert_eq!(cut.output_tokens, Some(2));
        assert_eq!(cut.finish_reason[0].finish_reason, "max_output_tokens");
        assert_eq!(responses_extra(cut, "status"), "incomplete");
        assert_eq!(responses_extra(cut, "previous_response_id"), "resp_mock_0000");
    }
}

#[test]
fn openai_responses_sse_over_http1_chunked_and_h2c() {
    for name in ["openai_responses_h1_sse", "openai_responses_h2c_sse"] {
        let c = collect_files(&[&format!("{name}.pcapng")]);
        assert_eq!(c.workunits.len(), 2, "{name}");
        let (full, cut) = (&c.workunits[0], &c.workunits[1]);
        for w in [full, cut] {
            assert!(w.stream && w.complete && w.sse_done == Some(true), "{name}");
            assert_eq!(w.outcome(), collector::stats::Outcome::Ok, "{name}");
            assert_eq!(w.protocol, "openai_responses");
            let events = w.sse_events.as_ref().unwrap();
            assert_eq!(events.iter().map(|e| e.len).sum::<u64>(), w.response_body_len);
        }
        // created, in_progress, item and part added, four deltas, text, part
        // and item done, completed.
        assert_eq!(full.sse_events.as_ref().unwrap().len(), 12, "{name}");
        assert_eq!(cut.sse_events.as_ref().unwrap().len(), 10, "{name}");
        assert_eq!((full.input_tokens, full.output_tokens), (Some(9), Some(4)));
        assert_eq!(full.finish_reason[0].finish_reason, "completed");
        assert_eq!(cut.finish_reason[0].finish_reason, "max_output_tokens");
        assert_eq!(
            bytes_where(&c, |b| b.unexplained + b.gap + b.http_other),
            0,
            "{name}"
        );
    }
}

#[test]
fn openai_responses_errors_are_workunits() {
    let c = collect_files(&["openai_responses_error_h1.pcapng"]);
    assert_eq!(c.workunits.len(), 2);
    let (missing, failed) = (&c.workunits[0], &c.workunits[1]);
    // A 404 JSON error body is read: an `ok` Workunit with a 4xx status.
    assert_eq!((missing.status, missing.complete), (404, true));
    assert_eq!(missing.outcome(), collector::stats::Outcome::Ok);
    assert!(missing.finish_reason.is_empty() && missing.response_id.is_none());
    assert_eq!(responses_extra(missing, "error_code"), "model_not_found");
    // A stream that ends in response.failed: a failure in band behind
    // HTTP 200, so `errored`.
    assert!(failed.stream && failed.complete && failed.sse_done == Some(true));
    assert_eq!(failed.outcome(), collector::stats::Outcome::Errored);
    assert_eq!(failed.finish_reason[0].finish_reason, "failed");
    assert_eq!(responses_extra(failed, "error_code"), "server_error");
    assert_eq!(responses_extra(failed, "status"), "failed");
}

/// Real Ollama: streamed chat and generate are NDJSON, `"stream": false`
/// and embed are one JSON object, and an unknown model is a JSON error.
#[test]
fn ollama_native_ndjson_and_json() {
    let c = collect_files(&["ollama_native.pcapng"]);
    assert!(c.flows.iter().all(|f| f.verdict == Some(Verdict::Http1)));
    assert_eq!(bytes_where(&c, |b| b.unexplained + b.gap + b.http_other), 0);
    let got: Vec<(&str, bool, u16, Option<&str>)> = c
        .workunits
        .iter()
        .map(|w| (w.endpoint, w.stream, w.status, w.response_content_type.as_deref()))
        .collect();
    let (nd, json) = (Some("application/x-ndjson"), Some("application/json"));
    assert_eq!(
        got,
        [
            ("/api/chat", true, 200, nd),
            ("/api/generate", true, 200, nd),
            ("/api/chat", false, 200, json),
            ("/api/generate", false, 200, json),
            ("/api/embed", false, 200, json),
            ("/api/chat", false, 404, json),
        ]
    );
    for w in &c.workunits {
        assert_eq!(w.protocol, "ollama");
        assert!(w.complete && w.outcome() == collector::stats::Outcome::Ok);
        assert_eq!(w.response_model, w.model.clone().filter(|_| w.status == 200));
        // NDJSON is not SSE, and Ollama sends no usage object.
        assert_eq!((w.sse_events.as_ref(), w.sse_done, &w.usage), (None, None, &None));
    }
    for w in &c.workunits[..4] {
        assert_eq!(w.model.as_deref(), Some("qwen2.5:0.5b"));
        assert_eq!((w.input_tokens, w.output_tokens), (Some(32), Some(8)));
        assert_eq!(w.finish_reason[0].finish_reason, "length");
        let x = w.extra.as_ref().unwrap();
        assert!(x["total_duration"].as_u64().unwrap() >= x["eval_duration"].as_u64().unwrap());
        // `done` is reported for streams only.
        assert_eq!(
            x["done"],
            if w.stream {
                serde_json::json!(true)
            } else {
                serde_json::Value::Null
            }
        );
    }
    let embed = &c.workunits[4];
    assert_eq!((embed.input_tokens, embed.output_tokens), (Some(5), None));
    assert!(embed.finish_reason.is_empty());
    assert_eq!(
        c.workunits[5].extra.as_ref().unwrap()["error"],
        "model 'no-such-model' not found"
    );
}

/// Ollama's OpenAI-compatible `/v1/*` endpoints are the OpenAI protocol's.
#[test]
fn ollama_openai_compatible_endpoints_decode_as_openai() {
    let c = collect_files(&["ollama_openai_compat.pcapng"]);
    assert_eq!(bytes_where(&c, |b| b.unexplained + b.gap + b.http_other), 0);
    let got: Vec<(&str, &str, bool)> = c
        .workunits
        .iter()
        .map(|w| (w.protocol, w.endpoint, w.stream))
        .collect();
    assert_eq!(
        got,
        [
            ("openai", "/v1/chat/completions", false),
            ("openai", "/v1/chat/completions", true),
        ]
    );
    assert!(c.workunits.iter().all(|w| w.complete && w.response_id.is_some()));
    assert_eq!(c.workunits[0].output_tokens, Some(8));
    assert_eq!(c.workunits[1].sse_done, Some(true));
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
    assert_eq!(
        hashes("openai_responses_h1_json"),
        hashes("openai_responses_h2c_json")
    );
    assert_eq!(
        hashes("openai_responses_h1_sse"),
        hashes("openai_responses_h2c_sse")
    );
    let h = hashes("openai_h1_json");
    assert!(h
        .iter()
        .all(|(a, b)| a.as_ref().unwrap().starts_with("f1e20") && b.is_some()));
}

#[test]
fn anthropic_json_over_http1_and_h2c() {
    for name in ["anthropic_h1_json", "anthropic_h2c_json"] {
        let c = collect_files(&[&format!("{name}.pcapng")]);
        assert_eq!(
            bytes_where(&c, |b| b.unexplained + b.gap + b.http_other),
            0,
            "{name}"
        );
        assert_eq!(c.workunits.len(), 2, "{name}");
        for w in &c.workunits {
            assert_eq!((w.protocol, w.endpoint), ("anthropic", "/v1/messages"));
            assert!(w.complete && !w.stream && w.sse_events.is_none(), "{name}");
            assert_eq!(w.outcome(), collector::stats::Outcome::Ok, "{name}");
            assert_eq!((&w.seed, &w.n), (&None, &None));
        }
        let ok = &c.workunits[0];
        assert_eq!(ok.status, 200);
        assert_eq!(ok.response_id.as_deref(), Some("msg_mock_0001"));
        assert_eq!(ok.response_model.as_deref(), Some("mock-model"));
        assert_eq!(ok.finish_reason[0].finish_reason, "end_turn");
        assert_eq!((ok.input_tokens, ok.output_tokens), (Some(9), Some(4)));
        let extra = ok.extra.as_ref().unwrap();
        assert_eq!(extra["cache_read_input_tokens"], 6);
        assert_eq!(extra["cache_creation_input_tokens"], 0);
        // An error body is still the protocol's: status and error type.
        let err = &c.workunits[1];
        assert_eq!(err.status, 400);
        assert!(err.finish_reason.is_empty() && err.usage.is_none());
        assert_eq!(err.extra.as_ref().unwrap()["error_type"], "invalid_request_error");
    }
}

#[test]
fn anthropic_sse_over_http1_chunked_and_h2c() {
    for name in ["anthropic_h1_sse", "anthropic_h2c_sse"] {
        let c = collect_files(&[&format!("{name}.pcapng")]);
        assert_eq!(c.workunits.len(), 2, "{name}");
        let ok = &c.workunits[0];
        assert!(ok.stream && ok.complete && ok.sse_done == Some(true), "{name}");
        // message_start, content_block_start, ping, four deltas,
        // content_block_stop, message_delta, message_stop.
        let events = ok.sse_events.as_ref().unwrap();
        assert_eq!(events.len(), 10, "{name}");
        assert_eq!(events.iter().map(|e| e.len).sum::<u64>(), ok.response_body_len);
        assert!(events.windows(2).all(|w| w[0].ts_ns < w[1].ts_ns));
        assert_eq!(ok.finish_reason[0].finish_reason, "end_turn");
        // message_delta's cumulative output count replaces message_start's.
        assert_eq!((ok.input_tokens, ok.output_tokens), (Some(9), Some(4)));
        assert_eq!(ok.extra.as_ref().unwrap()["cache_read_input_tokens"], 6);

        // An `error` event after the first token: the HTTP exchange is whole,
        // but the message never stopped.
        let cut = &c.workunits[1];
        assert_eq!((cut.status, cut.complete), (200, true), "{name}");
        assert_eq!(cut.sse_done, Some(false));
        assert_eq!(cut.sse_events.as_ref().unwrap().len(), 5);
        assert!(cut.finish_reason.is_empty());
        assert_eq!(cut.output_tokens, Some(1));
        assert_eq!(cut.extra.as_ref().unwrap()["error_type"], "overloaded_error");

        assert_eq!(
            bytes_where(&c, |b| b.unexplained + b.gap + b.http_other),
            0,
            "{name}"
        );
        assert!(bytes_where(&c, |b| b.framing) > 0);
    }
    let hashes = |name: &str| -> Vec<Option<String>> {
        collect_files(&[&format!("{name}.pcapng")])
            .workunits
            .iter()
            .map(|w| w.response_body_hash.clone())
            .collect()
    };
    assert_eq!(hashes("anthropic_h1_sse"), hashes("anthropic_h2c_sse"));
    assert_eq!(hashes("anthropic_h1_json"), hashes("anthropic_h2c_json"));
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

        // Only the blobs are missing: every other table is the same, and the
        // pack holds the same Workunit records, without bodies.
        let (without, none) = tables_and_bodies(&mut FileSource::new(fixture_paths(&names)), false);
        assert!(none.is_empty(), "{case}");
        let not_blobs =
            |t: &Files| -> Files { t.iter().filter(|(n, _)| n != "blobs.jsonl").cloned().collect() };
        assert_eq!(not_blobs(&without), not_blobs(&tables), "{case}");
        let records = |t: &Files, kind: &str| -> Vec<String> {
            let blobs = &t.iter().find(|(n, _)| n == "blobs.jsonl").unwrap().1;
            blobs
                .split(|&b| b == b'\n')
                .filter(|l| !l.is_empty())
                .map(|l| serde_json::from_slice::<serde_json::Value>(l).unwrap())
                .filter(|r| r["kind"] == kind)
                .map(|r| r["hash"].as_str().unwrap().to_string())
                .collect()
        };
        assert!(records(&without, "body").is_empty(), "{case}");
        assert_eq!(
            records(&without, "workunit"),
            records(&tables, "workunit"),
            "{case}"
        );
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

/// Tables are flushed and `by-exchange/` is extended as each window closes,
/// so a live run's rows and views are on disk before it ends, and a killed
/// run keeps every closed window.
#[test]
fn tables_and_views_are_on_disk_when_a_window_closes() {
    use collector::output::JsonlSink;
    use collector::run::run;
    use collector::{AssemblerConfig, DecoderConfig};

    let dir = tempfile::tempdir().unwrap();
    // Left by an earlier run into the same directory.
    std::fs::create_dir_all(dir.path().join("by-exchange/stale")).unwrap();
    std::fs::write(dir.path().join("by-exchange/stale/0.request.json"), "{}").unwrap();
    let mut sink = JsonlSink::create(dir.path()).unwrap();
    let mut source = FileSource::new(fixture_paths(&["openai_h1_sse.pcapng"]));
    run(
        &mut source,
        collect::WINDOW_NS,
        AssemblerConfig::default(),
        DecoderConfig::default(),
        &mut sink,
    )
    .unwrap();
    // No `finish()` and no `views::write`: only the window-close work has run.
    let on_disk = std::fs::read(dir.path().join("workunits.jsonl")).unwrap();
    let golden = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/openai_h1_sse/workunits.jsonl"),
    )
    .unwrap();
    assert!(!golden.is_empty());
    assert_eq!(on_disk, golden, "{}", first_diff(&golden, &on_disk));

    let live = view_tree(dir.path());
    assert!(
        live.iter().any(|(p, _)| p.ends_with(".response.merged.json")),
        "{live:?}"
    );
    collector::views::write(dir.path()).unwrap();
    assert_eq!(live, view_tree(dir.path()));
}

/// Every file under `by-exchange/`, with its link target or contents.
fn view_tree(out: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(dir: &Path, root: &Path, acc: &mut Vec<(String, Vec<u8>)>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            let name = p.strip_prefix(root).unwrap().display().to_string();
            let meta = std::fs::symlink_metadata(&p).unwrap();
            if meta.is_dir() {
                walk(&p, root, acc);
            } else if meta.file_type().is_symlink() {
                acc.push((
                    name,
                    std::fs::read_link(&p)
                        .unwrap()
                        .into_os_string()
                        .into_encoded_bytes(),
                ));
            } else {
                acc.push((name, std::fs::read(&p).unwrap()));
            }
        }
    }
    let root = out.join("by-exchange");
    let mut acc = Vec::new();
    walk(&root, &root, &mut acc);
    acc.sort();
    acc
}
