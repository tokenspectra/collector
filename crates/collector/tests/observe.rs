//! Logging and the counter registry (TS-28 acceptance, spec §14): the
//! counters agree with the tables, `/metrics` parses, `-v` logs one line
//! per Request Workunit, the snapshot answers SIGUSR1, and none of it
//! changes an output file.

#[path = "support/collect.rs"]
mod collect;
#[path = "support/fixtures.rs"]
mod fixtures;

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use collector::assembler::{EventRecord, PacketRecord, SegmentRecord};
use collector::decode::{
    BodyKey, Bucket, ExchangeRecord, FlowRecord, RecordSink, WindowClose, WorkunitRecord,
};
use collector::flow::FlowKind;
use collector::observe::StatsSink;
use collector::output::TABLES;
use collector::run::run;
use collector::stats::{serve_metrics, HttpClass, Outcome, Registry, Snapshot, VerdictLabel, BUCKETS, DIRS};
use collector::{AssemblerConfig, DecoderConfig, FileSource, PacketSource};

use collect::{collect_observed, fixture_paths, tables_and_bodies_with, Collected, WINDOW_NS};
use fixtures::cases;

fn observed(files: &[String]) -> (Collected, Snapshot) {
    let names: Vec<&str> = files.iter().map(String::as_str).collect();
    collect_observed(&mut FileSource::new(fixture_paths(&names)))
}

/// The registry's final counters, recomputed from the tables.
#[test]
fn final_counters_equal_the_tables() {
    for (case, files) in cases() {
        let (c, s) = observed(&files);
        let mut packets = [0u64; 7];
        let mut bytes = [0u64; 7];
        for p in c.packets.iter().filter(|p| p.flow.is_none()) {
            packets[VerdictLabel::Other as usize] += 1;
            bytes[VerdictLabel::Other as usize] += u64::from(p.orig_len);
        }
        let mut flows = [0u64; 7];
        let mut accounted = [[0u64; 2]; 5];
        let mut stream_bytes = 0;
        for f in &c.flows {
            let label = VerdictLabel::of(f.slice.kind, f.verdict) as usize;
            let (o, r) = (&f.slice.orig_stats, &f.slice.resp_stats);
            packets[label] += o.packets + r.packets;
            bytes[label] += o.wire_bytes + r.wire_bytes;
            if f.slice.ended {
                flows[label] += 1;
            }
            for (d, b) in [&f.orig_bytes, &f.resp_bytes].into_iter().enumerate() {
                for (i, bucket) in BUCKETS.into_iter().enumerate() {
                    accounted[i][d] += b.get(bucket);
                }
            }
            for st in [o, r] {
                stream_bytes += match (f.slice.kind, st.stream_start, st.stream_end) {
                    (FlowKind::Tcp, Some(a), Some(b)) => b - a,
                    (FlowKind::Tcp, _, _) => 0,
                    _ => st.payload_bytes,
                };
            }
        }
        let distinct = |it: &mut dyn Iterator<Item = String>| it.collect::<BTreeSet<_>>().len() as u64;
        let wu_flows = distinct(&mut c.workunits.iter().map(|w| w.flow.to_string()));
        let mid = distinct(
            &mut c
                .flows
                .iter()
                .filter(|f| f.slice.mid_stream_start)
                .map(|f| f.slice.flow.to_string()),
        );
        let new = distinct(
            &mut c
                .packets
                .iter()
                .filter_map(|p| p.flow.as_ref())
                .map(|f| f.to_string()),
        );
        let windows = c
            .packets
            .iter()
            .map(|p| p.window_start_ns)
            .collect::<BTreeSet<_>>()
            .len() as u64;
        let mut workunits = [[0u64; 4]; 3];
        for w in &c.workunits {
            let o = Outcome::ALL.iter().position(|o| *o == w.outcome()).unwrap();
            let h = HttpClass::ALL
                .iter()
                .position(|h| *h == HttpClass::of(w.status))
                .unwrap();
            workunits[o][h] += 1;
        }
        let gaps: Vec<_> = c.events.iter().filter(|e| e.kind.is_gap()).collect();

        assert_eq!(s.packets_seen, c.packets.len() as u64, "{case}");
        assert_eq!(
            s.bytes_seen,
            c.packets.iter().map(|p| u64::from(p.orig_len)).sum::<u64>(),
            "{case}"
        );
        assert_eq!(s.packets, packets, "{case}: packets by verdict");
        assert_eq!(s.packets.iter().sum::<u64>(), s.packets_seen, "{case}");
        assert_eq!(s.bytes, bytes, "{case}: bytes by verdict");
        assert_eq!(s.bytes.iter().sum::<u64>(), s.bytes_seen, "{case}");
        assert_eq!(s.flows, flows, "{case}: flows by verdict");
        assert_eq!((s.flows_new, s.flows_active), (new, 0), "{case}");
        assert_eq!(s.flows_closed(), new, "{case}: every Flow closed");
        assert_eq!(s.flows_with_workunit, wu_flows, "{case}");
        assert_eq!(s.accounted, accounted, "{case}: bytes by bucket");
        assert_eq!(
            s.accounted_total(),
            stream_bytes,
            "{case}: buckets sum to the total"
        );
        assert_eq!(s.workunits, workunits, "{case}");
        assert_eq!(s.workunits_total(), c.workunits.len() as u64, "{case}");
        assert_eq!(
            s.workunits_with(Outcome::Incomplete),
            c.workunits.iter().filter(|w| !w.complete).count() as u64,
            "{case}"
        );
        assert_eq!(s.gaps, gaps.len() as u64, "{case}");
        assert_eq!(s.gap_bytes, gaps.iter().map(|e| e.len).sum::<u64>(), "{case}");
        assert_eq!(s.mid_stream_starts, mid, "{case}");
        assert_eq!(s.windows_closed, windows, "{case}");
        assert_eq!(s.capture_drops, 0, "{case}");
    }
}

/// Expected counters for a few fixtures, written out by hand.
#[test]
fn expected_counter_tables() {
    let get = |case: &str| {
        let (_, files) = cases().into_iter().find(|(c, _)| c == case).unwrap();
        observed(&files).1
    };
    let ok_2xx = |s: &Snapshot| s.workunits_by(Outcome::Ok, HttpClass::S2xx);

    let s = get("openai_h1_json");
    assert_eq!((ok_2xx(&s), s.workunits_total()), (2, 2));
    assert_eq!(
        (
            s.flows_closed(),
            s.flows_by(VerdictLabel::Http1),
            s.flows_with_workunit
        ),
        (1, 1, 1)
    );
    assert_eq!(
        s.bucket_bytes(Bucket::Unexplained) + s.bucket_bytes(Bucket::Gap),
        0
    );

    let s = get("openai_h2c_sse");
    assert_eq!((ok_2xx(&s), s.workunits_total()), (2, 2));
    assert_eq!(s.flows_by(VerdictLabel::Http2), 1);
    assert!(s.bucket_bytes(Bucket::Framing) > 0);

    let s = get("http_other_h1");
    assert_eq!(s.workunits_total(), 0);
    assert!(s.bucket_bytes(Bucket::HttpOther) > 0);
    assert_eq!(s.bucket_bytes(Bucket::Workunit), 0);

    let s = get("lost_segment");
    assert_eq!((s.gaps, s.gap_bytes), (1, 32));
    assert_eq!(s.bucket_bytes(Bucket::Gap), 32);

    let s = get("retransmit_differs");
    assert_eq!(s.retransmits_differing, 2);
    assert!(s.retransmit_differing_bytes > 0 && s.retransmit_bytes >= s.retransmit_differing_bytes);

    let s = get("mid_stream");
    assert_eq!(s.mid_stream_starts, 1);

    let s = get("udp");
    assert_eq!(
        s.flows_by(VerdictLabel::Udp),
        2,
        "idle timeout starts a new generation"
    );
    assert_eq!(
        (s.packets_by(VerdictLabel::Udp), s.packets_by(VerdictLabel::Other)),
        (5, 1),
        "one non-IP packet"
    );

    let s = get("tls_plaintext");
    assert_eq!(s.flows_by(VerdictLabel::Tls), 1);
    assert_eq!(s.bucket_bytes(Bucket::Unexplained), s.accounted_total());

    let s = get("dumpcap_keepalive");
    assert_eq!((s.mid_stream_starts, s.windows_closed), (1, 3));
}

/// Wrapping the sink in a [`StatsSink`] changes no table and no body.
#[test]
fn counting_changes_no_output() {
    for (case, files) in cases() {
        let names: Vec<&str> = files.iter().map(String::as_str).collect();
        let plain = tables_and_bodies_with(&mut FileSource::new(fixture_paths(&names)), true, false);
        let counted = tables_and_bodies_with(&mut FileSource::new(fixture_paths(&names)), true, true);
        assert!(plain == counted, "{case}");
    }
}

/// Every [`RecordSink`] call, in order.
#[derive(Default)]
struct Recording(Vec<String>);

impl RecordSink for Recording {
    fn packet(&mut self, rec: &PacketRecord) {
        self.0.push(format!("packet {rec:?}"));
    }
    fn segment(&mut self, rec: &SegmentRecord, data: &[u8]) {
        self.0.push(format!("segment {rec:?} {data:?}"));
    }
    fn event(&mut self, rec: &EventRecord) {
        self.0.push(format!("event {rec:?}"));
    }
    fn flow(&mut self, rec: &FlowRecord) {
        self.0.push(format!("flow {rec:?}"));
    }
    fn exchange(&mut self, rec: &ExchangeRecord) {
        self.0.push(format!("exchange {rec:?}"));
    }
    fn workunit(&mut self, rec: &WorkunitRecord) {
        self.0.push(format!("workunit {rec:?}"));
    }
    fn body_data(&mut self, key: &BodyKey, data: &[u8]) {
        self.0.push(format!("body_data {key:?} {data:?}"));
    }
    fn body_end(&mut self, key: &BodyKey, hash: Option<&str>) {
        self.0.push(format!("body_end {key:?} {hash:?}"));
    }
    fn window_closed(&mut self, w: &WindowClose) {
        self.0.push(format!("window_closed {w:?}"));
    }
}

/// A [`StatsSink`] passes every call through, `window_closed` included.
#[test]
fn stats_sink_forwards_every_call() {
    let record = |files: &[String], observe: bool| {
        let names: Vec<&str> = files.iter().map(String::as_str).collect();
        let cfg = DecoderConfig {
            keep_bodies: true,
            ..DecoderConfig::default()
        };
        let mut sink = Recording::default();
        let source = &mut FileSource::new(fixture_paths(&names));
        if observe {
            let mut stats = StatsSink::new(&mut sink, Registry::new());
            run(source, WINDOW_NS, AssemblerConfig::default(), cfg, &mut stats).expect("run");
        } else {
            run(source, WINDOW_NS, AssemblerConfig::default(), cfg, &mut sink).expect("run");
        }
        sink.0
    };
    for (case, files) in cases() {
        let plain = record(&files, false);
        assert!(plain.iter().any(|c| c.starts_with("window_closed ")), "{case}");
        assert!(plain == record(&files, true), "{case}");
    }
}

fn http_get(addr: std::net::SocketAddr, path: &str) -> (String, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    let (head, body) = resp.split_once("\r\n\r\n").unwrap();
    (head.to_string(), body.to_string())
}

/// Parses Prometheus text format strictly enough for our output: every
/// sample belongs to a family declared by `# TYPE`, and its value parses.
fn parse_prometheus(text: &str) -> BTreeMap<String, f64> {
    let mut families = BTreeMap::new();
    let mut samples = BTreeMap::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (name, kind) = rest.split_once(' ').unwrap();
            assert!(matches!(kind, "counter" | "gauge"), "{line}");
            families.insert(name.to_string(), kind.to_string());
            continue;
        }
        if line.starts_with("# HELP ") {
            continue;
        }
        let (series, value) = line
            .rsplit_once(' ')
            .unwrap_or_else(|| panic!("bad line {line:?}"));
        let name = series.split('{').next().unwrap();
        assert!(name.starts_with("ts_collector_"), "{line}");
        assert!(families.contains_key(name), "no # TYPE for {line}");
        if let Some(labels) = series.strip_prefix(name) {
            if !labels.is_empty() {
                let inner = labels
                    .strip_prefix('{')
                    .and_then(|l| l.strip_suffix('}'))
                    .unwrap();
                for kv in inner.split(',') {
                    let (k, v) = kv.split_once('=').unwrap();
                    assert!(k.chars().all(|c| c.is_ascii_lowercase() || c == '_'), "{line}");
                    assert!(v.starts_with('"') && v.ends_with('"'), "{line}");
                }
            }
        }
        if families[name] == "counter" {
            assert!(name.ends_with("_total"), "{line}");
        }
        let v: f64 = value.parse().unwrap_or_else(|_| panic!("bad value in {line:?}"));
        assert!(
            samples.insert(series.to_string(), v).is_none(),
            "duplicate {line}"
        );
    }
    samples
}

#[test]
fn metrics_endpoint_is_scraped_and_parses() {
    let reg = Registry::new();
    let addr = serve_metrics("127.0.0.1:0", reg.clone()).unwrap();
    let mut sink = Collected::default();
    run(
        &mut FileSource::new(fixture_paths(&["openai_h1_sse.pcapng"])),
        WINDOW_NS,
        AssemblerConfig::default(),
        DecoderConfig::default(),
        &mut StatsSink::new(&mut sink, reg.clone()),
    )
    .unwrap();
    let (head, body) = http_get(addr, "/metrics");
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert!(head.contains("Content-Type: text/plain; version=0.0.4"), "{head}");
    let m = parse_prometheus(&body);
    let s = reg.snapshot();
    let v = |k: &str| m.get(k).copied().unwrap_or_else(|| panic!("missing {k}"));
    let total: f64 = VerdictLabel::ALL
        .iter()
        .map(|l| {
            v(&format!(
                "ts_collector_packets_total{{verdict=\"{}\"}}",
                l.as_str()
            ))
        })
        .sum();
    assert_eq!(total, sink.packets.len() as f64);
    assert_eq!(
        v("ts_collector_workunits_total{outcome=\"ok\",http_class=\"2xx\"}"),
        2.0
    );
    assert_eq!(
        v("ts_collector_flows_with_workunit_total"),
        2.0,
        "one connection per request"
    );
    assert_eq!(v("ts_collector_flows_active"), 0.0);
    assert_eq!(v("ts_collector_windows_closed_total"), s.windows_closed as f64);
    for b in BUCKETS {
        for d in DIRS {
            let k = format!(
                "ts_collector_accounted_bytes_total{{bucket=\"{}\",direction=\"{}\"}}",
                collector::stats::bucket_str(b),
                collector::stats::dir_str(d)
            );
            assert_eq!(v(&k), s.accounted_by(b, d) as f64, "{k}");
        }
    }
    assert!(v("ts_collector_last_window_lag_seconds") > 0.0);
    let (head, _) = http_get(addr, "/other");
    assert!(head.starts_with("HTTP/1.1 404"), "{head}");
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_collector")
}

/// `collector -v --log-format json files ...` over a case: (log lines, output dir).
fn run_cli(files: &[String], extra: &[&str]) -> (Vec<serde_json::Value>, tempfile::TempDir) {
    let out = tempfile::tempdir().unwrap();
    let paths: Vec<PathBuf> = fixture_paths(&files.iter().map(String::as_str).collect::<Vec<_>>());
    let output = Command::new(bin())
        .args(["--log-format", "json"])
        .args(extra)
        .args(["files", "-w", "1", "-o"])
        .arg(out.path())
        .args(&paths)
        .env_remove("RUST_LOG")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let lines = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}")))
        .collect();
    (lines, out)
}

fn golden(case: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(case)
}

/// With `-v`, one DEBUG line per Request Workunit, in table order; and the
/// tables written are still the golden ones.
#[test]
fn verbose_run_logs_one_line_per_workunit() {
    for (case, files) in cases() {
        let (lines, out) = run_cli(&files, &["-v"]);
        let logged: Vec<&str> = lines
            .iter()
            .filter(|l| l["level"] == "DEBUG" && l["message"] == "workunit")
            .map(|l| l["workunit_id"].as_str().unwrap())
            .collect();
        let table = std::fs::read_to_string(golden(&case).join("workunits.jsonl")).unwrap();
        let expected: Vec<String> = table
            .lines()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["workunit_id"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(logged, expected, "{case}");
        for l in lines.iter().filter(|l| l["message"] == "workunit") {
            for f in [
                "flow",
                "dir",
                "method",
                "path",
                "model",
                "status",
                "stream",
                "request_bytes",
                "response_bytes",
                "outcome",
            ] {
                assert!(!l[f].is_null(), "{case}: no {f} in {l}");
            }
        }
        let windows = lines
            .iter()
            .filter(|l| l["level"] == "INFO" && l["message"] == "window closed")
            .count();
        assert!(windows > 0, "{case}");
        assert_eq!(
            lines.iter().filter(|l| l["message"] == "run finished").count(),
            1,
            "{case}"
        );
        for t in TABLES {
            let name = format!("{t}.jsonl");
            let a = std::fs::read(out.path().join(&name)).unwrap();
            assert!(
                a == std::fs::read(golden(&case).join(&name)).unwrap(),
                "{case}/{name}"
            );
        }
    }
}

/// Log levels and metrics don't change any output file, bodies and views
/// included.
#[test]
fn logging_and_metrics_change_no_output_file() {
    let files = vec![
        "openai_h2c_sse.pcapng".to_string(),
        "lost_segment.pcapng".to_string(),
    ];
    let (_, quiet) = run_cli(&files, &["-qq"]);
    let (trace, loud) = run_cli(&files, &["-vv", "--metrics-addr", "127.0.0.1:0"]);
    assert!(trace
        .iter()
        .any(|l| l["level"] == "TRACE" && l["message"] == "segment"));
    assert!(trace.iter().any(|l| l["message"] == "serving metrics"));
    let tree = |d: &Path| -> Vec<(PathBuf, Vec<u8>)> {
        let mut out = Vec::new();
        let mut stack = vec![d.to_path_buf()];
        while let Some(p) = stack.pop() {
            for e in std::fs::read_dir(&p).unwrap() {
                let e = e.unwrap().path();
                let meta = std::fs::symlink_metadata(&e).unwrap();
                if meta.is_dir() {
                    stack.push(e);
                } else {
                    let bytes = if meta.file_type().is_symlink() {
                        std::fs::read_link(&e)
                            .unwrap()
                            .into_os_string()
                            .into_encoded_bytes()
                    } else {
                        std::fs::read(&e).unwrap()
                    };
                    out.push((e.strip_prefix(d).unwrap().to_path_buf(), bytes));
                }
            }
        }
        out.sort();
        out
    };
    let (a, b) = (tree(quiet.path()), tree(loud.path()));
    assert!(a.len() > TABLES.len());
    assert!(a == b, "outputs differ between -qq and -vv with metrics");
}

#[test]
fn quiet_run_logs_nothing_and_log_level_overrides() {
    let files = vec!["openai_h1_json.pcapng".to_string()];
    let (lines, _) = run_cli(&files, &["-q"]);
    assert!(lines.is_empty(), "{lines:?}");
    let (lines, _) = run_cli(&files, &["-q", "--log-level", "debug"]);
    assert!(lines.iter().any(|l| l["message"] == "workunit"));
}

/// Statistics blocks report drops from the start of the capture: the
/// latest one counts.
#[test]
fn capture_drops_come_from_interface_statistics() {
    use pcap_file::pcapng::blocks::interface_description::{
        InterfaceDescriptionBlock, InterfaceDescriptionOption,
    };
    use pcap_file::pcapng::blocks::interface_statistics::{
        InterfaceStatisticsBlock, InterfaceStatisticsOption,
    };
    use pcap_file::pcapng::PcapNgWriter;

    let fx = fixtures::all()
        .into_iter()
        .find(|f| f.name == "lost_segment")
        .unwrap();
    let frames = &fx.files[0].1;
    let mut w = PcapNgWriter::new(Vec::new()).unwrap();
    w.write_pcapng_block(InterfaceDescriptionBlock {
        linktype: pcap_file::DataLink::ETHERNET,
        snaplen: 0,
        options: vec![
            InterfaceDescriptionOption::IfName(Cow::Borrowed("tap0")),
            InterfaceDescriptionOption::IfTsResol(9),
        ],
    })
    .unwrap();
    let isb = |n| InterfaceStatisticsBlock {
        interface_id: 0,
        timestamp: 0,
        options: vec![InterfaceStatisticsOption::IsbIfDrop(n)],
    };
    for (i, f) in frames.iter().enumerate() {
        if i == 2 {
            w.write_pcapng_block(isb(3)).unwrap();
        }
        w.write_pcapng_block(pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock {
            interface_id: 0,
            timestamp: Duration::from_nanos(f.ts_ns),
            original_len: f.orig_len,
            data: Cow::Borrowed(&f.data),
            options: vec![],
        })
        .unwrap();
    }
    w.write_pcapng_block(isb(7)).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("drops.pcapng");
    std::fs::write(&path, w.into_inner()).unwrap();

    let mut src = FileSource::new([&path]);
    let (_, s) = collect_observed(&mut src);
    assert_eq!(src.capture_drops(), Some(7));
    assert_eq!(s.capture_drops, 7);
    assert_eq!(
        FileSource::new(fixture_paths(&["lost_segment.pcapng"])).capture_drops(),
        None
    );
}

/// SIGUSR1 prints the snapshot table while a live run is going: a stand-in
/// dumpcap hands over one ring file, then keeps the ring open.
#[cfg(unix)]
#[test]
fn sigusr1_prints_a_snapshot() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let script = tmp.path().join("fake-dumpcap");
    let ring_file = fixture_paths(&["openai_h1_json.pcapng"]).remove(0);
    std::fs::write(
        &script,
        format!("#!/bin/sh\necho '{}'\nsleep 3\n", ring_file.display()),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut child = Command::new(bin())
        .args(["-v", "ring", "-i", "lo", "-w", "1", "--dumpcap"])
        .arg(&script)
        .arg("-d")
        .arg(tmp.path().join("ring"))
        .arg("-o")
        .arg(tmp.path().join("out"))
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    // Wait until the handler is in place and the ring file has been read.
    let (mut ready, mut workunits) = (false, 0);
    for line in lines.by_ref() {
        let line = line.unwrap();
        ready |= line.contains("snapshot on SIGUSR1");
        workunits += usize::from(line.contains("DEBUG workunit "));
        if ready && workunits == 2 {
            break;
        }
    }
    assert!(ready);
    let status = Command::new("kill")
        .args(["-USR1", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let rest: Vec<String> = lines.map(Result::unwrap).collect();
    assert!(child.wait().unwrap().success());
    let text = rest.join("\n");
    assert!(text.contains("TokenSpectra Collector snapshot"), "{text}");
    assert!(
        text.contains("request workunits            2 ok, 0 errored, 0 incomplete"),
        "{text}"
    );
    assert!(text.contains("run finished"), "{text}");
}
