//! Outcomes of OpenAI Responses streams through the whole pipeline
//! (TS-30, spec §5): only a stream that reaches `response.completed` or
//! `response.incomplete` is `ok`; `response.failed`, an `error` event, or no
//! terminal event at all is `errored`; a gap is `incomplete`.

#[path = "support/collect.rs"]
mod collect;
#[path = "support/fixtures.rs"]
mod fixtures;

use collector::decode::WorkunitRecord;
use collector::run::run;
use collector::stats::Outcome;
use collector::{AssemblerConfig, DecoderConfig, FileSource};

use collect::{Collected, WINDOW_NS};
use fixtures::{Conn, Frame, ACK, CLIENT, MS, PSH, SERVER, T0};

fn event(kind: &str, data: &str) -> String {
    format!("event: {kind}\ndata: {data}\n\n")
}

fn created() -> String {
    event(
        "response.created",
        r#"{"type":"response.created","response":{"id":"resp_1","object":"response","status":"in_progress","model":"m"}}"#,
    )
}

fn delta(text: &str) -> String {
    event(
        "response.output_text.delta",
        &format!(r#"{{"type":"response.output_text.delta","delta":"{text}"}}"#),
    )
}

fn terminal(kind: &str, status: &str, details: &str) -> String {
    event(
        kind,
        &format!(
            r#"{{"type":"{kind}","response":{{"id":"resp_1","object":"response","status":"{status}","model":"m",{details}"usage":{{"input_tokens":3,"output_tokens":2}}}}}}"#
        ),
    )
}

/// One connection: a streamed `/v1/responses` request, then `body` as an
/// SSE response cut into segments at `cuts`; the piece `lose` is never
/// captured.
fn exchange(port: u16, body: &str, cuts: &[usize], lose: Option<usize>) -> Vec<Frame> {
    let req_body = r#"{"model":"m","input":"hi","stream":true}"#;
    let req = format!(
        "POST /v1/responses HTTP/1.1\r\nhost: 10.0.0.2:8000\r\ncontent-type: application/json\r\n\
         content-length: {}\r\n\r\n{req_body}",
        req_body.len()
    );
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\n\r\n",
        body.len()
    );
    let at = T0 + u64::from(port) * MS;
    let mut c = Conn::new((CLIENT.0, port), SERVER, 1000, 9000);
    let mut f = Vec::new();
    c.handshake(at, &mut f);
    f.push(c.send(true, at + 10 * MS, PSH | ACK, req.as_bytes()));
    f.push(c.send(false, at + 20 * MS, PSH | ACK, head.as_bytes()));
    let mut bounds = vec![0];
    bounds.extend_from_slice(cuts);
    bounds.push(body.len());
    for (i, w) in bounds.windows(2).enumerate() {
        let seg = c.send(
            false,
            at + (21 + i as u64) * MS,
            PSH | ACK,
            &body.as_bytes()[w[0]..w[1]],
        );
        if lose != Some(i) {
            f.push(seg);
        }
    }
    f.push(c.ack(true, at + 40 * MS));
    c.close(at + 50 * MS, &mut f);
    f
}

fn by_port(c: &Collected, port: u16) -> &WorkunitRecord {
    let tag = format!(":{port}|");
    c.workunits
        .iter()
        .find(|w| w.flow.to_string().contains(&tag))
        .unwrap_or_else(|| panic!("no Workunit on port {port}"))
}

#[test]
fn only_a_completed_or_incomplete_stream_is_ok() {
    let start = [created(), delta("He"), delta("llo")].concat();
    let completed = format!("{start}{}", terminal("response.completed", "completed", ""));
    let cases: [(u16, String, &[usize], Option<usize>); 6] = [
        (42001, completed.clone(), &[], None),
        // HTTP ends cleanly, no terminal event.
        (42002, start.clone(), &[], None),
        (
            42003,
            format!(
                "{start}{}",
                terminal(
                    "response.failed",
                    "failed",
                    r#""error":{"code":"server_error","message":"x"},"#
                )
            ),
            &[],
            None,
        ),
        (
            42004,
            format!(
                "{start}{}",
                terminal(
                    "response.incomplete",
                    "incomplete",
                    r#""incomplete_details":{"reason":"max_output_tokens"},"#
                )
            ),
            &[],
            None,
        ),
        // A gap in the first delta: the stream stops framing there, though
        // `response.completed` was sent after it.
        (
            42005,
            completed,
            &[created().len() + 5, created().len() + 10],
            Some(1),
        ),
        (
            42006,
            format!(
                "{start}{}",
                event(
                    "error",
                    r#"{"type":"error","code":"rate_limit_exceeded","message":"slow down","param":null}"#
                )
            ),
            &[],
            None,
        ),
    ];
    let mut frames = Vec::new();
    for (port, body, cuts, lose) in &cases {
        frames.extend(exchange(*port, body, cuts, *lose));
    }
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    std::io::Write::write_all(&mut file, &fixtures::pcapng(&frames)).expect("write");
    let mut c = Collected::default();
    run(
        &mut FileSource::new(vec![file.path().to_path_buf()]),
        WINDOW_NS,
        AssemblerConfig::default(),
        DecoderConfig::default(),
        &mut c,
    )
    .expect("run");

    let w = by_port(&c, 42001);
    assert_eq!(w.protocol, "openai_responses");
    assert_eq!((w.complete, w.sse_done), (true, Some(true)));
    assert_eq!(w.outcome(), Outcome::Ok);

    let w = by_port(&c, 42002);
    assert_eq!(
        (w.complete, w.sse_done),
        (true, Some(false)),
        "missing completion"
    );
    assert!(w.finish_reason.is_empty());
    assert_eq!(w.outcome(), Outcome::Errored, "missing completion");

    let w = by_port(&c, 42003);
    assert_eq!((w.complete, w.sse_done), (true, Some(true)), "failed");
    assert_eq!(w.finish_reason[0].finish_reason, "failed");
    assert_eq!(w.outcome(), Outcome::Errored, "failed");

    let w = by_port(&c, 42004);
    assert_eq!((w.complete, w.sse_done), (true, Some(true)), "incomplete");
    assert_eq!(w.finish_reason[0].finish_reason, "max_output_tokens");
    assert_eq!(w.output_tokens, Some(2));
    assert_eq!(w.outcome(), Outcome::Ok, "incomplete is a whole response");

    let w = by_port(&c, 42005);
    assert!(!w.complete, "gap");
    assert_eq!(w.outcome(), Outcome::Incomplete, "a gap comes first");

    let w = by_port(&c, 42006);
    assert_eq!((w.complete, w.sse_done), (true, Some(true)), "error event");
    assert_eq!(w.outcome(), Outcome::Errored, "error event");
}
