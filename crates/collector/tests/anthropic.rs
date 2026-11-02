//! Outcomes of Anthropic Messages streams through the whole pipeline
//! (TS-31, spec §5): only a stream that reaches `message_stop` is `ok`, a
//! `max_tokens` stop included; a clean HTTP end without `message_stop`, or
//! an in-band `error` event, is `errored`; a gap is `incomplete`. A whole
//! JSON body that is neither a `message` nor an `error` is `errored`.

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

fn start() -> String {
    [
        event(
            "message_start",
            r#"{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"m","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":3,"output_tokens":1}}}"#,
        ),
        event(
            "content_block_start",
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
        ),
        delta("He"),
        delta("llo"),
    ]
    .concat()
}

fn delta(text: &str) -> String {
    event(
        "content_block_delta",
        &format!(
            r#"{{"type":"content_block_delta","index":0,"delta":{{"type":"text_delta","text":"{text}"}}}}"#
        ),
    )
}

/// `content_block_stop`, `message_delta` with `stop_reason`, and
/// `message_stop` unless `stop` is false.
fn end(stop_reason: &str, stop: bool) -> String {
    let mut s = event("content_block_stop", r#"{"type":"content_block_stop","index":0}"#);
    s += &event(
        "message_delta",
        &format!(
            r#"{{"type":"message_delta","delta":{{"stop_reason":"{stop_reason}","stop_sequence":null}},"usage":{{"output_tokens":2}}}}"#
        ),
    );
    if stop {
        s += &event("message_stop", r#"{"type":"message_stop"}"#);
    }
    s
}

/// One connection: a streamed `/v1/messages` request, then `body` as an SSE
/// response cut into segments at `cuts`; the piece `lose` is never captured.
fn exchange(port: u16, body: &str, cuts: &[usize], lose: Option<usize>) -> Vec<Frame> {
    connection(port, true, body, cuts, lose)
}

/// A `/v1/messages` request, streamed or not, answered with `body` as SSE
/// or as one JSON document.
fn connection(port: u16, stream: bool, body: &str, cuts: &[usize], lose: Option<usize>) -> Vec<Frame> {
    let req_body = format!(
        r#"{{"model":"m","max_tokens":2,"messages":[{{"role":"user","content":"hi"}}],"stream":{stream}}}"#
    );
    let media_type = if stream {
        "text/event-stream"
    } else {
        "application/json"
    };
    let req = format!(
        "POST /v1/messages HTTP/1.1\r\nhost: 10.0.0.2:8000\r\ncontent-type: application/json\r\n\
         anthropic-version: 2023-06-01\r\ncontent-length: {}\r\n\r\n{req_body}",
        req_body.len()
    );
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {media_type}\r\ncontent-length: {}\r\n\r\n",
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
fn only_a_stream_that_reaches_message_stop_is_ok() {
    let s = start();
    let finished = format!("{s}{}", end("end_turn", true));
    let cases: [(u16, String, &[usize], Option<usize>); 5] = [
        (43001, finished.clone(), &[], None),
        // HTTP ends cleanly, no message_stop.
        (43002, format!("{s}{}", end("end_turn", false)), &[], None),
        // A gap in the last delta: framing stops there, though message_stop
        // was sent after it.
        (43003, finished, &[s.len() - 40, s.len() - 30], Some(1)),
        // An in-band error event behind HTTP 200.
        (
            43004,
            format!(
                "{s}{}",
                event(
                    "error",
                    r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#
                )
            ),
            &[],
            None,
        ),
        (43005, format!("{s}{}", end("max_tokens", true)), &[], None),
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

    let w = by_port(&c, 43001);
    assert_eq!(w.protocol, "anthropic");
    assert_eq!((w.complete, w.sse_done), (true, Some(true)));
    assert_eq!(w.finish_reason[0].finish_reason, "end_turn");
    assert_eq!(w.outcome(), Outcome::Ok);

    let w = by_port(&c, 43002);
    assert_eq!((w.complete, w.sse_done), (true, Some(false)), "no message_stop");
    // The stop reason arrived; the stream still did not end.
    assert_eq!(w.finish_reason[0].finish_reason, "end_turn");
    assert_eq!(w.outcome(), Outcome::Errored, "no message_stop");

    let w = by_port(&c, 43003);
    assert!(!w.complete, "gap");
    assert_eq!(w.outcome(), Outcome::Incomplete, "a gap comes first");

    let w = by_port(&c, 43004);
    assert_eq!((w.complete, w.sse_done), (true, Some(false)), "error event");
    assert!(w.finish_reason.is_empty());
    assert_eq!(w.extra.as_ref().unwrap()["error_type"], "overloaded_error");
    assert_eq!(w.outcome(), Outcome::Errored, "error event");

    let w = by_port(&c, 43005);
    assert_eq!((w.complete, w.sse_done), (true, Some(true)), "max_tokens");
    assert_eq!(w.finish_reason[0].finish_reason, "max_tokens");
    assert_eq!(w.output_tokens, Some(2));
    assert_eq!(w.outcome(), Outcome::Ok, "max_tokens is a whole response");
}

#[test]
fn a_json_body_that_is_not_a_message_or_an_error_is_errored() {
    let message = r#"{"id":"msg_1","type":"message","role":"assistant","model":"m","content":[{"type":"text","text":"Hello"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":3,"output_tokens":2}}"#;
    let mut frames = connection(43101, false, message, &[], None);
    frames.extend(connection(43102, false, r#"{"type":"unexpected"}"#, &[], None));
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

    let w = by_port(&c, 43101);
    assert_eq!((w.protocol, w.stream, w.complete), ("anthropic", false, true));
    assert_eq!(w.response_id.as_deref(), Some("msg_1"));
    assert_eq!(w.outcome(), Outcome::Ok, "a message");

    let w = by_port(&c, 43102);
    assert_eq!((w.stream, w.complete, w.status), (false, true, 200));
    assert!(w.response_id.is_none() && w.finish_reason.is_empty());
    assert_eq!(w.outcome(), Outcome::Errored, "an unexpected JSON type");
}
