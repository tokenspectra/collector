//! A Wire Protocol defined only here, in its own module, proves a new
//! protocol needs nothing outside that module but one registry line
//! (`Protocols::default().with(&ndtest::NDTEST)`, in `registered()`).
//!
//! `ndtest` is shaped like the stage-6 protocols: an NDJSON stream on its
//! own path, named SSE events on another, and a path it shares with OpenAI,
//! claimed only when a header says so.

#[path = "support/collect.rs"]
mod collect;
#[path = "support/fixtures.rs"]
mod fixtures;

use collector::decode::{Bucket, WorkunitRecord};
use collector::observe::StatsSink;
use collector::run::run;
use collector::stats::Registry;
use collector::{AssemblerConfig, DecoderConfig, FileSource, Protocols};

use collect::{Collected, WINDOW_NS};
use fixtures::{Conn, Frame, ACK, CLIENT, MS, PSH, SERVER, T0};

mod ndtest {
    use collector::wire::{
        extra, FinishReason, Frame, Framing, Request, RequestHead, Response, ResponseDecoder, Route, Sniff,
        WireProtocol,
    };
    use serde::Serialize;
    use serde_json::Value;

    pub static NDTEST: NdTest = NdTest;

    pub const GENERATE: &str = "/api/generate";
    pub const EVENTS: &str = "/test/*/events";
    const SHARED: &str = "/v1/chat/completions";
    const ROUTES: &[Route] = &[Route::post(GENERATE), Route::post(EVENTS), Route::post(SHARED)];

    pub struct NdTest;

    impl WireProtocol for NdTest {
        fn id(&self) -> &'static str {
            "ndtest"
        }

        fn routes(&self) -> &'static [Route] {
            ROUTES
        }

        fn sniff(&self, endpoint: &'static str, head: &RequestHead<'_>) -> Sniff {
            match (endpoint, head.header("x-ndtest")) {
                (_, Some(_)) => Sniff::Yes,
                (SHARED, None) => Sniff::No,
                _ => Sniff::Maybe,
            }
        }

        fn request(&self, _: &'static str, body: &[u8]) -> Option<Request> {
            let v: Value = serde_json::from_slice(body).ok()?;
            // Body sniffing: this protocol's requests always name a `prompt`.
            v.get("prompt")?;
            Some(Request {
                model: v["model"].as_str().map(str::to_owned),
                stream: v["stream"].as_bool().unwrap_or(true),
                ..Request::default()
            })
        }

        fn response_framing(
            &self,
            endpoint: &'static str,
            req: &Request,
            media_type: Option<&str>,
        ) -> Option<Framing> {
            match (endpoint, media_type) {
                (EVENTS, Some("text/event-stream")) => Some(Framing::Sse),
                (_, Some("application/x-ndjson")) if req.stream => Some(Framing::Ndjson),
                (_, Some("application/json")) => Some(Framing::Json),
                _ => None,
            }
        }

        fn decoder(&self, _: &'static str, _: &Request) -> Box<dyn ResponseDecoder> {
            Box::<Decoder>::default()
        }
    }

    #[derive(Default)]
    struct Decoder {
        r: Response,
        frames: u64,
        events: Vec<String>,
    }

    /// The typed `extra` of an `ndtest` record.
    #[derive(Serialize)]
    struct Extra {
        frames: u64,
        events: Option<Vec<String>>,
    }

    impl ResponseDecoder for Decoder {
        fn frame(&mut self, frame: Frame<'_>) {
            self.frames += 1;
            if let Some(e) = frame.event {
                self.events.push(String::from_utf8_lossy(e).into_owned());
            }
            let Ok(v) = serde_json::from_slice::<Value>(frame.data) else {
                self.r.unreadable += 1;
                return;
            };
            if self.r.model.is_none() {
                self.r.model = v["model"].as_str().map(str::to_owned);
            }
            if v["done"] == true || frame.event == Some(b"stop") {
                self.r.done = true;
                if let Some(reason) = v["done_reason"].as_str() {
                    self.r.finish_reason = vec![FinishReason {
                        index: 0,
                        finish_reason: reason.to_owned(),
                    }];
                }
                self.r.input_tokens = v["prompt_eval_count"].as_u64();
                self.r.output_tokens = v["eval_count"].as_u64();
            }
        }

        fn finish(self: Box<Self>) -> Response {
            let events = (!self.events.is_empty()).then_some(self.events);
            Response {
                extra: extra(&Extra {
                    frames: self.frames,
                    events,
                }),
                ..self.r
            }
        }
    }
}

const NDJSON_BODY: &[u8] = b"{\"model\":\"m\",\"response\":\"He\",\"done\":false}\n\
{\"model\":\"m\",\"response\":\"llo\",\"done\":false}\n\
{\"model\":\"m\",\"response\":\"\",\"done\":true,\"done_reason\":\"stop\",\"prompt_eval_count\":7,\"eval_count\":2}\n";

const SSE_BODY: &[u8] = b"event: start\ndata: {\"model\":\"m\"}\n\n\
event: delta\ndata: {\"text\":\"hi\"}\n\n\
event: stop\ndata: {\"done_reason\":\"end\",\"eval_count\":1}\n\n";

fn request(path: &str, extra_headers: &str, body: &str) -> Vec<u8> {
    format!(
        "POST {path} HTTP/1.1\r\nhost: 10.0.0.2:8000\r\ncontent-type: application/json\r\n{extra_headers}\
         content-length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn response_head(media_type: &str, len: usize) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\ncontent-type: {media_type}\r\ncontent-length: {len}\r\n\r\n").into_bytes()
}

/// One connection: a request, then the response head and its body cut at
/// `cuts`; the piece listed in `lose` is never captured.
fn exchange(
    port: u16,
    at: u64,
    req: &[u8],
    head: &[u8],
    body: &[u8],
    cuts: &[usize],
    lose: Option<usize>,
) -> Vec<Frame> {
    let mut c = Conn::new((CLIENT.0, port), SERVER, 1000, 9000);
    let mut f = Vec::new();
    c.handshake(at, &mut f);
    f.push(c.send(true, at + 10 * MS, PSH | ACK, req));
    f.push(c.send(false, at + 20 * MS, PSH | ACK, head));
    let mut bounds = vec![0];
    bounds.extend_from_slice(cuts);
    bounds.push(body.len());
    for (i, w) in bounds.windows(2).enumerate() {
        let seg = c.send(false, at + (21 + i as u64) * MS, PSH | ACK, &body[w[0]..w[1]]);
        if lose != Some(i) {
            f.push(seg);
        }
    }
    f.push(c.ack(true, at + 40 * MS));
    c.close(at + 50 * MS, &mut f);
    f
}

const CHAT_JSON: &str =
    "{\"id\":\"c1\",\"model\":\"m\",\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}]}";
const ND_JSON: &str = "{\"model\":\"m\",\"done\":true,\"done_reason\":\"stop\"}";

fn capture() -> tempfile::NamedTempFile {
    let gen = request("/api/generate", "", "{\"model\":\"m\",\"prompt\":\"hi\"}");
    let nd = response_head("application/x-ndjson", NDJSON_BODY.len());
    let sse = response_head("text/event-stream", SSE_BODY.len());
    let shared_body = "{\"model\":\"m\",\"prompt\":\"hi\",\"stream\":false}";
    let mut frames = Vec::new();
    // 1. NDJSON, lines split across segments.
    frames.extend(exchange(
        40001,
        T0,
        &gen,
        &nd,
        NDJSON_BODY,
        &[5, 50, 51, 120],
        None,
    ));
    // 2. Named SSE events, one byte per segment for the first event.
    let events = request("/test/x/events", "", "{\"model\":\"m\",\"prompt\":\"hi\"}");
    let cuts: Vec<usize> = (1..30).collect();
    frames.extend(exchange(
        40002,
        T0 + 100 * MS,
        &events,
        &sse,
        SSE_BODY,
        &cuts,
        None,
    ));
    // 3. OpenAI's path, claimed by a header only ndtest sends.
    let marked = request("/v1/chat/completions", "x-ndtest: 1\r\n", shared_body);
    let json = response_head("application/json", ND_JSON.len());
    frames.extend(exchange(
        40003,
        T0 + 200 * MS,
        &marked,
        &json,
        ND_JSON.as_bytes(),
        &[],
        None,
    ));
    // 4. The same path without the header: OpenAI.
    let plain = request("/v1/chat/completions", "", "{\"model\":\"m\",\"messages\":[]}");
    let chat = response_head("application/json", CHAT_JSON.len());
    frames.extend(exchange(
        40004,
        T0 + 300 * MS,
        &plain,
        &chat,
        CHAT_JSON.as_bytes(),
        &[],
        None,
    ));
    // 5. NDJSON with a segment lost in the middle of the second line.
    frames.extend(exchange(
        40005,
        T0 + 400 * MS,
        &gen,
        &nd,
        NDJSON_BODY,
        &[50, 60],
        Some(1),
    ));
    // 6. ndtest's header on a body only OpenAI reads: the next claim wins.
    let openai_body = request(
        "/v1/chat/completions",
        "x-ndtest: 1\r\n",
        "{\"model\":\"m\",\"messages\":[]}",
    );
    frames.extend(exchange(
        40006,
        T0 + 500 * MS,
        &openai_body,
        &chat,
        CHAT_JSON.as_bytes(),
        &[],
        None,
    ));
    // 7. The response starts before the request body ends, so its bytes
    //    are held until the request is read, then replayed.
    let mut c = Conn::new((CLIENT.0, 40007), SERVER, 1000, 9000);
    let at = T0 + 600 * MS;
    c.handshake(at, &mut frames);
    let (head, tail) = gen.split_at(gen.len() - 4);
    frames.push(c.send(true, at + 10 * MS, PSH | ACK, head));
    frames.push(c.send(
        false,
        at + 11 * MS,
        PSH | ACK,
        &[&nd[..], &NDJSON_BODY[..60]].concat(),
    ));
    frames.push(c.send(true, at + 12 * MS, PSH | ACK, tail));
    frames.push(c.send(false, at + 13 * MS, PSH | ACK, &NDJSON_BODY[60..]));
    frames.push(c.ack(true, at + 14 * MS));
    c.close(at + 20 * MS, &mut frames);
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    std::io::Write::write_all(&mut file, &fixtures::pcapng(&frames)).expect("write");
    file
}

fn collect(protocols: Protocols) -> (Collected, std::sync::Arc<Registry>) {
    let file = capture();
    let reg = Registry::new();
    let mut sink = Collected::default();
    let cfg = DecoderConfig {
        protocols,
        ..DecoderConfig::default()
    };
    run(
        &mut FileSource::new(vec![file.path().to_path_buf()]),
        WINDOW_NS,
        AssemblerConfig::default(),
        cfg,
        &mut StatsSink::new(&mut sink, reg.clone()),
    )
    .expect("run");
    (sink, reg)
}

/// The one registry line.
fn registered() -> Protocols {
    Protocols::default().with(&ndtest::NDTEST)
}

fn by_port(c: &Collected, port: u16) -> &WorkunitRecord {
    let tag = format!(":{port}|");
    c.workunits
        .iter()
        .find(|w| w.flow.to_string().contains(&tag))
        .unwrap_or_else(|| panic!("no Workunit on port {port}"))
}

#[test]
fn a_registered_protocol_decodes_its_own_workunits() {
    let (c, reg) = collect(registered());
    assert_eq!(c.workunits.len(), 7);

    let w = by_port(&c, 40001);
    assert_eq!((w.protocol, w.endpoint), ("ndtest", ndtest::GENERATE));
    assert!(w.complete && w.stream && w.outcome() == collector::stats::Outcome::Ok);
    assert_eq!((w.input_tokens, w.output_tokens), (Some(7), Some(2)));
    assert_eq!(w.finish_reason[0].finish_reason, "stop");
    assert_eq!(w.response_model.as_deref(), Some("m"));
    assert_eq!(w.extra, Some(serde_json::json!({"frames": 3, "events": null})));
    // `sse_events` and `sse_done` are for SSE only.
    assert_eq!((w.sse_events.as_ref(), w.sse_done), (None, None));

    let w = by_port(&c, 40002);
    assert_eq!((w.protocol, w.endpoint), ("ndtest", ndtest::EVENTS));
    assert!(w.complete && w.outcome() == collector::stats::Outcome::Ok);
    assert_eq!(
        w.extra,
        Some(serde_json::json!({"frames": 3, "events": ["start", "delta", "stop"]}))
    );
    assert_eq!(w.sse_events.as_ref().map(Vec::len), Some(3));
    assert_eq!((w.sse_done, w.output_tokens), (Some(true), Some(1)));

    // Header evidence beats registry order on a shared path...
    assert_eq!(by_port(&c, 40003).protocol, "ndtest");
    assert_eq!(
        by_port(&c, 40003).response_content_type.as_deref(),
        Some("application/json")
    );
    // ...without it the path stays OpenAI's...
    assert_eq!(by_port(&c, 40004).protocol, "openai");
    assert_eq!(by_port(&c, 40004).response_id.as_deref(), Some("c1"));
    // ...and a body ndtest cannot read falls through to OpenAI.
    assert_eq!(by_port(&c, 40006).protocol, "openai");

    // A gap mid-stream: the cut line is lost, framing resumes after it.
    let w = by_port(&c, 40005);
    assert!(!w.complete && w.outcome() == collector::stats::Outcome::Incomplete);
    assert_eq!(w.extra, Some(serde_json::json!({"frames": 2, "events": null})));
    assert_eq!(w.output_tokens, Some(2), "the last line is read");

    let w = by_port(&c, 40007);
    assert!(w.complete && w.outcome() == collector::stats::Outcome::Ok);
    assert_eq!(w.extra, Some(serde_json::json!({"frames": 3, "events": null})));
    assert_eq!(w.output_tokens, Some(2));

    let s = reg.snapshot();
    let total = |p: &str| s.workunits_by_protocol[p].iter().flatten().sum::<u64>();
    assert_eq!((total("ndtest"), total("openai")), (5, 2));
}

#[test]
fn without_the_registry_line_only_openai_is_decoded() {
    let (c, _) = collect(Protocols::default());
    let ports: Vec<String> = c.workunits.iter().map(|w| w.flow.to_string()).collect();
    assert_eq!(c.workunits.len(), 3, "{ports:?}");
    assert!(c.workunits.iter().all(|w| w.protocol == "openai"));
    let other = c
        .exchanges
        .iter()
        .filter(|e| e.bucket == Bucket::HttpOther)
        .count();
    assert_eq!(other, 4);
}
