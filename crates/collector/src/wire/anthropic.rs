//! The Anthropic Messages API Wire Protocol.
//!
//! A pair is a Request Workunit only if the request is `POST /v1/messages`
//! carrying an `anthropic-version` header, with a JSON object body, and the
//! response is `application/json`, or `text/event-stream` when the request
//! set `stream: true`. Every SDK sends the header, and it tells Anthropic
//! traffic apart on gateways that also serve OpenAI paths.
//!
//! A JSON response is a `message` object, or an `error` object on a
//! non-2xx status. A stream is named events: `message_start` (id, model,
//! input usage), `content_block_start`/`_delta`/`_stop`, `message_delta`
//! (`stop_reason`, cumulative usage), `message_stop` (the end-of-stream
//! marker), `ping`, and `error`, which may arrive mid-stream after a 200.
//! Unknown event types are skipped, since the API may add new ones; a whole
//! JSON body of any type but `message` or `error` is not read.
//!
//! Outcome: `done` is set only by `message_stop`. A stream that ends
//! without it (a clean HTTP end), or that carries an in-band `error` event,
//! is counted as not read, so the Workunit is `errored`; a gap still makes
//! it `incomplete` first. Any `stop_reason`, `max_tokens` included, is a
//! whole response. A JSON error body on a non-2xx status is read.

use serde::Serialize;
use serde_json::{Map, Value};

use super::{
    FinishReason, Frame, Framing, Request, RequestHead, Response, ResponseDecoder, Route, Sniff, WireProtocol,
};

pub const MESSAGES: &str = "/v1/messages";

const ROUTES: &[Route] = &[Route::post(MESSAGES)];

pub struct Anthropic;

impl WireProtocol for Anthropic {
    fn id(&self) -> &'static str {
        "anthropic"
    }

    fn routes(&self) -> &'static [Route] {
        ROUTES
    }

    fn sniff(&self, _endpoint: &'static str, head: &RequestHead<'_>) -> Sniff {
        if head.header("anthropic-version").is_some() {
            Sniff::Yes
        } else {
            Sniff::No
        }
    }

    fn request(&self, _endpoint: &'static str, body: &[u8]) -> Option<Request> {
        let v: Value = serde_json::from_slice(body).ok()?;
        let v = v.as_object()?;
        Some(Request {
            model: v.get("model").and_then(Value::as_str).map(str::to_owned),
            stream: v.get("stream").and_then(Value::as_bool).unwrap_or(false),
            seed: None,
            n: None,
            extra: None,
        })
    }

    fn response_framing(
        &self,
        _endpoint: &'static str,
        request: &Request,
        media_type: Option<&str>,
    ) -> Option<Framing> {
        match media_type {
            Some("application/json") => Some(Framing::Json),
            Some("text/event-stream") if request.stream => Some(Framing::Sse),
            _ => None,
        }
    }

    fn decoder(&self, _endpoint: &'static str, request: &Request) -> Box<dyn ResponseDecoder> {
        Box::new(Decoder {
            stream: request.stream,
            ..Decoder::default()
        })
    }
}

/// The record's `extra` for Anthropic.
#[derive(Serialize)]
struct Extra {
    /// Prompt tokens written to and read from the prompt cache; Anthropic's
    /// `input_tokens` leaves both out.
    cache_creation_input_tokens: Option<u64>,
    cache_read_input_tokens: Option<u64>,
    /// The stop sequence that ended the message, when `stop_reason` is
    /// `stop_sequence`.
    stop_sequence: Option<String>,
    /// `error.type` of an `error` body or event, e.g. `overloaded_error`.
    error_type: Option<String>,
}

/// Record fields gathered from a response: one JSON object, or every event
/// in order.
#[derive(Default)]
struct Decoder {
    id: Option<String>,
    model: Option<String>,
    stop_reason: Option<String>,
    stop_sequence: Option<String>,
    /// `message_start`'s usage with each `message_delta`'s fields laid over
    /// it, since the delta counts are cumulative.
    usage: Option<Map<String, Value>>,
    error_type: Option<String>,
    unreadable: u64,
    /// `message_stop` was seen.
    done: bool,
    /// The request asked for a stream.
    stream: bool,
    /// The response was one JSON body (a message or an error), not events.
    json_body: bool,
    /// An `error` event arrived in the stream.
    failed: bool,
}

impl Decoder {
    /// A `message` object: the whole JSON body, or `message_start`'s.
    fn message(&mut self, m: &Value) {
        if self.id.is_none() {
            self.id = str_field(m, "id");
        }
        if self.model.is_none() {
            self.model = str_field(m, "model");
        }
        self.stop(m);
        self.merge_usage(m.get("usage"));
    }

    /// `stop_reason` and `stop_sequence`, null until the message ends.
    fn stop(&mut self, v: &Value) {
        if let Some(r) = str_field(v, "stop_reason") {
            self.stop_reason = Some(r);
        }
        if let Some(s) = str_field(v, "stop_sequence") {
            self.stop_sequence = Some(s);
        }
    }

    fn merge_usage(&mut self, usage: Option<&Value>) {
        let Some(u) = usage.and_then(Value::as_object) else {
            return;
        };
        let merged = self.usage.get_or_insert_with(Map::new);
        for (k, v) in u {
            if !v.is_null() || !merged.contains_key(k) {
                merged.insert(k.clone(), v.clone());
            }
        }
    }
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_owned)
}

impl ResponseDecoder for Decoder {
    fn frame(&mut self, frame: Frame<'_>) {
        let Ok(v) = serde_json::from_slice::<Value>(frame.data) else {
            self.unreadable += 1;
            return;
        };
        // The API names every stream event, so a frame without a name is
        // a whole JSON body: a `message`, or an `error` on a non-2xx status.
        if frame.event.is_none() {
            self.json_body = true;
            match v.get("type").and_then(Value::as_str) {
                Some("message") => self.message(&v),
                Some("error") => self.error_type = v.get("error").and_then(|e| str_field(e, "type")),
                _ => self.unreadable += 1,
            }
            return;
        }
        // The data's `type` repeats the event name.
        let kind = v
            .get("type")
            .and_then(Value::as_str)
            .map(str::as_bytes)
            .or(frame.event);
        match kind {
            Some(b"message_start") => match v.get("message") {
                Some(m) => self.message(m),
                None => self.unreadable += 1,
            },
            Some(b"message_delta") => {
                if let Some(d) = v.get("delta") {
                    self.stop(d);
                }
                self.merge_usage(v.get("usage"));
            }
            Some(b"message_stop") => self.done = true,
            Some(b"error") => {
                // Fails the stream in band, behind HTTP 200.
                self.failed = true;
                self.error_type = v.get("error").and_then(|e| str_field(e, "type"));
            }
            // New event types may be added (API versioning policy).
            Some(_) => {}
            None => self.unreadable += 1,
        }
    }

    fn finish(self: Box<Self>) -> Response {
        let unfinished = self.stream && !self.json_body && !self.done;
        let usage = self.usage.map(Value::Object);
        let tokens = |k: &str| usage.as_ref().and_then(|u| u.get(k)).and_then(Value::as_u64);
        let extra = super::extra(&Extra {
            cache_creation_input_tokens: tokens("cache_creation_input_tokens"),
            cache_read_input_tokens: tokens("cache_read_input_tokens"),
            stop_sequence: self.stop_sequence,
            error_type: self.error_type,
        });
        Response {
            input_tokens: tokens("input_tokens"),
            output_tokens: tokens("output_tokens"),
            id: self.id,
            model: self.model,
            finish_reason: self
                .stop_reason
                .map(|finish_reason| FinishReason {
                    index: 0,
                    finish_reason,
                })
                .into_iter()
                .collect(),
            usage,
            done: self.done,
            // Not read whole: the shared outcome check makes it `errored`.
            unreadable: self.unreadable + u64::from(self.failed || unfinished),
            extra,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::openai::OpenAi;
    use crate::wire::Protocols;
    use serde_json::json;

    fn claims(target: &str, headers: &[(&str, &str)]) -> Vec<String> {
        let h: Vec<(Vec<u8>, Vec<u8>)> = headers
            .iter()
            .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect();
        Protocols::default()
            .claims("POST", target, &h)
            .iter()
            .map(|c| format!("{c:?}"))
            .collect()
    }

    #[test]
    fn claimed_by_path_and_version_header() {
        let v = [("anthropic-version", "2023-06-01")];
        assert_eq!(claims("/v1/messages", &v), ["anthropic:/v1/messages"]);
        assert_eq!(claims("/v1/messages?beta=true", &v), ["anthropic:/v1/messages"]);
        assert!(claims("/v1/messages", &[]).is_empty());
        assert!(claims("/v1/messages/count_tokens", &v).is_empty());
        assert!(claims("/v1/messages/batches", &v).is_empty());
        // The header alone claims nothing on an OpenAI path.
        assert_eq!(
            claims("/v1/chat/completions", &v),
            ["openai:/v1/chat/completions"]
        );
        assert!(OpenAi.routes().iter().all(|r| r.path != MESSAGES));
    }

    #[test]
    fn request_fields() {
        let r = Anthropic
            .request(
                MESSAGES,
                br#"{"model":"m","max_tokens":4,"stream":true,"messages":[]}"#,
            )
            .unwrap();
        assert_eq!(r.model.as_deref(), Some("m"));
        assert!(r.stream);
        assert_eq!((r.seed, r.n), (None, None));
        assert_eq!(Anthropic.request(MESSAGES, b"{\"model\":"), None);
        assert_eq!(Anthropic.request(MESSAGES, b"[1]"), None);
    }

    #[test]
    fn response_rule() {
        let plain = Request::default();
        let stream = Request {
            stream: true,
            ..Request::default()
        };
        let f = |r: &Request, t: Option<&str>| Anthropic.response_framing(MESSAGES, r, t);
        assert_eq!(f(&plain, Some("application/json")), Some(Framing::Json));
        assert_eq!(f(&stream, Some("application/json")), Some(Framing::Json));
        assert_eq!(f(&stream, Some("text/event-stream")), Some(Framing::Sse));
        assert_eq!(f(&plain, Some("text/event-stream")), None);
        assert_eq!(f(&plain, None), None);
    }

    fn decode(frames: &[(Option<&str>, &str)]) -> Response {
        let stream = Request {
            stream: frames.iter().any(|(e, _)| e.is_some()),
            ..Request::default()
        };
        let mut d = Anthropic.decoder(MESSAGES, &stream);
        for (event, data) in frames {
            d.frame(Frame {
                event: event.map(str::as_bytes),
                data: data.as_bytes(),
            });
        }
        d.finish()
    }

    #[test]
    fn decodes_a_message() {
        let r = decode(&[(
            None,
            r#"{"id":"msg_1","type":"message","role":"assistant","model":"m","content":[{"type":"text","text":"Hi"}],"stop_reason":"stop_sequence","stop_sequence":"\n\n","usage":{"input_tokens":9,"output_tokens":4,"cache_creation_input_tokens":0,"cache_read_input_tokens":128}}"#,
        )]);
        assert_eq!((r.id.as_deref(), r.model.as_deref()), (Some("msg_1"), Some("m")));
        assert_eq!(
            r.finish_reason,
            [FinishReason {
                index: 0,
                finish_reason: "stop_sequence".into()
            }]
        );
        assert_eq!((r.input_tokens, r.output_tokens), (Some(9), Some(4)));
        assert_eq!(
            r.extra,
            Some(json!({
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 128,
                "stop_sequence": "\n\n",
                "error_type": null,
            }))
        );
        // A JSON body has no end-of-stream marker.
        assert!(!r.done && r.unreadable == 0);
    }

    #[test]
    fn a_json_body_must_be_a_message_or_an_error() {
        for body in [
            r#"{"type":"unexpected"}"#,
            r#"{"type":"message_stop"}"#,
            "{}",
            "[1]",
        ] {
            assert_eq!(decode(&[(None, body)]).unreadable, 1, "{body}");
        }
    }

    #[test]
    fn decodes_an_error_body() {
        let r = decode(&[(
            None,
            r#"{"type":"error","error":{"type":"invalid_request_error","message":"max_tokens: Field required"}}"#,
        )]);
        assert!(r.finish_reason.is_empty() && r.usage.is_none());
        assert_eq!(r.extra.unwrap()["error_type"], "invalid_request_error");
        assert_eq!(r.unreadable, 0);
    }

    #[test]
    fn decodes_a_stream() {
        let r = decode(&[
            (
                Some("message_start"),
                r#"{"type":"message_start","message":{"id":"msg_2","type":"message","role":"assistant","content":[],"model":"m","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":9,"output_tokens":1,"cache_read_input_tokens":3}}}"#,
            ),
            (
                Some("content_block_start"),
                r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
            ),
            (Some("ping"), r#"{"type": "ping"}"#),
            (
                Some("content_block_delta"),
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}"#,
            ),
            (
                Some("content_block_stop"),
                r#"{"type":"content_block_stop","index":0}"#,
            ),
            (Some("some_future_event"), r#"{"type":"some_future_event"}"#),
            (
                Some("message_delta"),
                r#"{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":4,"cache_read_input_tokens":null}}"#,
            ),
            (Some("message_stop"), r#"{"type":"message_stop"}"#),
        ]);
        assert_eq!(r.id.as_deref(), Some("msg_2"));
        assert_eq!(r.finish_reason[0].finish_reason, "end_turn");
        // message_delta's cumulative count replaces message_start's; a null
        // does not erase a count already seen.
        assert_eq!(
            r.usage,
            Some(json!({"input_tokens": 9, "output_tokens": 4, "cache_read_input_tokens": 3}))
        );
        assert_eq!((r.input_tokens, r.output_tokens), (Some(9), Some(4)));
        assert_eq!(
            r.extra,
            Some(json!({
                "cache_creation_input_tokens": null,
                "cache_read_input_tokens": 3,
                "stop_sequence": null,
                "error_type": null,
            }))
        );
        assert!(r.done && r.unreadable == 0);
    }

    #[test]
    fn an_error_event_mid_stream() {
        let r = decode(&[
            (
                Some("message_start"),
                r#"{"type":"message_start","message":{"id":"msg_3","model":"m","usage":{"input_tokens":9,"output_tokens":1}}}"#,
            ),
            (
                Some("error"),
                r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#,
            ),
            (Some("message_start"), "not json"),
        ]);
        assert_eq!(r.id.as_deref(), Some("msg_3"));
        assert!(r.finish_reason.is_empty() && !r.done);
        assert_eq!(r.extra.unwrap()["error_type"], "overloaded_error");
        // The frame that is not JSON, and the failure itself.
        assert_eq!(r.unreadable, 2);
    }

    #[test]
    fn a_stream_without_message_stop_is_not_read_whole() {
        let start = (
            Some("message_start"),
            r#"{"type":"message_start","message":{"id":"msg_4","model":"m","usage":{"input_tokens":9,"output_tokens":1}}}"#,
        );
        let delta = (
            Some("message_delta"),
            r#"{"type":"message_delta","delta":{"stop_reason":"max_tokens"},"usage":{"output_tokens":4}}"#,
        );
        let r = decode(&[start, delta]);
        assert!(!r.done);
        assert_eq!(r.unreadable, 1);
        // With message_stop, a max_tokens stop is a whole response.
        let r = decode(&[start, delta, (Some("message_stop"), r#"{"type":"message_stop"}"#)]);
        assert_eq!(r.finish_reason[0].finish_reason, "max_tokens");
        assert!(r.done && r.unreadable == 0);
    }
}
