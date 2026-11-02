//! The OpenAI Responses API Wire Protocol: `POST /v1/responses`.
//!
//! A pair is a Request Workunit if the request body is JSON and the response
//! is `application/json` (one response object, or an `{"error": ...}` body),
//! or `text/event-stream` when the request set `stream: true`. A stream is
//! named events (`event: response.output_text.delta`), each with a JSON
//! `data` object whose `type` repeats the name. Events that carry a
//! `response` object (`response.created`, `response.in_progress`, and the
//! terminal ones) give the record fields; the last one wins, so the terminal
//! event's status and usage are kept.
//!
//! The Responses API has no finish reason per choice. The record's
//! `finish_reason` at index 0 is the reason the response ended: the
//! `incomplete_details.reason` of an `incomplete` response (such as
//! `max_output_tokens`), else its final status (`completed`, `failed`,
//! `cancelled`). A response still `queued` or `in_progress` has none.
//!
//! Outcome: a stream is read whole only once `response.completed` or
//! `response.incomplete` arrives. `incomplete` (e.g. `max_output_tokens`)
//! is a whole, readable response, like a Chat Completions `finish_reason:
//! length`. A stream that ends without a terminal event, and a failure in
//! band behind HTTP 200 (`response.failed`, an `error` event, or a response
//! object with status `failed`), are counted as not read, so the Workunit
//! is `errored`; a gap still makes it `incomplete` first.

use serde::Serialize;
use serde_json::{Map, Value};

use super::{extra, FinishReason, Frame, Framing, Request, Response, ResponseDecoder, Route, WireProtocol};

pub const RESPONSES: &str = "/v1/responses";

const ROUTES: &[Route] = &[Route::post(RESPONSES)];

/// Stream events after which the response is over.
const TERMINAL: &[&str] = &[
    "response.completed",
    "response.incomplete",
    "response.failed",
    "error",
];

pub struct OpenAiResponses;

impl WireProtocol for OpenAiResponses {
    fn id(&self) -> &'static str {
        "openai_responses"
    }

    fn routes(&self) -> &'static [Route] {
        ROUTES
    }

    fn request(&self, _endpoint: &'static str, body: &[u8]) -> Option<Request> {
        let v: Value = serde_json::from_slice(body).ok()?;
        Some(Request {
            model: v.get("model").and_then(Value::as_str).map(str::to_owned),
            stream: v.get("stream").and_then(Value::as_bool).unwrap_or(false),
            ..Request::default()
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

/// The record's `extra` for this protocol.
#[derive(Serialize)]
struct Extra {
    /// The response's last status: `completed`, `incomplete`, `failed`,
    /// `cancelled`, `queued` or `in_progress`.
    status: Option<String>,
    /// `error.code` of a failed response, an `error` event, or an error
    /// body (its `type` when it has no code).
    error_code: Option<String>,
    previous_response_id: Option<String>,
    service_tier: Option<String>,
}

#[derive(Default)]
struct Decoder {
    id: Option<String>,
    model: Option<String>,
    status: Option<String>,
    incomplete_reason: Option<String>,
    error_code: Option<String>,
    previous_response_id: Option<String>,
    service_tier: Option<String>,
    usage: Option<Value>,
    unreadable: u64,
    /// A terminal stream event was seen.
    done: bool,
    /// The request asked for a stream.
    stream: bool,
    /// The response was one JSON body (a response object or an error), not
    /// a stream of events.
    json_body: bool,
    /// The response failed in band: `response.failed`, an `error` event, or
    /// status `failed`.
    failed: bool,
}

fn string(o: &Map<String, Value>, k: &str) -> Option<String> {
    o.get(k).and_then(Value::as_str).map(str::to_owned)
}

/// `code`, else `type`, of an error object.
fn error_code(e: &Value) -> Option<String> {
    let e = e.as_object()?;
    string(e, "code").or_else(|| string(e, "type"))
}

impl Decoder {
    /// Takes the fields of a response object; later objects override.
    fn response(&mut self, r: &Map<String, Value>) {
        let set = |slot: &mut Option<String>, k: &str| {
            if let Some(v) = string(r, k) {
                *slot = Some(v);
            }
        };
        set(&mut self.id, "id");
        set(&mut self.model, "model");
        set(&mut self.status, "status");
        self.failed |= self.status.as_deref() == Some("failed");
        set(&mut self.previous_response_id, "previous_response_id");
        set(&mut self.service_tier, "service_tier");
        if let Some(reason) = r
            .get("incomplete_details")
            .and_then(|d| d.get("reason"))
            .and_then(Value::as_str)
        {
            self.incomplete_reason = Some(reason.to_owned());
        }
        if let Some(code) = r.get("error").and_then(error_code) {
            self.error_code = Some(code);
        }
        if let Some(u) = r.get("usage").filter(|u| u.is_object()) {
            self.usage = Some(u.clone());
        }
    }
}

impl ResponseDecoder for Decoder {
    fn frame(&mut self, frame: Frame<'_>) {
        let Ok(Value::Object(v)) = serde_json::from_slice::<Value>(frame.data) else {
            self.unreadable += 1;
            return;
        };
        if frame.event.is_none() && v.get("object").and_then(Value::as_str) == Some("response") {
            // A whole JSON body: the response object itself.
            self.json_body = true;
            self.response(&v);
            return;
        }
        if frame.event.is_none() && !v.contains_key("type") {
            // A JSON error body: {"error": {...}}.
            self.json_body = true;
            match v.get("error").filter(|e| e.is_object()) {
                Some(e) => self.error_code = error_code(e),
                None => self.unreadable += 1,
            }
            return;
        }
        let kind = v
            .get("type")
            .and_then(Value::as_str)
            .or_else(|| frame.event.and_then(|e| std::str::from_utf8(e).ok()));
        let Some(kind) = kind else {
            self.unreadable += 1;
            return;
        };
        if let Some(Value::Object(r)) = v.get("response") {
            self.response(r);
        }
        if kind == "error" {
            self.failed = true;
            if let Some(code) = string(&v, "code") {
                self.error_code = Some(code);
            }
        }
        if TERMINAL.contains(&kind) {
            self.done = true;
        }
    }

    fn finish(self: Box<Self>) -> Response {
        let unfinished = self.stream && !self.json_body && !self.done;
        let tokens = |k: &str| self.usage.as_ref().and_then(|u| u.get(k)).and_then(Value::as_u64);
        let reason = match self.status.as_deref() {
            Some("incomplete") => self.incomplete_reason.clone().or(self.status.clone()),
            Some("queued" | "in_progress") | None => None,
            Some(s) => Some(s.to_owned()),
        };
        Response {
            input_tokens: tokens("input_tokens"),
            output_tokens: tokens("output_tokens"),
            extra: extra(&Extra {
                status: self.status,
                error_code: self.error_code,
                previous_response_id: self.previous_response_id,
                service_tier: self.service_tier,
            }),
            id: self.id,
            model: self.model,
            finish_reason: reason
                .map(|finish_reason| FinishReason {
                    index: 0,
                    finish_reason,
                })
                .into_iter()
                .collect(),
            usage: self.usage,
            done: self.done,
            // Not read whole: the shared outcome check makes it `errored`.
            unreadable: self.unreadable + u64::from(self.failed || unfinished),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::wire::Protocols;

    fn decode(frames: &[(Option<&str>, &str)]) -> Response {
        let stream = Request {
            stream: frames.iter().any(|(e, _)| e.is_some()),
            ..Request::default()
        };
        let mut d = OpenAiResponses.decoder(RESPONSES, &stream);
        for (event, data) in frames {
            d.frame(Frame {
                event: event.map(str::as_bytes),
                data: data.as_bytes(),
            });
        }
        d.finish()
    }

    #[test]
    fn claims_only_post_v1_responses() {
        let p = Protocols::default();
        let claim = |m: &str, t: &str| p.claims(m, t, &[]).first().map(|c| (c.protocol.id(), c.endpoint));
        assert_eq!(
            claim("POST", "/v1/responses"),
            Some(("openai_responses", RESPONSES))
        );
        assert_eq!(
            claim("POST", "http://gw/v1/responses?x=1"),
            Some(("openai_responses", RESPONSES))
        );
        assert_eq!(claim("GET", "/v1/responses"), None);
        assert_eq!(claim("GET", "/v1/responses/resp_1"), None);
        assert_eq!(claim("POST", "/v1/responses/resp_1/cancel"), None);
    }

    #[test]
    fn request_fields() {
        let r = OpenAiResponses
            .request(RESPONSES, br#"{"model":"m","input":"hi","stream":true,"seed":7}"#)
            .unwrap();
        assert_eq!((r.model.as_deref(), r.stream), (Some("m"), true));
        // The Responses API has no seed or n.
        assert_eq!((r.seed, r.n), (None, None));
        assert_eq!(OpenAiResponses.request(RESPONSES, b"{\"model\":"), None);
    }

    #[test]
    fn response_rule() {
        let plain = Request::default();
        let stream = Request {
            stream: true,
            ..Request::default()
        };
        let f = |r: &Request, t: Option<&str>| OpenAiResponses.response_framing(RESPONSES, r, t);
        assert_eq!(f(&plain, Some("application/json")), Some(Framing::Json));
        assert_eq!(f(&stream, Some("text/event-stream")), Some(Framing::Sse));
        assert_eq!(f(&plain, Some("text/event-stream")), None);
        assert_eq!(f(&plain, None), None);
    }

    #[test]
    fn decodes_a_response_object() {
        let r = decode(&[(
            None,
            r#"{"id":"resp_1","object":"response","status":"completed","model":"m-2026","error":null,
               "incomplete_details":null,"previous_response_id":"resp_0","service_tier":"default",
               "usage":{"input_tokens":9,"output_tokens":4,"total_tokens":13}}"#,
        )]);
        assert_eq!(
            (r.id.as_deref(), r.model.as_deref()),
            (Some("resp_1"), Some("m-2026"))
        );
        assert_eq!((r.input_tokens, r.output_tokens), (Some(9), Some(4)));
        assert_eq!(r.finish_reason[0].finish_reason, "completed");
        assert_eq!(
            r.extra,
            Some(json!({"status": "completed", "error_code": null,
                        "previous_response_id": "resp_0", "service_tier": "default"}))
        );
        assert_eq!(r.unreadable, 0);
    }

    #[test]
    fn incomplete_reports_its_reason() {
        let r = decode(&[(
            None,
            r#"{"object":"response","status":"incomplete","incomplete_details":{"reason":"max_output_tokens"}}"#,
        )]);
        assert_eq!(r.finish_reason[0].finish_reason, "max_output_tokens");
        assert_eq!(r.extra.unwrap()["status"], "incomplete");
        assert_eq!(r.unreadable, 0, "incomplete is a readable response");
    }

    #[test]
    fn error_body_is_read() {
        let r = decode(&[(
            None,
            r#"{"error":{"message":"no","type":"invalid_request_error","param":"model","code":"model_not_found"}}"#,
        )]);
        assert_eq!(r.unreadable, 0);
        assert!(r.finish_reason.is_empty() && r.id.is_none());
        assert_eq!(r.extra.unwrap()["error_code"], "model_not_found");
        let r = decode(&[(None, r#"{"error":{"type":"server_error"}}"#)]);
        assert_eq!(r.extra.unwrap()["error_code"], "server_error");
        assert_eq!(decode(&[(None, r#"{"x":1}"#)]).unreadable, 1);
    }

    #[test]
    fn decodes_a_stream() {
        let r = decode(&[
            (
                Some("response.created"),
                r#"{"type":"response.created","sequence_number":0,"response":{"id":"resp_1","object":"response","status":"in_progress","model":"m","usage":null}}"#,
            ),
            (
                Some("response.output_text.delta"),
                r#"{"type":"response.output_text.delta","sequence_number":1,"delta":"Hi"}"#,
            ),
            (Some("response.output_text.delta"), "not json"),
            (
                Some("response.completed"),
                r#"{"type":"response.completed","sequence_number":2,"response":{"id":"resp_1","object":"response","status":"completed","model":"m","usage":{"input_tokens":3,"output_tokens":1}}}"#,
            ),
        ]);
        assert_eq!(r.id.as_deref(), Some("resp_1"));
        assert_eq!(r.finish_reason[0].finish_reason, "completed");
        assert_eq!((r.input_tokens, r.output_tokens), (Some(3), Some(1)));
        assert_eq!((r.unreadable, r.done), (1, true));
    }

    #[test]
    fn a_stream_cut_before_its_end_has_no_reason() {
        let r = decode(&[(
            Some("response.created"),
            r#"{"type":"response.created","response":{"object":"response","status":"in_progress"}}"#,
        )]);
        assert!(!r.done && r.finish_reason.is_empty());
        assert_eq!(r.extra.unwrap()["status"], "in_progress");
        // A stream request: ending before a terminal event is not read whole.
        assert_eq!(r.unreadable, 1);
    }

    #[test]
    fn failed_and_error_events_end_the_stream() {
        let r = decode(&[(
            Some("response.failed"),
            r#"{"type":"response.failed","response":{"object":"response","status":"failed","error":{"code":"server_error","message":"x"}}}"#,
        )]);
        assert_eq!((r.done, r.unreadable), (true, 1));
        assert_eq!(r.finish_reason[0].finish_reason, "failed");
        assert_eq!(r.extra.unwrap()["error_code"], "server_error");
        let r = decode(&[(
            Some("error"),
            r#"{"type":"error","code":"rate_limit_exceeded","message":"slow down","param":null}"#,
        )]);
        assert!(r.done && r.finish_reason.is_empty());
        assert_eq!(r.unreadable, 1);
        assert_eq!(r.extra.unwrap()["error_code"], "rate_limit_exceeded");
    }

    #[test]
    fn an_event_name_stands_in_for_a_missing_type() {
        let r = decode(&[(
            Some("response.completed"),
            r#"{"response":{"status":"completed"}}"#,
        )]);
        assert!(r.done && r.unreadable == 0);
    }
}
