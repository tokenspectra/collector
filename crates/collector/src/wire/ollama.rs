//! The Ollama native Wire Protocol: `/api/chat`, `/api/generate` and
//! `/api/embed`.
//!
//! Chat and generate stream by default: the request omits `stream` or sets
//! it `true`, and the response is NDJSON (`application/x-ndjson`), one JSON
//! object per line, the last one with `"done": true` and the counts and
//! durations. With `"stream": false` the response is that last object alone,
//! as `application/json`. Embed always answers with one JSON object.
//!
//! Ollama's OpenAI-compatible `/v1/*` endpoints are the OpenAI protocol's;
//! this module serves only the native paths.

use serde::Serialize;
use serde_json::Value;

use super::{extra, FinishReason, Frame, Framing, Request, Response, ResponseDecoder, Route, WireProtocol};

pub const CHAT: &str = "/api/chat";
pub const GENERATE: &str = "/api/generate";
pub const EMBED: &str = "/api/embed";

const ROUTES: &[Route] = &[Route::post(CHAT), Route::post(GENERATE), Route::post(EMBED)];

pub struct Ollama;

impl WireProtocol for Ollama {
    fn id(&self) -> &'static str {
        "ollama"
    }

    fn routes(&self) -> &'static [Route] {
        ROUTES
    }

    fn request(&self, endpoint: &'static str, body: &[u8]) -> Option<Request> {
        let v: Value = serde_json::from_slice(body).ok()?;
        let v = v.as_object()?;
        // Embed never streams; chat and generate stream unless told not to.
        let stream = endpoint != EMBED && v.get("stream").and_then(Value::as_bool).unwrap_or(true);
        let seed = v
            .get("options")
            .and_then(|o| o.get("seed"))
            .filter(|s| s.is_number())
            .cloned();
        Some(Request {
            model: v.get("model").and_then(Value::as_str).map(str::to_owned),
            stream,
            seed,
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
            Some("application/x-ndjson") if request.stream => Some(Framing::Ndjson),
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

/// The typed `extra` of an `ollama` record. Durations are nanoseconds, as
/// Ollama sends them.
#[derive(Serialize)]
struct Extra {
    total_duration: Option<u64>,
    load_duration: Option<u64>,
    prompt_eval_duration: Option<u64>,
    eval_duration: Option<u64>,
    /// Streamed responses only: the `"done": true` line arrived.
    done: Option<bool>,
    /// An `error` object, sent instead of a result or mid-stream.
    error: Option<String>,
}

/// Record fields gathered from a response: one JSON object, or every NDJSON
/// line in order. Counts, durations and the reason come from the last
/// object, the one with `"done": true` (embed has no `done`, so its only
/// object counts).
#[derive(Default)]
struct Decoder {
    stream: bool,
    model: Option<String>,
    done: bool,
    done_reason: Option<String>,
    prompt_eval_count: Option<u64>,
    eval_count: Option<u64>,
    total_duration: Option<u64>,
    load_duration: Option<u64>,
    prompt_eval_duration: Option<u64>,
    eval_duration: Option<u64>,
    error: Option<String>,
    unreadable: u64,
}

impl ResponseDecoder for Decoder {
    fn frame(&mut self, frame: Frame<'_>) {
        let Ok(Value::Object(v)) = serde_json::from_slice::<Value>(frame.data) else {
            self.unreadable += 1;
            return;
        };
        if self.model.is_none() {
            self.model = v.get("model").and_then(Value::as_str).map(str::to_owned);
        }
        if let Some(e) = v.get("error") {
            self.error = Some(e.as_str().map_or_else(|| e.to_string(), str::to_owned));
        }
        let last = v.get("done").and_then(Value::as_bool).unwrap_or(!self.stream);
        if !last {
            return;
        }
        self.done |= v.get("done") == Some(&Value::Bool(true));
        let num = |k: &str| v.get(k).and_then(Value::as_u64);
        self.done_reason = v.get("done_reason").and_then(Value::as_str).map(str::to_owned);
        self.prompt_eval_count = num("prompt_eval_count");
        self.eval_count = num("eval_count");
        self.total_duration = num("total_duration");
        self.load_duration = num("load_duration");
        self.prompt_eval_duration = num("prompt_eval_duration");
        self.eval_duration = num("eval_duration");
    }

    fn finish(self: Box<Self>) -> Response {
        Response {
            id: None,
            model: self.model,
            finish_reason: self
                .done_reason
                .map(|finish_reason| FinishReason {
                    index: 0,
                    finish_reason,
                })
                .into_iter()
                .collect(),
            // Ollama sends counts at the top level, not a usage object.
            usage: None,
            input_tokens: self.prompt_eval_count,
            output_tokens: self.eval_count,
            done: self.done,
            unreadable: self.unreadable,
            extra: extra(&Extra {
                total_duration: self.total_duration,
                load_duration: self.load_duration,
                prompt_eval_duration: self.prompt_eval_duration,
                eval_duration: self.eval_duration,
                done: self.stream.then_some(self.done),
                error: self.error,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{openai, Protocols};

    fn claims(target: &str) -> Vec<String> {
        Protocols::default()
            .claims("POST", target, &[])
            .iter()
            .map(|c| format!("{c:?}"))
            .collect()
    }

    #[test]
    fn native_paths_only() {
        assert_eq!(claims("/api/chat"), ["ollama:/api/chat"]);
        assert_eq!(claims("/api/generate?x"), ["ollama:/api/generate"]);
        assert_eq!(claims("http://h:11434/api/embed"), ["ollama:/api/embed"]);
        // Ollama's OpenAI-compatible endpoints belong to OpenAI.
        assert_eq!(claims(openai::CHAT_COMPLETIONS), ["openai:/v1/chat/completions"]);
        assert!(claims("/api/tags").is_empty() && claims("/api/embeddings").is_empty());
        assert!(Protocols::default().claims("GET", "/api/chat", &[]).is_empty());
    }

    #[test]
    fn request_fields() {
        let r = Ollama
            .request(CHAT, br#"{"model":"m","messages":[],"options":{"seed":7}}"#)
            .unwrap();
        assert_eq!(r.model.as_deref(), Some("m"));
        assert!(r.stream, "streams by default");
        assert_eq!(r.seed, Some(Value::from(7)));
        assert!(
            !Ollama
                .request(GENERATE, br#"{"model":"m","stream":false}"#)
                .unwrap()
                .stream
        );
        assert!(
            !Ollama
                .request(EMBED, br#"{"model":"m","input":"x"}"#)
                .unwrap()
                .stream
        );
        assert_eq!(Ollama.request(CHAT, b"[1]"), None);
        assert_eq!(Ollama.request(CHAT, b"{\"model\":"), None);
    }

    #[test]
    fn response_rule() {
        let plain = Request::default();
        let stream = Request {
            stream: true,
            ..Request::default()
        };
        let f = |r: &Request, t: Option<&str>| Ollama.response_framing(CHAT, r, t);
        assert_eq!(f(&stream, Some("application/x-ndjson")), Some(Framing::Ndjson));
        assert_eq!(f(&stream, Some("application/json")), Some(Framing::Json));
        assert_eq!(f(&plain, Some("application/json")), Some(Framing::Json));
        assert_eq!(f(&plain, Some("application/x-ndjson")), None);
        assert_eq!(f(&stream, Some("text/event-stream")), None);
        assert_eq!(f(&stream, None), None);
    }

    fn decode(stream: bool, frames: &[&[u8]]) -> Response {
        let req = Request {
            stream,
            ..Request::default()
        };
        let mut d = Ollama.decoder(CHAT, &req);
        for &data in frames {
            d.frame(Frame { event: None, data });
        }
        d.finish()
    }

    #[test]
    fn decodes_a_stream() {
        let r = decode(
            true,
            &[
                br#"{"model":"m","message":{"role":"assistant","content":"Hi"},"done":false}"#,
                b"not json",
                br#"{"model":"m","message":{"role":"assistant","content":""},"done":true,"done_reason":"stop",
                    "total_duration":9,"load_duration":1,"prompt_eval_count":5,"prompt_eval_duration":2,
                    "eval_count":3,"eval_duration":4}"#,
            ],
        );
        assert_eq!(r.model.as_deref(), Some("m"));
        assert_eq!(
            r.finish_reason,
            [FinishReason {
                index: 0,
                finish_reason: "stop".into()
            }]
        );
        assert_eq!((r.input_tokens, r.output_tokens), (Some(5), Some(3)));
        assert_eq!((r.done, r.unreadable, r.usage), (true, 1, None));
        assert_eq!(
            r.extra,
            Some(
                serde_json::json!({"total_duration":9,"load_duration":1,"prompt_eval_duration":2,
                "eval_duration":4,"done":true,"error":null})
            )
        );
    }

    #[test]
    fn a_stream_cut_short_is_not_done() {
        let r = decode(true, &[br#"{"model":"m","response":"a","done":false}"#]);
        assert_eq!((r.done, r.input_tokens), (false, None));
        assert_eq!(r.extra.unwrap()["done"], false);
        let r = decode(
            true,
            &[
                br#"{"model":"m","response":"a","done":false}"#,
                br#"{"error":"runner died"}"#,
            ],
        );
        assert_eq!(r.extra.unwrap()["error"], "runner died");
    }

    #[test]
    fn decodes_a_single_object() {
        let r = decode(
            false,
            &[br#"{"model":"m","response":"Hi","done":true,"done_reason":"length","eval_count":2}"#],
        );
        assert_eq!((r.done, r.output_tokens), (true, Some(2)));
        assert_eq!(r.finish_reason[0].finish_reason, "length");
        // Embed has no `done`: its one object is the last.
        let r = decode(
            false,
            &[br#"{"model":"m","embeddings":[[0.1]],"total_duration":5,"prompt_eval_count":3}"#],
        );
        assert_eq!((r.done, r.input_tokens, r.output_tokens), (false, Some(3), None));
        assert!(r.finish_reason.is_empty());
        assert_eq!(r.extra.unwrap()["total_duration"], 5);
        // An error reply.
        let r = decode(false, &[br#"{"error":"model \"x\" not found"}"#]);
        assert_eq!(r.extra.unwrap()["error"], "model \"x\" not found");
    }
}
