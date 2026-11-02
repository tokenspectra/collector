//! The OpenAI Wire Protocol: Chat Completions and legacy Completions.
//!
//! A pair is a Request Workunit only if the request is `POST
//! /v1/chat/completions` or `POST /v1/completions` with a JSON body, and the
//! response is `application/json`, or `text/event-stream` when the request
//! set `stream: true`. Legacy Completions stays because self-hosted servers
//! such as vLLM still serve it.

use std::collections::BTreeMap;

use serde_json::Value;

use super::{FinishReason, Frame, Framing, Request, Response, ResponseDecoder, Route, WireProtocol};

pub const CHAT_COMPLETIONS: &str = "/v1/chat/completions";
pub const COMPLETIONS: &str = "/v1/completions";

const ROUTES: &[Route] = &[Route::post(CHAT_COMPLETIONS), Route::post(COMPLETIONS)];

pub struct OpenAi;

impl WireProtocol for OpenAi {
    fn id(&self) -> &'static str {
        "openai"
    }

    fn routes(&self) -> &'static [Route] {
        ROUTES
    }

    fn request(&self, _endpoint: &'static str, body: &[u8]) -> Option<Request> {
        let v: Value = serde_json::from_slice(body).ok()?;
        Some(Request {
            model: v.get("model").and_then(Value::as_str).map(str::to_owned),
            stream: v.get("stream").and_then(Value::as_bool).unwrap_or(false),
            seed: v.get("seed").filter(|s| s.is_number()).cloned(),
            n: v.get("n").filter(|s| s.is_number()).cloned(),
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

    fn decoder(&self, _endpoint: &'static str, _request: &Request) -> Box<dyn ResponseDecoder> {
        Box::<Decoder>::default()
    }
}

/// Record fields gathered from a response: one JSON object, or every SSE
/// chunk in order.
#[derive(Default)]
struct Decoder {
    id: Option<String>,
    model: Option<String>,
    finish: BTreeMap<u64, String>,
    usage: Option<Value>,
    unreadable: u64,
    /// An SSE `data: [DONE]` was seen.
    done: bool,
}

impl ResponseDecoder for Decoder {
    fn frame(&mut self, frame: Frame<'_>) {
        if frame.data == b"[DONE]" {
            self.done = true;
            return;
        }
        let Ok(v) = serde_json::from_slice::<Value>(frame.data) else {
            self.unreadable += 1;
            return;
        };
        if self.id.is_none() {
            self.id = v.get("id").and_then(Value::as_str).map(str::to_owned);
        }
        if self.model.is_none() {
            self.model = v.get("model").and_then(Value::as_str).map(str::to_owned);
        }
        if let Some(choices) = v.get("choices").and_then(Value::as_array) {
            for (i, c) in choices.iter().enumerate() {
                let index = c.get("index").and_then(Value::as_u64).unwrap_or(i as u64);
                if let Some(r) = c.get("finish_reason").and_then(Value::as_str) {
                    self.finish.insert(index, r.to_owned());
                }
            }
        }
        if let Some(u) = v.get("usage").filter(|u| u.is_object()) {
            self.usage = Some(u.clone());
        }
    }

    fn finish(self: Box<Self>) -> Response {
        let tokens = |k: &str| self.usage.as_ref().and_then(|u| u.get(k)).and_then(Value::as_u64);
        Response {
            input_tokens: tokens("prompt_tokens"),
            output_tokens: tokens("completion_tokens"),
            id: self.id,
            model: self.model,
            finish_reason: self
                .finish
                .into_iter()
                .map(|(index, finish_reason)| FinishReason { index, finish_reason })
                .collect(),
            usage: self.usage,
            done: self.done,
            unreadable: self.unreadable,
            extra: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Protocols;

    fn endpoint(method: &str, target: &str) -> Option<&'static str> {
        let p = Protocols::none().with(&OpenAi);
        p.claims(method, target, &[]).first().map(|c| c.endpoint)
    }

    #[test]
    fn endpoints() {
        assert_eq!(endpoint("POST", "/v1/chat/completions"), Some(CHAT_COMPLETIONS));
        assert_eq!(endpoint("POST", "/v1/completions?x=1"), Some(COMPLETIONS));
        assert_eq!(
            endpoint("POST", "http://gw:8000/v1/completions"),
            Some(COMPLETIONS)
        );
        assert_eq!(endpoint("GET", "/v1/chat/completions"), None);
        assert_eq!(endpoint("POST", "/v1/chat/completions/"), None);
        assert_eq!(endpoint("POST", "/v1/models"), None);
        assert_eq!(endpoint("POST", "/health"), None);
    }

    #[test]
    fn request_fields() {
        let r = OpenAi
            .request(
                CHAT_COMPLETIONS,
                br#"{"model":"m","stream":true,"seed":7,"messages":[]}"#,
            )
            .unwrap();
        assert_eq!(r.model.as_deref(), Some("m"));
        assert!(r.stream);
        assert_eq!(r.seed, Some(Value::from(7)));
        assert_eq!(OpenAi.request(CHAT_COMPLETIONS, b"{\"model\":"), None);
        assert_eq!(
            OpenAi.request(CHAT_COMPLETIONS, b"[1]").unwrap(),
            Request::default()
        );
    }

    #[test]
    fn response_rule() {
        let plain = Request::default();
        let stream = Request {
            stream: true,
            ..Request::default()
        };
        let f = |r: &Request, t: Option<&str>| OpenAi.response_framing(CHAT_COMPLETIONS, r, t);
        assert_eq!(f(&plain, Some("application/json")), Some(Framing::Json));
        assert_eq!(f(&stream, Some("application/json")), Some(Framing::Json));
        assert_eq!(f(&stream, Some("text/event-stream")), Some(Framing::Sse));
        assert_eq!(f(&plain, Some("text/event-stream")), None);
        assert_eq!(f(&plain, Some("text/plain")), None);
        assert_eq!(f(&plain, None), None);
    }

    #[test]
    fn decodes_stream_chunks() {
        let mut d = OpenAi.decoder(CHAT_COMPLETIONS, &Request::default());
        for data in [
            &br#"{"id":"c1","model":"m","choices":[{"index":0,"delta":{"content":"a"},"finish_reason":null}]}"#[..],
            br#"{"id":"c1","choices":[{"index":1,"finish_reason":"length"},{"index":0,"finish_reason":"stop"}]}"#,
            br#"{"id":"c1","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":2}}"#,
            b"not json",
            b"[DONE]",
        ] {
            d.frame(Frame { event: None, data });
        }
        let r = d.finish();
        assert_eq!(r.id.as_deref(), Some("c1"));
        assert_eq!(
            r.finish_reason,
            [
                FinishReason {
                    index: 0,
                    finish_reason: "stop".into()
                },
                FinishReason {
                    index: 1,
                    finish_reason: "length".into()
                }
            ]
        );
        assert_eq!(r.usage.unwrap()["completion_tokens"], 2);
        assert_eq!((r.input_tokens, r.output_tokens), (Some(3), Some(2)));
        assert_eq!((r.unreadable, r.done), (1, true));
    }
}
