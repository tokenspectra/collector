//! The OpenAI Wire Protocol (L3, spec §5): which HTTP exchanges are Request
//! Workunits, and the record fields read from their bodies.
//!
//! A pair is a Request Workunit only if the request is `POST
//! /v1/chat/completions` or `POST /v1/completions` with a JSON body, and the
//! response is `application/json`, or `text/event-stream` when the request
//! set `stream: true`. Bodies are parsed for record fields only; they are
//! never re-serialised, and their hashes cover the bytes as on the wire.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

pub const CHAT_COMPLETIONS: &str = "/v1/chat/completions";
pub const COMPLETIONS: &str = "/v1/completions";

/// The Workunit endpoint a request targets, if any.
pub(crate) fn endpoint(method: &str, target: &str) -> Option<&'static str> {
    if method != "POST" {
        return None;
    }
    // Absolute form (`http://host/path`), as sent to a proxy.
    let path = match target.split_once("://") {
        Some((_, rest)) => rest.find('/').map_or("/", |i| &rest[i..]),
        None => target,
    };
    let path = path.split(['?', '#']).next().unwrap_or(path);
    [CHAT_COMPLETIONS, COMPLETIONS].into_iter().find(|e| *e == path)
}

/// Fields read from a request body.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Request {
    pub model: Option<String>,
    pub stream: bool,
    pub seed: Option<Value>,
    pub n: Option<Value>,
}

/// Parses a request body; `None` if it is not JSON.
pub(crate) fn parse_request(body: &[u8]) -> Option<Request> {
    let v: Value = serde_json::from_slice(body).ok()?;
    Some(Request {
        model: v.get("model").and_then(Value::as_str).map(str::to_owned),
        stream: v.get("stream").and_then(Value::as_bool).unwrap_or(false),
        seed: v.get("seed").filter(|s| s.is_number()).cloned(),
        n: v.get("n").filter(|s| s.is_number()).cloned(),
    })
}

/// Whether a response with this media type completes a Workunit.
pub(crate) fn response_matches(media_type: Option<&str>, stream: bool) -> bool {
    match media_type {
        Some("application/json") => true,
        Some("text/event-stream") => stream,
        _ => false,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FinishReason {
    pub index: u64,
    pub finish_reason: String,
}

/// Record fields gathered from a response: one JSON object, or every SSE
/// chunk in order.
#[derive(Clone, Debug, Default)]
pub(crate) struct Response {
    pub id: Option<String>,
    pub model: Option<String>,
    pub finish: BTreeMap<u64, String>,
    pub usage: Option<Value>,
    /// Bodies or SSE chunks that were not JSON.
    pub unparsed: u64,
    /// An SSE `data: [DONE]` was seen.
    pub done: bool,
}

impl Response {
    /// Takes in one JSON body or SSE `data` payload.
    pub fn absorb(&mut self, data: &[u8]) {
        if data == b"[DONE]" {
            self.done = true;
            return;
        }
        let Ok(v) = serde_json::from_slice::<Value>(data) else {
            self.unparsed += 1;
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

    pub fn finish_reasons(&self) -> Vec<FinishReason> {
        self.finish
            .iter()
            .map(|(&index, r)| FinishReason {
                index,
                finish_reason: r.clone(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let r = parse_request(br#"{"model":"m","stream":true,"seed":7,"messages":[]}"#).unwrap();
        assert_eq!(r.model.as_deref(), Some("m"));
        assert!(r.stream);
        assert_eq!(r.seed, Some(Value::from(7)));
        assert_eq!(parse_request(b"{\"model\":").map(|_| ()), None);
        assert_eq!(parse_request(b"[1]").unwrap(), Request::default());
    }

    #[test]
    fn response_rule() {
        assert!(response_matches(Some("application/json"), false));
        assert!(response_matches(Some("application/json"), true));
        assert!(response_matches(Some("text/event-stream"), true));
        assert!(!response_matches(Some("text/event-stream"), false));
        assert!(!response_matches(Some("text/plain"), false));
        assert!(!response_matches(None, false));
    }

    #[test]
    fn absorbs_stream_chunks() {
        let mut r = Response::default();
        r.absorb(br#"{"id":"c1","model":"m","choices":[{"index":0,"delta":{"content":"a"},"finish_reason":null}]}"#);
        r.absorb(br#"{"id":"c1","choices":[{"index":1,"finish_reason":"length"},{"index":0,"finish_reason":"stop"}]}"#);
        r.absorb(br#"{"id":"c1","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":2}}"#);
        r.absorb(b"not json");
        r.absorb(b"[DONE]");
        assert_eq!(r.id.as_deref(), Some("c1"));
        assert_eq!(
            r.finish_reasons(),
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
        assert_eq!((r.unparsed, r.done), (1, true));
    }
}
