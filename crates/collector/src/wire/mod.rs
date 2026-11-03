//! Wire Protocols (L3, spec §5): which HTTP exchanges are Request
//! Workunits, and the record fields read from their bodies.
//!
//! Each protocol implements [`WireProtocol`] in its own module and is
//! listed once in [`BUILTIN`]. It declares the routes it serves, may sniff
//! request headers and the request body to tell itself apart from another
//! protocol on the same path, picks the [`Framing`] of a response, and
//! decodes frames into the common [`Response`] fields. The decoder
//! ([`crate::decode`]) does the rest: HTTP, byte accounting, hashing, and
//! cutting bodies into frames.
//!
//! Bodies are parsed for record fields only; they are never re-serialised,
//! and their hashes cover the bytes as on the wire.

pub mod anthropic;
pub mod framing;
pub mod ollama;
pub mod openai;
pub mod openai_responses;

use std::cmp::Reverse;
use std::fmt;

use serde::Serialize;
use serde_json::Value;

pub use framing::{Frame, Framing};

/// Every Wire Protocol the Collector decodes, in precedence order (see
/// [`Protocols::claims`]). A new protocol adds one line here.
pub const BUILTIN: &[&dyn WireProtocol] = &[
    &openai::OpenAi,
    &openai_responses::OpenAiResponses,
    &ollama::Ollama,
    &anthropic::Anthropic,
];

/// A route a protocol serves: an HTTP method and a path pattern.
///
/// The pattern is matched against the request path without its query or
/// fragment. `*` matches any run of characters other than `/`, so
/// `/v1beta/models/*:generateContent` matches one model name. The pattern
/// is also the record's `endpoint`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub method: &'static str,
    pub path: &'static str,
}

impl Route {
    pub const fn post(path: &'static str) -> Self {
        Route { method: "POST", path }
    }

    /// Literal characters in the pattern: more is more specific.
    fn literal_len(&self) -> usize {
        self.path.bytes().filter(|&b| b != b'*').count()
    }

    fn matches(&self, method: &str, path: &str) -> bool {
        self.method == method && glob(self.path.as_bytes(), path.as_bytes())
    }
}

/// `*` matches any run of bytes other than `/`.
fn glob(pat: &[u8], s: &[u8]) -> bool {
    match pat.split_first() {
        None => s.is_empty(),
        Some((b'*', rest)) => (0..=s.len())
            .take_while(|&i| i == 0 || s[i - 1] != b'/')
            .any(|i| glob(rest, &s[i..])),
        Some((&c, rest)) => s.first() == Some(&c) && glob(rest, &s[1..]),
    }
}

/// What a protocol sees of a request head.
pub struct RequestHead<'a> {
    pub method: &'a str,
    /// The path, without query or fragment, also for absolute-form targets.
    pub path: &'a str,
    headers: &'a [(Vec<u8>, Vec<u8>)],
}

impl<'a> RequestHead<'a> {
    pub(crate) fn new(method: &'a str, path: &'a str, headers: &'a [(Vec<u8>, Vec<u8>)]) -> Self {
        RequestHead {
            method,
            path,
            headers,
        }
    }

    /// The first value of header `name` (lowercase).
    pub fn header(&self, name: &str) -> Option<&'a [u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n == name.as_bytes())
            .map(|(_, v)| v.as_slice())
    }
}

/// The path of a request target: absolute form (`http://host/path`, as
/// sent to a proxy) reduced to its path, query and fragment removed.
pub fn target_path(target: &str) -> &str {
    let path = match target.split_once("://") {
        Some((_, rest)) => rest.find('/').map_or("/", |i| &rest[i..]),
        None => target,
    };
    path.split(['?', '#']).next().unwrap_or(path)
}

/// Header evidence for or against a protocol on a matching route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Sniff {
    /// The headers rule this protocol out.
    No,
    /// No evidence either way.
    Maybe,
    /// A header only this protocol sends (e.g. `anthropic-version`).
    Yes,
}

/// Common fields read from a request body.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Request {
    pub model: Option<String>,
    /// The request asked for a streamed response.
    pub stream: bool,
    pub seed: Option<Value>,
    pub n: Option<Value>,
    /// Protocol-specific request fields, for the protocol's own decoder.
    pub extra: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FinishReason {
    pub index: u64,
    pub finish_reason: String,
}

/// Common fields read from a response, whatever its framing.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Response {
    pub id: Option<String>,
    pub model: Option<String>,
    /// Finish or stop reasons, by choice index (`0` when the protocol has
    /// one output).
    pub finish_reason: Vec<FinishReason>,
    /// The usage object as the protocol reports it.
    pub usage: Option<Value>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    /// The protocol's end-of-stream marker was seen (`data: [DONE]`,
    /// `message_stop`, `"done": true`).
    pub done: bool,
    /// Frames the protocol could not read (not JSON, or not its shape).
    pub unreadable: u64,
    /// Protocol-specific fields: a JSON object built from the protocol's own
    /// typed struct with [`extra`], never new top-level columns.
    pub extra: Option<Value>,
}

/// A protocol's typed extras as the record's `extra` object; `None` when
/// every field is null.
pub fn extra<T: Serialize>(fields: &T) -> Option<Value> {
    match serde_json::to_value(fields).ok()? {
        Value::Object(m) if m.values().any(|v| !v.is_null()) => Some(Value::Object(m)),
        _ => None,
    }
}

/// Reads one response's frames, in order.
pub trait ResponseDecoder: Send {
    /// One SSE event, NDJSON line, or the whole JSON body.
    fn frame(&mut self, frame: Frame<'_>);
    /// The fields read; called once, after the last frame.
    fn finish(self: Box<Self>) -> Response;
}

/// One Wire Protocol. Implementations hold no state: per-response state
/// lives in the [`ResponseDecoder`] they hand out.
pub trait WireProtocol: Send + Sync {
    /// Stable id: the record's `protocol` and the `protocol` metric label.
    fn id(&self) -> &'static str;

    /// The routes this protocol serves.
    fn routes(&self) -> &'static [Route];

    /// Header evidence on a matching route, for paths several protocols
    /// serve. The default has none.
    fn sniff(&self, _endpoint: &'static str, _head: &RequestHead<'_>) -> Sniff {
        Sniff::Maybe
    }

    /// Reads a complete request body; `None` if it is not this protocol's
    /// request (not JSON, or the wrong shape), which leaves it to the next
    /// claim.
    fn request(&self, endpoint: &'static str, body: &[u8]) -> Option<Request>;

    /// The framing the response is read with, from its media type
    /// (lowercase, no parameters); `None` if the response does not complete
    /// a Workunit of this protocol.
    fn response_framing(
        &self,
        endpoint: &'static str,
        request: &Request,
        media_type: Option<&str>,
    ) -> Option<Framing>;

    /// A fresh decoder for one response.
    fn decoder(&self, endpoint: &'static str, request: &Request) -> Box<dyn ResponseDecoder>;
}

/// A protocol's claim on a request: it serves the route, and its headers
/// did not rule it out.
#[derive(Clone, Copy)]
pub struct Claim {
    pub protocol: &'static dyn WireProtocol,
    pub endpoint: &'static str,
}

impl fmt::Debug for Claim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.protocol.id(), self.endpoint)
    }
}

/// The protocols a [`Decoder`](crate::Decoder) matches requests against.
#[derive(Clone)]
pub struct Protocols {
    list: Vec<&'static dyn WireProtocol>,
}

impl Default for Protocols {
    fn default() -> Self {
        let mut p = Protocols { list: Vec::new() };
        for &proto in BUILTIN {
            p = p.with(proto);
        }
        p
    }
}

impl fmt::Debug for Protocols {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.ids()).finish()
    }
}

impl Protocols {
    /// No protocols: every HTTP exchange is `http_other`.
    pub fn none() -> Self {
        Protocols { list: Vec::new() }
    }

    /// Adds `protocol` after the ones already listed.
    ///
    /// # Panics
    /// If a protocol with the same id is already listed.
    pub fn with(mut self, protocol: &'static dyn WireProtocol) -> Self {
        assert!(
            !self.ids().any(|id| id == protocol.id()),
            "Wire Protocol {} registered twice",
            protocol.id()
        );
        self.list.push(protocol);
        self
    }

    pub fn ids(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.list.iter().map(|p| p.id())
    }

    /// Every protocol that claims a request, best first. A protocol claims
    /// it when one of its routes matches (the first such route is its
    /// endpoint) and its [`sniff`](WireProtocol::sniff) is not
    /// [`Sniff::No`]. Claims are ordered by
    ///
    /// 1. header evidence: [`Sniff::Yes`] before [`Sniff::Maybe`];
    /// 2. route specificity: more literal characters in the pattern first,
    ///    so an exact path beats a pattern;
    /// 3. registry order.
    ///
    /// The request body then goes to each claim in turn; the first whose
    /// [`request`](WireProtocol::request) reads it owns the exchange.
    pub fn claims(&self, method: &str, target: &str, headers: &[(Vec<u8>, Vec<u8>)]) -> Vec<Claim> {
        let path = target_path(target);
        let head = RequestHead::new(method, path, headers);
        let mut claims: Vec<(Sniff, usize, usize, Claim)> = Vec::new();
        for (order, &protocol) in self.list.iter().enumerate() {
            let Some(route) = protocol.routes().iter().find(|r| r.matches(method, path)) else {
                continue;
            };
            let sniff = protocol.sniff(route.path, &head);
            if sniff == Sniff::No {
                continue;
            }
            let claim = Claim {
                protocol,
                endpoint: route.path,
            };
            claims.push((sniff, route.literal_len(), order, claim));
        }
        claims.sort_by_key(|&(sniff, literal, order, _)| (Reverse(sniff), Reverse(literal), order));
        claims.into_iter().map(|(.., c)| c).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        id: &'static str,
        routes: &'static [Route],
        /// Header that makes this protocol `Yes`; its absence is `Maybe`.
        marker: Option<&'static str>,
        /// Header that rules it out.
        veto: Option<&'static str>,
    }

    impl WireProtocol for Fake {
        fn id(&self) -> &'static str {
            self.id
        }
        fn routes(&self) -> &'static [Route] {
            self.routes
        }
        fn sniff(&self, _: &'static str, head: &RequestHead<'_>) -> Sniff {
            if self.veto.is_some_and(|h| head.header(h).is_some()) {
                Sniff::No
            } else if self.marker.is_some_and(|h| head.header(h).is_some()) {
                Sniff::Yes
            } else {
                Sniff::Maybe
            }
        }
        fn request(&self, _: &'static str, _: &[u8]) -> Option<Request> {
            None
        }
        fn response_framing(&self, _: &'static str, _: &Request, _: Option<&str>) -> Option<Framing> {
            None
        }
        fn decoder(&self, _: &'static str, _: &Request) -> Box<dyn ResponseDecoder> {
            unreachable!()
        }
    }

    static A: Fake = Fake {
        id: "a",
        routes: &[Route::post("/v1/messages"), Route::post("/v1/*")],
        marker: None,
        veto: Some("x-not-a"),
    };
    static B: Fake = Fake {
        id: "b",
        routes: &[Route::post("/v1/messages")],
        marker: Some("b-version"),
        veto: None,
    };
    static C: Fake = Fake {
        id: "c",
        routes: &[Route::post("/v1/*")],
        marker: None,
        veto: None,
    };

    fn ids(p: &Protocols, target: &str, headers: &[(&str, &str)]) -> Vec<String> {
        let h: Vec<(Vec<u8>, Vec<u8>)> = headers
            .iter()
            .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect();
        p.claims("POST", target, &h)
            .iter()
            .map(|c| format!("{c:?}"))
            .collect()
    }

    #[test]
    fn globs() {
        assert!(glob(b"/v1/*", b"/v1/x"));
        assert!(glob(b"/v1/*", b"/v1/"));
        assert!(!glob(b"/v1/*", b"/v1/x/y"));
        assert!(glob(b"/m/*:gen", b"/m/gemini-2:gen"));
        assert!(!glob(b"/m/*:gen", b"/m/a/b:gen"));
        assert!(glob(b"/a", b"/a") && !glob(b"/a", b"/ab"));
    }

    #[test]
    fn target_paths() {
        assert_eq!(target_path("/v1/completions?x=1"), "/v1/completions");
        assert_eq!(target_path("http://gw:8000/v1/completions#f"), "/v1/completions");
        assert_eq!(target_path("http://gw:8000"), "/");
    }

    #[test]
    fn precedence_is_evidence_then_specificity_then_order() {
        let p = Protocols::none().with(&A).with(&B).with(&C);
        // Same exact route: registry order.
        assert_eq!(
            ids(&p, "/v1/messages", &[]),
            ["a:/v1/messages", "b:/v1/messages", "c:/v1/*"]
        );
        // A header only B sends puts B first.
        assert_eq!(
            ids(&p, "/v1/messages", &[("b-version", "1")]),
            ["b:/v1/messages", "a:/v1/messages", "c:/v1/*"]
        );
        // A veto drops A.
        assert_eq!(
            ids(&p, "/v1/messages", &[("x-not-a", "")]),
            ["b:/v1/messages", "c:/v1/*"]
        );
        // Only the patterns match.
        assert_eq!(ids(&p, "/v1/other?q", &[]), ["a:/v1/*", "c:/v1/*"]);
        assert!(ids(&p, "/v2/messages", &[]).is_empty());
        // Registry order is the last tie-break, so it alone changes the order.
        let q = Protocols::none().with(&C).with(&A);
        assert_eq!(ids(&q, "/v1/other", &[]), ["c:/v1/*", "a:/v1/*"]);
    }

    #[test]
    #[should_panic(expected = "registered twice")]
    fn duplicate_ids_panic() {
        let _ = Protocols::none().with(&A).with(&A);
    }

    #[test]
    fn builtin_ids_are_unique() {
        assert_eq!(
            Protocols::default().ids().collect::<Vec<_>>(),
            ["openai", "openai_responses", "ollama", "anthropic"]
        );
    }

    #[test]
    fn extra_drops_all_null_objects() {
        #[derive(Serialize)]
        struct E {
            a: Option<u32>,
        }
        assert_eq!(extra(&E { a: None }), None);
        assert_eq!(extra(&E { a: Some(1) }), Some(serde_json::json!({"a": 1})));
    }
}
