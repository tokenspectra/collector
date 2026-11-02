//! Views of the kept bodies for people (spec §8 "Two views of the same
//! bodies").
//!
//! `by-exchange/{flow}/{exchange}.{request|response}.{ext}` are symlinks to
//! `bodies/{multihash}`, and SSE Workunits also get
//! `{exchange}.response.merged.json`: the streamed chunks joined into one
//! completion object. Everything here is derived from `http.jsonl` and
//! `bodies/`, rebuilt from scratch on each call, and safe to delete. The
//! merged file is not evidence: it is never hashed, stored or compared.
//!
//! Nothing from the Operator goes into a name unchecked: the Flow id is
//! sanitised, the exchange is a number, the extension comes from a fixed
//! list, and the body name must parse as a multihash.

use std::collections::BTreeMap;
use std::io::{self, BufRead};
use std::path::Path;

use serde::Serialize;
use serde_json::Value;

use crate::mh;
use crate::output::BODIES;
use crate::sse::Sse;

pub const BY_EXCHANGE: &str = "by-exchange";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub links: u64,
    pub merged: u64,
}

/// `{flow}`: every character outside `[A-Za-z0-9._-]` becomes `_`.
pub fn flow_dir(flow: &str) -> String {
    flow.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// `{ext}` from the parsed media type of a `content-type` value.
pub fn ext(content_type: Option<&str>) -> &'static str {
    let media = content_type
        .and_then(|c| c.split(';').next())
        .map(|m| m.trim().to_ascii_lowercase());
    match media.as_deref() {
        Some("application/json") => "json",
        Some("text/event-stream") => "sse",
        _ => "bin",
    }
}

/// Rebuilds `by-exchange/` in the output directory `out`.
pub fn write(out: &Path) -> io::Result<Summary> {
    let root = out.join(BY_EXCHANGE);
    if root.exists() {
        std::fs::remove_dir_all(&root)?;
    }
    let bodies = out.join(BODIES);
    let mut summary = Summary::default();
    let http = std::fs::File::open(out.join("http.jsonl"))?;
    for line in io::BufReader::new(http).lines() {
        let row: Value = serde_json::from_str(&line?)?;
        let (Some(flow), Some(exchange)) = (row["flow"].as_str(), row["exchange"].as_u64()) else {
            continue;
        };
        let dir = root.join(flow_dir(flow));
        for role in ["request", "response"] {
            let m = &row[role];
            // Only names that parse as a multihash, for bodies that exist
            // and are not empty.
            let Some(hash) = m["body_hash"].as_str().filter(|h| mh::parse(h).is_some()) else {
                continue;
            };
            if m["body_len"].as_u64().unwrap_or(0) == 0 || !bodies.join(hash).is_file() {
                continue;
            }
            std::fs::create_dir_all(&dir)?;
            let ext = ext(m["content_type"].as_str());
            let link = dir.join(format!("{exchange}.{role}.{ext}"));
            std::os::unix::fs::symlink(Path::new("../..").join(BODIES).join(hash), link)?;
            summary.links += 1;
            if role == "response" && row["bucket"] == "workunit" && ext == "sse" {
                let body = std::fs::read(bodies.join(hash))?;
                let mut merged = serde_json::to_vec_pretty(&merge_sse(&body))?;
                merged.push(b'\n');
                std::fs::write(dir.join(format!("{exchange}.response.merged.json")), merged)?;
                summary.merged += 1;
            }
        }
    }
    Ok(summary)
}

#[derive(Debug, Default, Serialize)]
struct Message {
    role: Option<String>,
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning: Option<String>,
}

#[derive(Debug, Default, Serialize)]
struct Choice {
    index: u64,
    /// Chat completions.
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<Message>,
    /// Text completions.
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    finish_reason: Option<String>,
}

/// The merged view of an OpenAI SSE body, shaped like the non-streaming
/// response.
#[derive(Debug, Default, Serialize)]
pub struct Merged {
    id: Option<String>,
    object: String,
    created: Option<Value>,
    model: Option<String>,
    choices: Vec<Choice>,
    usage: Option<Value>,
    /// `[DONE]` never arrived, or an event did not parse.
    incomplete: bool,
    unparsed_events: u64,
}

/// Joins the `chat.completion.chunk` (or text completion) events of an SSE
/// body: per choice, `role`, `content` and `reasoning` joined in event
/// order and the last `finish_reason`; `id`, `created`, `model` from the
/// first event; the last `usage`.
pub fn merge_sse(body: &[u8]) -> Merged {
    let mut events = Vec::new();
    let mut sse = Sse::default();
    sse.push(body, 0, &mut events);
    let mut m = Merged {
        object: "chat.completion".into(),
        ..Merged::default()
    };
    let mut first = true;
    let mut done = false;
    let mut choices: BTreeMap<u64, Choice> = BTreeMap::new();
    for e in events {
        if e.data == b"[DONE]" {
            done = true;
            continue;
        }
        let Ok(v) = serde_json::from_slice::<Value>(&e.data) else {
            m.unparsed_events += 1;
            continue;
        };
        if first {
            first = false;
            m.id = v["id"].as_str().map(str::to_owned);
            m.created = v.get("created").cloned();
            m.model = v["model"].as_str().map(str::to_owned);
            if v["object"] == "text_completion" {
                m.object = "text_completion".into();
            }
        }
        if v["usage"].is_object() {
            m.usage = Some(v["usage"].clone());
        }
        for (i, c) in v["choices"].as_array().into_iter().flatten().enumerate() {
            let index = c["index"].as_u64().unwrap_or(i as u64);
            let ch = choices.entry(index).or_insert_with(|| Choice {
                index,
                ..Choice::default()
            });
            if let Some(t) = c["text"].as_str() {
                ch.text.get_or_insert_with(String::new).push_str(t);
            }
            let d = &c["delta"];
            if d.is_object() {
                let msg = ch.message.get_or_insert_with(Message::default);
                if let Some(r) = d["role"].as_str() {
                    msg.role.get_or_insert_with(|| r.to_owned());
                }
                if let Some(t) = d["content"].as_str() {
                    msg.content.push_str(t);
                }
                if let Some(t) = d["reasoning"].as_str().or(d["reasoning_content"].as_str()) {
                    msg.reasoning.get_or_insert_with(String::new).push_str(t);
                }
            }
            if let Some(r) = c["finish_reason"].as_str() {
                ch.finish_reason = Some(r.to_owned());
            }
        }
    }
    m.choices = choices.into_values().collect();
    m.incomplete = !done || m.unparsed_events > 0 || sse.broken;
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_sanitised() {
        assert_eq!(
            flow_dir("tap0|tcp|[::1]:443|10.0.0.2:80|0"),
            "tap0_tcp____1__443_10.0.0.2_80_0"
        );
        assert_eq!(flow_dir("../../etc"), ".._.._etc");
        assert_eq!(ext(Some("Application/JSON; charset=utf-8")), "json");
        assert_eq!(ext(Some("text/event-stream")), "sse");
        assert_eq!(ext(Some("text/html")), "bin");
        assert_eq!(ext(None), "bin");
    }

    #[test]
    fn merges_chat_chunks() {
        let body = concat!(
            "data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}\n\n",
            "data: {\"id\":\"c\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning\":\"hm\",\"content\":\"Hi\"}},{\"index\":1,\"delta\":{\"content\":\"Yo\"}}]}\n\n",
            "data: {\"id\":\"c\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"!\"},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"id\":\"c\",\"choices\":[],\"usage\":{\"total_tokens\":3}}\n\n",
            "data: [DONE]\n\n",
        );
        let m = serde_json::to_value(merge_sse(body.as_bytes())).unwrap();
        assert_eq!(m["object"], "chat.completion");
        assert_eq!(m["choices"][0]["message"]["content"], "Hi!");
        assert_eq!(m["choices"][0]["message"]["role"], "assistant");
        assert_eq!(m["choices"][0]["message"]["reasoning"], "hm");
        assert_eq!(m["choices"][0]["finish_reason"], "stop");
        assert_eq!(m["choices"][1]["message"]["content"], "Yo");
        assert_eq!(m["usage"]["total_tokens"], 3);
        assert_eq!(
            (m["incomplete"].as_bool(), m["unparsed_events"].as_u64()),
            (Some(false), Some(0))
        );
    }

    #[test]
    fn cut_off_stream_is_marked_incomplete() {
        let body = b"data: {\"object\":\"text_completion\",\"choices\":[{\"index\":0,\"text\":\"a\"}]}\n\ndata: {oops\n\n";
        let m = serde_json::to_value(merge_sse(body)).unwrap();
        assert_eq!(m["object"], "text_completion");
        assert_eq!(m["choices"][0]["text"], "a");
        assert_eq!(
            (m["incomplete"].as_bool(), m["unparsed_events"].as_u64()),
            (Some(true), Some(1))
        );
    }
}
