//! Index-table schemas (spec §8), one per table.
//!
//! Each table has a fixed schema below, so a column keeps its type in every
//! window: nested records are flattened (`orig_stats.packets` →
//! `orig_stats_packets`), and values sent by the Operator in arbitrary JSON
//! (`usage`, `seed`, …) or lists are kept as JSON text. Every column is
//! optional. A test checks that every field the records serialise has a
//! column.

use serde_json::Value;

/// A column's type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Int,
    /// A double, for ratios the Collector computes (entropy, rates).
    Float,
    Bool,
    Str,
    /// Any JSON value, written as JSON text.
    Json,
}

use Kind::{Bool, Float, Int, Json, Str};

/// A column: its path in the JSON row (`.` between nested names) and type.
pub type Column = (&'static str, Kind);

/// Index tables, in the order they are written.
pub const TABLES: [&str; 10] = [
    "packets",
    "segments",
    "events",
    "flows",
    "dns",
    "features",
    "http",
    "workunits",
    "chunks",
    "blobs",
];

const PACKETS: &[Column] = &[
    ("link", Str),
    ("window_start_ns", Int),
    ("index", Int),
    ("ts_ns", Int),
    ("cap_len", Int),
    ("orig_len", Int),
    ("hash", Str),
    ("flow", Str),
    ("dir", Str),
    ("tcp_flags", Str),
    ("stream_off", Int),
    ("payload_len", Int),
    ("note", Str),
];

const SEGMENTS: &[Column] = &[
    ("flow", Str),
    ("dir", Str),
    ("stream_off", Int),
    ("len", Int),
    ("window_start_ns", Int),
    ("index", Int),
    ("pkt_off", Int),
    ("ts_ns", Int),
];

const EVENTS: &[Column] = &[
    ("flow", Str),
    ("dir", Str),
    ("kind", Str),
    ("stream_off", Int),
    ("len", Int),
    ("window_start_ns", Int),
    ("index", Int),
];

const FLOWS: &[Column] = &[
    ("window_start_ns", Int),
    ("flow", Str),
    ("link", Str),
    ("kind", Str),
    ("generation", Int),
    ("orig", Str),
    ("resp", Str),
    ("first_ts_ns", Int),
    ("slice_first_ts_ns", Int),
    ("slice_last_ts_ns", Int),
    ("mid_stream_start", Bool),
    ("syn", Bool),
    ("syn_ack", Bool),
    ("fin_orig", Bool),
    ("fin_resp", Bool),
    ("rst", Bool),
    ("ended", Bool),
    ("orig_stats.packets", Int),
    ("orig_stats.wire_bytes", Int),
    ("orig_stats.payload_bytes", Int),
    ("orig_stats.stream_start", Int),
    ("orig_stats.stream_end", Int),
    ("orig_stats.gap_bytes", Int),
    ("orig_stats.retransmit_bytes", Int),
    ("orig_stats.retransmit_diff_bytes", Int),
    ("orig_stats.datagrams", Int),
    ("orig_stats.slice_hash", Str),
    ("resp_stats.packets", Int),
    ("resp_stats.wire_bytes", Int),
    ("resp_stats.payload_bytes", Int),
    ("resp_stats.stream_start", Int),
    ("resp_stats.stream_end", Int),
    ("resp_stats.gap_bytes", Int),
    ("resp_stats.retransmit_bytes", Int),
    ("resp_stats.retransmit_diff_bytes", Int),
    ("resp_stats.datagrams", Int),
    ("resp_stats.slice_hash", Str),
    ("verdict", Str),
    ("orig_bytes.workunit", Int),
    ("orig_bytes.http_other", Int),
    ("orig_bytes.framing", Int),
    ("orig_bytes.unexplained", Int),
    ("orig_bytes.gap", Int),
    ("orig_bytes.fact", Int),
    ("resp_bytes.workunit", Int),
    ("resp_bytes.http_other", Int),
    ("resp_bytes.framing", Int),
    ("resp_bytes.unexplained", Int),
    ("resp_bytes.gap", Int),
    ("resp_bytes.fact", Int),
    ("orig_desync", Str),
    ("resp_desync", Str),
];

const DNS: &[Column] = &[
    ("window_start_ns", Int),
    ("index", Int),
    ("ts_ns", Int),
    ("flow", Str),
    ("dir", Str),
    ("response", Bool),
    ("qname", Str),
    ("qtype", Int),
    ("qclass", Int),
    ("qname_len", Int),
    ("labels", Int),
    ("label_len_max", Int),
    ("qname_entropy", Float),
    ("txt_records", Int),
    ("txt_bytes", Int),
    ("txt_max", Int),
    ("size", Int),
    ("trailing_bytes", Int),
];

/// One family of columns per decoder (`dns_*` now); a later decoder adds
/// its own family after these, so earlier columns never move.
const FEATURES: &[Column] = &[
    ("window_start_ns", Int),
    ("flow", Str),
    ("link", Str),
    ("dns.messages", Int),
    ("dns.queries", Int),
    ("dns.responses", Int),
    ("dns.other_datagrams", Int),
    ("dns.query_bytes", Int),
    ("dns.response_bytes", Int),
    ("dns.bytes", Int),
    ("dns.query_rate", Float),
    ("dns.qname_entropy_max", Float),
    ("dns.qname_entropy_mean", Float),
    ("dns.qname_len_max", Int),
    ("dns.label_len_max", Int),
    ("dns.label_len_mean", Float),
    ("dns.txt_records", Int),
    ("dns.txt_bytes", Int),
    ("dns.txt_max", Int),
];

macro_rules! message {
    ($p:literal) => {
        [
            (concat!($p, ".dir"), Str),
            (concat!($p, ".stream_start"), Int),
            (concat!($p, ".stream_end"), Int),
            (concat!($p, ".first_ts_ns"), Int),
            (concat!($p, ".last_ts_ns"), Int),
            (concat!($p, ".method"), Str),
            (concat!($p, ".target"), Str),
            (concat!($p, ".status"), Int),
            (concat!($p, ".content_type"), Str),
            (concat!($p, ".content_encoding"), Str),
            (concat!($p, ".body_len"), Int),
            (concat!($p, ".body_gap_bytes"), Int),
            (concat!($p, ".body_hash"), Str),
            (concat!($p, ".decoded_len"), Int),
            (concat!($p, ".decoded_hash"), Str),
            (concat!($p, ".decode_error"), Str),
            (concat!($p, ".complete"), Bool),
        ]
    };
}

const REQUEST: [Column; 17] = message!("request");
const RESPONSE: [Column; 17] = message!("response");

const HTTP_HEAD: &[Column] = &[
    ("flow", Str),
    ("exchange", Int),
    ("http", Str),
    ("h2_stream", Int),
    ("bucket", Str),
    ("workunit_id", Str),
];

const HTTP_TAIL: &[Column] = &[("interim_responses", Int), ("reset", Bool)];

const WORKUNITS: &[Column] = &[
    ("workunit_id", Str),
    ("flow", Str),
    ("exchange", Int),
    ("http", Str),
    ("h2_stream", Int),
    ("endpoint", Str),
    ("received_ts_ns", Int),
    ("completed_ts_ns", Int),
    ("model", Str),
    ("stream", Bool),
    ("seed", Json),
    ("n", Json),
    ("status", Int),
    ("response_content_type", Str),
    ("request_body_hash", Str),
    ("request_body_len", Int),
    ("request_decoded_hash", Str),
    ("response_body_hash", Str),
    ("response_body_len", Int),
    ("response_decoded_hash", Str),
    ("response_id", Str),
    ("response_model", Str),
    ("finish_reason", Json),
    ("usage", Json),
    ("sse_events", Json),
    ("sse_done", Bool),
    ("complete", Bool),
    ("protocol", Str),
    ("input_tokens", Int),
    ("output_tokens", Int),
    ("extra", Json),
];

const CHUNKS: &[Column] = &[
    ("link", Str),
    ("window_start_ns", Int),
    ("key", Str),
    ("chunk_hash", Str),
    ("merkle_root", Str),
    ("packets", Int),
    ("truncated_packets", Int),
    ("kept_bytes", Int),
    ("truncated_bytes", Int),
    ("pcapng_len", Int),
    ("stored_len", Int),
    ("parts", Int),
];

const BLOBS: &[Column] = &[
    ("hash", Str),
    ("kind", Str),
    ("workunit_id", Str),
    ("window_start_ns", Int),
    ("pack", Str),
    ("offset", Int),
    ("len", Int),
    ("raw_len", Int),
];

/// The columns of `table`.
pub fn schema(table: &str) -> Vec<Column> {
    match table {
        "packets" => PACKETS.to_vec(),
        "segments" => SEGMENTS.to_vec(),
        "events" => EVENTS.to_vec(),
        "flows" => FLOWS.to_vec(),
        "dns" => DNS.to_vec(),
        "features" => FEATURES.to_vec(),
        "http" => [HTTP_HEAD, &REQUEST, &RESPONSE, HTTP_TAIL].concat(),
        "workunits" => WORKUNITS.to_vec(),
        "chunks" => CHUNKS.to_vec(),
        "blobs" => BLOBS.to_vec(),
        _ => panic!("unknown index table {table}"),
    }
}

/// Fields of `row` with no column in `table`: names of leaves, flattening
/// nested objects unless their column is `Json`. Empty when the schema
/// covers the row.
pub fn uncovered(table: &str, row: &Value) -> Vec<String> {
    let columns = schema(table);
    let mut out = Vec::new();
    fn walk(v: &Value, path: String, columns: &[Column], out: &mut Vec<String>) {
        if columns
            .iter()
            .any(|&(p, k)| p == path && (k == Json || !v.is_object()))
        {
            return;
        }
        match v {
            Value::Object(m) if !m.is_empty() => {
                for (k, x) in m {
                    let p = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{path}.{k}")
                    };
                    walk(x, p, columns, out);
                }
            }
            _ if path.is_empty() => {}
            _ => out.push(path),
        }
    }
    walk(row, String::new(), &columns, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn uncovered_names_missing_fields() {
        let row = json!({"hash": "x", "kind": "body", "extra": {"a": 1}});
        assert_eq!(uncovered("blobs", &row), vec!["extra.a".to_string()]);
        let wu = json!({"usage": {"prompt_tokens": 1}, "seed": [1]});
        assert!(uncovered("workunits", &wu).is_empty());
    }
}
