# Collector: capture, hashing and object store

**Status**: Draft

> Moved from [tokenspectra `docs/design/collector.md`](https://github.com/tokenspectra/tokenspectra/blob/fc185ea/docs/design/collector.md) so the spec sits next to its code. Section numbers are unchanged; earlier history is in that repo.

How the Phase 2 Rust Collector turns traffic on a Link into hashed, stored evidence: pcapng chunks, Flows, Slices and Request Workunits, all addressable by BLAKE3 hash. It runs live or on `.pcap`/`.pcapng` files. Terms are in [CONTEXT.md](https://github.com/tokenspectra/tokenspectra/blob/main/CONTEXT.md). Evidence is in [collector-capture-and-store.md](https://github.com/tokenspectra/tokenspectra/blob/main/docs/research/collector-capture-and-store.md). The Collector's place in the system is in [architecture.md](https://github.com/tokenspectra/tokenspectra/blob/main/docs/design/architecture.md) §3–4.

## Settled (TS-22, Ángel Manuel Martín, 2026-11-01)

1. **Hash function: BLAKE3.**
2. **Hash at three levels:** L0 pcapng chunks, each Flow's byte stream per Slice, and Request Workunit bodies.
3. **Hash 100% of payload**, even when the Capture Rate keeps less.
4. **The Collector writes blobs directly to the object store.** The control plane holds the index and serves reads by hash.
5. **Plain (unkeyed) BLAKE3 in v1.** Keyed names come with the Payload privacy work, before any real Site (§10).
6. **v1 taps plaintext.** TLS, if any, ends before the Tap.
7. **Live and offline:** live capture through dumpcap or similar, and the same Collector runs on `.pcap`/`.pcapng` files.
8. **pcapng chunks go into the object store.** Non-OpenAI traffic is detected, hashed and kept as well.

Everything below these eight points is proposal, not settled.

> _Contradicts [ADR-0001](https://github.com/tokenspectra/tokenspectra/blob/main/docs/adr/0001-plaintext-via-key-disclosure-first.md) and [poc.md](https://github.com/tokenspectra/tokenspectra/blob/main/docs/design/poc.md) (Approved)._ Both put key disclosure (Envoy `key_log`) first and plaintext tap points later. Point 6 swaps that order for v1. It matches the v1 API Tap, which serves plain HTTP with no TLS (TS-15). The keylog path stays possible later (§9). ADR-0001 and poc.md need an owner's note or a superseding ADR.

## 1. Scope

**In v1:**
- packet input: live and from files;
- Flow assembly (TCP; UDP as datagrams);
- protocol identification for every Flow;
- HTTP/1.1 and HTTP/2;
- a pluggable Wire Protocol layer (§5) with shared response framing (SSE, NDJSON) → Request Workunits:
  - OpenAI Chat Completions and legacy Completions (TS-29);
  - OpenAI Responses, Anthropic Messages and Ollama native, one module each (TS-30 to TS-32);
- hashing, the Capture Rate cut, the object-store layout;
- metadata and records sent to the control plane.

**Not in v1:**
- TLS decryption (§9);
- Intermediate Workunits;
- Signatures and Kinds;
- Wire Protocols that are not HTTP (gRPC payloads, Dynamo TCP);
- QUIC payload parsing;
- assigning statuses, which stays with the Classifier.

## 2. Layers

```
L0  network packets on a Link   → pcapng chunk per window     every Flow, any protocol
L1  Flow (TCP stream, per dir)  → Flow index + Slice hashes   every Flow, any protocol
L2  HTTP message                → header block, body bytes    Flows that parse as HTTP
L3  Wire Protocol               → Request Workunit record     HTTP that a registered protocol reads
```

- L0 and L1 don't depend on the protocol. Every byte on every Link reaches L1, so byte accounting and hashing cover 100% of traffic.
- **Each layer is an index into the one below.** A Request Workunit body is a byte range of a Flow stream, which is a set of packets in L0 chunks. Anyone holding the L0 chunks can rebuild and re-check every layer above. Plaintext makes this a pure rehash, with no key in the chain.
- **Only L0 bytes and L2 bodies are stored as blobs.** L1 is never stored a second time; it can always be rebuilt from L0.

## 3. Input: one parser, two sources

```rust
trait PacketSource {           // yields packets in capture order
    fn next(&mut self) -> Option<Result<CapturedPacket>>;
}
// CapturedPacket { link_id, ts_ns, orig_len, data /* captured bytes */ }
```

- **`FileSource`** reads `.pcap` and `.pcapng` with `pcap-file`, which is pure Rust (research §3). It takes one file or an ordered list.
- **`RingSource`** is the live mode. It runs as one process:
  - `dumpcap -i <if> -b interval:<W> -b printname:stdout -w <dir>/link.pcapng`.
  - It reads each file name dumpcap prints when the file closes, then hands that file to `FileSource`.
  - **Never use `-b files:N`**: dumpcap deletes the oldest files, and we lose packets if the Collector falls behind (research §1). The Collector deletes local files itself, after upload.
  - **Capture filter:** `ring -f/--filter <bpf>` passes a BPF capture filter to dumpcap (`-f`), e.g. `tcp port 11434` to keep only the inference port. It is for tests and local runs.
    - Packets the filter drops never reach the Collector, so they appear nowhere: not in any byte bucket, not as a gap. A filtered run accounts for a subset of the Link, never for the whole Link.
    - So the filter is logged when dumpcap starts (§14).
- **`LiveSource`** (later) reads libpcap directly through the `pcap` crate, for lower latency. Only if the file handoff turns out too slow.
- **Determinism:** the same input files always give the same output, byte for byte.
  - Every timestamp comes from the capture, never the wall clock.
  - This is what makes golden-file tests possible (§12), and lets a third party re-run the Collector over our archive.
- **Windows:** the Slice window length `W` comes from the control plane. `-b interval:W` cuts dumpcap files at wall-clock multiples of `W`, so file boundaries match Slice boundaries (research §1).
  - Offline input is re-cut into windows by packet timestamp.
- **Links:** one dumpcap per Link, or one pcapng with an Interface Description Block per Link. `link_id` comes from the interface.
  - The PoC has a single Software Tap Link (poc.md).

## 4. Flow assembly (L1)

- **Flow key:** (`link_id`, protocol, the two endpoints sorted, a generation counter). The counter starts a new Flow when a 4-tuple is reused after FIN/RST or a long idle gap.
- **TCP:** reassemble each direction into an ordered byte stream, and record:
  - **stream offset → (chunk, packet index, offset in packet)**, so any byte range maps back to L0;
  - **gaps:** bytes the Tap never saw (loss or truncation). Gaps are recorded, never guessed;
  - retransmits and overlaps. If retransmitted bytes differ, record it as an anomaly; it may be an attack on the reassembler.
- **A Flow outlives a chunk and may start mid-stream.** A keep-alive Flow appeared in every ring file, and none had its SYN (research §1).
  - The Collector carries Flow state across chunks.
  - It accepts a Flow first seen without a handshake and marks it `mid_stream_start`.
- **UDP:** a Flow is a 4-tuple with an idle timeout. Each datagram stays a separate unit, with no stream.
- **Other IP protocols:** one Flow per (protocol, endpoints), counted in bytes only.
- **Per-Flow, per-Slice metadata (100%):** bytes and packets per direction; first and last timestamps; gaps; handshake flags; the protocol verdict (§5); byte accounting (§5).

## 5. Protocol identification and non-OpenAI traffic

Ports and ALPN are hints at most. A Flow is a protocol only when its bytes parse as that protocol.

**Order of attempts** on the first bytes of each direction:

| Test | Verdict |
|---|---|
| `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` preface | `http2` |
| HTTP/1.x request or status line | `http1` |
| TLS handshake record header (`0x16 0x03` then a version byte) | `tls` (opaque in v1; suspicious on a plaintext Link) |
| refines `http2`: `content-type: application/grpc` | `grpc` (parsed as HTTP/2, payload opaque) |
| none of these | `opaque` |

**Within HTTP**, a message pair is a Request Workunit only if a registered Wire Protocol:
- claims the request: one of its routes matches the method and path, and its headers do not rule it out;
- reads the request body;
- accepts the response's media type, which also fixes the response framing.

Everything else is `http:other`, e.g. `/health`, `/metrics`, `/v1/models`, other paths, or unparseable JSON.

**Wire Protocols (TS-29).** Each protocol is one module behind the `WireProtocol` trait, listed once in a fixed registry. Adding one changes nothing outside its module but that registry line. A protocol declares:
- **routes:** an HTTP method and a path pattern, matched against the path without query or fragment (absolute-form targets are reduced to their path). `*` matches any run of characters other than `/`. The pattern is the record's `endpoint`;
- **header sniffing**, optional: for each matching route, `yes` (a header only this protocol sends, e.g. `anthropic-version`), `maybe` (no evidence), or `no` (ruled out). This serves gateways and self-hosted servers that expose several APIs on one port;
- **request reading:** whether a complete request body of at most `max_body` (after its content coding is removed) is its request, and the common request fields. Saying no is body sniffing: the next claim gets the body;
- **response framing:** from the request and the response media type, `json`, `sse` or `ndjson`, or none (not a Workunit);
- **a frame decoder:** frames in, common record fields and `extra` out. Protocols never see bytes.

**Precedence is deterministic.** The claims on a request are ordered by header evidence (`yes` before `maybe`), then route specificity (more literal characters first, so an exact path beats a pattern), then registry order. The request body goes to each claim in that order; the first that reads it owns the exchange. The OpenAI module is first in the registry.

**Per protocol.**
- **Ollama native (`ollama`, TS-32).** Routes `POST /api/chat`, `/api/generate`, `/api/embed`; no header sniffing (the paths are its own); the request is any JSON object. Chat and generate stream unless the request sets `"stream": false`: the response is `ndjson` (`application/x-ndjson`), the last line carrying `"done": true`; otherwise, and always for embed, it is one `json` object. `model` and `options.seed` come from the request; from the last object, `done_reason` → `finish_reason[0]`, `prompt_eval_count` → `input_tokens`, `eval_count` → `output_tokens`. Ollama sends no usage object, so `usage` is null. `extra`: `total_duration`, `load_duration`, `prompt_eval_duration`, `eval_duration` (ns, as sent), `done` (streams only: whether the `"done": true` line arrived, the NDJSON counterpart of `sse_done`) and `error`. Ollama's OpenAI-compatible `/v1/*` endpoints are claimed by OpenAI, not here; a captured fixture checks it.

**Response framing** is shared, so protocols handle events, not bytes. Bodies are framed after chunked encoding is removed, then after any content coding is decoded (below).

**Content codings (TS-37).** Python clients send `Accept-Encoding: gzip, deflate` by default, and proxies may compress JSON, so the Collector decodes `gzip` (and `x-gzip`, several members allowed), `deflate` (zlib as RFC 9110 says, or raw deflate as some servers send it, told apart by the first two bytes), `br` and `zstd`, on requests and responses, for every HTTP body.
- **For parsing only.** The body hash, the stored body and `body_len` stay on the wire bytes (§6, §8). The decoded bytes feed body sniffing, the framers and the protocols, and get a second hash, `decoded_hash` (§6).
- **As it streams.** A coded SSE or NDJSON response is decoded as it arrives, so frames keep the capture time of the bytes that carried them. `sse_events` offsets and lengths then count decoded bytes.
- **Bomb cap.** Decoding stops when a body passes either cap, absolute or as a ratio (`DecoderConfig::decode_limits`): **64 MiB decoded per body**, and **100 decoded bytes per wire byte** once past the first **1 MiB** decoded, so small bodies that compress well are never stopped. The body is still hashed, counted and kept; it is not read, so the Workunit is `errored`, and a WARN line names the cap.
- **When decoding stops,** the `http` row says why in `decode_error`: `unsupported` (another coding, e.g. `compress`, or more than one: `gzip, br`), `corrupt`, `truncated` (the body ended before the coded stream did), `incomplete` (the message never ended), `gap`, `over_cap`, `over_ratio`. Such a body has no `decoded_hash` and is not read.

| Framing | Frames | After a gap |
|---|---|---|
| `json` | The whole body, read once complete | Not read |
| `sse` | Events (WHATWG `text/event-stream`): lines end in CRLF, LF or CR, a blank line ends an event, only events with `data` are reported. Each frame carries its `event:` name when it has one, so one framer serves data-only streams (OpenAI Chat) and named-event streams (OpenAI Responses, Anthropic) | Framing stops: event boundaries are lost |
| `ndjson` | One JSON value per line, LF with an optional CR before it, blank lines skipped (Ollama native) | The cut line is lost; framing starts again at the next line, since a JSON line holds no raw newline |

- A frame splits across any number of TCP segments, HTTP/1 chunks or HTTP/2 DATA frames; a frame's capture time is that of its last byte.
- Lines longer than 16 MiB are dropped, not truncated. An SSE event that loses a field line this way is dropped whole (a comment line loses nothing). Either way the frame counts as lost, so the Workunit is `errored` (§14). An NDJSON body's last line may lack its newline.
- When response bytes arrive before the request body is read (a server that answers early), they are held, up to `max_body`, and replayed once a protocol owns the exchange.

**The common record** (`workunits`, §8) stays compatible with TS-15 and is the same for every protocol: `protocol` (the protocol's id), `endpoint`, `model`, `stream`, `status`, timing, body hashes and byte counts, `finish_reason` per choice index, `usage` as sent with `input_tokens` and `output_tokens` read from it when the protocol reports them, `complete`. `seed`, `n`, `response_id`, `response_model` are filled where the protocol has them. `sse_events` and `sse_done` are set for `sse` framing only; `sse_done` means the protocol's end-of-stream marker arrived (`data: [DONE]` for OpenAI, `message_stop` for Anthropic). Protocol-specific fields go in `extra`, one JSON object built from the protocol's own typed struct, `null` when empty, never new top-level columns.

**OpenAI Responses** (`openai_responses`, TS-30). Route `POST /v1/responses` with a JSON body; the response is `application/json`, or `sse` when the request set `stream: true`. Retrieval (`GET /v1/responses/{id}`) and cancel are `http_other`. A stream is named events whose `data` is a JSON object with a matching `type`. The decoder only reads the events that carry a `response` object (`response.created`, `response.in_progress` and the terminal ones), plus `error`; the last one wins. Ollama (0.40) serves the same route and events.
- `model`, `stream` from the request; it has no `seed` or `n`. `response_id`, `response_model` and `usage` come from the response object; `input_tokens` and `output_tokens` are read from `usage`.
- `finish_reason[0]`: the API has no per-choice finish reason, so this is why the response ended. For an `incomplete` response it is `incomplete_details.reason` (e.g. `max_output_tokens`); otherwise it is the final status (`completed`, `failed`, `cancelled`). A `queued` or `in_progress` response has none.
- `sse_done`: `response.completed`, `response.incomplete`, `response.failed` or `error` arrived.
- Outcome (§14): a stream is `ok` only when it ends in `response.completed` or `response.incomplete`. `incomplete` (e.g. `max_output_tokens`, recorded as the finish reason) is a whole, readable response, like a Chat Completions `finish_reason: length`. A stream with no terminal event, and a failure in band behind HTTP 200 (`response.failed`, an `error` event, or a response object with status `failed`), is `errored`. A gap makes it `incomplete` first.
- `extra`: `status` (the last status), `error_code` (`error.code` of a failed response, an `error` event or an error body, else its `type`), `previous_response_id`, `service_tier`.
- An error body (`{"error": {...}}`, e.g. a 404 for an unknown model) is read: an `ok` Workunit with a `4xx` status and no finish reason.

**Anthropic Messages** (`anthropic`, TS-31; [API reference](https://docs.anthropic.com/en/api/messages)). Route `POST /v1/messages`, claimed only with an `anthropic-version` header (`yes`; without it, `no`, so the exchange is `http_other`). Every SDK and Anthropic's own examples send the header, and it tells Anthropic traffic apart on a gateway that also serves OpenAI paths. `/v1/messages/count_tokens` and `/v1/messages/batches` are not Workunits. The request body must be a JSON object; the response is `application/json`, or `sse` when the request set `stream: true`. A JSON body is a `message`, or an `error` object on a non-2xx status. A stream is named events, each `data` repeating its name as `type`: `message_start` (id, model, input usage), `content_block_start`, `content_block_delta`, `content_block_stop`, `message_delta` (`stop_reason`, cumulative usage), `message_stop`, `ping`, and `error`, which can arrive behind HTTP 200 and ends the stream. Unknown event types are skipped, since the API adds new ones.
- `model`, `stream` from the request; it has no `seed` or `n`. `response_id`, `response_model` from the message.
- `finish_reason[0]`: `stop_reason` (`end_turn`, `max_tokens`, `stop_sequence`, `tool_use`, ...).
- `usage`: `message_start`'s usage with each `message_delta`'s fields laid over it, since the delta counts are cumulative (a `null` does not erase a count). `input_tokens`, `output_tokens` are read from it; as the API reports them, `input_tokens` leaves out cached prompt tokens.
- `sse_done`: `message_stop` arrived.
- Outcome (§14): `done` is set only by `message_stop`, so only a stream that reaches it is `ok`, whatever its `stop_reason` (`max_tokens` is a whole response, recorded as the finish reason). A stream that ends cleanly without `message_stop`, and one with an in-band `error` event behind HTTP 200, are counted as not read, so they are `errored`; a gap makes the Workunit `incomplete` first. An error body on a non-2xx status is read: an `ok` Workunit with that status and `error_type` set. A whole JSON body of any other `type` (the API names every stream event, so an unnamed frame is a body) is not read, so it is `errored`.
- `extra`: `cache_creation_input_tokens`, `cache_read_input_tokens`, `stop_sequence`, and `error_type` (`error.type` of an error body or event, e.g. `overloaded_error`).

**Byte accounting.** For each Flow, direction and Slice, every stream byte falls in exactly one bucket:

| Bucket | Meaning |
|---|---|
| `workunit` | Inside a Request Workunit's HTTP message (headers and body) |
| `http_other` | Inside a parsed HTTP message that is not a Workunit |
| `framing` | Protocol overhead around messages: HTTP/2 frame headers, SETTINGS, PING, chunked-encoding lines |
| `unexplained` | Everything else, plus every byte of `tls`/`opaque`/`grpc` Flows |
| `gap` | Bytes counted by sequence numbers but never captured |

- The Collector reports buckets and verdicts. **It never assigns a status.**
- The Classifier applies the rules from [architecture.md](https://github.com/tokenspectra/tokenspectra/blob/main/docs/design/architecture.md) §5:
  - `http_other` needs an Allowlist rule;
  - on a Flow covered by a Placement, `unexplained` bytes mean no Provenance, so Refuted ([ADR-0002](https://github.com/tokenspectra/tokenspectra/blob/main/docs/adr/0002-reproduce-every-byte-no-byte-accounting.md));
  - elsewhere, they leave the Slice Characterized or Unknown.
- **Flows with no Workunit are hashed and stored like every other Flow.** L0 and L1 don't care about the protocol. The only difference is retention (§7): these Flows are the alarm, so they're kept in full.

## 6. Hashing

BLAKE3 everywhere, at 3.4 GiB/s per core and 10 GiB/s on 4 threads on a modest VM (research §3). Hashing 100% of a 1–10 Gbps Link costs about one core [Inf].

| What | Hash | Why |
|---|---|---|
| **L0 chunk** | `blake3(uncompressed pcapng bytes)` | Names the stored chunk. Hashing before compression means a different zstd level never changes the name |
| **L0 packet** | `blake3(captured bytes)` per packet, combined into a Merkle root per chunk, stored in the chunk index | Proves a single packet is in a chunk without fetching the chunk |
| **L1 Slice** | `slice_hash[n] = blake3(slice_hash[n-1] ‖ flow_id ‖ dir ‖ stream bytes of Slice n)`, with `slice_hash[-1]` = the Flow's first-seen record | One commitment per window. The chain commits to the whole Flow so far, so long keep-alive or HTTP/2 Flows don't wait for FIN. **Gap bytes are left out and listed separately** |
| **L2 body** | `blake3(body bytes as on the wire)`, after removing chunked encoding but before any `Content-Encoding` is decoded | Names the stored body. Never hash re-serialised JSON: it has no canonical form, and these bytes are adversarial |
| **L2 decoded body** | `blake3(body bytes once the content coding is decoded)`, only for a coded body decoded to its end within the cap (§5): `decoded_hash` on the `http` row, `request_decoded_hash` and `response_decoded_hash` on the Workunit | Compares bytes that do not depend on the coding (e.g. with a Tap that records the decoded request). A commitment, not a name: no blob is stored under it |
| **L2 SSE** | One hash over the whole response body (all events), not one per event | One blob per response. Event offsets and timestamps go in the record |
| **L3 record** | `blake3(record bytes)` | Integrity of the record. Not its identity |

- **Hash 100%.** Every byte is hashed at L0 and L1, and every L2 body, even when the Capture Rate drops the payload (§7).
  - A hash of a dropped payload is a commitment: if a dispute comes up, the Operator can be asked to produce the bytes, which must match.
  - Hashing everything reveals nothing about which Workunits the sampling kept.
- **`workunit_id` stays a unique id, not a content hash.** Two identical seeded requests produce identical bytes, and they must still count as two Workunits.
  - Proposal: `workunit_id = blake3(flow_id ‖ dir ‖ request start offset)`, written as a multihash like every other hash. It is unique, deterministic from the capture, and stable across re-runs.
  - TS-15's API Tap uses a UUID. The two meet through the request body hash (§11).
- **Multihash (proposal).** Every stored hash is a [multihash](https://github.com/multiformats/multihash): `<code><length><digest>`, code and length as unsigned varints. BLAKE3 is code `0x1e` ([multicodec table](https://github.com/multiformats/multicodec/blob/master/table.csv)) with its default 32-byte output, so a BLAKE3 hash is the 34 bytes `1e 20 <digest>`. This replaces the earlier `b3:<hex>` tags.
  - **Text form,** in index columns, object keys and file names: multibase base16 lowercase, `f` followed by the hex of the multihash, so `f1e20` + 64 hex digits. The last 64 digits are what `b3sum` prints. Lowercase hex is safe in paths and S3 keys.
  - **A second algorithm needs no migration.** SHA-256 (for FIPS, or with hardware SHA on Arm) is code `0x12`, so its names start `f1220`. See research §8 for which CPUs speed up which hashes. They don't change the BLAKE3 choice.
  - **Crate:** [`multihash`](https://crates.io/crates/multihash) 0.19 from multiformats, core only: `Multihash::<32>::wrap(0x1e, digest)` to build, `from_bytes` to parse with length checks. Its one dependency is `unsigned-varint`. Hashing stays in the `blake3` crate.
    - Not `multihash-codetable`: it adds hasher plumbing (`multihash-derive`, `digest`) we don't need, and builds `blake3` with default features off.
    - Not `multibase`: the text form is `f` + hex, a few lines. Add it if a second base is ever needed.
  - **Parsing is strict.** For now a name is accepted only as `f1e20` + 64 lowercase hex digits; anything else is rejected, not guessed at.
- **Encodings (TS-26).** The rules above, made exact:
  - **L0 packet:** `blake3(captured bytes)`, the `hash` column of `packets`. The Merkle root over a chunk's packets, in packet order, uses leaves `blake3(0x00 ‖ packet hash)` and nodes `blake3(0x01 ‖ left ‖ right)`, so a leaf never passes for a node; an odd node at the end of a level moves up unchanged.
  - **L1 Slice:** `slice_hash[n] = blake3(slice_hash[n-1] ‖ flow_id ‖ 0x00 ‖ dir ‖ bytes)`, with `dir` one byte (`0` orig, `1` resp), the same layout as `workunit_id`. `slice_hash[-1] = blake3(flow_id ‖ 0x00 ‖ first_ts_ns as u64 big-endian)`. Every Slice row has one per direction (`orig_stats.slice_hash`, `resp_stats.slice_hash`), even when that direction sent nothing. UDP and other IP protocols have no stream: each datagram's captured payload goes in with a u32 big-endian length prefix, so datagram boundaries are committed too.
  - **L3 record:** the record bytes are the `workunits` row's JSON, as written in the table.
- **Bao (later).** Verified range reads against a body or chunk hash. Bao is beta and unaudited (research §6), so v1 verifies whole objects only.

## 7. Capture Rate and retention at the packet level

The Collector holds one window in memory (or on local disk), hashes all of it, then writes the L0 chunk:

| Traffic | What the stored chunk keeps |
|---|---|
| Packets carrying bytes of a **kept** Request Workunit (chosen at the Capture Rate) | Full packets |
| Packets of **`unexplained`, `tls`, `opaque`, `grpc`** Flows (the alarm) | Full packets, up to a per-Flow-per-Slice byte cap, then truncated |
| Handshakes, control frames, `http_other` | Full packets (small) |
| Everything else (Workunits not kept) | Truncated to headers (e.g. 128 B captured) |

- **Truncation keeps the original length.** pcapng records captured and original length per packet (research §2). Metadata and byte accounting stay at 100% while payload follows the Capture Rate.
- **Unpredictable sampling.** The Capture Rate draw needs randomness the Operator can't predict (CONTEXT.md). The Collector uses a per-window secret from the control plane, never derived from the traffic.
  - This is separate from the Sampler's Recompute Rate secret, which never reaches the edge (architecture.md §3).
- **Deletion is the control plane's job**, under the Retention Policy. The Collector only writes.

**As built (TS-26).**
- **Which packets.** A packet is kept in full unless:
  - it carries `unexplained` bytes, or is a UDP or other IP datagram with payload (the alarm): then full until the Flow's alarm packets in this Slice pass `--alarm-cap` captured bytes (default 16 MiB), truncated after;
  - it carries bytes of a Request Workunit the Capture Rate did not keep, and otherwise only `framing` or `gap` bytes: then truncated to `--truncate-to` bytes (default 128).
  - A packet with any `http_other` or kept Workunit byte stays whole, and so does one an anomaly event points at (e.g. `retransmit_differs`), since it is evidence.
- **The draw.** `--capture-rate` (default 1: keep every Workunit). A Workunit is kept when the first 8 bytes of `keyed_hash(window secret, workunit_id)`, read as a big-endian integer, fall below `rate · 2^64`. The window is the one the request started in.
  - Until the control plane hands out secrets, each window's secret is `keyed_hash(run key, window_start_ns as u64 big-endian)`, with the run key from `--capture-key`. A rate below 1 without a key is refused, never filled in from the traffic or the clock.
- **When a chunk is written.** A packet's class needs its bytes' buckets, which can wait a window for a response head (§5). So a window is held until it has closed and every TCP packet in it has its buckets, or until two more windows have closed; packets still unknown then are kept in full.
- **Bodies are not cut.** Bodies stay in packs at any Capture Rate (§13).

## 8. Object-store layout

The seam is the `object_store` crate's `ObjectStore` trait (research §3):
- `LocalFileSystem` for the PoC. Retention beyond a local buffer is out of PoC scope (poc.md).
- `AmazonS3` for any S3-compatible service later. Community MinIO is now source-only and unmaintained (research §4), so the self-hosted store is an open choice.

**Keys.** Everything is written once with `PutMode::Create`: `If-None-Match: *` on S3; on local FS a repeat put fails with `AlreadyExists` (research §3–4).

```
raw/{site}/{collector}/{link}/{yyyy}/{mm}/{dd}/{window_start}-{chunk_multihash}.pcapng.zst
packs/{site}/{collector}/{yyyy}/{mm}/{dd}/{window_start}.pack          # L2 bodies + L3 records
index/{site}/{collector}/{yyyy}/{mm}/{dd}/{window_start}/{table}.parquet
```

- **As built (TS-26):** `{window_start}` is the window start in nanoseconds since the Unix epoch, the `window_start_ns` column; `{yyyy}/{mm}/{dd}` is its UTC date; `{site}` and `{collector}` come from `--site` and `--collector-id` (default `local`); `{link}` is the Link with every character outside `[A-Za-z0-9._-]` replaced by `_`. The CLI writes to `--store`: a directory (`LocalFileSystem`, default `<out>/store`), or `s3://bucket[/prefix]` (TS-38), Amazon S3 or an S3-compatible store, with credentials and region from the `AWS_*` environment variables.
  - **The endpoint is required.** It comes from `--s3-endpoint`, else `AWS_ENDPOINT`; with neither, the Collector refuses to start, before capture begins or anything is written. There is no fallback to AWS's default endpoint (Amazon S3 itself is named explicitly, e.g. `https://s3.eu-west-1.amazonaws.com`), so evidence cannot leave for a store nobody named. The endpoint is pinned (the SDK's `AWS_ENDPOINT_URL_S3` cannot move it) and named in the startup log.
  - Every put is write-once: `PutMode::Create`, `If-None-Match: *` on S3. A store that ignores the header could overwrite objects; CI checks the S3 path against VersityGW.
  - A put that finds the object already there reads it back: the same bytes (a re-run over the same capture) are left alone, other bytes fail the run. Nothing is overwritten.
- **The spool (TS-38).** The Operator runs the object store, so it is outside the protected boundary and may be down. With an `s3://` store, every object is first written to a local spool (`--spool`, default `<out>/spool`), which stays inside the boundary, exactly as to the local store: synced on each put, the window's manifest committed after its objects are there. An uploader thread copies spooled objects out in the order they were written and removes each once the store holds it.
  - **Write-once upload.** Each upload is a `PutMode::Create` put. The same bytes already in the store count as uploaded; other bytes stop the uploader and fail the run, as a conflicting put does without a spool. Any other error is retried after a pause that doubles from 250 ms up to 30 s, for as long as it takes.
  - **An outage delays evidence instead of ending the run.** The run goes on writing the spool; manifests are committed and shipped, naming objects the store does not hold yet.
  - **Backpressure.** The spool holds at most `--spool-max-mib` (default 4096). A put reserves its bytes before it writes, waiting until uploads make room, so sealing windows stops and the run is held back instead of filling the disk. A failed put frees its reservation; an object is queued for upload only once it is synced. An object bigger than the whole spool goes in once the spool is empty. An uploaded object's bytes count until its file is removed; a removal that fails is retried and keeps its room.
  - **One owner.** A spool is locked (`.lock` in it) while a run or `collector upload` has it open; a second process fails to open it.
  - **Stopping while the spool is full.** The stop signal that ends `ring` also ends the wait for room: the next put that does not fit fails, the run reports `stopped with the spool full`, and the uploader still gets `--upload-wait-s`. Windows sealed before then are in the spool; the rest are only in dumpcap's ring files, which are kept, so running `collector files` over them once the store is back recreates the same objects (puts are deterministic and write-once).
  - **Open (owner's call, TS-38 review):** while the store is down and the spool is full, `ring` keeps capturing into its ring files, which are not capped. Bounding them means stopping capture or dropping input.
  - **End of a run.** The uploader has `--upload-wait-s` (default 30) to empty the spool. What is left stays on disk; the next run uploads it first, or `collector upload` does.
  - Objects are uploaded as spooled. TS-47 adds encryption to the auditor in the uploader, between the spool and the store.
- **L0 chunks:** one object per Link per window, zstd-compressed. If a chunk passes a size cap (1 GiB stored), split it into `-partN` objects.
  - As built (TS-38): the compressed chunk is cut into 1 GiB pieces, `{key}-part0`, `{key}-part1`, …, each a single write-once put; joined in order they are the compressed chunk. The `chunks` row keeps the whole chunk's `key`, `chunk_hash` and `stored_len`, and `parts` says how many objects hold it (1: the object at `key`).
  - Why not `put_multipart`: `object_store` (0.14) completes a multipart upload without `If-None-Match`, so it could overwrite an object. S3 single puts take up to 5 GiB.
  - The name includes the chunk hash, so a chunk can be checked from its name alone.
- **Packs:** L2 bodies and L3 records are KB-sized, and object stores charge per request. One pack per window holds many items:
  - each item is a separate zstd frame;
  - a pack index maps `blake3 → (pack key, offset, length)`;
  - any item is one Range GET plus a single-frame decode (research §5);
  - the pack follows the zstd seekable format, so standard tools can still read it.
  - Identical bodies within a window are stored once.
- **Which bodies (proposal, TS-25):** every HTTP body that has a `body_hash` is kept, request and response, Workunit or `http_other`.
  - Kept by default. An option (`--no-bodies`) turns body storage off. Hashes, lengths and every index table stay the same; only the blobs are missing.
  - Bytes as hashed (§6): chunked encoding removed, content coding kept, one blob per SSE response. A body with a gap has no `body_hash` and is not kept; its packets are still in L0.
  - Packs hold them, beside every Request Workunit record (TS-26). The Collector also writes one file per body, `bodies/{multihash}`, next to its output tables, as the local view. `b3sum` of the file prints the last 64 digits of its name.
  - Why: without them, reading a request or response means reassembling its Flow from L0 chunks. With them, every body hash in the index can be read directly (`GET /blobs/{blake3}`, §11).
  - Bodies hold plaintext prompts and outputs (§10). The option is for runs that should keep hashes only.
- **Two views of the same bodies (proposal).** Keep both:
  - `bodies/` is the store: named by hash, checked by name, each body stored once, bytes exactly as hashed.
  - `by-exchange/` is for people: named by Flow and exchange, derived from the `http` table and `bodies/`, safe to delete.
  - A live run adds each window's exchanges as the window closes, right after the tables are flushed (§11), so the view keeps up with the run. The end of a run (or `collector views`) rebuilds it from scratch; a new run into the same directory removes the old one first.

  ```
  bodies/{multihash}                                       # the store
  by-exchange/{flow}/{exchange}.request.{ext}  -> ../../bodies/{multihash}
  by-exchange/{flow}/{exchange}.response.{ext} -> ../../bodies/{multihash}
  by-exchange/{flow}/{exchange}.response.merged.json       # SSE Workunits only
  ```

  - The links point at the store and never copy it. `--no-bodies` writes neither tree.
  - **Nothing from the Operator goes into a name unchecked.** `{flow}` is the Flow id with every character outside `[A-Za-z0-9._-]` replaced by `_`. `{exchange}` is the exchange number. `{ext}` comes from a fixed list chosen by the parsed media type: `json` for `application/json`, `sse` for `text/event-stream`, otherwise `bin`.
  - The tree is local output only. The object store keeps packs and the index (§8); the Store serves the same views on read (§11).
- **Merged view of OpenAI streaming (proposal).** Written for OpenAI SSE Workunits only, chosen by route, since the `http` row carries no protocol. An SSE response is a series of `chat.completion.chunk` events, one token delta each. `{exchange}.response.merged.json` joins them into one `chat.completion` object, shaped like a non-streaming response:
  - per choice `index`: `role`, `content` and `reasoning` joined in event order, the last `finish_reason`; plus `id`, `created`, `model` from the first event and the last `usage`;
  - `"incomplete": true` when `[DONE]` never arrived or an event did not parse, with the count of unparsed events, so a cut-off capture is still readable but never looks whole.
- **The merged view sits beside the raw SSE body, never in its place.** It is derived, like the links:
  - **Not evidence.** It is never hashed as a body, never stored in packs, never compared with the API Tap. §6 forbids hashing re-serialised JSON.
  - **Lossy.** Event boundaries, per-event capture times (in `sse_events`), and any field the merge doesn't know are dropped. The raw body stays the source; the merged file is rebuilt from it.
  - **Deterministic.** Same body, same file, so two runs stay byte-identical (§12).
  - **Decoded first.** A coded body is stored as on the wire; the merge decodes it (§5) before reading its events, and one that does not decode merges as incomplete.
  - Only the raw body is checked by name. A reader who doubts the merged file rebuilds it from `bodies/`.
- **Index tables (Parquet), one set per window:**
  - `flows`: per-Flow, per-Slice metadata, verdict, buckets, Slice hash;
  - `packets`: chunk, packet index, timestamp, Flow, direction, stream offset, captured and original length, packet hash;
  - `workunits`: L3 records;
  - `blobs`: hash → pack location.
  - As built (TS-26), also `segments`, `events` and `http`, the same tables as the local JSONL, and `chunks`: one row per L0 chunk with its key, chunk hash, Merkle root, packet count and the Capture Rate's kept and truncated bytes, and (TS-38) the number of `parts` it is stored in.
  - Each table has a fixed schema, so a column keeps its type in every window. Nested records are flattened (`orig_stats.packets` → `orig_stats_packets`). Values the Operator sends as arbitrary JSON (`usage`, `seed`, `n`), and lists, are JSON text. Every column is optional.
  - A row goes in the window it belongs to (a packet's, a Slice's) while that window is held; otherwise, and for `http`, `workunits` and pack items, in the newest window held when it is written.
- **Local view.** `bodies/` and `by-exchange/` stay beside the tables as the local view; packs are the store.
- **Tamper evidence (optional):** S3 Object Lock in compliance mode makes objects WORM, even for the account root. It needs versioning (research §4).
- **S3 checksums are not our hashes.** S3 has no BLAKE3 (research §4). Our hashes live in the index and the key names. S3's own checksum (e.g. CRC64NVME) only protects the upload.
- **Dedup across turns (later).** In multi-turn chat, each request resends the whole conversation. FastCDC chunking of request bodies (research §3) could store the shared history once. Not in v1.

## 9. TLS, later

- When TLS returns (ADR-0001), dumpcap still captures ciphertext into the same L0 chunks.
- The Collector decrypts with a disclosed key log and runs the same L1–L3 on the plaintext.
- L1 hashing is then done twice: over the ciphertext stream (the Observation) and over the plaintext stream (what the Workunits index into).
- Stored chunks can carry the key log in a pcapng Decryption Secrets Block, so a human can open them decrypted in Wireshark (research §2). Keys are as sensitive as payload and follow the same retention.

## 10. Privacy and keyed hashes

- **Why it matters:** a plain hash used as a name lets anyone who sees the names test a guess.
  - Example: hash "Summarize Acme's Q3 losses" and look for that hash in a bucket listing or index. A match confirms the text was sent, without opening any object.
  - Long, unique prompts are safe in practice; short or templated ones are guessable. [dynamo-mooncake-xllm-wire.md](https://github.com/tokenspectra/tokenspectra/blob/main/docs/research/dynamo-mooncake-xllm-wire.md) flags the same risk for Dynamo's `tokens_hash`.
- **Keyed BLAKE3** (`keyed_hash`, 256-bit key; research §3) fixes this. Only holders of the auditor's key can compute names. An outside verifier needs the key for that audit.
- **v1 (settled):** plain BLAKE3, a private bucket, encryption at rest.
- **Before a real Site (proposal):** keyed hashes for L2 body names and the `blobs` index, alongside the "Payload privacy" roadmap item. L0 chunk names can stay plain: they hash a whole window of packets, which nobody can guess.
- **Stored chunks contain plaintext.** v1 taps plaintext, so L0 chunks and packs hold prompts and outputs. Both need encryption at rest and access control.

## 11. Outputs and retrieval

**To the control plane**, per window:
- the index tables (§8), or their object keys;
- a small window manifest: Collector id, Link ids, window, chunk hashes, pack keys, totals.

**Locally**, the JSONL tables are flushed as each window closes. A live run's files are readable up to the last closed window, and a run that is killed keeps every row written before its last window closed.

Transport follows TS-15:
- an append-only local log as the source of truth;
- a shipper POSTs to the control plane's ingest, deduplicated by window and Collector;
- offline runs use the same ingest path.

**As built (TS-27):**
- **Manifest:** one JSON object per sealed window, written once its chunks, pack and index tables are in the store: `site`, `collector`, `window_start_ns`, `window_ns`, `links`, `chunks` (the window's `chunks` rows: key, chunk hash, Merkle root, counts), `pack` (key, or null), `index` (per table: key and row count), and `totals` (packets, wire bytes, kept and truncated bytes, Flow rows, exchanges, Request Workunits, events, blobs). Object keys, not rows: the control plane reads the tables from the store. Every field comes from the capture, so the manifest is deterministic (§3); capture drops are left out, since live and offline report them differently.
- **Log:** `<out>/manifests.jsonl`, one manifest per line, each synced to disk before the run goes on. A manifest is appended only once every object it names is synced (the local store runs with fsync), and a new log's directory entry is synced before its first line. Only ever appended to, across runs too; a partial last line from a crash is cut off by the next run before it appends.
- **Shipper:** with `--ingest http://host:port/path`, a thread POSTs each complete line past its cursor, one request per window, body as logged, with `Idempotency-Key: {collector}/{window_start_ns}`. The cursor (`<out>/manifests.shipped`, a byte offset) moves only past lines the ingest accepted, so each line is sent at least once.
  - Any 2xx is accepted: a first copy, or a repeat of the same bytes. 408, 429, 5xx and connection errors are retried with backoff. At the end of a run the shipper has `--ship-wait-s` in all: the deadline is checked before each POST and at least every 50 ms during it (address lookup, connect, upload, response), so the run ends within the budget plus that slice even when the ingest stops reading mid-upload; lines not shipped by then stay pending. They are not counted then: the shipper stops without reading the rest of the log, however long it is, and the run's last log line leaves the count out; `collector ship` counts and sends them later. A lookup or connect cut short is left to finish on a detached thread: the connect within the request timeout, the lookup when the resolver gives up. Any other status stops the shipper: a 409 means the ingest holds that window with other bytes, the same rule as a store put (§8).
  - Lines left over stay in the log; `collector ship` sends them later.
  - v1 speaks plain `http://`, like the Tap (Settled 6).

**Cross-check with the API Tap.**
- The API Tap (TS-15) records "the client request as received". The Collector sees the same request on the Link.
- The two must have equal request-body hashes. A mismatch is an Observation contradiction for the Classifier.
- The forwarded request differs by design, because the gateway injects fields, so it is not compared.

**Retrieval by hash** is served by the control plane's Store, not by Collectors, which multiply per Link and may be gone:
- `GET /blobs/{blake3}` returns the body: the index lookup, one Range GET, one frame decode.
  - Proposal: `?view=merged` returns the merged view of an SSE body (§8), computed on read from the verified body and never stored.
- `GET /workunits/{workunit_id}` returns the record with its blob hashes.
- `GET /chunks/{blake3}` returns an L0 chunk (decompressed, or as stored).
- `GET /flows/{flow_id}/slices/{n}` returns the packets for one Slice: from the `packets` table, Range GETs into the chunk, then a new pcapng written on the fly.

**Every read is verified:** the Store recomputes BLAKE3 and rejects a mismatch. The bucket is never trusted.

Consumers: the Sampler and Recompute Worker (by `workunit_id`), human review in Wireshark (Slice pcapng), and later the Flow/Slice drill-down in the Console.

## 12. Acceptance (proposal)

_As built (TS-27): 1, 2, 4 and 6 run in CI over the whole golden set, all four Wire Protocols included; 2 compares whole output directories, object store and manifest log included. 3 runs end to end with `tools/live_e2e.sh`, which needs capture rights, over a mixed workload from the capture harness. 5 needs a real Tap._

1. **Golden files:** a set of `.pcapng` files with expected index tables and hashes, run in CI. It covers:
   - HTTP/1.1 JSON, HTTP/1.1 SSE with chunked encoding, h2c JSON and SSE;
   - a Flow spanning windows, a mid-stream start, a lost segment, a retransmit with different bytes;
   - `/health`, a TLS Flow on the plaintext Link, a non-HTTP TCP Flow, UDP;
   - content codings (TS-37): gzip JSON, gzip SSE flushed per event, and one Flow with `deflate` (zlib and raw), `br`, `zstd`, a gzip request body, an unknown coding, a gzip bomb and a cut-off gzip stream.
2. **Determinism:** two runs over the same files give byte-identical tables.
3. **Live equals offline:** a live `RingSource` run and a `FileSource` run over the same dumpcap files give the same output.
4. **Round trip:** every stored body and chunk can be fetched by hash, and verifies.
   - Locally: every `body_hash` has a file in `bodies/` named by it, whose `b3sum` matches the name, and every `by-exchange/` link resolves to it.
5. **ROADMAP A2:** metadata for 100% of External Flows, and a Request Workunit for every request of a registered Wire Protocol, on a real Tap.
6. **Wire Protocols:** a protocol registered only in a test decodes its Workunits with no change outside its module but one registry line. The framing has unit tests for SSE (both styles) and NDJSON, with frames split across TCP segments and gaps mid-stream.

## 13. Open questions

- **Window length `W`** and the in-memory budget for holding one window at line rate.
- **Self-hosted S3-compatible store**, now that community MinIO has no binaries.
- **Truncated-packet length** and the per-Flow cap for alarm Flows. TS-26 defaults to 128 B and 16 MiB per Flow per Slice, both flags.
- **The `workunit_id` scheme**, and whether TS-15's UUID moves to it.
- **dumpcap throughput and drops** at Link speed. Only loopback has been tested so far.
- **Keyed-hash key management** (rotation, disclosure for audits), for the Payload privacy work.
- **Frame offsets for NDJSON.** `sse_events` records each SSE event's offset, length and capture time. NDJSON lines get the same from the framer but are not written yet; whether they go in `sse_events`, a renamed column, or `extra` is for TS-32 to settle.
- **Merged views for other protocols.** The merge (§8) knows OpenAI chunks only. Each protocol could supply its own, which needs the protocol on the `http` row or a join with `workunits`.
- **`extra` across protocols.** One JSON column keeps the schema fixed (§8 Parquet). If a field turns out common to several protocols, it should become a column rather than stay in `extra`.
- **Keyed BLAKE3 in multihash.** The multicodec table has no code for keyed BLAKE3. Written under `0x1e`, a keyed hash would look like a plain one. The Payload privacy work (§10) needs its own code, from the private-use range or registered.
- **Who writes `by-exchange/`.** The Collector writes it now, as each window closes (TS-28). It could move to a separate tool over the Collector's output: the merge is more parsing of Operator bytes, and the Collector is the component that must stay small.
- **Bodies and the Capture Rate.** Bodies are kept by default (§8). Whether the Capture Rate also drops bodies of Workunits it doesn't keep, as it truncates their packets in L0 (§7), is open. So is a size cap per body, and the window a body belongs to when its message spans two.

## 14. Observability

Console logs and counters for the people running a Collector (TS-28). **They are diagnostics only:** never part of the deterministic outputs (§3), and the only place wall-clock time appears. Turning logging or metrics up or down changes no output file.

**Logs** use `tracing` and go to stdout, as text (default) or JSON lines (`--log-format json`).

- Level: INFO by default; `-v` DEBUG, `-vv` TRACE; `-q` WARN, `-qq` ERROR. `--log-level <error|warn|info|debug|trace>` overrides the short flags, and `RUST_LOG`, when set, overrides both.
- **ERROR:** dumpcap missing, not permitted or failing; write failures in the output; anything that ends the run.
- **WARN:** capture drops reported by dumpcap or pcapng; a Flow that hits the reassembly buffer cap (`gap_buffer_limit`); a body over the size cap (`DecoderConfig::max_body`), hashed and counted but not read; a coded body that passes the decode cap (§5), hashed and counted but not read.
- **INFO:** one line when dumpcap starts, with the interface and the capture filter (`none` if unset), so a filtered run is visible (§3); one line per closed window and one summary on exit. The window line has packets, bytes, Flows (new, active, closed), Request Workunits (`ok`, `errored`, `incomplete`), the share of accounted bytes in the `workunit` bucket, the share of closed Flows that carried a Workunit, gaps, and packets/s and Mbit/s over the window length.
- **DEBUG:** one line per Request Workunit as it is emitted: `workunit_id`, Flow, Wire Protocol, request direction, method, path, model, HTTP status, `stream`, request and response body bytes, outcome. Also each new and closed Flow (with its verdict), gaps and anomalies.
- **TRACE:** each reassembled segment.

**Counters: one registry, three views.** One in-process registry, updated by the pipeline. The registry sits beside the sink: it sees every record on its way out and forwards it unchanged. It is read by:

- the INFO line per window, above;
- **an on-demand snapshot:** `s` or Enter when stdin is a terminal (read key by key, echo off), or `SIGUSR1` at any time, prints a table of cumulative totals and last-window rates to stdout (as one JSON line under `--log-format json`);
- **`/metrics`:** Prometheus text format, served when `--metrics-addr` is given (off by default; e.g. `127.0.0.1:9464`). Raw counters and gauges only; ratios are computed in the snapshot and in PromQL.

Metrics, all prefixed `ts_collector_` (labels in brackets):

| Metric | Meaning |
|---|---|
| `packets_total`, `bytes_total` `[verdict]` | Packets and wire bytes. `verdict`: `http1`, `http2`, `tls`, `grpc`, `opaque` for TCP Flows; `udp`; `other` for other IP protocols, packets with no Flow, and Flows with no payload yet |
| `flows_total` `[verdict]` | Closed Flows, by final verdict |
| `flows_active` | Flows seen and not yet closed (gauge) |
| `flows_with_workunit_total` | Closed Flows that carried at least one Request Workunit; over `flows_total`, the share of Flows that carry Workunits |
| `accounted_bytes_total` `[bucket, direction]` | Stream bytes per bucket (§5) and direction (`orig`, `resp`); `workunit` over the sum is the share of bandwidth that is Workunits |
| `workunits_total` `[protocol, outcome, http_class]` | Request Workunits. `protocol`: the Wire Protocol's id (`openai`, `openai_responses`, `ollama`, `anthropic`); every built-in protocol is listed, at zero until seen. `outcome`: `ok` (both messages complete, no gap, response read), `incomplete` (a gap, or the Flow ended mid-message), `errored` (complete, but the protocol could not read the response: a body or frame that isn't its JSON, a content coding that could not be decoded (§5), a dropped line, or over the size cap). `http_class`: `2xx`, `4xx`, `5xx`, `none` |
| `gaps_total`, `gap_bytes_total` | Gaps (§4) and their bytes |
| `retransmit_bytes_total`, `retransmit_differing_bytes_total` | Retransmitted stream bytes, and those that differ from the first copy |
| `retransmits_differing_total` | `retransmit_differs` anomalies |
| `mid_stream_starts_total` | Flows first seen without a handshake |
| `capture_drops_total` | Packets the capture reports dropped: the latest pcapng Interface Statistics `isb_ifdrop` per Link (it counts from the start of the capture), or dumpcap's final report |
| `windows_closed_total` | Windows closed |
| `last_window_lag_seconds` | Wall clock at the close of the last window minus that window's end in capture time (gauge). Near `W` live; meaningless offline |

- **Counts follow the tables.** Packets by verdict and bytes by bucket are added as each Flow row (§8) is written, so they can trail by a window: a row waits until every byte in it has a bucket (§5). At the end of a run they equal the tables exactly, and the buckets sum to every Flow's stream bytes.
- **Capture Rate and store (TS-26):**

| Metric | Meaning |
|---|---|
| `capture_packets_total` `[cut]` | Packets written to L0 chunks, `full` or `truncated` |
| `capture_kept_bytes_total`, `capture_truncated_bytes_total` | Captured bytes written to chunks, and captured bytes the Capture Rate cut |
| `store_objects_total`, `store_bytes_total` `[kind]` | Objects written and their bytes; `kind`: `chunk`, `pack`, `index` |
| `store_existing_total` | Puts that found the same object already there (a re-run) |
| `uploads_total`, `upload_bytes_total` | Spooled objects the uploader put to the remote store, and their bytes (TS-38) |
| `uploads_existing_total` | Uploads that found the same bytes already in the remote store |
| `upload_retries_total` | Upload attempts that failed and are retried: a rising count is an outage |
| `spool_objects`, `spool_bytes` (gauges) | Objects and bytes in the spool, waiting to be uploaded |
