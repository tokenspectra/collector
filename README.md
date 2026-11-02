# TokenSpectra Collector

The Rust Collector for [TokenSpectra](https://github.com/tokenspectra/tokenspectra). It sits at the receiving end of one or more Taps. It records metadata for 100% of traffic on each Link, decodes Request Workunits, and hashes and stores everything as evidence the auditor can check.

## Spec

The spec lives here; the rest of the design is in the main repo. Read them before writing code:

- **Spec:** [`docs/spec.md`](docs/spec.md) in this repo (Draft; the "Settled" section is binding). It moved here from the main repo's `docs/design/collector.md`.
- **Evidence:** [`docs/research/collector-capture-and-store.md`](https://github.com/tokenspectra/tokenspectra/blob/main/docs/research/collector-capture-and-store.md). Covers dumpcap, pcapng, the Rust crates, S3, zstd, and BLAKE3, including hardware acceleration.
- **Terms:** [`CONTEXT.md`](https://github.com/tokenspectra/tokenspectra/blob/main/CONTEXT.md). Use the glossary exactly (Flow, Slice, Link, Workunit…).
- **Context:** [`architecture.md`](https://github.com/tokenspectra/tokenspectra/blob/main/docs/design/architecture.md) and [ADR-0003](https://github.com/tokenspectra/tokenspectra/blob/main/docs/adr/0003-rust-datapath-python-control-ts-console.md) (why Rust).

## In short

- **Input:** live capture (dumpcap ring buffer, read as each file closes) or `.pcap`/`.pcapng` files, through one deterministic parser.
- **Layers:** L0 pcapng chunks → L1 Flows (TCP reassembly) → L2 HTTP/1.1, HTTP/2, SSE → L3 OpenAI Wire Protocol → Request Workunits.
- **Every Flow gets a protocol verdict and byte accounting,** OpenAI or not.
- **Hashing:** BLAKE3, written as multihashes (`f1e20…`, spec §6), over 100% of payload: chunks, Flow streams per Slice, bodies.
- **Storage:** write-once objects through the `object_store` crate (local FS for the PoC, S3-compatible later): compressed chunks, packs, Parquet index tables. Reads by hash go through the control plane and are verified.

## Status

- Stage 1 (TS-24): packet input and Flow assembly.
- Stage 2 (TS-25): protocol identification, byte accounting, HTTP/1.1, h2c, SSE and OpenAI Request Workunits.
- Stage 3 (TS-28): console logging with verbosity levels, and one counter registry read by the window log line, an on-demand snapshot and Prometheus `/metrics` (spec §14).

Hashing of chunks and Slices, the Capture Rate cut and the object store come next. Implementation is tracked in Multica.

## Layout

`crates/collector` is the library and the `collector` binary:

| Module | Spec | What it does |
|---|---|---|
| `source` | §3 | `PacketSource` trait; `FileSource` reads `.pcap`/`.pcapng` with `pcap-file`. Timestamps come from the capture only |
| `ring` | §3 | `RingSource`: `dumpcap -b interval:W -b printname:stdout`, reads each file as dumpcap closes it. Never `-b files:N` |
| `window` | §3 | Cuts packets into windows by capture time; a packet's L0 address is (Link, window, index) |
| `net` | | Bounds-checked Ethernet/SLL/raw, IPv4/IPv6, TCP/UDP decoding |
| `assembler`, `tcp` | §4 | Flows and Slices: TCP reassembly per direction, gaps, retransmits, `mid_stream_start`, UDP datagrams, other IP protocols |
| `decode` | §5 | Protocol verdicts, request/response pairing, Workunit decisions, byte accounting per Flow, direction and Slice |
| `http1`, `http2`, `hpack`, `sse` | §5 | Hand-written, bounds-checked parsers: HTTP/1.1 (chunked included), h2c frames, HPACK, server-sent events |
| `openai` | §5 | The OpenAI Wire Protocol: which exchanges are Request Workunits, and the record fields read from their bodies |
| `output` | | JSON Lines tables (below) |
| `stats`, `observe` | §14 | The counter registry, its snapshot table and `/metrics`; `StatsSink`, which counts and logs every record on its way to the real sink and forwards it unchanged |

### Tables

| Table | One row per | Notes |
|---|---|---|
| `packets` | captured packet | L0 address, Flow, direction, stream offset |
| `segments` | in-order run of stream bytes | stream offset → (window, packet, offset in packet), capture time |
| `events` | gap or anomaly | `gap_lost`, `gap_truncated`, `retransmit_differs`, … |
| `flows` | Flow per Slice | Flow metadata, `verdict`, and `orig_bytes`/`resp_bytes` buckets |
| `http` | HTTP request/response pair | method, target, status, content type, body length, `body_hash`, bucket, `workunit_id` |
| `workunits` | Request Workunit | the record below |

### Bodies

Every hash is a multihash in base16 (spec §6): `f1e20` followed by the 64 hex digits `b3sum` prints. That covers `body_hash`, `request_body_hash`, `response_body_hash`, `workunit_id` and body file names. `collector::mh::parse` accepts only that form.

Every HTTP body that has a `body_hash` is kept as `<out>/bodies/<body_hash>`: requests and responses, Workunit or `http_other` (spec §8). `b3sum` of a file prints the last 64 digits of its name, and identical bodies are stored once.

- The bytes are the bytes that were hashed: chunked encoding removed, content coding kept, one file per SSE response.
- A body with a gap has no `body_hash` and is not kept; its packets are still in L0.
- `--no-bodies` turns this off. Hashes, lengths and every table stay the same; only `bodies/` and `by-exchange/` are missing.
- **`by-exchange/`** is a view for people. A live run adds each window's exchanges as the window closes; the end of a run, or `collector views <out>`, rebuilds it from scratch:
  - `by-exchange/<flow>/<exchange>.request.<ext>` and `.response.<ext>` are symlinks to `../../bodies/<hash>`. `<flow>` is the Flow id with every character outside `[A-Za-z0-9._-]` replaced by `_`. `<ext>` is `json`, `sse` or `bin`, from the parsed media type. Empty bodies get no link.
  - `<exchange>.response.merged.json`, for SSE Workunits only, joins the streamed chunks into one `chat.completion` (or `text_completion`) object: per choice, `role`, `content` and `reasoning` joined and the last `finish_reason`; `id`, `created` and `model` from the first event; the last `usage`. `incomplete: true` means `[DONE]` never arrived or an event didn't parse (`unparsed_events`).
  - The merged file is derived and lossy. It is not evidence: it is never hashed, stored or compared with the API Tap. The raw body in `bodies/` is the source.
- Bodies hold plaintext prompts and outputs (spec §10).
- Packs replace the per-body files once the object store lands.

### Verdicts and byte accounting (spec §5)

- **Verdict** from the first bytes of each direction, never ports: the HTTP/2 preface → `http2`; an HTTP/1 request or status line → `http1`; a TLS record header → `tls`; `content-type: application/grpc` on an h2c request → `grpc`; anything else → `opaque`. UDP and other IP protocols are `opaque`. A Flow with no payload yet has `verdict: null`.
- **Buckets.** Every stream byte of a Flow, direction and Slice is in exactly one of `workunit`, `http_other`, `framing`, `unexplained`, `gap`. They sum to `stream_end - stream_start` (TCP) or the payload bytes (UDP, other IP).
  - `framing`: chunk-size lines and the CRLF after each chunk, blank lines between HTTP/1 messages, the h2 preface, frame headers, padding, priority fields and the SETTINGS, PING, GOAWAY, WINDOW_UPDATE, PRIORITY and RST_STREAM frames.
  - `unexplained`: every byte of `tls`, `opaque` and `grpc` Flows, unknown h2 frame types, and everything after a parser loses sync (`orig_desync`/`resp_desync` say why).
  - `gap`: bytes counted by sequence numbers but never captured. A gap inside a body of known length (Content-Length, chunk data, a DATA frame) keeps the parser in sync; a gap in a head, a chunk-size line or a frame header does not.
- **Rows wait for their bytes.** A request is a Workunit only once its response head says so, so a Slice row is written when every byte in it has a bucket, which can be a window later. Rows stay in window order per Flow.
- The Collector reports verdicts and buckets; it never assigns a status.

### Request Workunits

A request/response pair is a Request Workunit when the request is `POST /v1/chat/completions` or `POST /v1/completions` with a body that parses as JSON, and the response is `application/json`, or `text/event-stream` when the request set `"stream": true` (spec §5). Everything else is `http_other`.

The record follows the TS-15 capture record where the Link shows the field:

| TS-15 field | `workunits` column | Notes |
|---|---|---|
| `workunit_id` | `workunit_id` | Multihash BLAKE3 of (Flow id, `0x00`, request direction, request start offset as u64 big-endian): the spec §6 proposal. Unique and stable across re-runs; not a content hash |
| received / completed timestamps | `received_ts_ns`, `completed_ts_ns` | capture time of the first request byte and the last response byte |
| `model`, `stream` | `model`, `stream` | from the request body; also `seed`, `n` |
| client request as received | `request_body_hash`, `request_body_len` | BLAKE3 of the body as on the wire (chunked encoding removed, content coding kept): the cross-check key with the API Tap (spec §11) |
| `finish_reason` | `finish_reason` | per choice index, from the JSON body or the SSE chunks |
| `usage` | `usage` | as sent |
| | `response_body_hash`, `response_id`, `response_model`, `status` | |
| | `sse_events`, `sse_done` | each event's body offset, length and capture time; whether `data: [DONE]` arrived. One hash covers the whole SSE body (spec §6) |
| | `complete` | both messages reached their end with no gap |
| `manifest_id`, `upstream`, forwarded request, token ids, logprobs, `scorable` | | not on the Link: the API Tap's side. The bodies themselves are stored by hash in the next stage |

A body with a gap has `body_hash: null`. A request body that is incomplete, has a gap, uses a content coding or exceeds `DecoderConfig::max_body` (16 MiB) cannot be checked as JSON, so its pair is `http_other`.

### Not in v1

- No resynchronisation after a parser loses sync: a Flow first seen in the middle of an HTTP message is `opaque`, or `unexplained` from the lost point on. A keep-alive Flow seen mid-stream between messages parses normally.
- HTTP/1.1 `Upgrade` (including h2c via Upgrade) and CONNECT tunnels: the bytes after the switch are `unexplained`. h2c works with prior knowledge.
- gRPC payloads, TLS, content-coded bodies: identified, not decoded.

## Running

```sh
# Offline, over files in order (window = Slice length).
cargo run -- files -w 10 -o out/ capture-1.pcapng capture-2.pcapng

# Live, through a dumpcap ring buffer. dumpcap needs the wireshark group.
sg wireshark -c "cargo run -- ring -i lo -w 10 -t 60"
```

- `-o/--out` defaults to `ts-captures/` in the current directory (created if missing).
- `-d/--ring-dir` defaults to `<tmp>/tokenspectra-ring-<interface>`.
- If dumpcap is missing, not runnable (not in the `wireshark` group) or fails (e.g. unknown interface), `ring` exits non-zero with a message saying which, and how to fix it. `files` never needs dumpcap.
- `--no-bodies`: keep hashes only, no `bodies/` or `by-exchange/` directory.
- `collector views <out>`: rebuild `by-exchange/` from `http.jsonl` and `bodies/`.
- Other short flags: `-w/--window-s`, `-i/--interface`, `-t/--duration-s`, `-f/--filter` (dumpcap's capture filter).

### Logs and stats (spec §14)

Logs go to stdout; they are diagnostics and never change an output file.

- Default INFO: one line per closed window (packets, bytes, Flows new/active/closed, Request Workunits ok/errored/incomplete, Workunit share of bytes and of closed Flows, gaps, packets/s, Mbit/s) and a summary on exit.
- `-v` DEBUG adds one line per Request Workunit and per new or closed Flow; `-vv` TRACE adds every reassembled segment. `-q` keeps WARN and ERROR, `-qq` ERROR only.
- `--log-level <error|warn|info|debug|trace>` overrides `-v`/`-q`; `RUST_LOG` overrides both. `--log-format json` writes JSON lines.
- **Snapshot:** press `s` or Enter (stdin a terminal), or send `SIGUSR1`, for a table of totals and the last window's rates.
- **Metrics:** `--metrics-addr 127.0.0.1:9464` serves Prometheus text at `/metrics`, `ts_collector_*` counters and gauges. Off by default.

### Smoke test

Live, with a terminal (needs dumpcap and the `wireshark` group):

```sh
cargo build
sg wireshark -c "target/debug/collector -v --metrics-addr 127.0.0.1:9464 ring -i lo -w 5 -t 120"
```

1. Make some traffic on `lo` (e.g. `uv run fixtures/capture/mock_openai.py` and a client, or `curl localhost:<port>`). Every 5 s an INFO `window closed` line appears; with `-v`, a DEBUG `workunit` line per OpenAI request.
2. Press `s`, then Enter: each prints the snapshot table. The keys are not echoed.
3. From another shell: `curl -s 127.0.0.1:9464/metrics | grep ts_collector_workunits_total`.
4. Snapshot without a terminal: `kill -USR1 $(pgrep -x collector)` prints the same table. Or run detached, e.g. `target/debug/collector files -o out/ big.pcapng </dev/null &` then `kill -USR1 %1`.
5. Ctrl-C (or `-t` running out) ends the run; the terminal is back in its normal mode.

Offline, without dumpcap: `target/debug/collector -v files -w 1 -o /tmp/ts crates/collector/tests/fixtures/openai_h1_sse.pcapng` logs two `workunit` lines, matching `crates/collector/tests/golden/openai_h1_sse/workunits.jsonl`.

## Tests

```sh
cargo test --workspace
```

- **Golden files:** `crates/collector/tests/fixtures/*.pcapng`, with expected tables in `tests/golden/<case>/`. After an intended output change: `UPDATE_GOLDEN=1 cargo test -p collector --test golden`, then review the diff. Three kinds of fixture:
  - **Captured OpenAI traffic** (`openai_h1_json`, `openai_h1_sse`, `openai_h2c_json`, `openai_h2c_sse`, `http_other_h1`): the official OpenAI Python SDK (and httpx for `/health`, `/v1/models` and a malformed body) against a mock OpenAI-compatible server, over HTTP/1.1 and h2c, captured with dumpcap. See below.
  - **Synthetic** fixtures, built packet by packet in `tests/support/fixtures.rs` and written by `cargo run -p collector --example gen_fixtures`: edge cases a live run can't produce on demand (lost segment, retransmit with different bytes, mid-stream start, Flows spanning windows, UDP, non-HTTP TCP, a TLS Flow on the plaintext Link, gRPC over h2c, HTTP/1.1 pipelining and a request whose response lands in the next window).
  - `dumpcap_keepalive-*`: real dumpcap ring files of a keep-alive Flow whose SYN predates the capture.
- **Logs and stats** (`tests/observe.rs`): the registry's final counters equal what the tables say, bytes by bucket sum to every Flow's bytes, `/metrics` is scraped and parsed, a `-v` run over every golden case logs one DEBUG line per expected Workunit, `SIGUSR1` prints the snapshot during a ring run, and runs at `-qq` and at `-vv` with metrics write identical output trees. The keypress snapshot needs a terminal, so it is in the smoke test above.
- Besides the expected tables, the tests check that every body with a `body_hash` is kept under its hash, that every `by-exchange/` link resolves to a body matching its name, and that `--no-bodies` changes no table. They also check that buckets sum to each Flow's bytes in every fixture, that two runs are byte-identical, and that corrupted payloads never panic the parsers or break the accounting.
- **Capturing the OpenAI fixtures again** (only when the mock or the scenarios change; CI never captures). Needs [uv](https://docs.astral.sh/uv/) and dumpcap; Python dependencies are pinned in the scripts:

  ```sh
  sg wireshark -c "uv run fixtures/capture/capture.py"                  # every scenario
  sg wireshark -c "uv run fixtures/capture/capture.py openai_h2c_sse"   # one scenario
  ```

  `fixtures/capture/mock_openai.py` serves fixed bodies on loopback, so only client headers and timing vary between captures. A small vLLM model would add realism, but the mock needs no GPU and keeps bodies fixed.
- **Live equals offline:** needs capture rights, so it is skipped unless enabled:

  ```sh
  sg wireshark -c "TS_LIVE_DUMPCAP=1 cargo test -p collector --test live -- --nocapture"
  ```
