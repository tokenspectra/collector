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
- **Layers:** L0 pcapng chunks → L1 Flows (TCP reassembly) → L2 HTTP/1.1, HTTP/2 → L3 Wire Protocols (OpenAI and Anthropic today; one module each) → Request Workunits.
- **Every Flow gets a protocol verdict and byte accounting,** whether a Wire Protocol claims it or not.
- **Hashing:** BLAKE3, written as multihashes (`f1e20…`, spec §6), over 100% of payload: chunks, Flow streams per Slice, bodies.
- **Storage:** write-once objects through the `object_store` crate (local FS for the PoC, S3-compatible later): compressed chunks, packs, Parquet index tables. Reads by hash go through the control plane and are verified.

## Status

- Stage 1 (TS-24): packet input and Flow assembly.
- Stage 2 (TS-25): protocol identification, byte accounting, HTTP/1.1, h2c, SSE and OpenAI Request Workunits.
- Stage 3 (TS-28): console logging with verbosity levels, and one counter registry read by the window log line, an on-demand snapshot and Prometheus `/metrics` (spec §14).
- Stage 4 (TS-26): BLAKE3 packet hashes and a Merkle root per chunk, the Slice hash chain, the Capture Rate cut, and the object store: zstd pcapng chunks, packs and Parquet index tables (spec §6–8).
- Stage 5 (TS-29): a generic Wire Protocol layer: the `WireProtocol` trait and registry, shared SSE and NDJSON framing, OpenAI Chat Completions and legacy Completions ported onto it (spec §5).
- Stage 6 (TS-32): the Ollama native Wire Protocol: `/api/chat`, `/api/generate` (NDJSON or JSON) and `/api/embed`.
- Stage 6 (TS-31): the Anthropic Messages API Wire Protocol (spec §5).

Implementation is tracked in Multica.

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
| `http1`, `http2`, `hpack` | §5 | Hand-written, bounds-checked parsers: HTTP/1.1 (chunked included), h2c frames, HPACK |
| `wire` | §5 | The `WireProtocol` trait, the registry (`wire::BUILTIN`) and matching precedence |
| `wire::framing` | §5 | Response framing shared by every protocol: SSE (data-only and named events), NDJSON, whole JSON |
| `wire::openai` | §5 | The OpenAI Wire Protocol: Chat Completions and legacy Completions |
| `wire::ollama` | §5 | The Ollama native Wire Protocol: `/api/chat`, `/api/generate`, `/api/embed` |
| `wire::anthropic` | §5 | The Anthropic Messages API Wire Protocol |
| `output` | | JSON Lines tables (below) |
| `chunk` | §6, §8 | L0 chunks as pcapng, written byte for byte; the Merkle root over a chunk's packet hashes |
| `capture` | §7 | The Capture Rate cut: which packets a chunk keeps in full, the keyed draw per Workunit |
| `pack` | §8 | Packs: one zstd frame per item, plus a zstd seekable seek table |
| `index` | §8 | Index tables as Parquet, one fixed schema per table |
| `store` | §6–8 | `StoreSink`: holds each window, then writes its chunks, pack and index through `object_store`, write-once |
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
| `chunks` | L0 chunk (Link × window) | object key, `chunk_hash`, `merkle_root`, packets, and the Capture Rate's kept and truncated bytes |
| `blobs` | pack item | hash, `body` or `workunit`, pack key, offset and length of its zstd frame |

`packets.hash` is the BLAKE3 of the captured bytes. `flows` rows carry `orig_stats.slice_hash` and `resp_stats.slice_hash`, the Slice hash chain (spec §6).

### Object store (spec §8)

Every run writes, under `--store` (default `<out>/store`), once per window:

```
raw/{site}/{collector}/{link}/{yyyy}/{mm}/{dd}/{window_start_ns}-{chunk_hash}.pcapng.zst
packs/{site}/{collector}/{yyyy}/{mm}/{dd}/{window_start_ns}.pack
index/{site}/{collector}/{yyyy}/{mm}/{dd}/{window_start_ns}/{table}.parquet
```

- **Chunks:** one pcapng per Link per window, zstd-compressed, named by the BLAKE3 of the uncompressed pcapng: `zstd -dc <chunk> | b3sum` prints the last 64 digits of its name. Wireshark opens it. Truncated packets keep their original length.
- **Packs:** bodies (unless `--no-bodies`) and Request Workunit records, one zstd frame each; `blobs` says where. `zstd -dc` of a pack prints every item joined.
- **Index:** the eight tables above as Parquet, one fixed schema per table.
- Every put is create-only. Re-running over the same capture into the same store leaves identical objects alone; an object with other bytes fails the run.
- `--site` and `--collector-id` (default `local`) fill the key prefix.

### Capture Rate (spec §7)

Hashes and every table cover 100% of traffic. Only the stored chunk follows the Capture Rate:

- `--capture-rate <0..1>` (default 1, keep everything): the share of Request Workunits whose packets stay whole. The others are truncated to `--truncate-to` bytes (default 128).
- The draw is keyed per window. Until the control plane sends the secrets, they come from `--capture-key <64 hex digits>`, which a rate below 1 requires.
- Alarm traffic (`unexplained` bytes, `tls`/`opaque`/`grpc`, UDP and other IP protocols) is kept whole up to `--alarm-cap` captured bytes per Flow per Slice (default 16 MiB).
- Handshakes, control frames, `http_other`, and packets an anomaly points at are always whole. Bodies are kept in packs at any rate.

### Bodies

Every hash is a multihash in base16 (spec §6): `f1e20` followed by the 64 hex digits `b3sum` prints. That covers `body_hash`, `request_body_hash`, `response_body_hash`, `workunit_id` and body file names. `collector::mh::parse` accepts only that form.

Every HTTP body that has a `body_hash` is kept as `<out>/bodies/<body_hash>`: requests and responses, Workunit or `http_other` (spec §8). `b3sum` of a file prints the last 64 digits of its name, and identical bodies are stored once.

- The bytes are the bytes that were hashed: chunked encoding removed, content coding kept, one file per SSE response.
- A body with a gap has no `body_hash` and is not kept; its packets are still in L0.
- `--no-bodies` turns this off. Hashes, lengths and every table stay the same; only `bodies/` and `by-exchange/` are missing.
- **`by-exchange/`** is a view for people. A live run adds each window's exchanges as the window closes; the end of a run, or `collector views <out>`, rebuilds it from scratch:
  - `by-exchange/<flow>/<exchange>.request.<ext>` and `.response.<ext>` are symlinks to `../../bodies/<hash>`. `<flow>` is the Flow id with every character outside `[A-Za-z0-9._-]` replaced by `_`. `<ext>` is `json`, `sse` or `bin`, from the parsed media type. Empty bodies get no link.
  - `<exchange>.response.merged.json`, for OpenAI SSE Workunits only, joins the streamed chunks into one `chat.completion` (or `text_completion`) object: per choice, `role`, `content` and `reasoning` joined and the last `finish_reason`; `id`, `created` and `model` from the first event; the last `usage`. `incomplete: true` means `[DONE]` never arrived or an event didn't parse (`unparsed_events`).
  - The merged file is derived and lossy. It is not evidence: it is never hashed, stored or compared with the API Tap. The raw body in `bodies/` is the source.
- Bodies hold plaintext prompts and outputs (spec §10).
- `bodies/` is the local view; the store keeps the same bodies in packs.

### Verdicts and byte accounting (spec §5)

- **Verdict** from the first bytes of each direction, never ports: the HTTP/2 preface → `http2`; an HTTP/1 request or status line → `http1`; a TLS record header → `tls`; `content-type: application/grpc` on an h2c request → `grpc`; anything else → `opaque`. UDP and other IP protocols are `opaque`. A Flow with no payload yet has `verdict: null`.
- **Buckets.** Every stream byte of a Flow, direction and Slice is in exactly one of `workunit`, `http_other`, `framing`, `unexplained`, `gap`. They sum to `stream_end - stream_start` (TCP) or the payload bytes (UDP, other IP).
  - `framing`: chunk-size lines and the CRLF after each chunk, blank lines between HTTP/1 messages, the h2 preface, frame headers, padding, priority fields and the SETTINGS, PING, GOAWAY, WINDOW_UPDATE, PRIORITY and RST_STREAM frames.
  - `unexplained`: every byte of `tls`, `opaque` and `grpc` Flows, unknown h2 frame types, and everything after a parser loses sync (`orig_desync`/`resp_desync` say why).
  - `gap`: bytes counted by sequence numbers but never captured. A gap inside a body of known length (Content-Length, chunk data, a DATA frame) keeps the parser in sync; a gap in a head, a chunk-size line or a frame header does not.
- **Rows wait for their bytes.** A request is a Workunit only once its response head says so, so a Slice row is written when every byte in it has a bucket, which can be a window later. Rows stay in window order per Flow.
- The Collector reports verdicts and buckets; it never assigns a status.

### Request Workunits

A request/response pair is a Request Workunit when a registered Wire Protocol claims its route, reads its request body, and accepts its response media type (spec §5). For OpenAI: `POST /v1/chat/completions`, `POST /v1/completions` or `POST /v1/responses` (the Responses API) with a JSON body, answered with `application/json`, or `text/event-stream` when the request set `"stream": true`. For Ollama native: `POST /api/chat`, `/api/generate` or `/api/embed` with a JSON object body, answered with `application/json`, or `application/x-ndjson` when the request streams (chat and generate stream unless `"stream": false`). Ollama's `/v1/*` endpoints are OpenAI's. For Anthropic: `POST /v1/messages` with an `anthropic-version` header and a JSON object body, under the same response rule. Everything else is `http_other`.

**Adding a Wire Protocol** takes one module under `crates/collector/src/wire/` implementing `WireProtocol` (routes, optional header sniffing, request parsing, the response `Framing`, a frame decoder) and one line in `wire::BUILTIN`. Its fields beyond the common columns go in `extra`. `crates/collector/tests/wire_protocol.rs` registers a protocol that lives only in that test.

The record follows the TS-15 capture record where the Link shows the field:

| TS-15 field | `workunits` column | Notes |
|---|---|---|
| `workunit_id` | `workunit_id` | Multihash BLAKE3 of (Flow id, `0x00`, request direction, request start offset as u64 big-endian): the spec §6 proposal. Unique and stable across re-runs; not a content hash |
| received / completed timestamps | `received_ts_ns`, `completed_ts_ns` | capture time of the first request byte and the last response byte |
| `model`, `stream` | `model`, `stream` | from the request body; also `seed`, `n` |
| client request as received | `request_body_hash`, `request_body_len` | BLAKE3 of the body as on the wire (chunked encoding removed, content coding kept): the cross-check key with the API Tap (spec §11) |
| | `protocol`, `endpoint` | the Wire Protocol's id (`openai`, `openai_responses`, `ollama`, `anthropic`) and the route pattern the request matched |
| `finish_reason` | `finish_reason` | per choice index, from the JSON body or the stream's frames |
| `usage` | `usage`, `input_tokens`, `output_tokens` | `usage` as sent; the token counts read from it when the protocol reports them (OpenAI: `prompt_tokens`, `completion_tokens`; Anthropic: `input_tokens`, `output_tokens`). Ollama sends no usage object: `usage` is `null`, the counts are `prompt_eval_count` and `eval_count`, and `finish_reason` is `done_reason` |
| | `response_body_hash`, `response_id`, `response_model`, `status` | |
| | `sse_events`, `sse_done` | each event's body offset, length and capture time; whether the protocol's end-of-stream marker arrived (OpenAI `data: [DONE]`, Anthropic `message_stop`). One hash covers the whole SSE body (spec §6) |
| | `complete` | both messages reached their end with no gap |
| | `extra` | protocol-specific fields as one JSON object, `null` when there are none (always for OpenAI). Anthropic: cache token counts, `stop_sequence`, `error_type`. Ollama: `total_duration`, `load_duration`, `prompt_eval_duration`, `eval_duration` (ns), `done` (streams only: the `"done": true` line arrived) and `error` |
| `manifest_id`, `upstream`, forwarded request, token ids, logprobs, `scorable` | | not on the Link: the API Tap's side |

A body with a gap has `body_hash: null`. A request body that is incomplete, has a gap, uses a content coding or exceeds `DecoderConfig::max_body` (16 MiB) cannot be checked as JSON, so its pair is `http_other`.

### Not in v1

- No resynchronisation after a parser loses sync: a Flow first seen in the middle of an HTTP message is `opaque`, or `unexplained` from the lost point on. A keep-alive Flow seen mid-stream between messages parses normally.
- HTTP/1.1 `Upgrade` (including h2c via Upgrade) and CONNECT tunnels: the bytes after the switch are `unexplained`. h2c works with prior knowledge.
- gRPC payloads, TLS, content-coded bodies: identified, not decoded.

## Quick start: traffic → capture → viewer

Capture a local LLM's traffic on loopback and browse it. Tested on Linux (Ubuntu).

**You need:**
- Rust (`cargo`).
- **dumpcap**, Wireshark's capture tool, runnable without root:
  - Debian/Ubuntu: `sudo apt install wireshark-common`, answer **Yes** to "non-superusers capture" (or `sudo dpkg-reconfigure wireshark-common`), then `sudo usermod -aG wireshark $USER`.
  - Fedora: `sudo dnf install wireshark-cli`, then `sudo usermod -aG wireshark $USER`.
  - The group applies at next login; until then wrap commands in `sg wireshark -c "..."`. Check with `dumpcap -D`.
- [Ollama](https://ollama.com) (or any OpenAI-compatible server), and Python 3: the traffic script uses the standard library only.
- A browser.

**Run it**, from the repo root:

```sh
ollama pull qwen2.5:0.5b                                            # small model; any model works

# terminal 1: capture lo in 10 s windows
sg wireshark -c "cargo run -- -v ring -i lo -w 10 -o ts-captures-demo"

# terminal 2: 5 rounds of prompts, some multi-turn, streamed
python3 tools/llm_traffic.py --stream --count 5 --interval 10
```

When the script ends, wait one window and press Ctrl-C in terminal 1. Then open `viewer/index.html` in the browser, choose `ts-captures-demo/`, and go to **Request Workunits › conversation**.

- `tools/llm_traffic.py` speaks `POST /v1/chat/completions`, or the Responses API `POST /v1/responses` with `--api responses` (Ollama serves both; they decode as OpenAI). Ollama's native `/api/chat`, `/api/generate` and `/api/embed` decode as `ollama`. Flags: `--api`, `--model`, `--host` (e.g. `http://localhost:8000` for vLLM), `--stream`, `--multiturn`, `--count`, `--seed`; see `--help`.
- Ollama also talks to its own llama.cpp runner on a random loopback port (`/completion`, `/tokenize`, `/health`). That shows up as `http_other`; the viewer still rebuilds its conversation from the templated prompt.
- `ts-captures*` is gitignored. Bodies hold the prompts and replies in plaintext.

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
- **Metrics:** `--metrics-addr 127.0.0.1:9464` serves Prometheus text at `/metrics`, `ts_collector_*` counters and gauges. Off by default. Capture Rate and store counters: `capture_packets_total{cut}`, `capture_kept_bytes_total`, `capture_truncated_bytes_total`, `store_objects_total{kind}`, `store_bytes_total{kind}`, `store_existing_total`.

### Smoke test

Live, with a terminal (needs dumpcap and the `wireshark` group):

```sh
cargo build
sg wireshark -c "target/debug/collector -v --metrics-addr 127.0.0.1:9464 ring -i lo -w 5 -t 120"
```

1. Make some traffic on `lo` (e.g. `uv run fixtures/capture/mock_server.py` and a client, or `curl localhost:<port>`). Every 5 s an INFO `window closed` line appears; with `-v`, a DEBUG `workunit` line per OpenAI request.
2. Press `s`, then Enter: each prints the snapshot table. The keys are not echoed.
3. From another shell: `curl -s 127.0.0.1:9464/metrics | grep ts_collector_workunits_total`.
4. Snapshot without a terminal: `kill -USR1 $(pgrep -x collector)` prints the same table. Or run detached, e.g. `target/debug/collector files -o out/ big.pcapng </dev/null &` then `kill -USR1 %1`.
5. Ctrl-C (or `-t` running out) ends the run; the terminal is back in its normal mode.

Offline, without dumpcap: `target/debug/collector -v files -w 1 -o /tmp/ts crates/collector/tests/fixtures/openai_h1_sse.pcapng` logs two `workunit` lines, matching `crates/collector/tests/golden/openai_h1_sse/workunits.jsonl`.

### Viewer

`viewer/index.html` browses an output folder in the browser: open the file, then pick or drop the folder. It is plain HTML and JS with no build step, and reads files locally.

- Navigate Link › Flow › Slice or Exchange › Request Workunit › conversation, with packets, windows, bodies and events linked both ways.
- Hashes show their multihash type and digest. BLAKE3 in the page checks a body against its name, a chunk's `merkle_root` against its packet hashes, and a Workunit record against its blob.
- Stacked graphs per Link and Flow over windows: Workunit (`workunit`), Other HTTP (`http_other` + `framing`), Unexplained (`unexplained` + `gap`). These group buckets; they are not statuses.
- Reads the JSONL tables and `bodies/`, not the Parquet index or the stored chunks.

## Tests

```sh
cargo test --workspace
```

- **Golden files:** `crates/collector/tests/fixtures/*.pcapng`, with expected tables in `tests/golden/<case>/`. After an intended output change: `UPDATE_GOLDEN=1 cargo test -p collector --test golden`, then review the diff. Three kinds of fixture:
  - **Captured OpenAI traffic** (`openai_h1_json`, `openai_h1_sse`, `openai_h2c_json`, `openai_h2c_sse`, `http_other_h1`): the official OpenAI Python SDK (and httpx for `/health`, `/v1/models` and a malformed body) against a mock OpenAI-compatible server, over HTTP/1.1 and h2c, captured with dumpcap. See below.
  - **Captured Anthropic traffic** (`anthropic_h1_json`, `anthropic_h1_sse`, `anthropic_h2c_json`, `anthropic_h2c_sse`): the official Anthropic Python SDK against the same mock's `/v1/messages`, over HTTP/1.1 and h2c. Each JSON case adds a 400 error body; each SSE case adds a 200 stream cut off by an `error` event after the first token.
  - **Synthetic** fixtures, built packet by packet in `tests/support/fixtures.rs` and written by `cargo run -p collector --example gen_fixtures`: edge cases a live run can't produce on demand (lost segment, retransmit with different bytes, mid-stream start, Flows spanning windows, UDP, non-HTTP TCP, a TLS Flow on the plaintext Link, gRPC over h2c, HTTP/1.1 pipelining and a request whose response lands in the next window).
  - `dumpcap_keepalive-*`: real dumpcap ring files of a keep-alive Flow whose SYN predates the capture.
- **Store** (`tests/store.rs`): every body, Workunit record and chunk is fetched by hash and verifies; each chunk's packets match the `packets` table and its Merkle root; Slice hashes are recomputed from the streams; two runs write byte-identical stores, and a re-run finds every object already there; an object with other bytes is never overwritten; a Capture Rate of 0 truncates exactly the Workunit packets and changes no table but `chunks`; the alarm cap; Parquet holds the same rows as the JSONL tables.
- **Wire Protocols** (`tests/wire_protocol.rs`): a protocol defined only in the test, registered with one line, decodes NDJSON and named-SSE Workunits, wins a shared path by header and falls through to OpenAI on a body it cannot read, resumes NDJSON framing after a lost segment, and fills `protocol`, the token counts, `extra` and the `protocol` metric label. Framing unit tests split SSE (both styles) and NDJSON across segments and gaps.
- **Anthropic outcomes** (`tests/anthropic.rs`): streams built packet by packet. Only one that reaches `message_stop` is `ok`, a `max_tokens` stop included; a clean end without `message_stop`, or an in-band `error` event, is `errored`; a gap is `incomplete`; a JSON body that is neither a `message` nor an `error` is `errored`.
- **Logs and stats** (`tests/observe.rs`): the registry's final counters equal what the tables say, bytes by bucket sum to every Flow's bytes, `/metrics` is scraped and parsed, a `-v` run over every golden case logs one DEBUG line per expected Workunit, `SIGUSR1` prints the snapshot during a ring run, and runs at `-qq` and at `-vv` with metrics write identical output trees. The keypress snapshot needs a terminal, so it is in the smoke test above.
- Besides the expected tables, the tests check that every body with a `body_hash` is kept under its hash, that every `by-exchange/` link resolves to a body matching its name, and that `--no-bodies` changes no table. They also check that buckets sum to each Flow's bytes in every fixture, that two runs are byte-identical, and that corrupted payloads never panic the parsers or break the accounting.
- **Capturing the protocol fixtures again** (only when the mock or the scenarios change; CI never captures). Needs [uv](https://docs.astral.sh/uv/) and dumpcap; Python dependencies are pinned in the scripts:

  ```sh
  sg wireshark -c "uv run fixtures/capture/capture.py"                  # every scenario
  sg wireshark -c "uv run fixtures/capture/capture.py openai_h2c_sse"   # one scenario
  ```

  `fixtures/capture/mock_server.py` serves HTTP/1.1 and h2c on loopback; each Wire Protocol adds its routes in its own module (`mock_openai.py`, `mock_anthropic.py`) and its scenarios in another (`capture_openai.py`, `capture_anthropic.py`), plus one line in each script's list. It serves fixed bodies, so only client headers and timing vary between captures. A small vLLM model would add realism, but the mock needs no GPU and keeps bodies fixed.
- **Live equals offline:** needs capture rights, so it is skipped unless enabled:

  ```sh
  sg wireshark -c "TS_LIVE_DUMPCAP=1 cargo test -p collector --test live -- --nocapture"
  ```
- **PR diff size:** CI's `PR diff size` job posts a sticky comment with the production lines a PR changes: files under `src/`, with test files and inline `#[cfg(test)]` modules stripped from both sides, so fixtures and golden tables don't count. It is informational, never a gate. Locally:

  ```sh
  scripts/pr-diff-stats.py origin/main HEAD
  scripts/pr-diff-stats.py --self-test
  ```
