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
- HTTP/1.1, HTTP/2 and SSE;
- the OpenAI Wire Protocol → Request Workunits;
- hashing, the Capture Rate cut, the object-store layout;
- metadata and records sent to the control plane.

**Not in v1:**
- TLS decryption (§9);
- Intermediate Workunits;
- Signatures and Kinds;
- Wire Protocols other than OpenAI (Anthropic Messages, gRPC, Dynamo TCP);
- QUIC payload parsing;
- assigning statuses, which stays with the Classifier.

## 2. Layers

```
L0  network packets on a Link   → pcapng chunk per window     every Flow, any protocol
L1  Flow (TCP stream, per dir)  → Flow index + Slice hashes   every Flow, any protocol
L2  HTTP message                → header block, body bytes    Flows that parse as HTTP
L3  Wire Protocol               → Request Workunit record     HTTP that parses as OpenAI
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

**Within HTTP**, a message pair is an OpenAI Request Workunit only if:
- it is `POST /v1/chat/completions` or `POST /v1/completions`;
- the request body is JSON;
- the response is `application/json`, or `text/event-stream` when `stream=true`.

Everything else is `http:other`, e.g. `/health`, `/metrics`, `/v1/models`, other paths, or unparseable JSON.

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
- **Non-OpenAI Flows are hashed and stored like every other Flow.** L0 and L1 don't care about the protocol. The only difference is retention (§7): these Flows are the alarm, so they're kept in full.

## 6. Hashing

BLAKE3 everywhere, at 3.4 GiB/s per core and 10 GiB/s on 4 threads on a modest VM (research §3). Hashing 100% of a 1–10 Gbps Link costs about one core [Inf].

| What | Hash | Why |
|---|---|---|
| **L0 chunk** | `blake3(uncompressed pcapng bytes)` | Names the stored chunk. Hashing before compression means a different zstd level never changes the name |
| **L0 packet** | `blake3(captured bytes)` per packet, combined into a Merkle root per chunk, stored in the chunk index | Proves a single packet is in a chunk without fetching the chunk |
| **L1 Slice** | `slice_hash[n] = blake3(slice_hash[n-1] ‖ flow_id ‖ dir ‖ stream bytes of Slice n)`, with `slice_hash[-1]` = the Flow's first-seen record | One commitment per window. The chain commits to the whole Flow so far, so long keep-alive or HTTP/2 Flows don't wait for FIN. **Gap bytes are left out and listed separately** |
| **L2 body** | `blake3(body bytes as on the wire)`, after removing chunked encoding but before any `Content-Encoding` is decoded | Names the stored body. Never hash re-serialised JSON: it has no canonical form, and these bytes are adversarial |
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

- **L0 chunks:** one object per Link per window, zstd-compressed. If a chunk passes a size cap (e.g. 1 GiB), split it into `-partN` objects.
  - Big objects use `put_multipart` (5 MiB–5 GiB parts, ≤ 10,000 parts; research §4).
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
  - Until packs exist, the Collector writes one file per body, `bodies/{multihash}`, next to its output tables. `b3sum` of the file prints the last 64 digits of its name.
  - Why: without them, reading a request or response means reassembling its Flow from L0 chunks. With them, every body hash in the index can be read directly (`GET /blobs/{blake3}`, §11).
  - Bodies hold plaintext prompts and outputs (§10). The option is for runs that should keep hashes only.
- **Two views of the same bodies (proposal).** Keep both:
  - `bodies/` is the store: named by hash, checked by name, each body stored once, bytes exactly as hashed.
  - `by-exchange/` is for people: named by Flow and exchange, rebuilt from the `http` table and `bodies/`, safe to delete.

  ```
  bodies/{multihash}                                       # the store
  by-exchange/{flow}/{exchange}.request.{ext}  -> ../../bodies/{multihash}
  by-exchange/{flow}/{exchange}.response.{ext} -> ../../bodies/{multihash}
  by-exchange/{flow}/{exchange}.response.merged.json       # SSE Workunits only
  ```

  - The links point at the store and never copy it. `--no-bodies` writes neither tree.
  - **Nothing from the Operator goes into a name unchecked.** `{flow}` is the Flow id with every character outside `[A-Za-z0-9._-]` replaced by `_`. `{exchange}` is the exchange number. `{ext}` comes from a fixed list chosen by the parsed media type: `json` for `application/json`, `sse` for `text/event-stream`, otherwise `bin`.
  - The tree is local output only. The object store keeps packs and the index (§8); the Store serves the same views on read (§11).
- **Merged view of OpenAI streaming (proposal).** An SSE response is a series of `chat.completion.chunk` events, one token delta each. `{exchange}.response.merged.json` joins them into one `chat.completion` object, shaped like a non-streaming response:
  - per choice `index`: `role`, `content` and `reasoning` joined in event order, the last `finish_reason`; plus `id`, `created`, `model` from the first event and the last `usage`;
  - `"incomplete": true` when `[DONE]` never arrived or an event did not parse, with the count of unparsed events, so a cut-off capture is still readable but never looks whole.
- **The merged view sits beside the raw SSE body, never in its place.** It is derived, like the links:
  - **Not evidence.** It is never hashed as a body, never stored in packs, never compared with the API Tap. §6 forbids hashing re-serialised JSON.
  - **Lossy.** Event boundaries, per-event capture times (in `sse_events`), and any field the merge doesn't know are dropped. The raw body stays the source; the merged file is rebuilt from it.
  - **Deterministic.** Same body, same file, so two runs stay byte-identical (§12).
  - Only the raw body is checked by name. A reader who doubts the merged file rebuilds it from `bodies/`.
- **Index tables (Parquet), one set per window:**
  - `flows`: per-Flow, per-Slice metadata, verdict, buckets, Slice hash;
  - `packets`: chunk, packet index, timestamp, Flow, direction, stream offset, captured and original length, packet hash;
  - `workunits`: L3 records;
  - `blobs`: hash → pack location.
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

Transport follows TS-15:
- an append-only local log as the source of truth;
- a shipper POSTs to the control plane's ingest, deduplicated by window and Collector;
- offline runs use the same ingest path.

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

1. **Golden files:** a set of `.pcapng` files with expected index tables and hashes, run in CI. It covers:
   - HTTP/1.1 JSON, HTTP/1.1 SSE with chunked encoding, h2c JSON and SSE;
   - a Flow spanning windows, a mid-stream start, a lost segment, a retransmit with different bytes;
   - `/health`, a TLS Flow on the plaintext Link, a non-HTTP TCP Flow, UDP.
2. **Determinism:** two runs over the same files give byte-identical tables.
3. **Live equals offline:** a live `RingSource` run and a `FileSource` run over the same dumpcap files give the same output.
4. **Round trip:** every stored body and chunk can be fetched by hash, and verifies.
   - Locally: every `body_hash` has a file in `bodies/` named by it, whose `b3sum` matches the name, and every `by-exchange/` link resolves to it.
5. **ROADMAP A2:** metadata for 100% of External Flows, and a Request Workunit for every OpenAI request, on a real Tap.

## 13. Open questions

- **Window length `W`** and the in-memory budget for holding one window at line rate.
- **Self-hosted S3-compatible store**, now that community MinIO has no binaries.
- **Truncated-packet length** (128 B?), and the per-Flow cap for alarm Flows.
- **The `workunit_id` scheme**, and whether TS-15's UUID moves to it.
- **dumpcap throughput and drops** at Link speed. Only loopback has been tested so far.
- **Keyed-hash key management** (rotation, disclosure for audits), for the Payload privacy work.
- **Anthropic Messages** (`/v1/messages`) as the second Wire Protocol. It needs its own research.
- **Keyed BLAKE3 in multihash.** The multicodec table has no code for keyed BLAKE3. Written under `0x1e`, a keyed hash would look like a plain one. The Payload privacy work (§10) needs its own code, from the private-use range or registered.
- **Who writes `by-exchange/`.** The Collector at the end of a run, or a separate tool over its output. The merge is more parsing of Operator bytes, and the Collector is the component that must stay small.
- **Bodies and the Capture Rate.** Bodies are kept by default (§8). Whether the Capture Rate also drops bodies of Workunits it doesn't keep, as it truncates their packets in L0 (§7), is open. So is a size cap per body, and the window a body belongs to when its message spans two.
