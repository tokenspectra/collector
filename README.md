# TokenSpectra Collector

The Rust Collector for [TokenSpectra](https://github.com/tokenspectra/tokenspectra). It sits at the receiving end of one or more Taps. It records metadata for 100% of traffic on each Link, decodes Request Workunits, and hashes and stores everything as evidence the auditor can check.

## Spec

The design lives in the main repo. Read it before writing code:

- **Spec:** [`docs/design/collector.md`](https://github.com/tokenspectra/tokenspectra/blob/main/docs/design/collector.md) (Draft; the "Settled" section is binding).
- **Evidence:** [`docs/research/collector-capture-and-store.md`](https://github.com/tokenspectra/tokenspectra/blob/main/docs/research/collector-capture-and-store.md). Covers dumpcap, pcapng, the Rust crates, S3, zstd, and BLAKE3, including hardware acceleration.
- **Terms:** [`CONTEXT.md`](https://github.com/tokenspectra/tokenspectra/blob/main/CONTEXT.md). Use the glossary exactly (Flow, Slice, Link, Workunit…).
- **Context:** [`architecture.md`](https://github.com/tokenspectra/tokenspectra/blob/main/docs/design/architecture.md) and [ADR-0003](https://github.com/tokenspectra/tokenspectra/blob/main/docs/adr/0003-rust-datapath-python-control-ts-console.md) (why Rust).

## In short

- **Input:** live capture (dumpcap ring buffer, read as each file closes) or `.pcap`/`.pcapng` files, through one deterministic parser.
- **Layers:** L0 pcapng chunks → L1 Flows (TCP reassembly) → L2 HTTP/1.1, HTTP/2, SSE → L3 OpenAI Wire Protocol → Request Workunits.
- **Every Flow gets a protocol verdict and byte accounting,** OpenAI or not.
- **Hashing:** BLAKE3, tagged `b3:`, over 100% of payload: chunks, Flow streams per Slice, bodies.
- **Storage:** write-once objects through the `object_store` crate (local FS for the PoC, S3-compatible later): compressed chunks, packs, Parquet index tables. Reads by hash go through the control plane and are verified.

## Status

No code yet. Implementation is tracked in Multica.
