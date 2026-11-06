# TokenSpectra Collector

The Rust Collector, plus `viewer/index.html`, a no-build HTML viewer for its output folders. [docs/spec.md](docs/spec.md) is the spec; [README.md](README.md) is a short quick start.

## Keep the viewer in step with the Collector

The viewer is how people read a capture, so it must understand everything the Collector produces. Any PR that changes what the Collector decodes or writes updates `viewer/index.html` in the same PR:

- **New Wire Protocol** (`wire::BUILTIN`): add an entry to `FORMATS` whose `id` is the `protocol` tag, reading its response frames (SSE, NDJSON or whole JSON), and teach `requestTurns` its request shape. The protocol pill and the conversation then work for it.
- **New framing, or a changed end-of-stream marker:** `framingOf`/`framesOf` and the Workunit page.
- **New or renamed table, column, bucket, verdict or `extra` field:** show it where its table is shown (the Workunit, exchange, Flow and Slice pages, the stacked graphs' `CLASSES`).

Check it with `collector files -o /tmp/x <fixture>.pcapng` on the protocol's fixtures, then open the folder in the viewer: the conversation and the body's **merged** tab must show the reply text, and the Workunit must show its protocol pill. Derived views (merged text, conversations) are never evidence; the raw bodies are.

`node viewer/check.mjs` (run in CI) renders body slots with a stub DOM: captured values such as headers must reach `innerHTML` only through `esc`, and new rendering of Operator bytes gets a check there.

## Keep parsing free of I/O

The parse modules (`PARSE` in `crates/collector/tests/boundary.rs`) will run pinned in two places, on the device and in the Rechecker. They import only each other and the `commit` and `bundle` crates, and that test fails otherwise. Rows leave through `RecordSink`, counters through an `Observer`, and anything about stored objects through `store::ObjectSink`. A module that belongs to the parser goes on the list; everything else counts as I/O.

## Keep the core crates below the Collector

`commit` (the trusted core: Merkle tree, hash names) and `bundle` (the manifest and index-table formats) never depend on `collector`, and neither reaches I/O. `commit` stays `no_std` and builds for `wasm32-unknown-unknown`. Their allowed dependencies are `CRATES` in `crates/collector/tests/boundary.rs`; a new one goes on that list, reviewed hardest for `commit`. Signing keys, the on-disk log and writing Parquet stay in `collector`.
