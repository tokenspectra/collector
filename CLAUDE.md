# TokenSpectra Collector

The Rust Collector, plus `viewer/index.html`, a no-build HTML viewer for its output folders. [docs/spec.md](docs/spec.md) is the spec; [README.md](README.md) is a short quick start.

## Keep the viewer in step with the Collector

The viewer is how people read a capture, so it must understand everything the Collector produces. Any PR that changes what the Collector decodes or writes updates `viewer/index.html` in the same PR:

- **New Wire Protocol** (`wire::BUILTIN`): add an entry to `FORMATS` whose `id` is the `protocol` tag, reading its response frames (SSE, NDJSON or whole JSON), and teach `requestTurns` its request shape. The protocol pill and the conversation then work for it.
- **New framing, or a changed end-of-stream marker:** `framingOf`/`framesOf` and the Workunit page.
- **New or renamed table, column, bucket, verdict or `extra` field:** show it where its table is shown (the Workunit, exchange, Flow and Slice pages, the stacked graphs' `CLASSES`).

Check it with `collector files -o /tmp/x <fixture>.pcapng` on the protocol's fixtures, then open the folder in the viewer: the conversation and the body's **merged** tab must show the reply text, and the Workunit must show its protocol pill. Derived views (merged text, conversations) are never evidence; the raw bodies are.
