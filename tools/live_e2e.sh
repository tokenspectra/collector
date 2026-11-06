#!/usr/bin/env bash
# Live equals offline, end to end (spec §12.3), over the mixed workload
# (fixtures/capture/workload.py: OpenAI Chat, OpenAI Responses, Anthropic,
# Ollama, streaming and not, plus non-LLM noise).
#
# 1. `collector ring` captures `lo` live while the workload runs, writing
#    tables, the object store and the manifest log to <work>/live and
#    shipping each window to a mock ingest.
# 2. `collector files` re-runs over the ring files dumpcap closed, into
#    <work>/offline, shipping to the same ingest.
# 3. The two output directories must be identical, and the ingest must have
#    taken every offline manifest as a repeat of a live one (no conflicts).
#
# The ring files stay in <work>/ring, the capture for tools/bench.py.
# Needs capture rights:
#
#     sg wireshark -c "tools/live_e2e.sh ../e2e 200"
set -euo pipefail

WORK=${1:?usage: live_e2e.sh <work dir> [duration_s]}
DURATION=${2:-60}
WINDOW=${WINDOW:-10}
WORKERS=${WORKERS:-8}
INGEST_PORT=${INGEST_PORT:-18090}
BIN=target/release/collector
INGEST="http://127.0.0.1:$INGEST_PORT/ingest/windows"

cargo build --release -q
rm -rf "$WORK/live" "$WORK/offline" "$WORK/ring" "$WORK/ingest"
mkdir -p "$WORK/ring" "$WORK/ingest"
FILTER=$(uv run -q fixtures/capture/workload.py --print-filter)
echo "filter: $FILTER"

python3 tools/mock_ingest.py --port "$INGEST_PORT" --dir "$WORK/ingest" >/dev/null &
INGEST_PID=$!
trap 'kill $INGEST_PID 2>/dev/null || true' EXIT
sleep 0.5

# dumpcap stops on its own after the workload; the Collector then drains.
"$BIN" -q --dev-plain-http --ingest "$INGEST" --collector-id live-e2e \
    ring -i lo -w "$WINDOW" -B 256 -f "$FILTER" -t $((DURATION + 15)) -d "$WORK/ring" -o "$WORK/live" \
    >"$WORK/live.log" 2>&1 &
RING_PID=$!
sleep 3
uv run -q fixtures/capture/workload.py --duration "$DURATION" --workers "$WORKERS" | tee "$WORK/workload.json"
wait $RING_PID
tail -n 3 "$WORK/live.log"

"$BIN" -q --dev-plain-http --ingest "$INGEST" --collector-id live-e2e \
    files -w "$WINDOW" -o "$WORK/offline" "$WORK"/ring/*.pcapng >"$WORK/offline.log" 2>&1

echo "ring files: $(ls "$WORK"/ring/*.pcapng | wc -l), $(du -cb "$WORK"/ring/*.pcapng | tail -1 | cut -f1) bytes"
echo "manifests: $(wc -l <"$WORK/live/manifests.jsonl") live, $(wc -l <"$WORK/offline/manifests.jsonl") offline"
STATS=$(curl -s "http://127.0.0.1:$INGEST_PORT/stats")
echo "ingest: $STATS"
# The shipper's cursor is its own state, not an output.
diff -r -q -x manifests.shipped "$WORK/live" "$WORK/offline"
python3 - "$STATS" "$WORK/live/manifests.jsonl" <<'PY'
import json, sys
stats, n = json.loads(sys.argv[1]), sum(1 for _ in open(sys.argv[2]))
assert stats == {"accepted": n, "duplicates": n, "conflicts": 0}, stats
PY
echo "live equals offline: identical output directories, $(du -sh "$WORK/live" | cut -f1) each"
