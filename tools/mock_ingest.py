#!/usr/bin/env python3
"""A stand-in for the control plane's ingest (spec §11), for live and
benchmark runs: the control-plane Store is out of the Collector's scope.

Takes POST <any path> with a window manifest as the body and an
`Idempotency-Key: <collector>/<window_start_ns>` header. Keeps each window
once under --dir/<collector>/<window_start_ns>.json: 200 for a first copy
or a repeat of the same bytes, 409 for other bytes. GET /stats returns the
counts. Standard library only:

    python3 tools/mock_ingest.py --port 18090 --dir /tmp/ingest
    collector --ingest http://127.0.0.1:18090/ingest/windows files ...
"""

import argparse
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SAFE = re.compile(r"[^A-Za-z0-9._-]")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18090)
    ap.add_argument("--dir", required=True, type=Path)
    args = ap.parse_args()
    lock = threading.Lock()
    stats = {"accepted": 0, "duplicates": 0, "conflicts": 0}

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, doc):
            body = json.dumps(doc).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            with lock:
                self.reply(200, stats)

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("content-length", 0)))
            key = self.headers.get("idempotency-key", "")
            collector, _, window = key.rpartition("/")
            if not collector or not window.isdigit():
                return self.reply(400, {"error": "Idempotency-Key must be <collector>/<window_start_ns>"})
            path = args.dir / SAFE.sub("_", collector) / f"{window}.json"
            with lock:
                if not path.exists():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(body)
                    stats["accepted"] += 1
                    return self.reply(200, {"status": "accepted"})
                if path.read_bytes() == body:
                    stats["duplicates"] += 1
                    return self.reply(200, {"status": "duplicate"})
                stats["conflicts"] += 1
                return self.reply(409, {"error": f"window {key} already held with other bytes"})

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"listening on {args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
