# /// script
# requires-python = ">=3.11"
# dependencies = ["openai==3.42.1", "anthropic==2.3.0", "ollama==0.6.3", "httpx[http2]==0.28.1", "httpx2[http2]==2.16.0", "h2==4.4.1"]
# ///
"""A mixed workload on loopback for the live RingSource run and the
throughput benchmark (TS-27).

Drives the official SDKs, as capture.py does, against mock_server.py over
HTTP/1.1 and h2c, streaming and not: OpenAI Chat and legacy Completions,
OpenAI Responses, Anthropic Messages and Ollama native (the mock, for
volume). A real local Ollama, if one listens on --ollama-port, gets a
trickle of requests too. Beside them runs non-LLM noise: HTTP downloads
(http_other), an opaque TCP stream, and UDP datagrams.

Requests carry conversation histories of random size, so request bodies
dominate the bytes, as in multi-turn chat. Runs for --duration seconds
and prints the capture filter that covers every port it uses:

    uv run fixtures/capture/workload.py --duration 300 --workers 12
    uv run fixtures/capture/workload.py --print-filter
"""

import argparse
import json
import math
import os
import random
import socket
import socketserver
import subprocess
import sys
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import anthropic
import httpx
import httpx2
import ollama
import openai

HERE = Path(__file__).resolve().parent
MODEL = "mock-model"
WORDS = ("token flow slice link window capture rate packet stream hash chunk body request response "
         "model prompt reply cluster gateway latency budget audit evidence verify sample").split()


def filler(rng, size):
    out, n = [], 0
    while n < size:
        w = rng.choice(WORDS)
        out.append(w)
        n += len(w) + 1
    return " ".join(out)


def history(rng, max_kb):
    """A conversation of log-uniform total size, 200 B to max_kb KiB."""
    total = int(math.exp(rng.uniform(math.log(200), math.log(max_kb * 1024))))
    turns = rng.randint(1, 6)
    msgs = []
    for i in range(turns * 2 - 1):
        role = "user" if i % 2 == 0 else "assistant"
        msgs.append({"role": role, "content": filler(rng, total // (turns * 2 - 1))})
    return msgs


class Noise:
    """Non-LLM traffic: HTTP downloads, an opaque TCP sink, a UDP sink."""

    def __init__(self, http_port, tcp_port, udp_port):
        blob = os.urandom(1 << 20)

        class Download(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                n = int(self.path.rsplit("/", 1)[-1] or 0)
                self.send_response(200)
                self.send_header("content-type", "application/octet-stream")
                self.send_header("content-length", str(n))
                self.end_headers()
                while n > 0:
                    k = min(n, len(blob))
                    self.wfile.write(blob[:k])
                    n -= k

            def log_message(self, *_):
                pass

        class Sink(socketserver.BaseRequestHandler):
            def handle(self):
                while self.request.recv(65536):
                    pass

        self.http = ThreadingHTTPServer(("127.0.0.1", http_port), Download)
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        self.tcp = socketserver.ThreadingTCPServer(("127.0.0.1", tcp_port), Sink)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", udp_port))
        for target in (self.http.serve_forever, self.tcp.serve_forever, self._drain_udp):
            threading.Thread(target=target, daemon=True).start()
        self.blob = blob

    def _drain_udp(self):
        while True:
            self.udp.recv(65536)


class Worker:
    def __init__(self, args, seed, stats, lock):
        self.args, self.rng, self.stats, self.lock = args, random.Random(seed), stats, lock
        base = f"http://127.0.0.1:{args.port}"
        self.openai = {h2: openai.OpenAI(base_url=f"{base}/v1", api_key="none", max_retries=0,
                                         http_client=httpx.Client(http1=not h2, http2=h2)) for h2 in (False, True)}
        self.anthropic = {h2: anthropic.Anthropic(base_url=base, api_key="none", max_retries=0,
                                                  http_client=httpx2.Client(http1=not h2, http2=h2))
                          for h2 in (False, True)}
        self.ollama = ollama.Client(host=base)
        self.noise = httpx.Client(base_url=f"http://127.0.0.1:{args.noise_port}")
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def count(self, kind):
        with self.lock:
            self.stats[kind] += 1

    def one(self):
        r, a = self.rng, self.args
        stream, h2 = r.random() < 0.5, r.random() < 0.5
        kinds = ["chat", "completions", "responses", "anthropic", "ollama", "download", "opaque", "udp"]
        weights = [24, 6, 16, 18, 16, 8 * a.noise, 4 * a.noise, 4 * a.noise]
        kind = r.choices(kinds, weights)[0]
        msgs = history(r, a.max_prompt_kb)
        if kind == "chat":
            c = self.openai[h2].chat.completions.create(model=MODEL, messages=msgs, stream=stream, max_tokens=a.tokens)
            if stream:
                for _ in c:
                    pass
        elif kind == "completions":
            prompt = "\n".join(m["content"] for m in msgs)
            c = self.openai[h2].completions.create(model=MODEL, prompt=prompt, stream=stream, max_tokens=a.tokens)
            if stream:
                for _ in c:
                    pass
        elif kind == "responses":
            c = self.openai[h2].responses.create(model=MODEL, input=msgs, stream=stream)
            if stream:
                for _ in c:
                    pass
        elif kind == "anthropic":
            c = self.anthropic[h2].messages.create(model=MODEL, messages=msgs, max_tokens=a.tokens, stream=stream)
            if stream:
                for _ in c:
                    pass
        elif kind == "ollama":
            if r.random() < 0.5:
                c = self.ollama.chat(model=MODEL, messages=msgs, stream=stream)
            else:
                c = self.ollama.generate(model=MODEL, prompt=msgs[-1]["content"], stream=stream)
            if stream:
                for _ in c:
                    pass
            kind = "ollama_mock"
        elif kind == "download":
            n = int(math.exp(r.uniform(math.log(16 << 10), math.log(4 << 20))))
            self.noise.get(f"/bytes/{n}").read()
        elif kind == "opaque":
            with socket.create_connection(("127.0.0.1", a.opaque_port)) as s:
                for _ in range(r.randint(1, 64)):
                    s.sendall(os.urandom(r.randint(64, 16 << 10)))
        else:
            for _ in range(r.randint(1, 32)):
                self.udp.sendto(os.urandom(r.randint(32, 1200)), ("127.0.0.1", a.udp_port))
        self.count(f"{kind}{'_stream' if stream and kind not in ('download', 'opaque', 'udp') else ''}")

    def run(self, deadline):
        while time.monotonic() < deadline:
            try:
                self.one()
            except Exception as e:  # keep going: the workload is traffic, not a test
                self.count(f"error:{type(e).__name__}")


def real_ollama(args, deadline, stats, lock):
    """A trickle against a real Ollama: authentic NDJSON and JSON."""
    c = ollama.Client(host=f"http://127.0.0.1:{args.ollama_port}")
    rng = random.Random(args.seed)
    opts = {"seed": 7, "temperature": 0, "num_predict": 16}
    while time.monotonic() < deadline:
        stream = rng.random() < 0.5
        try:
            if rng.random() < 0.5:
                r = c.chat(model=args.ollama_model, messages=[{"role": "user", "content": filler(rng, 200)}],
                           options=opts, stream=stream)
            else:
                r = c.generate(model=args.ollama_model, prompt=filler(rng, 200), options=opts, stream=stream)
            if stream:
                for _ in r:
                    pass
            kind = "ollama_real" + ("_stream" if stream else "")
        except Exception as e:
            kind = f"error:ollama_real:{type(e).__name__}"
            time.sleep(1)
        with lock:
            stats[kind] += 1


def capture_filter(a):
    tcp = [a.port, a.noise_port, a.opaque_port] + ([a.ollama_port] if a.ollama_port else [])
    return " or ".join([f"tcp port {p}" for p in tcp] + [f"udp port {a.udp_port}"])


def ollama_up(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=float, default=60, help="seconds of traffic")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--seed", type=int, default=27)
    ap.add_argument("--port", type=int, default=18000, help="mock_server.py")
    ap.add_argument("--noise-port", type=int, default=18001, help="HTTP downloads")
    ap.add_argument("--opaque-port", type=int, default=18002, help="opaque TCP")
    ap.add_argument("--udp-port", type=int, default=18003)
    ap.add_argument("--ollama-port", type=int, default=11434, help="a real Ollama; 0 for none")
    ap.add_argument("--ollama-model", default="qwen2.5:0.5b")
    ap.add_argument("--tokens", type=int, default=64, help="tokens per mock reply")
    ap.add_argument("--event-gap", type=float, default=0.002, help="seconds between mock stream frames")
    ap.add_argument("--max-prompt-kb", type=int, default=96)
    ap.add_argument("--noise", type=float, default=1.0, help="weight of non-LLM traffic")
    ap.add_argument("--start-delay", type=float, default=0, help="seconds to wait before sending")
    ap.add_argument("--print-filter", action="store_true", help="print the capture filter and exit")
    a = ap.parse_args()
    if a.ollama_port and not ollama_up(a.ollama_port):
        print(f"no Ollama on :{a.ollama_port}; skipping the real-Ollama trickle", file=sys.stderr)
        a.ollama_port = 0
    if a.print_filter:
        print(capture_filter(a))
        return
    server = subprocess.Popen([sys.executable, str(HERE / "mock_server.py"), "--port", str(a.port),
                               "--tokens", str(a.tokens), "--event-gap", str(a.event_gap)],
                              stdout=subprocess.PIPE, text=True)
    try:
        server.stdout.readline()
        Noise(a.noise_port, a.opaque_port, a.udp_port)
        time.sleep(a.start_delay)
        stats, lock = Counter(), threading.Lock()
        deadline = time.monotonic() + a.duration
        threads = [threading.Thread(target=Worker(a, a.seed * 1000 + i, stats, lock).run, args=(deadline,))
                   for i in range(a.workers)]
        if a.ollama_port:
            threads.append(threading.Thread(target=real_ollama, args=(a, deadline, stats, lock)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        print(json.dumps({"requests": dict(sorted(stats.items())), "filter": capture_filter(a)}, indent=1))
    finally:
        server.terminate()
        server.wait()


if __name__ == "__main__":
    main()
