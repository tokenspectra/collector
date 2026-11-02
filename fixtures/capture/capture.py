# /// script
# requires-python = ">=3.11"
# dependencies = ["openai==3.42.1", "httpx[http2]==0.28.1", "h2==4.4.1"]
# ///
"""Captures real OpenAI-protocol traffic into golden .pcapng fixtures.

Starts mock_openai.py on loopback, then for each scenario starts dumpcap on
`lo`, drives the official OpenAI Python SDK (or httpx) against the mock over
HTTP/1.1 or h2c, stops dumpcap and writes
crates/collector/tests/fixtures/<scenario>.pcapng.

Run once, from the repo root, and commit the files; CI only replays them.
dumpcap needs the wireshark group:

    sg wireshark -c "uv run fixtures/capture/capture.py"
    sg wireshark -c "uv run fixtures/capture/capture.py openai_h2c_sse"   # one scenario
"""

import argparse
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import httpx
import openai

HERE = Path(__file__).resolve().parent
OUT = HERE.parent.parent / "crates/collector/tests/fixtures"
MODEL = "mock-model"
MESSAGES = [{"role": "user", "content": "Say hello."}]


def sdk(port, http2):
    http_client = httpx.Client(http1=not http2, http2=http2)
    return openai.OpenAI(
        base_url=f"http://127.0.0.1:{port}/v1", api_key="none", http_client=http_client, max_retries=0
    )


def json_calls(c):
    c.chat.completions.create(model=MODEL, messages=MESSAGES, seed=7, max_tokens=4)
    c.completions.create(model=MODEL, prompt="Say hello.", max_tokens=4)


def sse_calls(c):
    for _ in c.chat.completions.create(
        model=MODEL, messages=MESSAGES, seed=7, max_tokens=4, stream=True,
        stream_options={"include_usage": True},
    ):
        pass
    for _ in c.completions.create(model=MODEL, prompt="Say hello.", max_tokens=4, stream=True):
        pass


def http_other(port):
    with httpx.Client(base_url=f"http://127.0.0.1:{port}") as c:
        c.get("/health")
        c.get("/v1/models")
        # Not JSON: the pair is http_other, not a Workunit.
        c.post("/v1/chat/completions", content=b'{"model":', headers={"content-type": "application/json"})


def with_sdk(http2, calls):
    def run(port):
        c = sdk(port, http2)
        calls(c)
        c.close()

    return run


SCENARIOS = {
    "openai_h1_json": with_sdk(False, json_calls),
    "openai_h1_sse": with_sdk(False, sse_calls),
    "openai_h2c_json": with_sdk(True, json_calls),
    "openai_h2c_sse": with_sdk(True, sse_calls),
    "http_other_h1": http_other,
}


def capture(name, port, dumpcap):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / f"{name}.pcapng"
        cmd = [dumpcap, "-i", "lo", "-f", f"tcp port {port}", "-w", str(path)]
        proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, text=True)
        ready = threading.Event()
        log = []

        def watch():
            for line in proc.stderr:
                log.append(line)
                if line.startswith("Capturing on"):
                    ready.set()

        threading.Thread(target=watch, daemon=True).start()
        if not ready.wait(10):
            proc.kill()
            sys.exit(f"dumpcap did not start (run under `sg wireshark -c ...`?):\n{''.join(log)}")
        time.sleep(0.3)
        SCENARIOS[name](port)
        time.sleep(0.3)
        proc.send_signal(signal.SIGINT)
        proc.wait(10)
        OUT.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, OUT / path.name)
        print(f"wrote {OUT / path.name}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scenarios", nargs="*", default=list(SCENARIOS))
    ap.add_argument("--port", type=int, default=18000)
    ap.add_argument("--dumpcap", default="dumpcap")
    args = ap.parse_args()
    server = subprocess.Popen(
        [sys.executable, str(HERE / "mock_openai.py"), "--port", str(args.port)],
        stdout=subprocess.PIPE, text=True,
    )
    try:
        server.stdout.readline()
        for name in args.scenarios:
            capture(name, args.port, args.dumpcap)
    finally:
        server.terminate()
        server.wait()


if __name__ == "__main__":
    main()
