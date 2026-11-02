# /// script
# requires-python = ">=3.11"
# dependencies = ["openai==3.42.1", "httpx[http2]==0.28.1", "h2==4.4.1"]
# ///
"""Captures real Wire Protocol traffic into golden .pcapng fixtures.

Starts mock_server.py on loopback, then for each scenario starts dumpcap on
`lo`, drives a client (an official SDK, or httpx) against the mock over
HTTP/1.1 or h2c, stops dumpcap and writes
crates/collector/tests/fixtures/<scenario>.pcapng.

Scenarios live with their protocol: capture_openai.py, ... each export
`SCENARIOS`, a dict from fixture name to a function of the port. A new
protocol adds its module and one line to SCENARIO_MODULES, plus its client
SDK to the dependencies above.

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

import capture_openai
import capture_openai_responses

HERE = Path(__file__).resolve().parent
OUT = HERE.parent.parent / "crates/collector/tests/fixtures"

# One line per Wire Protocol.
SCENARIO_MODULES = [capture_openai, capture_openai_responses]


def scenarios():
    table = {}
    for module in SCENARIO_MODULES:
        for name, run in module.SCENARIOS.items():
            if name in table:
                sys.exit(f"scenario {name} defined twice")
            table[name] = run
    return table


SCENARIOS = scenarios()


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
        [sys.executable, str(HERE / "mock_server.py"), "--port", str(args.port)],
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
