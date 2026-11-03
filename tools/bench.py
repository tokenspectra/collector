#!/usr/bin/env python3
"""Throughput per core of `collector files` over a capture (TS-27).

Runs the release binary over the given .pcap/.pcapng files, the way an
offline run does (tables, bodies, views, object store, manifest log), and
reports input bytes and packets per CPU-second. The pipeline is one
thread, so CPU time is the cost on one core; wall time includes waiting on
the disk. Each configuration runs --runs times into a fresh directory; the
best run is reported. CPU time and peak RSS are the run's own process,
from wait4(2).

    python3 tools/bench.py ../e2e/ring/*.pcapng
    python3 tools/bench.py --runs 3 --out-dir /dev/shm/bench ../e2e/ring/*.pcapng
"""

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BIN = Path(__file__).resolve().parent.parent / "target/release/collector"

CONFIGS = {
    "default": [],
    "no-bodies": ["--no-bodies"],
}


def cpu_model():
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def run_once(files, extra, out_root):
    out = Path(tempfile.mkdtemp(dir=out_root))
    try:
        t0 = time.perf_counter()
        child = subprocess.Popen([str(BIN), "-q", *extra, "files", "-o", str(out), *map(str, files)])
        # This child's own usage; RUSAGE_CHILDREN's ru_maxrss is the largest
        # of every child so far, cargo build included.
        _, status, usage = os.wait4(child.pid, 0)
        wall = time.perf_counter() - t0
        child.returncode = os.waitstatus_to_exitcode(status)
        if child.returncode != 0:
            raise subprocess.CalledProcessError(child.returncode, child.args)
        manifests = [json.loads(l) for l in open(out / "manifests.jsonl")]
        totals = {k: sum(m["totals"][k] for m in manifests) for k in ("packets", "bytes", "workunits", "flows")}
        return {
            "wall_s": wall,
            "user_s": usage.ru_utime,
            "sys_s": usage.ru_stime,
            "max_rss_mib": usage.ru_maxrss / 1024,
            "windows": len(manifests),
            **totals,
        }
    finally:
        shutil.rmtree(out, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--runs", type=int, default=2)
    ap.add_argument("--out-dir", type=Path,
                    help="where runs write (default: a temp dir); use a real disk, fsync on tmpfs costs nothing")
    ap.add_argument("--config", choices=list(CONFIGS), action="append")
    args = ap.parse_args()
    subprocess.run(["cargo", "build", "--release", "-q"], check=True, cwd=BIN.parent.parent.parent)
    size = sum(f.stat().st_size for f in args.files)
    out_root = args.out_dir or Path(tempfile.gettempdir())
    out_root.mkdir(parents=True, exist_ok=True)
    print(f"{len(args.files)} files, {size / 1e9:.3f} GB; {cpu_model()}, {os.cpu_count()} CPUs", file=sys.stderr)
    report = {"input_bytes": size, "files": len(args.files), "cpu": cpu_model(), "results": {}}
    for name in args.config or list(CONFIGS):
        runs = [run_once(args.files, CONFIGS[name], out_root) for _ in range(args.runs)]
        best = min(runs, key=lambda r: r["user_s"] + r["sys_s"])
        best["max_rss_mib"] = max(r["max_rss_mib"] for r in runs)
        cpu = best["user_s"] + best["sys_s"]
        best.update({
            "cpu_s": cpu,
            "mb_per_cpu_s": size / 1e6 / cpu,
            "wire_mbit_per_cpu_s": best["bytes"] * 8 / 1e6 / cpu,
            "packets_per_cpu_s": best["packets"] / cpu,
            "workunits_per_cpu_s": best["workunits"] / cpu,
            "mb_per_wall_s": size / 1e6 / best["wall_s"],
        })
        report["results"][name] = best
        print(f"{name:>10}: {best['mb_per_cpu_s']:.1f} MB/s per core ({best['wire_mbit_per_cpu_s']:.0f} Mbit/s of wire bytes), "
              f"{best['packets_per_cpu_s']:.0f} packets/s, {best['workunits_per_cpu_s']:.0f} Workunits/s; "
              f"cpu {cpu:.1f} s, wall {best['wall_s']:.1f} s, max RSS {best['max_rss_mib']:.0f} MiB", file=sys.stderr)
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
