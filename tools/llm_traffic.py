#!/usr/bin/env python3
"""Send random prompts, and sometimes multi-turn conversations, to a local LLM server every N seconds.

Traffic for the Collector to capture. Speaks the OpenAI-compatible
POST /v1/chat/completions (Ollama, llama-server, vLLM, ...), the endpoint
the Collector decodes as Request Workunits. Standard library only:

    python3 tools/llm_traffic.py                          # Ollama on :11434, default model
    python3 tools/llm_traffic.py --model llama3.2:1b --stream --interval 10 --count 6
    python3 tools/llm_traffic.py --host http://localhost:8000 --model my-model   # vLLM
"""

import argparse
import json
import random
import sys
import time
import urllib.request

PROMPTS = [
    "Explain TCP slow start in two sentences.",
    "Write a haiku about datacenters.",
    "What is the capital of Australia?",
    "Give me three tips for writing clean Rust code.",
    "Summarize the plot of Hamlet in one paragraph.",
    "What's the difference between a process and a thread?",
    "Translate 'good morning, how are you?' into Spanish and French.",
    "List five prime numbers greater than 100.",
    "Why is the sky blue? Answer briefly.",
    "Suggest a name for a coffee shop run by robots.",
    "What does HTTP status 418 mean?",
    "Explain bit-exact reproducibility in floating point math.",
]

# Each conversation is a list of user turns; every turn is sent with the full history so far.
CONVERSATIONS = [
    [
        "What is the capital of Australia?",
        "Why wasn't Sydney chosen instead?",
        "Summarize your last two answers in one sentence.",
    ],
    [
        "Write a haiku about datacenters.",
        "Now make it rhyme.",
        "Translate the rhyming version into Spanish.",
    ],
    [
        "Explain TCP slow start in two sentences.",
        "How does congestion avoidance differ from that?",
    ],
    [
        "Suggest a name for a coffee shop run by robots.",
        "Give me a slogan for it.",
        "Write a one-line menu description for its signature drink.",
        "Which of the three things you wrote is the weakest? Improve it.",
    ],
    [
        "List five prime numbers greater than 100.",
        "What is the sum of those numbers?",
        "Is that sum prime?",
    ],
    [
        "What's the difference between a process and a thread?",
        "Give a concrete example where threads are the better choice.",
    ],
    [
        "My name is Ada and I like sailing. Remember that.",
        "Recommend a weekend trip for me.",
        "What's my name and hobby again?",
    ],
]


def read_reply(resp, stream: bool) -> str:
    """Pull the generated text out of an OpenAI-style response, streamed (SSE) or whole."""
    if not stream:
        return json.load(resp)["choices"][0]["message"]["content"]
    parts = []
    for raw in resp:
        line = raw.decode().strip()
        if line.startswith("data:"):
            data = line[len("data:"):].strip()
            if data == "[DONE]":
                break
            delta = json.loads(data)["choices"][0].get("delta", {})
            parts.append(delta.get("content") or "")
    return "".join(parts)


def send(args, prompt: str, history: list[dict]) -> str:
    """POST one request; `history` holds the earlier turns of a conversation (empty for single-turn)."""
    url = f"{args.host}/v1/chat/completions"
    messages = history + [{"role": "user", "content": prompt}]
    payload = {"model": args.model, "messages": messages, "stream": args.stream}
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as resp:
        return read_reply(resp, args.stream)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--model", default="qwen2.5:0.5b", help="model name the server knows (default qwen2.5:0.5b)")
    p.add_argument("--host", default="http://localhost:11434")
    p.add_argument("--interval", type=float, default=20.0, help="seconds between rounds (default 20)")
    p.add_argument("--count", type=int, default=0, help="stop after this many rounds (default 0: run until Ctrl-C)")
    p.add_argument("--seed", type=int, help="seed the prompt choice, for a repeatable sequence")
    p.add_argument("--prompts", help="file with one prompt per line (overrides built-in list)")
    p.add_argument("--stream", action="store_true", help="request a streamed response")
    p.add_argument("--multiturn", type=float, default=0.3,
                   help="probability (0-1) that a round is a multi-turn conversation (default 0.3)")
    p.add_argument("--turn-interval", type=float, default=5.0,
                   help="seconds between turns inside a conversation (default 5)")
    args = p.parse_args()

    if args.seed is not None:
        random.seed(args.seed)
    prompts = PROMPTS
    if args.prompts:
        with open(args.prompts) as f:
            prompts = [line.strip() for line in f if line.strip()]

    n = 0
    conv = 0
    while not args.count or n < args.count:
        n += 1
        if random.random() < args.multiturn:
            conv += 1
            turns = random.choice(CONVERSATIONS)
            label = f"{n} c{conv}"
        else:
            turns = [random.choice(prompts)]
            label = f"{n}"

        history: list[dict] = []
        for t, prompt in enumerate(turns, 1):
            tag = f"[{label}.{t}/{len(turns)}]" if len(turns) > 1 else f"[{label}]"
            print(f"{tag} > {prompt}", flush=True)
            start = time.monotonic()
            try:
                text = send(args, prompt, history)
            except Exception as e:  # keep going on errors, but abandon the conversation
                print(f"{tag} ! error: {e}\n", file=sys.stderr, flush=True)
                break
            print(f"{tag} < ({time.monotonic() - start:.1f}s) {text.strip()}\n", flush=True)
            history += [{"role": "user", "content": prompt}, {"role": "assistant", "content": text}]
            if t < len(turns):
                time.sleep(args.turn_interval)
        if not args.count or n < args.count:
            time.sleep(args.interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
