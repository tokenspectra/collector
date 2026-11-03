"""Ollama native scenarios for capture.py: the official Ollama Python SDK
against a real local Ollama, not the mock, since Ollama is plaintext and gives
the true traffic shape. Pull the model first:

    ollama pull qwen2.5:0.5b && ollama pull all-minilm

PORT tells capture.py to capture this server's port instead of starting the
mock. Greedy decoding, a fixed seed and few tokens keep the files small; the
bytes still vary between captures (durations, timestamps), which is fine
since the committed files are the fixtures.
"""

import os

import httpx
import ollama

PORT = int(os.environ.get("OLLAMA_PORT", "11434"))
MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:0.5b")
EMBED_MODEL = os.environ.get("OLLAMA_EMBED_MODEL", "all-minilm")
OPTIONS = {"seed": 7, "temperature": 0, "num_predict": 8}
MESSAGES = [{"role": "user", "content": "Say hello."}]


def client(port):
    return ollama.Client(host=f"http://127.0.0.1:{port}")


def native(port):
    c = client(port)
    # Streamed (the default): NDJSON, ending in a "done": true line.
    for _ in c.chat(model=MODEL, messages=MESSAGES, options=OPTIONS, stream=True):
        pass
    for _ in c.generate(model=MODEL, prompt="Say hello.", options=OPTIONS, stream=True):
        pass
    # "stream": false: one JSON object.
    c.chat(model=MODEL, messages=MESSAGES, options=OPTIONS, stream=False)
    c.generate(model=MODEL, prompt="Say hello.", options=OPTIONS, stream=False)
    c.embed(model=EMBED_MODEL, input="Say hello.")
    # A model that is not there: a JSON error, still a Workunit.
    try:
        c.chat(model="no-such-model", messages=MESSAGES, stream=False)
    except ollama.ResponseError:
        pass


def openai_compat(port):
    """Ollama's OpenAI-compatible endpoints: these decode as OpenAI."""
    with httpx.Client(base_url=f"http://127.0.0.1:{port}") as c:
        req = {"model": MODEL, "messages": MESSAGES, "seed": 7, "temperature": 0, "max_tokens": 8}
        c.post("/v1/chat/completions", json=req).raise_for_status()
        with c.stream("POST", "/v1/chat/completions", json={**req, "stream": True}) as r:
            r.raise_for_status()
            r.read()


SCENARIOS = {
    "ollama_native": native,
    "ollama_openai_compat": openai_compat,
}
