"""OpenAI scenarios for capture.py: the official OpenAI Python SDK (and
httpx for the http_other cases) against mock_openai.py, over HTTP/1.1 or h2c.
"""

import httpx
import openai

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
