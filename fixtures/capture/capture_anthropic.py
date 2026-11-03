"""Anthropic scenarios for capture.py: the official Anthropic Python SDK
against mock_anthropic.py, over HTTP/1.1 or h2c.
"""

import anthropic
import httpx2

from mock_anthropic import OVERLOADED

MODEL = "mock-model"
MESSAGES = [{"role": "user", "content": "Say hello."}]


def sdk(port, http2):
    # The SDK takes httpx2 clients, not httpx.
    http_client = httpx2.Client(http1=not http2, http2=http2)
    return anthropic.Anthropic(
        base_url=f"http://127.0.0.1:{port}", api_key="none", http_client=http_client, max_retries=0
    )


def json_calls(c):
    c.messages.create(model=MODEL, messages=MESSAGES, max_tokens=4)
    # A 400 error body: still a Workunit, with the status and error type.
    try:
        c.messages.create(model=MODEL, messages=MESSAGES, max_tokens=0)
    except anthropic.BadRequestError:
        pass


def sse_calls(c):
    for _ in c.messages.create(model=MODEL, messages=MESSAGES, max_tokens=4, stream=True):
        pass
    # A 200 stream cut off by an `error` event after the first token.
    try:
        for _ in c.messages.create(model=OVERLOADED, messages=MESSAGES, max_tokens=4, stream=True):
            pass
    except anthropic.APIError:
        pass


def with_sdk(http2, calls):
    def run(port):
        c = sdk(port, http2)
        calls(c)
        c.close()

    return run


SCENARIOS = {
    "anthropic_h1_json": with_sdk(False, json_calls),
    "anthropic_h1_sse": with_sdk(False, sse_calls),
    "anthropic_h2c_json": with_sdk(True, json_calls),
    "anthropic_h2c_sse": with_sdk(True, sse_calls),
}
