"""The OpenAI Wire Protocol for mock_server.py: Chat Completions and legacy
Completions (JSON, or SSE when the request sets "stream": true), and
GET /v1/models. A request body that is not JSON gets a 400 JSON error, as
vLLM does. Bodies are fixed, so captures only vary with client headers.
"""

import json

from mock_common import CREATED, MODEL, TOKENS, Reply, error, sse

DONE = b"data: [DONE]\n\n"


def chat_json(req):
    n = len(TOKENS)
    return {
        "id": "chatcmpl-mock-0001",
        "object": "chat.completion",
        "created": CREATED,
        "model": req.get("model", MODEL),
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "".join(TOKENS)},
                "logprobs": None,
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 9, "completion_tokens": n, "total_tokens": 9 + n},
    }


def completion_json(req):
    n = len(TOKENS)
    return {
        "id": "cmpl-mock-0001",
        "object": "text_completion",
        "created": CREATED,
        "model": req.get("model", MODEL),
        "choices": [{"index": 0, "text": "".join(TOKENS), "logprobs": None, "finish_reason": "length"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": n, "total_tokens": 5 + n},
    }


def chat_events(req):
    base = {"id": "chatcmpl-mock-0002", "object": "chat.completion.chunk", "created": CREATED,
            "model": req.get("model", MODEL)}
    yield {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""},
                                "logprobs": None, "finish_reason": None}]}
    for t in TOKENS:
        yield {**base, "choices": [{"index": 0, "delta": {"content": t}, "logprobs": None,
                                    "finish_reason": None}]}
    yield {**base, "choices": [{"index": 0, "delta": {}, "logprobs": None, "finish_reason": "stop"}]}
    if (req.get("stream_options") or {}).get("include_usage"):
        n = len(TOKENS)
        yield {**base, "choices": [], "usage": {"prompt_tokens": 9, "completion_tokens": n,
                                                "total_tokens": 9 + n}}


def completion_events(req):
    base = {"id": "cmpl-mock-0002", "object": "text_completion", "created": CREATED,
            "model": req.get("model", MODEL)}
    for i, t in enumerate(TOKENS):
        last = i == len(TOKENS) - 1
        yield {**base, "choices": [{"index": 0, "text": t, "logprobs": None,
                                    "finish_reason": "length" if last else None}]}


def completions(chat):
    def handle(body, _headers):
        try:
            req = json.loads(body)
        except ValueError:
            return error(400, {"object": "error", "message": "invalid JSON body", "type": "BadRequestError",
                               "code": 400})
        if req.get("stream"):
            events = [sse(e) for e in (chat_events(req) if chat else completion_events(req))]
            return Reply(200, "text/event-stream", events + [DONE])
        doc = chat_json(req) if chat else completion_json(req)
        return Reply(200, "application/json", json.dumps(doc).encode())

    return handle


def models(_body, _headers):
    doc = {"object": "list", "data": [{"id": MODEL, "object": "model", "created": CREATED,
                                       "owned_by": "tokenspectra"}]}
    return Reply(200, "application/json", json.dumps(doc).encode())


ROUTES = {
    ("POST", "/v1/chat/completions"): completions(chat=True),
    ("POST", "/v1/completions"): completions(chat=False),
    ("GET", "/v1/models"): models,
}
