"""The Anthropic Messages API Wire Protocol for mock_server.py: POST
/v1/messages, JSON or named SSE events when the request sets "stream": true.
Like the real API it answers 400 without an anthropic-version header, and
400 for max_tokens below 1. A streamed request for model "mock-overloaded"
gets a 200 stream that breaks off with an `error` event after the first
token, as the API does when it is overloaded mid-response. Bodies are fixed,
so captures only vary with client headers.
"""

import json

from mock_common import MODEL, TOKENS, Reply, error, sse

OVERLOADED = "mock-overloaded"
# Prompt tokens read from the prompt cache, so the record's extra has one.
CACHE_READ = 6


def invalid(message):
    return error(400, {"type": "error", "error": {"type": "invalid_request_error", "message": message},
                       "request_id": "req_mock_0001"})


def usage(output_tokens):
    return {"input_tokens": 9, "cache_creation_input_tokens": 0, "cache_read_input_tokens": CACHE_READ,
            "output_tokens": output_tokens}


def message_json(req):
    return {
        "id": "msg_mock_0001",
        "type": "message",
        "role": "assistant",
        "model": req.get("model", MODEL),
        "content": [{"type": "text", "text": "".join(TOKENS)}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": usage(len(TOKENS)),
    }


def message_events(req):
    model = req.get("model", MODEL)
    overloaded = model == OVERLOADED
    start = {"id": "msg_mock_0003" if overloaded else "msg_mock_0002", "type": "message", "role": "assistant",
             "model": model, "content": [], "stop_reason": None, "stop_sequence": None, "usage": usage(1)}
    yield sse({"type": "message_start", "message": start}, "message_start")
    yield sse({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
              "content_block_start")
    yield sse({"type": "ping"}, "ping")
    for i, t in enumerate(TOKENS):
        yield sse({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": t}},
                  "content_block_delta")
        if overloaded and i == 0:
            yield sse({"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}, "error")
            return
    yield sse({"type": "content_block_stop", "index": 0}, "content_block_stop")
    yield sse({"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
               "usage": {"output_tokens": len(TOKENS)}}, "message_delta")
    yield sse({"type": "message_stop"}, "message_stop")


def messages(body, headers):
    if "anthropic-version" not in headers:
        return invalid("anthropic-version: header is required")
    try:
        req = json.loads(body)
    except ValueError:
        return invalid("invalid JSON body")
    if req.get("max_tokens", 0) < 1:
        return invalid("max_tokens: must be greater than or equal to 1")
    if req.get("stream"):
        return Reply(200, "text/event-stream", list(message_events(req)))
    return Reply(200, "application/json", json.dumps(message_json(req)).encode())


ROUTES = {
    ("POST", "/v1/messages"): messages,
}
