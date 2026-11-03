"""The OpenAI Responses API for mock_server.py: POST /v1/responses, as one
JSON response object, or named SSE events when the request sets
"stream": true.

- `max_output_tokens` below the reply's length cuts it short: status
  `incomplete`, reason `max_output_tokens`.
- Model `missing-model` gets a 404 JSON error, as OpenAI sends.
- Model `failing-model` streams `response.failed` with a server error.

A request body that is not JSON gets a 400 JSON error. Bodies are fixed, so
captures only vary with client headers.
"""

import json

from mock_common import CREATED, MODEL, TOKENS, Reply, error, sse

RESP_ID = "resp_mock_0001"
MSG_ID = "msg_mock_0001"
INPUT_TOKENS = 9


def plan(req):
    """(status, incomplete reason, tokens sent, error) for a request."""
    if req.get("model") == "failing-model":
        return "failed", None, TOKENS[:1], {"code": "server_error", "message": "The model failed."}
    cap = req.get("max_output_tokens")
    if isinstance(cap, int) and cap < len(TOKENS):
        return "incomplete", "max_output_tokens", TOKENS[:cap], None
    return "completed", None, TOKENS, None


def message(tokens, status):
    return {
        "id": MSG_ID,
        "type": "message",
        "status": status,
        "role": "assistant",
        "content": [{"type": "output_text", "text": "".join(tokens), "annotations": [], "logprobs": []}],
    }


def response(req, status, reason=None, tokens=(), err=None, final=True):
    """The response object; `final` adds the output and usage."""
    n = len(tokens)
    return {
        "id": RESP_ID,
        "object": "response",
        "created_at": CREATED,
        "status": status,
        "background": False,
        "error": err,
        "incomplete_details": {"reason": reason} if reason else None,
        "instructions": None,
        "max_output_tokens": req.get("max_output_tokens"),
        "model": req.get("model", MODEL),
        "output": [message(tokens, "completed" if status == "completed" else "incomplete")] if final else [],
        "parallel_tool_calls": True,
        "previous_response_id": req.get("previous_response_id"),
        "service_tier": "default",
        "store": True,
        "temperature": 1.0,
        "text": {"format": {"type": "text"}},
        "tool_choice": "auto",
        "tools": [],
        "top_p": 1.0,
        "truncation": "disabled",
        "usage": {
            "input_tokens": INPUT_TOKENS,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens": n,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": INPUT_TOKENS + n,
        } if final else None,
        "metadata": {},
    }


def events(req):
    """(type, data) for each event, in the order OpenAI sends them."""
    status, reason, tokens, err = plan(req)
    yield "response.created", {"response": response(req, "in_progress", final=False)}
    yield "response.in_progress", {"response": response(req, "in_progress", final=False)}
    item = message([], "in_progress")
    item["content"] = []
    yield "response.output_item.added", {"output_index": 0, "item": item}
    part = {"type": "output_text", "text": "", "annotations": [], "logprobs": []}
    yield "response.content_part.added", {"item_id": MSG_ID, "output_index": 0, "content_index": 0, "part": part}
    for t in tokens:
        yield "response.output_text.delta", {"item_id": MSG_ID, "output_index": 0, "content_index": 0,
                                             "delta": t, "logprobs": []}
    if status == "failed":
        yield "response.failed", {"response": response(req, status, tokens=tokens, err=err)}
        return
    text = "".join(tokens)
    yield "response.output_text.done", {"item_id": MSG_ID, "output_index": 0, "content_index": 0,
                                        "text": text, "logprobs": []}
    done = message(tokens, "completed" if status == "completed" else "incomplete")
    yield "response.content_part.done", {"item_id": MSG_ID, "output_index": 0, "content_index": 0,
                                         "part": done["content"][0]}
    yield "response.output_item.done", {"output_index": 0, "item": done}
    yield f"response.{status}", {"response": response(req, status, reason, tokens)}


def responses(body, _headers):
    try:
        req = json.loads(body)
    except ValueError:
        return error(400, {"error": {"message": "We could not parse the JSON body of your request.",
                                     "type": "invalid_request_error", "param": None, "code": None}})
    if req.get("model") == "missing-model":
        return error(404, {"error": {"message": "The model `missing-model` does not exist.",
                                     "type": "invalid_request_error", "param": "model",
                                     "code": "model_not_found"}})
    if req.get("stream"):
        frames = [sse({"type": kind, "sequence_number": seq, **data}, event=kind)
                  for seq, (kind, data) in enumerate(events(req))]
        return Reply(200, "text/event-stream", frames)
    status, reason, tokens, err = plan(req)
    doc = response(req, status, reason, tokens, err)
    return Reply(200, "application/json", json.dumps(doc).encode())


ROUTES = {
    ("POST", "/v1/responses"): responses,
}
