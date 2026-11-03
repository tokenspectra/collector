"""The Ollama native Wire Protocol for mock_server.py: POST /api/chat and
/api/generate, NDJSON (the default) or one JSON object when the request sets
"stream": false. The fixtures come from a real Ollama (capture_ollama.py);
this mock is for volume, in the mixed workload (workload.py).
"""

import json

from mock_common import MODEL, TOKENS, Reply, error, ndjson

CREATED_AT = "2027-01-15T08:00:00.000000Z"


def done_fields(n):
    return {"done": True, "done_reason": "stop", "total_duration": 1_000_000, "load_duration": 1000,
            "prompt_eval_count": 9, "prompt_eval_duration": 1000, "eval_count": n, "eval_duration": 1000}


def handler(chat):
    def piece(model, text):
        if chat:
            return {"model": model, "created_at": CREATED_AT, "message": {"role": "assistant", "content": text}}
        return {"model": model, "created_at": CREATED_AT, "response": text}

    def handle(body, _headers):
        try:
            req = json.loads(body)
        except ValueError:
            return error(400, {"error": "invalid JSON body"})
        model = req.get("model", MODEL)
        if req.get("stream", True):
            lines = [ndjson({**piece(model, t), "done": False}) for t in TOKENS]
            lines.append(ndjson({**piece(model, ""), **done_fields(len(TOKENS))}))
            return Reply(200, "application/x-ndjson", lines)
        doc = {**piece(model, "".join(TOKENS)), **done_fields(len(TOKENS))}
        return Reply(200, "application/json; charset=utf-8", json.dumps(doc).encode())

    return handle


ROUTES = {
    ("POST", "/api/chat"): handler(chat=True),
    ("POST", "/api/generate"): handler(chat=False),
}
