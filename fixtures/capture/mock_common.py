"""What every mock Wire Protocol module shares: the reply shape, fixed values
and stream framing helpers. See mock_server.py.
"""

import json
from typing import NamedTuple

CREATED = 1_800_000_000
MODEL = "mock-model"
TOKENS = ["Hello", ",", " world", "!"]


class Reply(NamedTuple):
    """A response. `body` is bytes, or a list of frames (SSE events, NDJSON
    lines) that the server sends one at a time, chunked on HTTP/1.1, with a
    pause between them so each leaves in its own TCP segment."""

    status: int
    content_type: str
    body: bytes | list[bytes]


def compact(doc):
    return json.dumps(doc, separators=(",", ":")).encode()


def sse(doc, event=None):
    """One SSE event: `data:` only, or named with `event`."""
    head = f"event: {event}\n".encode() if event else b""
    return head + b"data: " + compact(doc) + b"\n\n"


def ndjson(doc):
    """One NDJSON line."""
    return compact(doc) + b"\n"


def error(status, doc):
    return Reply(status, "application/json", json.dumps(doc).encode())
