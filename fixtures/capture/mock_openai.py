# /// script
# requires-python = ">=3.11"
# dependencies = ["h2==4.4.1"]
# ///
"""A mock OpenAI-compatible server for capturing fixture traffic.

Serves HTTP/1.1 and cleartext HTTP/2 (h2c, prior knowledge) on one port:
a connection that starts with the HTTP/2 preface is HTTP/2. Response bodies
are fixed, so the captured bytes only vary with the client's headers.

Endpoints: POST /v1/chat/completions, POST /v1/completions (JSON, or SSE
when the request sets "stream": true), GET /health, GET /v1/models.
A request body that is not JSON gets a 400 JSON error, as vLLM does.

    uv run fixtures/capture/mock_openai.py --port 18000
"""

import argparse
import asyncio
import json

import h2.config
import h2.connection
import h2.events

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
CREATED = 1_800_000_000
MODEL = "mock-model"
TOKENS = ["Hello", ",", " world", "!"]
# Delay between SSE events, so each one leaves in its own TCP segment.
EVENT_GAP_S = 0.02


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


def sse(event):
    return b"data: " + json.dumps(event, separators=(",", ":")).encode() + b"\n\n"


def route(method, path, body):
    """Returns (status, content_type, body or a list of SSE events)."""
    path = path.split("?", 1)[0]
    if method == "GET" and path == "/health":
        return 200, "application/json", b"{}"
    if method == "GET" and path == "/v1/models":
        models = {"object": "list", "data": [{"id": MODEL, "object": "model", "created": CREATED,
                                              "owned_by": "tokenspectra"}]}
        return 200, "application/json", json.dumps(models).encode()
    if method == "POST" and path in ("/v1/chat/completions", "/v1/completions"):
        try:
            req = json.loads(body)
        except ValueError:
            err = {"object": "error", "message": "invalid JSON body", "type": "BadRequestError", "code": 400}
            return 400, "application/json", json.dumps(err).encode()
        chat = path == "/v1/chat/completions"
        if req.get("stream"):
            events = [sse(e) for e in (chat_events(req) if chat else completion_events(req))]
            return 200, "text/event-stream", events + [b"data: [DONE]\n\n"]
        doc = chat_json(req) if chat else completion_json(req)
        return 200, "application/json", json.dumps(doc).encode()
    return 404, "application/json", b'{"detail":"Not Found"}'


async def serve_h1(first, reader, writer):
    buf = first
    while True:
        while b"\r\n\r\n" not in buf:
            more = await reader.read(65536)
            if not more:
                return
            buf += more
        head, buf = buf.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        headers = {k.strip().lower(): v.strip() for k, v in (l.split(":", 1) for l in lines[1:])}
        length = int(headers.get("content-length", "0"))
        while len(buf) < length:
            more = await reader.read(65536)
            if not more:
                return
            buf += more
        body, buf = buf[:length], buf[length:]
        status, ctype, out = route(method, target, body)
        reason = {200: "OK", 400: "Bad Request", 404: "Not Found"}[status]
        if isinstance(out, list):
            writer.write(f"HTTP/1.1 {status} {reason}\r\ncontent-type: {ctype}; charset=utf-8\r\n"
                         f"transfer-encoding: chunked\r\n\r\n".encode())
            for ev in out:
                await asyncio.sleep(EVENT_GAP_S)
                writer.write(f"{len(ev):x}\r\n".encode() + ev + b"\r\n")
                await writer.drain()
            writer.write(b"0\r\n\r\n")
        else:
            writer.write(f"HTTP/1.1 {status} {reason}\r\ncontent-type: {ctype}\r\n"
                         f"content-length: {len(out)}\r\n\r\n".encode() + out)
        await writer.drain()


async def serve_h2(first, reader, writer):
    conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False, header_encoding="utf-8"))
    conn.initiate_connection()
    writer.write(conn.data_to_send())
    streams = {}
    data = first
    while True:
        for ev in conn.receive_data(data):
            if isinstance(ev, h2.events.RequestReceived):
                streams[ev.stream_id] = [dict(ev.headers), b""]
            elif isinstance(ev, h2.events.DataReceived):
                streams[ev.stream_id][1] += ev.data
                conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
            elif isinstance(ev, h2.events.StreamEnded):
                headers, body = streams.pop(ev.stream_id)
                status, ctype, out = route(headers[":method"], headers[":path"], body)
                conn.send_headers(ev.stream_id, [(":status", str(status)), ("content-type", ctype)])
                if isinstance(out, list):
                    for e in out:
                        writer.write(conn.data_to_send())
                        await writer.drain()
                        await asyncio.sleep(EVENT_GAP_S)
                        conn.send_data(ev.stream_id, e)
                    conn.end_stream(ev.stream_id)
                else:
                    conn.send_data(ev.stream_id, out, end_stream=True)
            elif isinstance(ev, h2.events.ConnectionTerminated):
                writer.write(conn.data_to_send())
                await writer.drain()
                return
        writer.write(conn.data_to_send())
        await writer.drain()
        data = await reader.read(65536)
        if not data:
            return


async def handle(reader, writer):
    try:
        first = b""
        while len(first) < len(PREFACE) and PREFACE.startswith(first):
            more = await reader.read(len(PREFACE) - len(first))
            if not more:
                return
            first += more
        if first == PREFACE:
            await serve_h2(first, reader, writer)
        else:
            await serve_h1(first, reader, writer)
    finally:
        writer.close()


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18000)
    args = ap.parse_args()
    server = await asyncio.start_server(handle, args.host, args.port)
    print(f"listening on {args.host}:{args.port}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
