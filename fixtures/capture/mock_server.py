# /// script
# requires-python = ">=3.11"
# dependencies = ["h2==4.4.1"]
# ///
"""A mock server for capturing fixture traffic, one module per Wire Protocol.

Serves HTTP/1.1 and cleartext HTTP/2 (h2c, prior knowledge) on one port:
a connection that starts with the HTTP/2 preface is HTTP/2. The transport
here is shared; each protocol module (mock_openai.py, ...) only lists its
routes in `ROUTES`, mapping (method, path) to a handler that takes the
request body and lowercase headers and returns a mock_common.Reply. A new
protocol adds its module and one line to PROTOCOLS. GET /health is served
for every protocol.

    uv run fixtures/capture/mock_server.py --port 18000
"""

import argparse
import asyncio
from http import HTTPStatus

import h2.config
import h2.connection
import h2.events

import mock_openai
import mock_openai_responses
from mock_common import Reply

# One line per Wire Protocol. Earlier modules win a (method, path) clash.
PROTOCOLS = [mock_openai, mock_openai_responses]

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
# Delay between stream frames, so each one leaves in its own TCP segment.
EVENT_GAP_S = 0.02


def routes():
    table = {}
    for module in PROTOCOLS:
        for key, handler in module.ROUTES.items():
            table.setdefault(key, handler)
    return table


ROUTES = routes()


def route(method, path, headers, body):
    """Returns (status, content_type, body or a list of frames)."""
    path = path.split("?", 1)[0]
    if method == "GET" and path == "/health":
        return Reply(200, "application/json", b"{}")
    handler = ROUTES.get((method, path))
    if handler is None:
        return Reply(404, "application/json", b'{"detail":"Not Found"}')
    return handler(body, headers)


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
        status, ctype, out = route(method, target, headers, body)
        reason = HTTPStatus(status).phrase
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
                status, ctype, out = route(headers[":method"], headers[":path"], headers, body)
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
