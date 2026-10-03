"""测试共用的假上游与网关夹具。

抽出来是因为 `test_pool.py`（号池路由）和 `test_admin.py`（管理面）都要一个
「能说两种协议、能被切成故障」的上游和一个起网关的上下文管理器。
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterator

from relayhub.gateway.pool import PROTOCOL_ANTHROPIC, UpstreamKey
from relayhub.gateway.service import RelayServer

REPLY_TEXT = "pong-from-upstream"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        return

    def _record(self, body: dict[str, Any]) -> None:
        self.server.requests.append(  # type: ignore[attr-defined]
            {
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": body,
            }
        )

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _chunk(self, text: str) -> None:
        data = text.encode("utf-8")
        self.wfile.write(f"{len(data):X}\r\n".encode("ascii") + data + b"\r\n")
        self.wfile.flush()

    def _begin_sse(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

    def _finish_sse(self) -> None:
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def _anthropic_stream(self) -> None:
        model = "glm-5.2"
        self._begin_sse()
        self._chunk(
            "event: message_start\n"
            + 'data: {"type":"message_start","message":{"id":"msg_up","type":"message",'
            + f'"role":"assistant","model":"{model}","content":[],"stop_reason":null,'
            + '"usage":{"input_tokens":7,"output_tokens":0}}}\n\n'
        )
        self._chunk(
            'event: content_block_start\ndata: {"type":"content_block_start","index":0,'
            '"content_block":{"type":"text","text":""}}\n\n'
        )
        self._chunk(
            'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,'
            f'"delta":{{"type":"text_delta","text":"{REPLY_TEXT}"}}}}\n\n'
        )
        self._chunk('event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n')
        self._chunk(
            'event: message_delta\ndata: {"type":"message_delta",'
            '"delta":{"stop_reason":"end_turn","stop_sequence":null},'
            '"usage":{"output_tokens":5}}\n\n'
        )
        self._chunk('event: message_stop\ndata: {"type":"message_stop"}\n\n')
        self._finish_sse()

    def _openai_stream(self, include_usage: bool) -> None:
        self._begin_sse()
        for chunk in (
            {"choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}]},
            {"choices": [{"index": 0, "delta": {"content": REPLY_TEXT}, "finish_reason": None}]},
            {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
        ):
            self._chunk(f"data: {json.dumps(chunk)}\n\n")
        if include_usage:
            self._chunk(
                "data: "
                + json.dumps(
                    {
                        "choices": [],
                        "usage": {"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12},
                    }
                )
                + "\n\n"
            )
        self._chunk("data: [DONE]\n\n")
        self._finish_sse()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            body = {}
        self._record(body)

        server = self.server
        if server.fail_status:  # type: ignore[attr-defined]
            self._json(server.fail_status, {"error": "upstream is down"})  # type: ignore[attr-defined]
            return

        streaming = bool(body.get("stream"))
        if server.protocol == PROTOCOL_ANTHROPIC:  # type: ignore[attr-defined]
            if streaming:
                self._anthropic_stream()
                return
            self._json(
                200,
                {
                    "id": "msg_up",
                    "type": "message",
                    "role": "assistant",
                    "model": body.get("model"),
                    "content": [{"type": "text", "text": REPLY_TEXT}],
                    "stop_reason": "end_turn",
                    "stop_sequence": None,
                    "usage": {"input_tokens": 7, "output_tokens": 5},
                },
            )
            return

        if streaming:
            self._openai_stream(bool((body.get("stream_options") or {}).get("include_usage")))
            return
        self._json(
            200,
            {
                "id": "chatcmpl-up",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": body.get("model"),
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": REPLY_TEXT},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12},
            },
        )


class FakeUpstream:
    def __init__(
        self,
        protocol: str = PROTOCOL_ANTHROPIC,
        fail_status: int = 0,
    ) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.protocol = protocol  # type: ignore[attr-defined]
        self.server.fail_status = fail_status  # type: ignore[attr-defined]
        self.server.requests = []  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "FakeUpstream":
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    @property
    def requests(self) -> list[dict[str, Any]]:
        return self.server.requests  # type: ignore[attr-defined]


def make_key(
    label: str, base_url: str, protocol: str = PROTOCOL_ANTHROPIC, **kwargs: Any
) -> UpstreamKey:
    return UpstreamKey(
        key_id=str(uuid.uuid4()),
        label=label,
        base_url=base_url,
        api_key="up_key",
        protocol=protocol,
        models=("glm-5.2",),
        model_windows={"glm-5.2": 1000000},
        **kwargs,
    )


@contextmanager
def gateway_for(router: Any, api_key: str | None = None) -> Iterator[str]:
    """起一个中转站，yield 出 base_url。"""
    server = RelayServer(("127.0.0.1", 0), router, api_key=api_key, event_delay=0.0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.base_url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
