"""本地假上游：验证号池 / 协议翻译，而不用真的烧上游配额。

    # 一个「会说 OpenAI 话」的本地模型服务
    python scripts/fake_upstream.py --port 18801 --protocol openai-chat

    # 一个一直回 503 的坏渠道（验证熔断与故障切换）
    python scripts/fake_upstream.py --port 18802 --fail-status 503

两种协议都实现，`--protocol` 决定它说哪种话。配合中转站这样用：

    python -m relayhub.gateway pool add --base-url http://127.0.0.1:18801 --protocol openai-chat --model glm-5.2:1000000
    python -m relayhub.gateway serve --pool <号池文件> --port 18799 --api-key rh_dev
    python -m relayhub.gateway check --base-url http://127.0.0.1:18799 --api-key rh_dev
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from relayhub.gateway.pool import PROTOCOL_ANTHROPIC, PROTOCOL_OPENAI_CHAT  # noqa: E402


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        if self.server.verbose:  # type: ignore[attr-defined]
            print(f"[fake-upstream] {fmt % args}", flush=True)

    # -- 写响应 ----------------------------------------------------------

    def _json(self, status: int, payload: dict) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _begin_sse(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

    def _chunk(self, text: str) -> None:
        data = text.encode("utf-8")
        self.wfile.write(f"{len(data):X}\r\n".encode("ascii") + data + b"\r\n")
        self.wfile.flush()
        delay = self.server.delay  # type: ignore[attr-defined]
        if delay:
            time.sleep(delay)

    def _finish_sse(self) -> None:
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    # -- 路由 ------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?")[0].rstrip("/") != "/v1/models":
            self._json(404, {"error": {"message": f"未知路径 {self.path}"}})
            return
        created = int(time.time())
        self._json(
            200,
            {
                "object": "list",
                "data": [
                    {
                        "id": model,
                        "object": "model",
                        "created": created,
                        "owned_by": "fake-upstream",
                        "context_window": self.server.context_window,  # type: ignore[attr-defined]
                    }
                    for model in self.server.models  # type: ignore[attr-defined]
                ],
            },
        )

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._json(400, {"error": {"message": "请求体不是合法 JSON"}})
            return

        if self.server.fail_status:  # type: ignore[attr-defined]
            self._json(
                self.server.fail_status,  # type: ignore[attr-defined]
                {"error": {"message": f"假上游故意返回 {self.server.fail_status}"}},  # type: ignore[attr-defined]
            )
            return

        # 上游只按自己那套协议回答；中转站该不该翻译由它的测试来断言。
        if self.server.protocol == PROTOCOL_ANTHROPIC:  # type: ignore[attr-defined]
            self._anthropic(body)
        else:
            self._openai(body)

    # -- Anthropic 形态 --------------------------------------------------

    def _anthropic(self, body: dict) -> None:
        model = str(body.get("model") or "unknown")
        text = self.server.text  # type: ignore[attr-defined]
        if body.get("stream"):
            message_id = f"msg_{uuid.uuid4().hex[:24]}"
            self._begin_sse()
            self._chunk(
                "event: message_start\ndata: "
                + json.dumps(
                    {
                        "type": "message_start",
                        "message": {
                            "id": message_id,
                            "type": "message",
                            "role": "assistant",
                            "model": model,
                            "content": [],
                            "stop_reason": None,
                            "stop_sequence": None,
                            "usage": {"input_tokens": 7, "output_tokens": 0},
                        },
                    },
                    ensure_ascii=False,
                )
                + "\n\n"
            )
            self._chunk(
                'event: content_block_start\ndata: {"type":"content_block_start","index":0,'
                '"content_block":{"type":"text","text":""}}\n\n'
            )
            self._chunk(
                "event: content_block_delta\ndata: "
                + json.dumps(
                    {
                        "type": "content_block_delta",
                        "index": 0,
                        "delta": {"type": "text_delta", "text": text},
                    },
                    ensure_ascii=False,
                )
                + "\n\n"
            )
            self._chunk(
                'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n'
            )
            self._chunk(
                'event: message_delta\ndata: {"type":"message_delta",'
                '"delta":{"stop_reason":"end_turn","stop_sequence":null},'
                '"usage":{"output_tokens":5}}\n\n'
            )
            self._chunk('event: message_stop\ndata: {"type":"message_stop"}\n\n')
            self._finish_sse()
            return

        self._json(
            200,
            {
                "id": f"msg_{uuid.uuid4().hex[:24]}",
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [{"type": "text", "text": text}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 7, "output_tokens": 5},
            },
        )

    # -- OpenAI 形态 -----------------------------------------------------

    def _openai(self, body: dict) -> None:
        model = str(body.get("model") or "unknown")
        text = self.server.text  # type: ignore[attr-defined]
        if body.get("stream"):
            stream_id = f"chatcmpl-{uuid.uuid4().hex[:20]}"
            base = {
                "id": stream_id,
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": model,
            }
            self._begin_sse()
            for chunk in (
                {**base, "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}]},
                {**base, "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}]},
                {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
            ):
                self._chunk(f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n")
            # 只有客户端要了 include_usage 才补 usage——和真实 OpenAI 行为一致
            if (body.get("stream_options") or {}).get("include_usage"):
                self._chunk(
                    "data: "
                    + json.dumps(
                        {
                            "choices": [],
                            "usage": {
                                "prompt_tokens": 7,
                                "completion_tokens": 5,
                                "total_tokens": 12,
                            },
                        }
                    )
                    + "\n\n"
                )
            self._chunk("data: [DONE]\n\n")
            self._finish_sse()
            return

        self._json(
            200,
            {
                "id": f"chatcmpl-{uuid.uuid4().hex[:20]}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": text},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12},
            },
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="本地假上游")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18801)
    parser.add_argument("--protocol", default=PROTOCOL_OPENAI_CHAT, choices=[PROTOCOL_ANTHROPIC, PROTOCOL_OPENAI_CHAT])
    parser.add_argument("--model", action="append", help="可重复；默认 glm-5.2")
    parser.add_argument("--text", default="pong-from-fake-upstream", help="固定回复文本")
    parser.add_argument("--context-window", type=int, default=1000000)
    parser.add_argument("--fail-status", type=int, default=0, help="非 0 则所有请求都回这个状态码")
    parser.add_argument("--delay", type=float, default=0.03, help="SSE 事件间隔秒数")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

    server = ThreadingHTTPServer((args.host, args.port), _Handler)
    server.protocol = args.protocol  # type: ignore[attr-defined]
    server.models = args.model or ["glm-5.2"]  # type: ignore[attr-defined]
    server.text = args.text  # type: ignore[attr-defined]
    server.context_window = args.context_window  # type: ignore[attr-defined]
    server.fail_status = args.fail_status  # type: ignore[attr-defined]
    server.delay = args.delay  # type: ignore[attr-defined]
    server.verbose = args.verbose  # type: ignore[attr-defined]

    print(
        f"假上游已启动：http://{args.host}:{args.port}  协议={args.protocol}  "
        f"模型={server.models}  "  # type: ignore[attr-defined]
        + (f"始终失败={args.fail_status}" if args.fail_status else "正常应答")
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
