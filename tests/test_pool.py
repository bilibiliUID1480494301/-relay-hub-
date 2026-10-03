"""号池与协议转换测试。

两层验证：
  * 单元层：熔断跳闸/冷却、候选排序、用量记账、持久化、请求翻译。
  * 集成层：起「假上游」（可切 anthropic / openai 协议、可切成故障），
    让真实 KeyPoolRouter 去发请求，再对着中转站跑一致性探测。
    其中「OpenAI 协议上游也要能通过 Anthropic 一致性探测」是最关键的一条——
    它才真正证明协议翻译是对的。
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator

import pytest

from relayhub.gateway import conformance, upstream
from relayhub.gateway.pool import (
    PROTOCOL_ANTHROPIC,
    PROTOCOL_OPENAI_CHAT,
    TIER_DISABLE,
    TIER_ERR,
    KeyPool,
    PoolError,
    UpstreamKey,
)
from relayhub.gateway.router import (
    KeyPoolRouter,
    ReloadingRouter,
    RouterError,
    config_fingerprint,
)
from relayhub.gateway.service import RelayServer
from relayhub.gateway.upstream import UpstreamError

REPLY_TEXT = "pong-from-upstream"


# ================================================================ 假上游


class _FakeUpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        return

    # -- 工具 ------------------------------------------------------------

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

    # -- 响应 ------------------------------------------------------------

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

    def _openai_stream(self, include_usage: bool, tool_reply: bool = False) -> None:
        self._begin_sse()
        if tool_reply:
            for chunk in (
                {"choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}]},
                {
                    "choices": [
                        {
                            "index": 0,
                            "delta": {
                                "tool_calls": [
                                    {
                                        "index": 0,
                                        "id": "call_test",
                                        "type": "function",
                                        "function": {"name": "get_weather", "arguments": ""},
                                    }
                                ]
                            },
                            "finish_reason": None,
                        }
                    ]
                },
                {
                    "choices": [
                        {
                            "index": 0,
                            "delta": {
                                "tool_calls": [
                                    {"index": 0, "function": {"arguments": '{"city": "北京"}'}}
                                ]
                            },
                            "finish_reason": None,
                        }
                    ]
                },
                {"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]},
            ):
                self._chunk(f"data: {json.dumps(chunk)}\n\n")
            if include_usage:
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
            self._openai_stream(
                bool((body.get("stream_options") or {}).get("include_usage")),
                bool(server.tool_reply),  # type: ignore[attr-defined]
            )
            return
        if server.tool_reply:  # type: ignore[attr-defined]
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
                            "message": {
                                "role": "assistant",
                                "content": "",
                                "tool_calls": [
                                    {
                                        "id": "call_test",
                                        "type": "function",
                                        "function": {
                                            "name": "get_weather",
                                            "arguments": '{"city": "北京"}',
                                        },
                                    }
                                ],
                            },
                            "finish_reason": "tool_calls",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 7,
                        "completion_tokens": 5,
                        "total_tokens": 12,
                    },
                },
            )
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
        tool_reply: bool = False,
    ) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeUpstreamHandler)
        self.server.protocol = protocol  # type: ignore[attr-defined]
        self.server.fail_status = fail_status  # type: ignore[attr-defined]
        self.server.tool_reply = tool_reply  # type: ignore[attr-defined]
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


def _key(label: str, base_url: str, protocol: str = PROTOCOL_ANTHROPIC, **kwargs: Any) -> UpstreamKey:
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
def _gateway(router: Any, api_key: str | None = None) -> Iterator[str]:
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


# ================================================================ 号池单元


def test_round_robin_rotates_start_point() -> None:
    pool = KeyPool([_key("a", "http://a"), _key("b", "http://b"), _key("c", "http://c")])
    first = [k.label for k in pool.candidates("glm-5.2")]
    second = [k.label for k in pool.candidates("glm-5.2")]
    assert first == ["a", "b", "c"]
    assert second == ["b", "c", "a"]


def test_least_failures_puts_healthy_key_first() -> None:
    keys = [_key("a", "http://a"), _key("b", "http://b")]
    pool = KeyPool(keys, strategy="least_failures")
    pool.report_failure(keys[0], "boom", trip=False)
    assert [k.label for k in pool.candidates("glm-5.2")][0] == "b"


def test_model_filter_excludes_unrelated_keys() -> None:
    relevant = _key("relevant", "http://a")
    other = UpstreamKey(
        key_id=str(uuid.uuid4()), label="other", base_url="http://b", api_key="k", models=("x",)
    )
    pool = KeyPool([relevant, other])
    assert [k.label for k in pool.candidates("glm-5.2")] == ["relevant"]
    # models 为空表示对全部模型开放
    open_key = UpstreamKey(
        key_id=str(uuid.uuid4()), label="open", base_url="http://c", api_key="k"
    )
    assert open_key.supports("anything")


def test_breaker_trips_then_cools_down() -> None:
    clock = {"now": 1000.0}
    keys = [_key("a", "http://a")]
    pool = KeyPool(
        keys, failure_threshold=2, cooldown_tiers={"err": 30.0}, clock=lambda: clock["now"]
    )

    pool.report_failure(keys[0], UpstreamError(503, "down", True))
    assert pool.candidates("glm-5.2") != []
    pool.report_failure(keys[0], UpstreamError(503, "down", True))
    assert pool.candidates("glm-5.2") == []

    clock["now"] += 29.0
    assert pool.candidates("glm-5.2") == []
    clock["now"] += 2.0
    assert [k.label for k in pool.candidates("glm-5.2")] == ["a"]


def test_non_retryable_failure_does_not_trip_breaker() -> None:
    keys = [_key("a", "http://a")]
    pool = KeyPool(keys, failure_threshold=1)
    pool.report_failure(keys[0], UpstreamError(400, "bad request", False), trip=False)
    assert keys[0].consecutive_failures == 0
    assert pool.candidates("glm-5.2") != []
    assert keys[0].usage.failed == 1


def test_success_resets_breaker_and_records_usage() -> None:
    keys = [_key("a", "http://a")]
    pool = KeyPool(keys, failure_threshold=2)
    pool.report_failure(keys[0], UpstreamError(503, "down", True))
    pool.report_success(keys[0], 7, 5)
    assert keys[0].consecutive_failures == 0
    assert (keys[0].usage.requests, keys[0].usage.ok) == (2, 1)
    assert (keys[0].usage.tokens_in, keys[0].usage.tokens_out) == (7, 5)


def test_pool_round_trips_through_disk(tmp_path: Path) -> None:
    path = tmp_path / "pool.json"
    keys = [_key("a", "http://a")]
    pool = KeyPool(keys, cooldown_tiers={"err": 15.0})
    pool.report_success(keys[0], 3, 4)
    pool.report_failure(keys[0], UpstreamError(500, "x", True))
    pool.save(path)

    reloaded = KeyPool.load(path)
    assert reloaded.cooldown_tiers["err"] == 15.0
    assert len(reloaded.keys) == 1
    key = reloaded.keys[0]
    assert key.label == "a"
    assert key.usage.tokens_in == 3
    assert (key.usage.ok, key.usage.failed) == (1, 1)
    assert key.model_windows == {"glm-5.2": 1000000}


def test_disable_and_reenable_key() -> None:
    keys = [_key("a", "http://a")]
    pool = KeyPool(keys)
    assert pool.set_enabled("a", False)
    assert pool.candidates("glm-5.2") == []
    assert pool.set_enabled("a", True)
    assert pool.candidates("glm-5.2") != []


def test_all_models_skips_disabled_keys() -> None:
    """/v1/models 的模型清单不收录已禁用渠道——列出一个必然 503 的模型只会误导客户端。

    冷却中的 Key 仍算启用：冷却会恢复，不该让模型清单来回抖动。
    """
    good = _key("good", "http://good")
    disabled = _key("off", "http://off", protocol=PROTOCOL_OPENAI_CHAT)
    disabled.models = ("qwen3-32b",)  # 只有禁用渠道声明的模型
    disabled.enabled = False
    cooling = _key("cool", "http://cool", protocol=PROTOCOL_OPENAI_CHAT)
    cooling.models = ("deepseek-v3",)
    cooling.disabled_until = time.time() + 600  # 冷却中，但 enabled=True
    pool = KeyPool([good, disabled, cooling])

    models = sorted(pool.all_models())
    assert "qwen3-32b" not in models  # 禁用渠道：不进清单
    assert "glm-5.2" in models and "deepseek-v3" in models  # 启用+冷却中：都进清单

    assert pool.set_enabled("off", True)
    assert "qwen3-32b" in pool.all_models()  # 重新启用即回到清单


# ================================================================ 请求翻译


def test_to_openai_request_moves_system_and_flattens_content() -> None:
    out = upstream.to_openai_request(
        {
            "model": "m",
            "max_tokens": 64,
            "system": "be terse",
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "hi"}]},
                {"role": "assistant", "content": "hello"},
            ],
        }
    )
    assert out["messages"][0] == {"role": "system", "content": "be terse"}
    assert out["messages"][1] == {"role": "user", "content": "hi"}
    assert out["messages"][2] == {"role": "assistant", "content": "hello"}
    assert out["max_tokens"] == 64


def test_to_openai_request_translates_anthropic_tools_and_tool_use() -> None:
    """Anthropic tools/tool_use/tool_result → OpenAI tools/tool_calls/tool 角色。"""
    out = upstream.to_openai_request(
        {
            "model": "m",
            "max_tokens": 64,
            "tools": [
                {
                    "name": "get_weather",
                    "description": "查天气",
                    "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}},
                }
            ],
            "messages": [
                {"role": "user", "content": "北京天气？"},
                {
                    "role": "assistant",
                    "content": [
                        {"type": "text", "text": "好"},
                        {
                            "type": "tool_use",
                            "id": "tu_1",
                            "name": "get_weather",
                            "input": {"city": "北京"},
                        },
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "tool_use_id": "tu_1", "content": "晴 25℃"}
                    ],
                },
            ],
        }
    )
    assert out["tools"] == [
        {
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "查天气",
                "parameters": {"type": "object", "properties": {"city": {"type": "string"}}},
            },
        }
    ]
    asst = out["messages"][1]
    assert asst["role"] == "assistant"
    assert asst["tool_calls"] == [
        {
            "id": "tu_1",
            "type": "function",
            "function": {"name": "get_weather", "arguments": '{"city": "北京"}'},
        }
    ]
    assert out["messages"][2] == {"role": "tool", "tool_call_id": "tu_1", "content": "晴 25℃"}


def test_normalize_base_appends_v1_like_client_does() -> None:
    assert upstream.normalize_base("http://h:1") == "http://h:1/v1"
    assert upstream.normalize_base("http://h:1/") == "http://h:1/v1"
    assert upstream.normalize_base("http://h:1/v1") == "http://h:1/v1"
    assert upstream.normalize_base("http://h:1/anthropic") == "http://h:1/anthropic/v1"


def test_to_anthropic_message_maps_usage_and_stop_reason() -> None:
    message, tokens_in, tokens_out = upstream.to_anthropic_message(
        {
            "choices": [{"message": {"content": "ok"}, "finish_reason": "length"}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 22},
        },
        "m",
    )
    assert message["content"][0]["text"] == "ok"
    assert message["stop_reason"] == "max_tokens"
    assert (tokens_in, tokens_out) == (11, 22)
    assert message["usage"] == {"input_tokens": 11, "output_tokens": 22}


# ================================================================ 入站翻译（OpenAI 客户端）


def test_to_anthropic_request_hoists_system_and_fills_max_tokens() -> None:
    out = upstream.to_anthropic_request(
        {
            "model": "m",
            "messages": [
                {"role": "system", "content": "只回答一个字"},
                {"role": "user", "content": [{"type": "text", "text": "hi"}]},
            ],
            "stop": "END",
        }
    )
    # Anthropic 的 system 是顶层字段，不是一条消息
    assert out["system"] == "只回答一个字"
    assert out["messages"] == [{"role": "user", "content": "hi"}]
    assert out["stop_sequences"] == ["END"]
    # OpenAI 客户端不传 max_tokens，但 Anthropic 上游必填
    assert out["max_tokens"] == upstream.DEFAULT_MAX_TOKENS


def test_to_anthropic_request_translates_openai_tools_and_tool_calls() -> None:
    """OpenAI tools/tool_calls/tool 角色 → Anthropic tools/tool_use/tool_result 块。"""
    out = upstream.to_anthropic_request(
        {
            "model": "m",
            "messages": [
                {"role": "system", "content": "只回一个字"},
                {"role": "user", "content": "北京天气？"},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "get_weather", "arguments": '{"city": "北京"}'},
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": "call_1", "content": "晴 25℃"},
            ],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "description": "查天气",
                        "parameters": {"type": "object", "properties": {"city": {"type": "string"}}},
                    },
                }
            ],
        }
    )
    assert out["system"] == "只回一个字"
    assert out["tools"] == [
        {
            "name": "get_weather",
            "description": "查天气",
            "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}},
        }
    ]
    assert out["messages"][1] == {
        "role": "assistant",
        "content": [
            {
                "type": "tool_use",
                "id": "call_1",
                "name": "get_weather",
                "input": {"city": "北京"},
            }
        ],
    }
    assert out["messages"][2] == {
        "role": "user",
        "content": [{"type": "tool_result", "tool_use_id": "call_1", "content": "晴 25℃"}],
    }


def test_openai_client_to_openai_upstream_tool_calls_round_trip() -> None:
    """OpenAI 客户端 + OpenAI 上游（都带 tools）：网关归一化到 Anthropic IR 再还原回 OpenAI 形态。

    这是「网关内部只认一种规范形态」最直接的证明——请求经过
    OpenAI→Anthropic→OpenAI 两次翻译后，tool_calls 必须原样回到客户端。
    """
    with FakeUpstream(protocol=PROTOCOL_OPENAI_CHAT, tool_reply=True) as up:
        pool = KeyPool([_key("up", up.base_url, protocol=PROTOCOL_OPENAI_CHAT)])
        with _gateway(KeyPoolRouter(pool)) as base:
            response = conformance.Probe(base).post(
                "/v1/chat/completions",
                {
                    "model": "glm-5.2",
                    "tools": [
                        {
                            "type": "function",
                            "function": {
                                "name": "get_weather",
                                "description": "查天气",
                                "parameters": {
                                    "type": "object",
                                    "properties": {"city": {"type": "string"}},
                                },
                            },
                        }
                    ],
                    "messages": [{"role": "user", "content": "北京天气？"}],
                },
            )[0]

    assert response.status == 200
    payload = json.loads(response.body.decode("utf-8"))
    assert payload["object"] == "chat.completion"
    msg = payload["choices"][0]["message"]
    assert msg["tool_calls"][0]["function"]["name"] == "get_weather"
    assert msg["tool_calls"][0]["function"]["arguments"] == '{"city": "北京"}'
    # 上游确实收到了翻译后的 OpenAI 形态请求（tools 已是 OpenAI 结构）
    sent = up.requests[0]["body"]
    assert sent["tools"][0]["type"] == "function"


def test_anthropic_client_to_openai_upstream_tool_use_round_trip() -> None:
    """Anthropic 客户端 + OpenAI 上游：上游回 tool_calls，网关要还原成 Anthropic 的 tool_use 块。"""
    with FakeUpstream(protocol=PROTOCOL_OPENAI_CHAT, tool_reply=True) as up:
        pool = KeyPool([_key("up", up.base_url, protocol=PROTOCOL_OPENAI_CHAT)])
        with _gateway(KeyPoolRouter(pool)) as base:
            response = conformance.Probe(base).post(
                "/v1/messages",
                {
                    "model": "glm-5.2",
                    "max_tokens": 64,
                    "tools": [
                        {
                            "name": "get_weather",
                            "description": "查天气",
                            "input_schema": {
                                "type": "object",
                                "properties": {"city": {"type": "string"}},
                            },
                        }
                    ],
                    "messages": [{"role": "user", "content": "北京天气？"}],
                },
            )[0]

    assert response.status == 200
    payload = json.loads(response.body.decode("utf-8"))
    assert payload["type"] == "message"
    tool_use = next(b for b in payload["content"] if b.get("type") == "tool_use")
    assert tool_use["name"] == "get_weather"
    assert tool_use["input"] == {"city": "北京"}


def test_openai_client_to_openai_upstream_tool_calls_stream() -> None:
    """流式：OpenAI 上游的 tool_calls 碎片要聚合成 OpenAI 客户端的 tool_calls chunk 序列。"""
    with FakeUpstream(protocol=PROTOCOL_OPENAI_CHAT, tool_reply=True) as up:
        pool = KeyPool([_key("up", up.base_url, protocol=PROTOCOL_OPENAI_CHAT)])
        with _gateway(KeyPoolRouter(pool)) as base:
            response, lines = conformance.Probe(base).post(
                "/v1/chat/completions",
                {
                    "model": "glm-5.2",
                    "stream": True,
                    "messages": [{"role": "user", "content": "北京天气？"}],
                },
                streaming=True,
                read_stream=True,
            )

    assert response.status == 200
    events = conformance.parse_sse(lines)
    chunks = [json.loads(data) for _, data in events if data and data != "[DONE]"]
    # OpenAI 的 SSE chunk 里 tool_calls 嵌在 choices[0].delta.tool_calls 下。
    collected: dict[int, dict[str, Any]] = {}
    for chunk in chunks:
        choices = chunk.get("choices") or [{}]
        choice = choices[0] if choices else {}
        delta = (choice or {}).get("delta") or {}
        for tc in delta.get("tool_calls", []) or []:
            idx = tc.get("index", 0)
            entry = collected.setdefault(idx, {"id": None, "name": "", "args": ""})
            if tc.get("id"):
                entry["id"] = tc["id"]
            if tc.get("function", {}).get("name"):
                entry["name"] = tc["function"]["name"]
            entry["args"] += tc.get("function", {}).get("arguments", "") or ""
    assert collected[0]["name"] == "get_weather"
    assert collected[0]["args"] == '{"city": "北京"}'
    last = [c for c in chunks if c.get("choices", [{}])[0].get("finish_reason")]
    assert last and last[-1]["choices"][0]["finish_reason"] == "tool_calls"


def test_openai_client_request_is_translated_for_anthropic_upstream() -> None:
    """OpenAI 客户端 + Anthropic 上游：请求体必须被翻译，不能原样怼给 /messages。

    这是「网关内部只认一种规范形态」的关键证据——少了它，上游会把 system 角色
    当成一轮普通对话，或者干脆报错，而且不报错的那种最难查。
    """
    with FakeUpstream(protocol=PROTOCOL_ANTHROPIC) as up:
        pool = KeyPool([_key("up", up.base_url, protocol=PROTOCOL_ANTHROPIC)])
        with _gateway(KeyPoolRouter(pool)) as base:
            response = conformance.Probe(base).post(
                "/v1/chat/completions",
                {
                    "model": "glm-5.2",
                    "messages": [
                        {"role": "system", "content": "只回答一个字"},
                        {"role": "user", "content": "hi"},
                    ],
                },
            )[0]

    assert response.status == 200
    sent = up.requests[0]["body"]
    assert up.requests[0]["path"].endswith("/v1/messages")
    assert sent["system"] == "只回答一个字"
    assert sent["messages"] == [{"role": "user", "content": "hi"}]
    assert sent["max_tokens"] > 0
    assert "stream_options" not in sent

    # 回给客户端的必须是 OpenAI 形态（choices[0].message）
    payload = json.loads(response.body.decode("utf-8"))
    assert payload["object"] == "chat.completion"
    assert payload["choices"][0]["message"]["content"] == REPLY_TEXT


def test_unknown_model_on_openai_path_uses_openai_error_shape() -> None:
    """两个口共用路由，但错误体形状各按各的规矩来。"""
    pool = KeyPool([_key("up", "http://127.0.0.1:1")])
    with _gateway(KeyPoolRouter(pool)) as base:
        response = conformance.Probe(base).post(
            "/v1/chat/completions", {"model": "nope", "messages": []}
        )[0]

    assert response.status == 404
    payload = json.loads(response.body.decode("utf-8"))
    assert "error" in payload
    assert "type" not in payload  # 顶层 type 是 Anthropic 的形状，不能混进来


# ================================================================ 路由集成


def test_router_fails_over_and_records_both_keys() -> None:
    with FakeUpstream(fail_status=503) as broken, FakeUpstream() as healthy:
        pool = KeyPool([_key("broken", broken.base_url), _key("healthy", healthy.base_url)])
        router = KeyPoolRouter(pool)
        outcome = router.relay("glm-5.2", {"messages": [{"role": "user", "content": "hi"}]}, False)

    assert outcome.label == "healthy"
    assert outcome.attempts == ["broken", "healthy"]
    assert outcome.message is not None
    assert outcome.message["content"][0]["text"] == REPLY_TEXT
    broken_key = pool.find_by_label("broken")
    healthy_key = pool.find_by_label("healthy")
    assert broken_key is not None and broken_key.usage.failed == 1
    assert broken_key.consecutive_failures == 1
    assert healthy_key is not None and healthy_key.usage.ok == 1
    assert pool.totals().tokens_in == 7


def test_router_raises_when_every_key_is_down() -> None:
    with FakeUpstream(fail_status=503) as first, FakeUpstream(fail_status=500) as second:
        pool = KeyPool([_key("a", first.base_url), _key("b", second.base_url)])
        router = KeyPoolRouter(pool)
        with pytest.raises(RouterError, match="全部 2 个渠道都失败"):
            router.relay("glm-5.2", {"messages": []}, False)


def test_router_reports_missing_model_clearly() -> None:
    pool = KeyPool([_key("a", "http://127.0.0.1:1")])
    router = KeyPoolRouter(pool)
    with pytest.raises(RouterError, match="没有任何 Key 声明支持模型"):
        router.relay("not-in-pool", {"messages": []}, False)


def test_disabled_channel_reports_a_distinct_reason() -> None:
    """「全部不可用」有两种原因，排查方向完全不同，不能糊成一句。

    这条分支是端到端真跑才抓出来的（`is_available()` 少传 now 直接 TypeError，
    客户端看到的是连接被掐断）——所以它必须留一条测试钉住。
    """
    keys = [_key("a", "http://a")]
    pool = KeyPool(keys)
    pool.set_enabled("a", False)
    router = KeyPoolRouter(pool)
    with pytest.raises(RouterError, match="已禁用") as info:
        router.relay("glm-5.2", {"messages": []}, False)
    assert info.value.status == 503
    assert "熔断冷却中" not in str(info.value)


def test_cooling_channel_reports_breaker_reason() -> None:
    clock = {"now": 1000.0}
    keys = [_key("a", "http://a")]
    pool = KeyPool(
        keys, failure_threshold=1, cooldown_tiers={"err": 30.0}, clock=lambda: clock["now"]
    )
    pool.report_failure(keys[0], UpstreamError(503, "down", True))
    router = KeyPoolRouter(pool)
    with pytest.raises(RouterError, match="熔断冷却中") as info:
        router.relay("glm-5.2", {"messages": []}, False)
    assert info.value.status == 503
    assert "已禁用" not in str(info.value)


def test_streaming_peek_prevents_header_before_failover() -> None:
    """流式：第一个 Key 连不上时必须在写响应头之前就换掉它。"""
    with FakeUpstream(fail_status=503) as broken, FakeUpstream() as healthy:
        pool = KeyPool([_key("broken", broken.base_url), _key("healthy", healthy.base_url)])
        router = KeyPoolRouter(pool)
        outcome = router.relay("glm-5.2", {"messages": []}, True)
        assert outcome.label == "healthy"
        events = list(outcome.events or [])
    names = [name for name, _ in events]
    assert names == [
        "message_start",
        "content_block_start",
        "content_block_delta",
        "content_block_stop",
        "message_delta",
        "message_stop",
    ]
    healthy_key = pool.find_by_label("healthy")
    assert healthy_key is not None and healthy_key.usage.ok == 1


# ================================================================ 端到端：协议翻译


@pytest.mark.parametrize("protocol", [PROTOCOL_ANTHROPIC, PROTOCOL_OPENAI_CHAT])
def test_conformance_passes_regardless_of_upstream_protocol(protocol: str) -> None:
    """最关键的一条：上游是 OpenAI 协议时，Anthropic 客户端也必须探测全过。

    这才能真正证明协议翻译（含流式）是对的，而不是「看起来字段差不多」。
    """
    with FakeUpstream(protocol=protocol) as up:
        pool = KeyPool([_key("up", up.base_url, protocol=protocol)])
        router = KeyPoolRouter(pool)
        server = RelayServer(("127.0.0.1", 0), router, api_key="rh_k", event_delay=0.03)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            results = conformance.run_checks(server.base_url, "rh_k")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    failures = [f"{r.name}: {r.detail}" for r in results if not r.ok]
    assert failures == [], failures

    # 上游真的收到了 OpenAI 形态的请求（而不是把 anthropic 原文发过去）
    first_post = up.requests[0]
    if protocol == PROTOCOL_OPENAI_CHAT:
        assert first_post["path"].endswith("/v1/chat/completions")
        assert first_post["headers"].get("authorization") == "Bearer up_key"
        assert "messages" in first_post["body"]
    else:
        assert first_post["path"].endswith("/v1/messages")
        assert first_post["headers"].get("x-api-key") == "up_key"


def test_openai_upstream_gets_system_as_system_message() -> None:
    """Anthropic 的顶层 system 必须落到 OpenAI 的 system 角色上，不能丢。"""
    with FakeUpstream(protocol=PROTOCOL_OPENAI_CHAT) as up:
        pool = KeyPool([_key("up", up.base_url, protocol=PROTOCOL_OPENAI_CHAT)])
        router = KeyPoolRouter(pool)
        router.relay(
            "glm-5.2",
            {"system": "只回答一个字", "messages": [{"role": "user", "content": "hi"}]},
            False,
        )
    assert up.requests[0]["body"]["messages"][0] == {"role": "system", "content": "只回答一个字"}


def test_usage_from_openai_stream_is_recorded() -> None:
    with FakeUpstream(protocol=PROTOCOL_OPENAI_CHAT) as up:
        pool = KeyPool([_key("up", up.base_url, protocol=PROTOCOL_OPENAI_CHAT)])
        router = KeyPoolRouter(pool)
        outcome = router.relay("glm-5.2", {"messages": []}, True)
        list(outcome.events or [])
        key = pool.find_by_label("up")
    assert key is not None
    assert (key.usage.tokens_in, key.usage.tokens_out) == (7, 5)


# ================================================================ 号池文件 · 热加载 · CLI


def _write_pool(path: Path, *keys: UpstreamKey, **options: Any) -> KeyPool:
    pool = KeyPool(list(keys), **options)
    pool.save(path)
    return pool


def test_config_fingerprint_ignores_runtime_state(tmp_path: Path) -> None:
    """用量与熔断状态变化不能算成「配置变了」。

    这是防「每请求 reload 一次」的那道闸：中转站每服务一个请求都会把用量落盘，
    若指纹把运行时字段算进去，round-robin 游标会被反复重置，
    轮询就悄悄退化成「永远挑第一个 Key」——单请求的测试根本看不出来。
    """
    path = tmp_path / "pool.json"
    key = _key("a", "http://a")
    pool = _write_pool(path, key)
    before = config_fingerprint(path)

    pool.report_success(key, 11, 22)
    pool.report_failure(key, UpstreamError(503, "down", True))
    pool.save(path)
    assert config_fingerprint(path) == before

    pool.add(_key("b", "http://b"))
    pool.save(path)
    assert config_fingerprint(path) != before


def test_reloading_router_sees_externally_added_key(tmp_path: Path) -> None:
    """不重启中转站，往号池文件里加一个 Key 就该生效。"""
    path = tmp_path / "pool.json"
    _write_pool(path, _key("a", "http://a"))
    router = ReloadingRouter(path)
    assert sorted(router.models()) == ["glm-5.2"]

    added = _key("b", "http://b", protocol=PROTOCOL_OPENAI_CHAT)
    added.models = ("qwen3-32b",)
    added.model_windows = {"qwen3-32b": 4096}
    pool = KeyPool.load(path)
    pool.add(added)
    pool.save(path)

    assert sorted(router.models()) == ["glm-5.2", "qwen3-32b"]
    assert router.models()["qwen3-32b"] == 4096


def test_pool_edit_recovers_service_without_restart(tmp_path: Path) -> None:
    """整条栈真跑：号池只指向坏上游 → 改号池 → 同一个中转站进程恢复出结果。"""
    path = tmp_path / "pool.json"
    with FakeUpstream(fail_status=503) as broken, FakeUpstream(
        protocol=PROTOCOL_OPENAI_CHAT
    ) as healthy:
        _write_pool(path, _key("dead", broken.base_url))
        router = ReloadingRouter(path)
        with _gateway(router) as base:
            probe = conformance.Probe(base)
            request = {
                "model": "glm-5.2",
                "max_tokens": 8,
                "messages": [{"role": "user", "content": "hi"}],
            }
            first = probe.post("/v1/messages", request)[0]
            assert first.status == 502, first.body  # 号池里唯一的渠道是坏的

            # 老师机上加一个能用的渠道——就是这个动作不该掐断正在答题的客户端
            pool = KeyPool.load(path)
            pool.add(_key("alive", healthy.base_url, protocol=PROTOCOL_OPENAI_CHAT))
            pool.save(path)

            second = probe.post("/v1/messages", request)[0]
            assert second.status == 200
            payload = json.loads(second.body.decode("utf-8"))
            assert payload["content"][0]["text"] == REPLY_TEXT

    assert healthy.requests[0]["path"].endswith("/v1/chat/completions")


def test_cli_pool_round_trip(tmp_path: Path) -> None:
    from relayhub.gateway.__main__ import main as cli_main

    path = tmp_path / "pool.json"
    assert cli_main(["pool", "init", "--pool", str(path)]) == 0
    assert (
        cli_main(
            [
                "pool",
                "add",
                "--pool",
                str(path),
                "--base-url",
                "http://127.0.0.1:9001",
                "--api-key",
                "sk-abcdefgh1234",
                "--label",
                "local",
                "--protocol",
                PROTOCOL_OPENAI_CHAT,
                "--model",
                "glm-5.2:1000000",
                "--model",
                "qwen3-32b",
            ]
        )
        == 0
    )
    key = KeyPool.load(path).find_by_label("local")
    assert key is not None
    assert key.protocol == PROTOCOL_OPENAI_CHAT
    assert key.models == ("glm-5.2", "qwen3-32b")
    assert key.model_windows == {"glm-5.2": 1000000}

    # 重名必须挡住，除非显式 --replace
    dup = ["pool", "add", "--pool", str(path), "--base-url", "http://x", "--label", "local"]
    assert cli_main(dup) == 1
    assert cli_main(dup + ["--replace"]) == 0
    assert len(KeyPool.load(path).keys) == 1

    assert cli_main(["pool", "disable", "--pool", str(path), "local"]) == 0
    disabled = KeyPool.load(path).find_by_label("local")
    assert disabled is not None and disabled.enabled is False
    assert cli_main(["pool", "ls", "--pool", str(path)]) == 0
    assert cli_main(["pool", "stats", "--pool", str(path), "--json"]) == 0
    assert cli_main(["pool", "enable", "--pool", str(path), "local"]) == 0
    assert cli_main(["pool", "rm", "--pool", str(path), "local"]) == 0
    assert KeyPool.load(path).keys == []


def test_cli_masks_upstream_key(tmp_path: Path, capsys: Any) -> None:
    """终端里的东西经常被截图贴群，上游 Key 不能整串打出来。"""
    from relayhub.gateway.__main__ import main as cli_main

    path = tmp_path / "pool.json"
    cli_main(["pool", "init", "--pool", str(path)])
    cli_main(
        [
            "pool",
            "add",
            "--pool",
            str(path),
            "--base-url",
            "http://h:9001",
            "--api-key",
            "sk-supersecret-9999",
            "--label",
            "k",
        ]
    )
    capsys.readouterr()
    cli_main(["pool", "ls", "--pool", str(path)])
    out = capsys.readouterr().out
    assert "sk-supersecret-9999" not in out
    assert "…9999" in out


# ================================================================ 模型映射 / 优先级 / 健康探测


def test_model_mapping_publishes_clean_names() -> None:
    """/v1/models 只露对外名；supports 按对外名判定。"""
    key = _key("a", "http://a")
    key.models = ("[满血]GLM-5.2", "[满血2]GLM-5.2")
    key.model_mapping = {"glm-5.2": "[满血]GLM-5.2"}
    pool = KeyPool([key])
    assert pool.all_models() == ["glm-5.2"]  # [满血2] 不对外
    assert key.supports("glm-5.2") is True
    assert key.supports("[满血]GLM-5.2") is False  # 对外名匹配，上游名不外露
    assert key.map_to_upstream("glm-5.2") == "[满血]GLM-5.2"
    assert key.map_to_upstream("other") == "other"  # 未映射名透传


def test_candidates_order_by_priority_then_strategy() -> None:
    """高优先级在前；同优先级组内才轮转——主/备语义。"""
    backup = _key("backup", "http://backup")
    primary_b = _key("primary-b", "http://primary-b")
    primary_a = _key("primary-a", "http://primary-a")
    primary_a.priority = 10
    primary_b.priority = 10
    backup.priority = 0
    pool = KeyPool([backup, primary_a, primary_b])

    first = pool.candidates("glm-5.2")
    assert [k.label for k in first][:2] in (["primary-a", "primary-b"], ["primary-b", "primary-a"])
    assert first[-1].label == "backup"  # 低优先级永远垫底

    # 主渠道全部冷却 → 备用顶上
    for key in (primary_a, primary_b):
        key.disabled_until = pool.now() + 9999
    assert [k.label for k in pool.candidates("glm-5.2")] == ["backup"]


def test_model_windows_reverse_mapped_to_public_names() -> None:
    key = _key("a", "http://a")
    key.models = ("[满血]GLM-5.2",)
    key.model_windows = {"[满血]GLM-5.2": 128000}
    key.model_mapping = {"glm-5.2": "[满血]GLM-5.2"}
    assert KeyPool([key]).model_windows() == {"glm-5.2": 128000}


def test_report_health_clears_err_but_never_disable() -> None:
    """健康恢复只洗白 err 冷却；鉴权失效（disable 档）绝不被 TCP 握手洗白。"""
    err_key = _key("err", "http://err")
    disable_key = _key("dis", "http://dis")
    disable_key.enabled = False
    disable_key.cooldown_tier = TIER_DISABLE
    pool = KeyPool([err_key, disable_key])

    err_key.cooldown_tier = TIER_ERR
    err_key.consecutive_failures = 3
    err_key.disabled_until = pool.now() + 600
    pool.report_health(err_key, ok=True)
    assert err_key.is_available(pool.now()) and err_key.cooldown_tier == ""

    pool.report_health(err_key, ok=False)
    assert err_key.consecutive_failures == 1  # 失败按通用错误计连败

    pool.report_health(disable_key, ok=True)
    assert disable_key.cooldown_tier == TIER_DISABLE and disable_key.enabled is False


def test_retries_config_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "pool.json"
    pool = KeyPool([_key("a", "http://a")], retries=3)
    pool.save(path)
    assert KeyPool.load(path).retries == 3
    with pytest.raises(PoolError):
        KeyPool([_key("a", "http://a")], retries=0)
