"""中转站 HTTP 服务层。

负责：鉴权、路由分发、SSE 写入、把结果编码成客户端要的字节形态。
不负责：选哪个上游 Key、坏了怎么办、用量怎么记——那是 `router.py` + `pool.py`。

`DemoRouter` 是返回固定文本的假路由，只当测试靶子用。
真跑请用 `router.KeyPoolRouter`。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable, Iterator

from .. import paths
from .. import __version__ as relayhub_version
from . import audit as audit_module
from . import clients as clients_module
from . import pluginlogs
from . import reqlog
from . import toip as toip_module
from .router import RelayOutcome, RouterError

ident_module = None  # 未安装客户端扩展包时的占位：身份头整段跳过
from .tokens import SCOPE_TEST, DownstreamToken, TokenStore, generate_token
from .upstream import UpstreamError, cache_from_usage, to_anthropic_request
from .users import RedeemStore, UserError, UserStore

ANTHROPIC_VERSION = "2023-06-01"


class ChannelError(RuntimeError):
    """演示用渠道故障（真实上游错误见 upstream.UpstreamError）。"""


@dataclass
class Channel:
    name: str
    models: dict[str, int] = field(default_factory=dict)
    broken: bool = False
    failures: int = 0
    successes: int = 0

    def complete(self, model: str, prompt: str) -> str:
        if self.broken:
            self.failures += 1
            raise ChannelError(f"channel {self.name} is down")
        self.successes += 1
        return f"[{self.name}] 收到 {len(prompt)} 字符，模型 {model}。"


class ChannelPool:
    """演示用渠道池：轮询 + 失败跳过。不含真实上游调用。"""

    def __init__(self, channels: list[Channel]) -> None:
        if not channels:
            raise ValueError("渠道池不能为空")
        self.channels = channels
        self._cursor = 0

    def candidates(self) -> Iterator[Channel]:
        total = len(self.channels)
        start = self._cursor
        self._cursor = (self._cursor + 1) % total
        for offset in range(total):
            yield self.channels[(start + offset) % total]

    def complete(self, model: str, prompt: str) -> tuple[str, Channel]:
        last: ChannelError | None = None
        for channel in self.candidates():
            try:
                return channel.complete(model, prompt), channel
            except ChannelError as exc:
                last = exc
        raise ChannelError(f"所有渠道均失败：{last}")

    def known_models(self) -> dict[str, int]:
        merged: dict[str, int] = {}
        for channel in self.channels:
            for model, window in channel.models.items():
                merged.setdefault(model, window)
        return merged


# ---------------------------------------------------------------- 请求解析


def extract_prompt(body: dict[str, Any]) -> str:
    """从两种协议的请求体里取出最后一条用户消息的文本。"""
    messages = body.get("messages") or []
    for message in reversed(messages):
        content = message.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            texts = [
                part.get("text", "")
                for part in content
                if isinstance(part, dict) and part.get("type") == "text"
            ]
            if texts:
                return "".join(texts)
    if isinstance(body.get("input"), str):
        return body["input"]
    return ""


# ---------------------------------------------------------------- 响应编码


def anthropic_message(
    model: str, text: str, input_tokens: int = 12, output_tokens: int = 8
) -> dict[str, Any]:
    return {
        "id": f"msg_{uuid.uuid4().hex[:24]}",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
    }


def anthropic_events(
    model: str,
    text: str,
    input_tokens: int = 12,
    output_tokens: int = 8,
    deltas: int = 1,
) -> list[tuple[str, dict[str, Any]]]:
    """Anthropic 流式事件序列。顺序与字段名必须严格正确，客户端才会接受。

    deltas>1 时把 text 均分成多段 delta（合成应答模拟真实生成节奏用），
    事件序列依然是合法形状：多个 content_block_delta 是真实模型的常态。
    """
    if deltas > 1:
        size = max(1, len(text) // deltas)
        pieces = [text[i : i + size] for i in range(0, len(text), size)][:deltas]
    else:
        pieces = [text] if text else [""]
    message_id = f"msg_{uuid.uuid4().hex[:24]}"
    events: list[tuple[str, dict[str, Any]]] = [
        (
            "message_start",
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
                    "usage": {"input_tokens": input_tokens, "output_tokens": 0},
                },
            },
        ),
        (
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        ),
    ]
    for piece in pieces:
        events.append(
            (
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": piece},
                },
            )
        )
    events.extend(
        [
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            (
                "message_delta",
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                    "usage": {"output_tokens": output_tokens},
                },
            ),
            ("message_stop", {"type": "message_stop"}),
        ]
    )
    return events


# Anthropic stop_reason → OpenAI finish_reason（upstream.py 里那份是反方向，别混用）
_FINISH_REASON_FROM_ANTHROPIC = {
    "end_turn": "stop",
    "max_tokens": "length",
    "stop_sequence": "stop",
    "tool_use": "tool_calls",
}


def _message_text(message: dict[str, Any]) -> str:
    pieces: list[str] = []
    for block in message.get("content") or []:
        if isinstance(block, dict) and block.get("type") == "text":
            pieces.append(str(block.get("text") or ""))
    return "".join(pieces)


def openai_completion(model: str, message: dict[str, Any]) -> dict[str, Any]:
    """Anthropic message → OpenAI chat.completion。

    路由层统一吐 Anthropic 形态（因为上游可能是 anthropic 也可能是 openai），
    所以「给 OpenAI 客户端的那一份」只能在这一层降级生成。
    message 里若含 tool_use 块，要还原成 OpenAI 的 tool_calls。
    """
    usage = message.get("usage") or {}
    tokens_in = int(usage.get("input_tokens") or 0)
    tokens_out = int(usage.get("output_tokens") or 0)
    text = _message_text(message)
    tool_uses = [
        block
        for block in message.get("content") or []
        if isinstance(block, dict) and block.get("type") == "tool_use"
    ]
    assistant: dict[str, Any] = {
        "role": "assistant",
        "content": text if not tool_uses else (text or ""),
    }
    if tool_uses:
        assistant["tool_calls"] = [
            {
                "id": block.get("id"),
                "type": "function",
                "function": {
                    "name": block.get("name"),
                    "arguments": json.dumps(block.get("input") or {}, ensure_ascii=False),
                },
            }
            for block in tool_uses
        ]
    return {
        "id": str(message.get("id") or f"chatcmpl-{uuid.uuid4().hex[:20]}"),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": str(message.get("model") or model),
        "choices": [
            {
                "index": 0,
                "message": assistant,
                "finish_reason": _FINISH_REASON_FROM_ANTHROPIC.get(
                    str(message.get("stop_reason")), "stop"
                ),
            }
        ],
        "usage": {
            "prompt_tokens": tokens_in,
            "completion_tokens": tokens_out,
            "total_tokens": tokens_in + tokens_out,
        },
    }


# ---------------- Responses API（OpenAI 新口 /v1/responses） ----------------


def _responses_content_text(content):
    """Responses 的 content（str / list[input_text|output_text 块]）→ 纯文本。"""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    parts = []
    items = content if isinstance(content, list) else [content]
    for c in items:
        if isinstance(c, dict):
            parts.append(str(c.get("text") or c.get("content") or ""))
        else:
            parts.append(str(c))
    return "".join(parts)


def responses_to_chat(body):
    """Responses 请求 → OpenAI chat 请求（随后走 to_anthropic_request 归一化）。

    input 支持 string 与 items 列表（message / function_call_output）；
    instructions 映射为 system；max_output_tokens 映射为 max_tokens；
    reasoning 等网关无法透传的字段安全忽略。
    """
    msgs = []
    if body.get("instructions"):
        msgs.append({"role": "system", "content": str(body["instructions"])})
    inp = body.get("input")
    if isinstance(inp, str):
        msgs.append({"role": "user", "content": inp})
    elif isinstance(inp, list):
        for item in inp:
            if not isinstance(item, dict):
                msgs.append({"role": "user", "content": str(item)})
                continue
            itype = item.get("type", "message")
            if itype == "function_call_output":
                msgs.append({"role": "tool", "tool_call_id": str(item.get("call_id") or ""),
                             "content": str(item.get("output") or "")})
                continue
            if itype in ("reasoning", "item_reference"):
                continue  # 网关不存推理态，安全丢弃
            role = item.get("role", "user")
            if role not in ("user", "assistant", "system", "developer"):
                role = "user"
            text = _responses_content_text(item.get("content"))
            if role == "developer":
                role = "system"
            msgs.append({"role": role, "content": text})
    else:
        msgs.append({"role": "user", "content": ""})

    chat = {"messages": msgs}
    for k in ("model", "temperature", "top_p", "stream", "tools", "tool_choice",
              "parallel_tool_calls", "user", "metadata"):
        if body.get(k) is not None:
            chat[k] = body[k]
    if body.get("max_output_tokens"):
        chat["max_tokens"] = body["max_output_tokens"]
    return chat


def responses_completion(model, message):
    """Anthropic message（网关 IR）→ Responses 非流式应答。"""
    usage = message.get("usage") or {}
    tokens_in = int(usage.get("input_tokens") or 0)
    tokens_out = int(usage.get("output_tokens") or 0)
    text = _message_text(message)
    rid = "resp_" + uuid.uuid4().hex[:24]
    mid = "msg_" + uuid.uuid4().hex[:24]
    return {
        "id": rid,
        "object": "response",
        "created_at": int(time.time()),
        "status": "completed",
        "model": model,
        "output": [{
            "type": "message", "id": mid, "role": "assistant",
            "status": "completed",
            "content": [{"type": "output_text", "text": text, "annotations": []}],
        }],
        "output_text": text,
        "usage": {"input_tokens": tokens_in, "output_tokens": tokens_out,
                  "total_tokens": tokens_in + tokens_out},
        "parallel_tool_calls": True,
    }


def responses_chunks(model, events):
    """Anthropic 事件流 → Responses SSE (event, payload) 序列（真增量）。

    事件序：response.created → output_item.added → content_part.added →
    每个 text_delta 一个 response.output_text.delta → text/part/item.done →
    response.completed（带 usage）。
    """
    rid = "resp_" + uuid.uuid4().hex[:24]
    mid = "msg_" + uuid.uuid4().hex[:24]
    created = int(time.time())
    seq = 0
    buf = ""
    tokens_in = tokens_out = 0

    def ev(name, payload):
        nonlocal seq
        seq += 1
        return (name, {"type": name, "sequence_number": seq, **payload})

    def resp_stub(status):
        return {"id": rid, "object": "response", "created_at": created,
                "status": status, "model": model, "output": [],
                "usage": {"input_tokens": tokens_in, "output_tokens": tokens_out,
                          "total_tokens": tokens_in + tokens_out}}

    yield ev("response.created", {"response": resp_stub("in_progress")})
    yield ev("response.in_progress", {"response": resp_stub("in_progress")})
    yield ev("response.output_item.added", {
        "output_index": 0,
        "item": {"type": "message", "id": mid, "role": "assistant",
                 "status": "in_progress", "content": []},
    })
    yield ev("response.content_part.added", {
        "item_id": mid, "output_index": 0, "content_index": 0,
        "part": {"type": "output_text", "text": "", "annotations": []},
    })
    for name, payload in events:
        if name == "message_start":
            u = (payload.get("message") or {}).get("usage") or {}
            tokens_in = int(u.get("input_tokens") or 0)
        elif name == "content_block_delta":
            d = payload.get("delta") or {}
            if d.get("type") == "text_delta":
                piece = d.get("text") or ""
                buf += piece
                yield ev("response.output_text.delta", {
                    "item_id": mid, "output_index": 0, "content_index": 0,
                    "delta": piece,
                })
        elif name == "message_delta":
            u = payload.get("usage") or {}
            tokens_out = int(u.get("output_tokens") or tokens_out)
    yield ev("response.output_text.done", {
        "item_id": mid, "output_index": 0, "content_index": 0, "text": buf,
    })
    yield ev("response.content_part.done", {
        "item_id": mid, "output_index": 0, "content_index": 0,
        "part": {"type": "output_text", "text": buf, "annotations": []},
    })
    yield ev("response.output_item.done", {
        "output_index": 0,
        "item": {"type": "message", "id": mid, "role": "assistant",
                 "status": "completed",
                 "content": [{"type": "output_text", "text": buf, "annotations": []}]},
    })
    done = resp_stub("completed")
    done["output"] = [{
        "type": "message", "id": mid, "role": "assistant", "status": "completed",
        "content": [{"type": "output_text", "text": buf, "annotations": []}],
    }]
    done["output_text"] = buf
    yield ev("response.completed", {"response": done})


def openai_chunks(
    model: str, events: Iterable[tuple[str, dict[str, Any]]]
) -> Iterator[dict[str, Any]]:
    """Anthropic 事件流 → OpenAI chat.completion.chunk 序列（不含末尾的 [DONE]）。

    真增量：每来一个 content_block_delta 立刻吐一个 chunk。若先把整条流收完再切分，
    OpenAI 客户端那边就退化成「等半天然后文字一次性出现」，SSE 白开了。
    """
    stream_id = f"chatcmpl-{uuid.uuid4().hex[:20]}"
    created = int(time.time())

    def chunk(
        delta: dict[str, Any],
        finish_reason: str | None = None,
        usage: dict[str, int] | None = None,
    ) -> dict[str, Any]:
        item: dict[str, Any] = {
            "id": stream_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
        }
        if usage is not None:
            item["usage"] = usage
        return item

    yield chunk({"role": "assistant", "content": ""})
    tokens_in = tokens_out = 0
    finish_reason = "stop"
    # Anthropic content 块索引 → OpenAI tool_calls 索引（文本块不占 tool_calls）
    tool_index_map: dict[int, int] = {}
    next_tool_idx = 0
    for name, payload in events:
        if name == "message_start":
            usage = (payload.get("message") or {}).get("usage") or {}
            tokens_in = int(usage.get("input_tokens") or 0)
            tokens_out = int(usage.get("output_tokens") or 0)
        elif name == "content_block_start":
            block = payload.get("content_block") or {}
            if block.get("type") == "tool_use":
                ai = int(payload.get("index") or 0)
                oi = tool_index_map.setdefault(ai, next_tool_idx)
                if oi == next_tool_idx:
                    next_tool_idx += 1
                yield chunk(
                    {
                        "tool_calls": [
                            {
                                "index": oi,
                                "id": block.get("id"),
                                "type": "function",
                                "function": {"name": block.get("name"), "arguments": ""},
                            }
                        ]
                    }
                )
        elif name == "content_block_delta":
            delta = payload.get("delta") or {}
            dtype = delta.get("type")
            if dtype == "text_delta" and delta.get("text"):
                yield chunk({"content": str(delta["text"])})
            elif dtype == "input_json_delta":
                ai = int(payload.get("index") or 0)
                oi = tool_index_map.get(ai, 0)
                yield chunk(
                    {
                        "tool_calls": [
                            {"index": oi, "function": {"arguments": delta.get("partial_json", "")}}
                        ]
                    }
                )
        elif name == "message_delta":
            delta = payload.get("delta") or {}
            finish_reason = _FINISH_REASON_FROM_ANTHROPIC.get(
                str(delta.get("stop_reason")), finish_reason
            )
            usage = payload.get("usage") or {}
            tokens_out = max(tokens_out, int(usage.get("output_tokens") or 0))
        elif name == "error":
            error = payload.get("error") or {}
            raise ChannelError(str(error.get("message") or payload))
    yield chunk({}, finish_reason)
    yield chunk(
        {},
        None,
        usage={
            "prompt_tokens": tokens_in,
            "completion_tokens": tokens_out,
            "total_tokens": tokens_in + tokens_out,
        },
    )


class DemoRouter:
    """返回固定文本的假路由，仅用于测试与演示。"""

    def __init__(self, pool: ChannelPool) -> None:
        self.pool = pool

    def models(self) -> dict[str, int]:
        return self.pool.known_models()

    def relay(
        self,
        model: str,
        payload: dict[str, Any],
        stream: bool,
        trace_headers: dict[str, str] | None = None,
        fp: str | None = None,
    ) -> RelayOutcome:
        text, channel = self.pool.complete(model, extract_prompt(payload))
        if stream:
            return RelayOutcome(
                label=channel.name, model=model, events=iter(anthropic_events(model, text))
            )
        return RelayOutcome(
            label=channel.name, model=model, message=anthropic_message(model, text)
        )


class TestRouter:
    """测试密钥（scope=test）专用路由：只回本地合成应答，绝不触达真实上游。

    用途：把网关挂上公网给第三方做性能测试——他们测到的是中转站自身的
    吞吐 / 延迟 / SSE 行为，不烧渠道配额，也摸不到真实模型。
    设计取舍：
      * 任意模型名都接（性能测试不在乎模型存不存在），所以 models() 返回空表；
      * 应答体量跟 max_tokens 成比例，让不同规模的压测有可比的传输量；
      * usage 按字节数估算，形态真实但数字与任何真实模型无关。
    """

    LABEL = "test-echo"

    def models(self) -> dict[str, int]:
        return {}

    def relay(
        self,
        model: str,
        payload: dict[str, Any],
        stream: bool,
        trace_headers: dict[str, str] | None = None,
        fp: str | None = None,
    ) -> RelayOutcome:
        prompt = extract_prompt(payload)
        try:
            max_tokens = int(payload.get("max_tokens") or 256)
        except (TypeError, ValueError):
            max_tokens = 256
        max_tokens = max(16, min(max_tokens, 4096))
        # 粗略按 1 token ≈ 4 字节合成正文；流式切成 24 段模拟真实生成节奏
        text = f"[relay-hub test-echo model={model}] " + "x" * (max_tokens * 4)
        tokens_in = max(1, len(prompt) // 4)
        tokens_out = max_tokens
        if stream:
            return RelayOutcome(
                label=self.LABEL,
                model=model,
                events=iter(
                    anthropic_events(
                        model, text, input_tokens=tokens_in, output_tokens=tokens_out, deltas=24
                    )
                ),
            )
        return RelayOutcome(
            label=self.LABEL,
            model=model,
            message=anthropic_message(
                model, text, input_tokens=tokens_in, output_tokens=tokens_out
            ),
        )


class RateLimiter:
    """进程内滑动窗口限流（令牌 RPM）。

    刻意不落盘：RPM 是短窗行为控制，重启清零无伤大雅；要持久的是
    日配额，那在 tokens.py 的 usage 里。窗口按令牌全文分桶——
    token_id 在热加载后对象会换，字符串身份不会。
    """

    def __init__(self, window_seconds: float = 60.0) -> None:
        self._window = window_seconds
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def check(self, secret: str, rpm: int) -> bool:
        """放行 =True；超限 =False（且本次不计入，不惩罚重试者）。"""
        if rpm <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            hits = [t for t in self._hits.get(secret, ()) if now - t < self._window]
            if len(hits) >= rpm:
                self._hits[secret] = hits
                return False
            hits.append(now)
            self._hits[secret] = hits
            # 顺手回收已清空的桶，防长跑膨胀
            if len(self._hits) > 1024:
                self._hits = {k: v for k, v in self._hits.items() if v}
            return True


class ConcurrencyGate:
    """并发闸门 + 有限排队（搜题场景的「排队不拒绝」）+ 优先队列。

    纯 429 限流在课堂场景体验很差：40 个学生同时交卷，只有前几个能拿到
    应答，剩下的直接失败还得手动重试。这里改成：在飞请求超过上限时进
    等待队列，排到就继续处理；只对两种情况才回 429——
      * 等待队列本身满了（说明排队也排不上了，硬拒）；
      * 排到了但一直没轮上（等到 queue_timeout 超时）。

    **优先队列**：acquire(priority=True) 的请求排 VIP 队——名额一释放先
    唤醒 VIP 等待者，普通队只在无 VIP 时被叫醒；新到的 VIP 更是直接插队
    （有空位就拿走，不等普通等待者醒来再抢）。谁是 VIP 由 policy.py 的
    优先名单决定（设备 ID / 令牌名 / IP），老师高峰期把自己或值班设备
    标优先即可。

    两个等待池共用同一把互斥锁（分别建 Condition），release 时刻意先叫
    VIP 队——这是唯一偏心的地方。进程内存态，重启清零；
    与 RateLimiter 互补——那个限「发起频率」，这个限「同时在跑多少个」。
    """

    def __init__(self, max_in_flight: int, queue_size: int, queue_timeout: float) -> None:
        self._max_in_flight = max(1, max_in_flight)
        self._queue_size = max(0, queue_size)
        self._queue_timeout = max(0.0, queue_timeout)
        mutex = threading.Lock()
        self._prio = threading.Condition(mutex)
        self._norm = threading.Condition(mutex)
        self._in_flight = 0
        self._prio_waiting = 0
        self._norm_waiting = 0

    def acquire(self, priority: bool = False) -> bool:
        """拿到并发名额 =True；队列满/排队超时 =False。priority=True 排 VIP 队。"""
        if self._queue_timeout <= 0 and self._in_flight >= self._max_in_flight:
            return False  # 配置成不排队：满即拒
        deadline = time.monotonic() + self._queue_timeout
        cond = self._prio if priority else self._norm
        with self._prio:  # 两把 Condition 同一把锁，用哪把进锁都一样
            if self._in_flight < self._max_in_flight:
                self._in_flight += 1
                return True
            if self._prio_waiting + self._norm_waiting >= self._queue_size:
                return False  # 队列也满了：硬拒，别让等待者无限堆积
            if priority:
                self._prio_waiting += 1
            else:
                self._norm_waiting += 1
            try:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return False  # 排到了但没轮上：超时拒绝
                    got = cond.wait(remaining)
                    if got and self._in_flight < self._max_in_flight:
                        self._in_flight += 1
                        return True
                    # got=False → 本次等到超时，下轮 remaining<=0 收尾；
                    # got=True 但名额被别的等待者抢走 → 回去继续等
            finally:
                if priority:
                    self._prio_waiting -= 1
                else:
                    self._norm_waiting -= 1

    def release(self) -> None:
        with self._prio:
            self._in_flight = max(0, self._in_flight - 1)
            # 先叫 VIP：VIP 等待者没被叫醒时名额留给普通队
            if self._prio_waiting > 0:
                self._prio.notify()
            elif self._norm_waiting > 0:
                self._norm.notify()

    @property
    def stats(self) -> dict[str, int]:
        with self._prio:
            return {
                "in_flight": self._in_flight,
                "waiting": self._prio_waiting + self._norm_waiting,
                "priority_waiting": self._prio_waiting,
                "max_in_flight": self._max_in_flight,
                "queue_size": self._queue_size,
            }


PANEL_HTML = """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>relay-hub 用户面板</title>
<style>
body{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;background:#F7F6F3;
color:#26215C;margin:0;display:flex;justify-content:center;min-height:100vh}
.box{background:#fff;border:1px solid #E3E1DA;border-radius:14px;padding:28px;
max-width:420px;width:92%;margin:60px 0;box-shadow:0 2px 8px rgba(38,33,92,.06);height:fit-content}
h2{margin:0 0 6px;font-size:18px}
p.sub{color:#5F5E5A;font-size:13px;margin:0 0 18px}
input{width:100%;box-sizing:border-box;padding:9px 11px;margin:6px 0 12px;border:1px solid #E3E1DA;
border-radius:8px;font:inherit}
button{background:#185FA5;color:#fff;border:none;border-radius:8px;padding:9px 14px;
font:inherit;cursor:pointer;width:100%}
button.ghost{background:transparent;color:#185FA5;border:1px solid #185FA5}
button:disabled{opacity:.5}
.row{display:flex;gap:8px}
.row button{flex:1}
dl{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;font-size:13px;margin:0 0 16px}
dt{color:#5F5E5A}dd{margin:0;font-family:ui-monospace,Consolas,monospace;word-break:break-all}
.err{color:#A32D2D;font-size:12px;min-height:16px;margin:4px 0}
.ok-msg{color:#0F6E56;font-size:12px;min-height:16px;margin:4px 0}
h3{font-size:13px;color:#5F5E5A;margin:18px 0 8px;font-weight:500}
</style></head><body><div class="box" id="app"></div>
<script>
var base='';
function esc(s){var d=document.createElement('div');d.textContent=s==null?'':s;return d.innerHTML;}
function h(html){document.getElementById('app').innerHTML=html;}
function err(m){var e=document.getElementById('msg');if(e){e.textContent=m||'';}}
async function api(path,body){
  var r=await fetch(base+path,{method:'POST',headers:{'Content-Type':'application/json'},
    body:body?JSON.stringify(body):undefined});
  var j=await r.json().catch(function(){return{ok:false,error:'响应解析失败'};});
  if(!r.ok&&!j.error){j.error='HTTP '+r.status;}
  return j;
}
async function refresh(){
  var r=await fetch(base+'/api/user/me');
  if(r.status===401){renderAuth(false);return;}
  var u=await r.json();
  renderHome(u);
}
function renderAuth(showRegister){
  h('<h2>relay-hub 用户面板</h2><p class="sub">'+(showRegister?'注册或登录以获取 API Key':'登录以管理你的 API Key 与额度')+'</p>'+
    '<label>用户名</label><input id="u"><label>密码</label><input id="p" type="password">'+
    '<div class="err" id="msg"></div>'+
    '<div class="row"><button onclick="doLogin()">登录</button>'+
    (showRegister?'<button class="ghost" onclick="doRegister()">注册</button>':'')+'</div>'+
    '<h3>API 接入</h3><p class="sub">Base URL：本页地址（/panel 前的部分）<br>端点：/v1/chat/completions 或 /v1/messages</p>');
  window.__reg=showRegister;
  document.getElementById('p').onkeydown=function(ev){if(ev.key==='Enter'){showRegister?doRegister():doLogin();}};
}
async function doLogin(){err('');var j=await api('/api/auth/login',{u:document.getElementById('u').value.trim(),p:document.getElementById('p').value});
  if(!j.ok){err(j.error);if(j.error&&(j.error.indexOf('不存在')>=0)&&window.__reg){err(j.error+'（可切换注册）');}return;}
  refresh();}
async function doRegister(){err('');var j=await api('/api/auth/register',{username:document.getElementById('u').value.trim(),password:document.getElementById('p').value});
  if(!j.ok){err(j.error);return;}
  renderHome({username:j.username,quota:j.quota,used:0,api_key_hint:'…'+j.token.slice(-4),unlimited:false});
  showKey(j.token);}
function renderHome(u){
  h('<h2>'+esc(u.username)+'</h2><p class="sub">'+(u.unlimited?'管理员（不限量）':'按量计费 · 分组 '+esc(u.group))+'</p>'+
    '<dl><dt>剩余额度</dt><dd>'+(u.unlimited?'∞':u.quota+' 点')+'</dd>'+
    '<dt>累计消耗</dt><dd>'+u.used+' 点</dd>'+
    '<dt>API Key</dt><dd>'+(u.api_key_hint?esc(u.api_key_hint):'（未发放）')+'</dd></dl>'+
    '<h3>兑换码</h3><input id="code" placeholder="rhx-…"><div class="ok-msg" id="msg"></div>'+
    '<button onclick="doRedeem()">兑换</button>'+
    '<h3>API Key</h3><button class="ghost" onclick="doRotate()">重置 Key（旧 Key 立即失效）</button>'+
    '<div class="row" style="margin-top:14px"><button class="ghost" onclick="logout()">退出登录</button></div>');
}
async function doRedeem(){err('');var j=await api('/api/user/redeem',{code:document.getElementById('code').value.trim()});
  if(!j.ok){err(j.error);return;}
  document.getElementById('msg').textContent='+'+j.credits+' 点，当前余额 '+j.quota;refresh();}
async function doRotate(){if(!confirm('旧 Key 立即失效，确定？'))return;
  var j=await api('/api/user/rotate-key',{});if(j.ok){showKey(j.token);refresh();}}
function showKey(t){h('<h2>你的新 API Key</h2><p class="sub">只显示这一次，立即复制保存</p>'+
  '<dl><dt>Key</dt><dd>'+esc(t)+'</dd></dl><button onclick="refresh()">我已保存，返回面板</button>');}
async function logout(){await api('/api/auth/logout',{});renderAuth(false);}
refresh();
</script></body></html>"""


# ---------------------------------------------------------------- HTTP 层


class RelayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "relayhub/0.2"

    @property
    def router(self) -> Any:
        return self.server.router  # type: ignore[attr-defined]

    @property
    def api_key(self) -> str | None:
        return self.server.api_key  # type: ignore[attr-defined]

    @property
    def tokens(self) -> TokenStore | None:
        return self.server.tokens  # type: ignore[attr-defined]

    @property
    def rate_limiter(self) -> RateLimiter:
        return self.server.rate_limiter  # type: ignore[attr-defined]

    @property
    def ip_limiter(self) -> RateLimiter:
        return self.server.ip_limiter  # type: ignore[attr-defined]

    @property
    def ip_rpm(self) -> int:
        return self.server.ip_rpm  # type: ignore[attr-defined]

    @property
    def conc_gate(self) -> ConcurrencyGate | None:
        return getattr(self.server, "conc_gate", None)  # type: ignore[attr-defined]

    @property
    def test_router(self) -> TestRouter:
        return self.server.test_router  # type: ignore[attr-defined]

    @property
    def users(self) -> UserStore | None:
        return getattr(self.server, "users", None)  # type: ignore[attr-defined]

    @property
    def redeem(self) -> RedeemStore | None:
        return getattr(self.server, "redeem", None)  # type: ignore[attr-defined]

    @property
    def loop_guard(self) -> LoopGuard:
        return self.server.loop_guard  # type: ignore[attr-defined]

    @property
    def response_cache(self) -> ResponseCache:
        return self.server.response_cache  # type: ignore[attr-defined]

    # -- 会话（用户面板） --------------------------------------------------

    SESSION_COOKIE = "rh_session"
    SESSION_TTL = 86400.0

    def _set_cookie_header(self, value: str, max_age: int) -> None:
        self.send_header(
            "Set-Cookie",
            f"{self.SESSION_COOKIE}={value}; Path=/; HttpOnly; Max-Age={max_age}; SameSite=Lax",
        )

    def _issue_session(self, user_id: str) -> str:
        sid = uuid.uuid4().hex + secrets.token_hex(16)
        with self.server.session_lock:  # type: ignore[attr-defined]
            self.server.sessions[sid] = (user_id, time.time() + self.SESSION_TTL)  # type: ignore[attr-defined]
        return sid

    def _drop_session(self) -> None:
        sid = self._session_id()
        if not sid:
            return
        with self.server.session_lock:  # type: ignore[attr-defined]
            self.server.sessions.pop(sid, None)  # type: ignore[attr-defined]

    def _session_id(self) -> str:
        cookie = self.headers.get("Cookie") or ""
        for part in cookie.split(";"):
            name, _, value = part.strip().partition("=")
            if name == self.SESSION_COOKIE:
                return value.strip()
        return ""

    def _session_user(self) -> Any:
        """会话 → User。无效/过期返回 None。"""
        sid = self._session_id()
        if not sid or self.users is None:
            return None
        with self.server.session_lock:  # type: ignore[attr-defined]
            entry = self.server.sessions.get(sid)  # type: ignore[attr-defined]
        if entry is None or time.time() > entry[1]:
            return None
        return self.users.pool.get(entry[0])

    def _send_json(self, status: int, payload: dict[str, Any], cookie: str | None = None,
                   cookie_max_age: int = 0) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        if cookie:
            self._set_cookie_header(cookie, cookie_max_age)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _issue_user_api_key(self, user: Any) -> str:
        """给用户发/换 API Key：绑定 user_id 的 normal 令牌，旧的全删。"""
        token_store = self.tokens
        if token_store is None:
            raise UserError("网关未启用下游令牌，无法发 API Key")
        secret = generate_token()
        record = DownstreamToken(
            token_id=str(uuid.uuid4()),
            name=f"user-{user.username}",
            token=secret,
            scope="normal",
            user_id=user.user_id,
            note=f"panel:{user.username}",
        )

        def change(pool: Any) -> None:
            for old in [t for t in pool.tokens if t.user_id == user.user_id]:
                pool.remove(old.token_id)
            pool.add(record)

        token_store.mutate(change)
        return secret

    def _handle_panel_api(self, path: str) -> None:
        """用户面板 API。/api/auth/* 无需会话；/api/user/* 需要会话。"""
        if self.users is None:
            self._send_json(503, {"ok": False, "error": "用户系统未启用"})
            return
        try:
            if path == "/api/auth/register":
                body = self._read_json() or {}
                user = self.users.register(
                    str(body.get("username") or ""), str(body.get("password") or "")
                )
                audit_module.record(
                    "panel.register",
                    path=paths.audit_path(),
                    username=user.username,
                    ip=self.client_address[0],
                )
                sid = self._issue_session(user.user_id)
                api_key = self._issue_user_api_key(user)
                self._send_json(
                    200,
                    {"ok": True, "username": user.username, "token": api_key,
                     "quota": user.quota},
                    cookie=sid,
                    cookie_max_age=int(self.SESSION_TTL),
                )
                return
            if path == "/api/auth/login":
                body = self._read_json() or {}
                user = self.users.verify(
                    str(body.get("username") or ""), str(body.get("password") or "")
                )
                if user is None:
                    # 登录失败也留痕（含 IP）：撞库/爆破在这里能看出来
                    audit_module.record(
                        "panel.login_failed",
                        path=paths.audit_path(),
                        username=str(body.get("username") or "")[:32],
                        ip=self.client_address[0],
                    )
                    self._send_json(401, {"ok": False, "error": "用户名或密码错误"})
                    return
                audit_module.record(
                    "panel.login",
                    path=paths.audit_path(),
                    username=user.username,
                    ip=self.client_address[0],
                )
                sid = self._issue_session(user.user_id)
                self._send_json(
                    200,
                    {"ok": True, "username": user.username},
                    cookie=sid,
                    cookie_max_age=int(self.SESSION_TTL),
                )
                return
            if path == "/api/auth/logout":
                self._drop_session()
                self._send_json(200, {"ok": True})
                return
            user = self._session_user()
            if user is None:
                self._send_json(401, {"ok": False, "error": "请先登录"})
                return
            if path == "/api/user/rotate-key":
                api_key = self._issue_user_api_key(user)
                self._send_json(200, {"ok": True, "token": api_key})
                return
            if path == "/api/user/redeem":
                body = self._read_json() or {}
                if self.redeem is None:
                    self._send_json(503, {"ok": False, "error": "兑换系统未启用"})
                    return
                credits = self.redeem.redeem(str(body.get("code") or ""), user.user_id)

                def _add_quota(pool: Any) -> None:
                    target = pool.get(user.user_id)
                    if target is None:
                        raise UserError("用户不存在")
                    if target.quota < 0:
                        target.used += credits  # 不限量管理员：兑换只记累计
                    else:
                        target.quota += credits

                self.users.mutate(_add_quota)
                fresh = self.users.pool.get(user.user_id)
                self._send_json(200, {"ok": True, "credits": credits, "quota": fresh.quota})
                return
            self._send_json(404, {"ok": False, "error": f"未知面板路径 {path}"})
        except UserError as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})

    @property
    def pairing(self) -> Any:
        return self.server.pairing  # type: ignore[attr-defined]

    @property
    def request_log(self) -> Any:
        return self.server.request_log  # type: ignore[attr-defined]

    @property
    def policy(self) -> Any:
        """接入策略（PolicyStore）。旧构造路径没有该属性时等价于「无策略」。"""
        return getattr(self.server, "policy", None)


    def _log_request(
        self,
        *,
        started: float,
        dialect: str,
        model: str = "",
        identity: DownstreamToken | None = None,
        ok: bool,
        stream: bool = False,
        status: int = 200,
        tokens_in: int = 0,
        tokens_out: int = 0,
        cache_read: int = 0,
        cache_creation: int = 0,
        cost: int = 0,
        channel: str = "",
        reason: str = "",
    ) -> None:
        """写一条请求明细。终端只有一个：本方法不该被同一请求调两次。"""
        if identity is not None:
            who = identity.name
        elif self.api_key or (self.tokens and self.tokens.pool.tokens):
            who = "master"
        else:
            who = "-"
        # 客户端身份：本请求解出的身份字段（无则全空，reqlog 就不写这些键）
        ident = getattr(self, "_ident", None) or {}
        ident_bad = ident.get("bad", "")
        latency_ms = (time.monotonic() - started) * 1000
        request_id = getattr(self, "_current_request_id", "")
        ip = self._client_ip()

        # 插件日志：**先于 request_log 的开关判断**——`--no-request-log` 是
        # 「别给这个网关留全局流水」的意思，不该顺带把插件自己的接入记录灭掉。
        # 两者服务的追问不同（见 pluginlogs 模块头部的三方分工表）。
        plugin = self._plugin_identity(identity)
        if plugin is not None:
            pluginlogs.record(
                self._plugin_log_home(),
                plugin["id"],
                plugin_version=plugin.get("version", ""),
                token=who,
                dialect=dialect,
                model=model,
                ok=ok,
                stream=stream,
                status=status,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                latency_ms=latency_ms,
                ip=ip,
                reason=reason,
            )

        log_path = self.request_log
        if log_path is None:
            return
        reqlog.record(
            log_path,
            token=who,
            dialect=dialect,
            model=model,
            channel=channel,
            ok=ok,
            stream=stream,
            status=status,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cache_read=cache_read,
            cache_creation=cache_creation,
            cost=cost,
            request_id=request_id,
            ip=ip,
            ident_user=ident.get("user", ""),
            ident_ver=ident.get("ver", ""),
            ident_dev=ident.get("dev", ""),
            ident_did=ident.get("did", ""),
            ident_src=("bad:" + ident_bad) if ident_bad else ident.get("src", ""),
            latency_ms=latency_ms,
            reason=reason,
        )

    # -- 插件身份与插件日志 ------------------------------------------------

    def _plugin_log_home(self) -> Any:
        """插件日志根目录。允许测试用 server.plugin_log_home 覆盖。"""
        override = getattr(self.server, "plugin_log_home", None)
        return override if override is not None else paths.relayhub_home()

    def _plugin_identity(
        self, identity: DownstreamToken | None = None
    ) -> dict[str, str] | None:
        """解出「这个请求属于哪个插件」。解不出返回 None（不写插件日志）。

        优先级：插件自报的头 → 令牌的 TOIP 绑定 → 无。

        为什么令牌绑定要排在头**之后**而不是之前：插件头是插件自己填的，
        能区分「同一台机器上的两个插件」；令牌绑定只能区分到设备。
        但头可以伪造，所以它只当分类标签用——**鉴权永远只看令牌**
        （`_authenticate`），伪造插件头最坏后果是把日志记到隔壁插件名下。

        校验必须走 `toip.sanitize_plugin_id` 同一套白名单：插件 id 会变成
        **目录名**，`../` 这类值能把日志写到数据根之外。
        """
        raw = (
            self.headers.get(toip_module.PLUGIN_ID_HEADER, "")
            or self.headers.get(toip_module.PLUGIN_ID_HEADER_GENERIC, "")
        ).strip()
        if not raw and identity is not None:
            raw = toip_module.plugin_of_note(identity.note)
        if not raw:
            return None
        try:
            plugin_id = toip_module.sanitize_plugin_id(raw)
        except toip_module.ToipError:
            # 非法插件 id 不拒请求（它不参与鉴权），只是不记插件日志。
            self.log_error("忽略非法的插件身份头：%r", raw[:80])
            return None
        return {
            "id": plugin_id,
            "version": self.headers.get(toip_module.PLUGIN_VERSION_HEADER, "").strip()[:32],
        }

    @property
    def toip(self) -> Any:
        """TOIP 接入服务。未配置站点身份时为 None（端点回 404）。"""
        return getattr(self.server, "toip", None)

    @property
    def event_delay(self) -> float:
        return self.server.event_delay  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        if self.server.verbose:  # type: ignore[attr-defined]
            super().log_message(fmt, *args)

    # -- 基础设施 --------------------------------------------------------
    # _send_json 在会话区定义（带 Set-Cookie 支持），这里不重复定义。

    def _send_html(self, html: str) -> None:
        raw = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _error(
        self,
        status: int,
        message: str,
        kind: str = "invalid_request_error",
        dialect: str = "anthropic",
    ) -> None:
        """两种客户端对错误体的形状要求不一样，别互相糊。

        Anthropic：{"type":"error","error":{"type":...,"message":...}}
        OpenAI   ：{"error":{"message":...,"type":...,"code":...}}
        """
        if dialect in ("openai", "responses"):
            self._send_json(status, {"error": {"message": message, "type": kind, "code": None}})
        else:
            self._send_json(status, {"type": "error", "error": {"type": kind, "message": message}})

    def _supplied_credential(self) -> str:
        """接受 Anthropic 的 x-api-key，也接受 OpenAI 的 Authorization: Bearer。

        两个口（有的客户端发 Bearer、有的发 x-api-key）都指到同一个鉴权面，
        所以这里对头部不做协议假设。
        """
        supplied = self.headers.get("x-api-key", "")
        if not supplied:
            auth = self.headers.get("Authorization", "")
            if auth.lower().startswith("bearer "):
                supplied = auth[7:]
        return supplied.strip()

    def _client_ip(self) -> str:
        """请求来源 IP（用于单 IP 限流）。

        优先取反向代理头：经过 nginx/frp 等转发时，client_address 是代理的
        回环地址，按它限流会把所有人的额度算到代理头上。多级代理取
        X-Forwarded-For 的**第一个**（最初客户端），但注意该头可被伪造——
        直连场景（无代理头）用 TCP 对端地址，不可伪造。
        """
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            first = forwarded.split(",")[0].strip()
            if first:
                return first
        real = (self.headers.get("X-Real-IP") or "").strip()
        if real:
            return real
        return self.client_address[0]

    def _handle_pair(self) -> None:
        """POST /v1/pair：发放下游令牌 + onboarding 载荷。

        两种发放模式（--pair-mode）：
          * code：带一次性配对码（带外传递），窗口没开直接拒。
          * auto-lan：局域网免码——来源是回环/私有地址即发，同设备幂等复用。
            公网来源自动退回配对码模式（没有码就 403）。
        响应里的 base_url 取 Host 头——客户端用哪个地址连上来，就用哪个地址
        回填 spec，多网卡/自定义端口都不需要网关猜。
        """
        pairing = self.pairing
        if pairing is None:
            self._error(404, "本网关未启用配对服务", "not_found_error")
            return
        body = self._read_json()
        if body is None:
            return
        code = str(body.get("code") or "").strip()
        device_name = str(body.get("name") or "").strip()
        client_id = str(body.get("client") or "app").strip().lower()
        try:
            clients_module.get(client_id)
        except KeyError as exc:
            self._error(400, str(exc), "invalid_request_error")
            return

        from .pairing import PairingError

        try:
            if code:
                record = pairing.redeem(code, device_name, client_id)
            elif str(getattr(self.server, "pair_mode", "code")) == "auto-lan":
                record = pairing.auto_pair(
                    device_name, client_id, ip=self._client_ip()
                )
            else:
                self._error(
                    403, "本站要求配对码：请向管理员索取", "permission_error",
                )
                return
        except PairingError as exc:
            self._error(403, str(exc), "permission_error")
            return

        host = self.headers.get("Host") or f"{self.server.server_address[0]}:{self.server.server_address[1]}"
        models = [
            {"model_id": model, "context_window": window or None}
            for model, window in sorted(self.router.models().items())
        ]
        payload = clients_module.onboarding(
            client_id,
            base_url=f"http://{host}",
            api_key=record.token,
            models=models,
        )
        self._send_json(200, payload)

    # -- TOIP 接入 ---------------------------------------------------------

    def _http_root(self) -> str:
        """本站对外的 HTTP 根地址（无尾斜杠），用于拼给插件的接入载荷。

        与 `_handle_pair` 同一口径取 Host 头：客户端用哪个地址连上来，
        就用哪个地址回填它的配置——多网卡/自定义端口/反代前缀都不需要
        网关猜，也不需要管理员维护一份「对外地址」配置（那是最容易过期的东西）。
        """
        host = self.headers.get("Host") or (
            f"{self.server.server_address[0]}:{self.server.server_address[1]}"
        )
        return f"http://{host}"

    def _handle_toip_station(self) -> None:
        """GET /v1/toip/station：公开的站点 TOIP 能力声明。

        未启用 TOIP 时回 404 而不是 200 + enabled:false——「这个站没有这个
        功能」与「这个站有这个功能但现在关着」对客户端是同一种处置（换配对码），
        但 404 让探测方一眼看出该换路子，不必解析 body。
        """
        service = self.toip
        if service is None or not service.enabled():
            self._error(404, "本网关未启用 TOIP 接入", "not_found_error")
            return
        payload = service.station_public()
        # base_url 一律以本次请求看到的地址为准（station 文件里的 base_url
        # 只在管理员显式写死时才用，那种场景是跨网段/NAT 后无法从来源推断）。
        payload["base_url"] = payload.get("base_url") or self._http_root()
        payload["models"] = len(self.router.models())
        self._send_json(200, payload)

    def _handle_toip_join(self, path: str) -> None:
        """POST /v1/toip/join|enroll：动态口令 / 登记口令 → 会话令牌 + 接入载荷。

        成功响应就是「插件自助接入所需的一切」：会话令牌、要写进客户端配置的
        base URL、可选的模型清单、以及一个 `dsh` 块（客户端就填这个，别的字段
        是给人看的）。字段命名刻意与 `clients.onboarding` 对齐，让「配对」和
        「TOIP」两条接入路径在客户端侧可以用同一套解析。
        """
        service = self.toip
        if service is None or not service.enabled():
            self._error(404, "本网关未启用 TOIP 接入", "not_found_error")
            return
        body = self._read_json("openai")
        if body is None:
            return

        code = str(body.get("code") or "").strip()
        ticket = str(body.get("ticket") or "").strip()
        if path == "/v1/toip/enroll" and not ticket:
            self._error(400, "enroll 需要登记口令 ticket", "invalid_request_error")
            return
        plugin_id = str(body.get("plugin") or body.get("plugin_id") or "").strip()
        if not plugin_id:
            self._error(
                400,
                "缺少 plugin（插件 id，用于分账与日志目录；建议 dsh-relayhub-bridge）",
                "invalid_request_error",
            )
            return
        # 设备名**不要**在这里默认成插件 id：那样会盖住 toip._grant 的
        # 「沿用旧令牌名」回退，导致同一台设备用动态口令重接后被改名
        # （tokens.json 与日志的 token 列跟着变，历史对不上）。
        name = str(body.get("name") or body.get("device") or "").strip()
        client_id = str(body.get("client") or "dsh").strip().lower()

        from .toip import ToipError

        ip = self._client_ip()
        try:
            result = service.join(
                code=code,
                ticket=ticket,
                name=name,
                plugin_id=plugin_id,
                ip=ip,
                client_id=client_id,
            )
        except ToipError as exc:
            self._error(
                403 if "无效" in str(exc) or "不正确" in str(exc) or "过期" in str(exc) else 400,
                str(exc),
                "permission_error",
            )
            return

        root = self._http_root()
        models = [
            {"model_id": model, "context_window": window or None}
            for model, window in sorted(self.router.models().items())
            if result.token.allows(model)
        ]
        # 复用客户端档案生成通用接入载荷：未知 client_id 会抛 KeyError，
        # 那不该让已经发出的令牌白丢，所以退化成通用形态。
        try:
            payload = clients_module.onboarding(
                client_id, base_url=root, api_key=result.token_plain, models=models
            )
        except KeyError:
            payload = {
                "client": client_id,
                "display_name": client_id,
                "status": "guided",
                "inbound": "anthropic-messages",
                "endpoint": "/v1/messages",
                "base_url": root,
                "api_key": result.token_plain,
                "models": models,
            }

        payload["protocol"] = toip_module.PROTOCOL
        payload["version"] = toip_module.PROTOCOL_VERSION
        current = service.station()
        payload["station"] = {
            "id": current.station_id if current else "",
            "base_url": root,
        }
        payload["plugin"] = {
            "id": result.plugin_id,
            "version": str(body.get("plugin_version") or "")[:32],
            # 插件下次重接用的路径与头名：写在响应里，插件不必硬编码。
            "join_path": "/v1/toip/join",
            "session_path": "/v1/toip/session",
            "headers": {
                "plugin_id": toip_module.PLUGIN_ID_HEADER,
                "plugin_version": toip_module.PLUGIN_VERSION_HEADER,
                "station_id": toip_module.STATION_ID_HEADER,
            },
        }
        payload["session"] = {
            "token": result.token_plain,
            "token_hint": toip_module.token_hint_of(result.token_plain),
            "expires_at": float(result.token.expires_at or 0.0),
            "rotated": result.returned_session,
        }
        # DSH 客户端区块：插件的配置面只需要照抄这三个值。
        # base_url 必须带 /v1——DSH 的 Messages 适配器只在 pathname 不以
        # /v1 结尾时补 /v1（`messagesApiRoot`），带 /v1 是唯一确定的写法。
        payload["dsh"] = {
            "provider": "relayhub",
            "baseURL": f"{root}/v1",
            "apiKey": result.token_plain,
            "models": [
                {"id": item["model_id"], "contextWindow": item["context_window"] or None}
                for item in models
            ],
        }
        payload["otp"] = {
            "algorithm": toip_module.TOTP_ALGORITHM.upper(),
            "digits": toip_module.TOTP_DIGITS,
            "period": int(toip_module.TOTP_STEP),
            # 方便插件在 UI 上提示「还剩几秒」，减少跨窗失败。
            "seconds_left": round(toip_module.totp_seconds_left(), 1),
        }
        self._send_json(200, payload)

    def _authenticate(self, dialect: str = "anthropic") -> tuple[bool, DownstreamToken | None]:
        """鉴权并返回本次请求的身份。

        返回 (通过?, 令牌身份)。令牌身份为 None 表示 master 凭证或未启用鉴权；
        失败时已经把 401 写回客户端。

        鉴权面按 one-api 的两层语义组织：
          * **master 凭证**（`serve --api-key`）：网关自持的根凭证，不记用量、不受模型限制。
          * **下游令牌**（tokens.json）：每台设备一个，可禁用、可限模型、按令牌记账。
        """
        token_store = self.tokens
        has_tokens = bool(token_store and token_store.pool.tokens)
        if not self.api_key and not has_tokens:
            return True, None
        supplied = self._supplied_credential()
        if not supplied:
            self._error(401, "缺少凭证", "authentication_error", dialect)
            return False, None
        if token_store is not None:
            match = token_store.find(supplied)
            if match is not None:
                if not match.enabled:
                    self._error(
                        401, f"令牌 {match.name} 已被禁用", "authentication_error", dialect
                    )
                    return False, None
                if match.is_expired():
                    self._error(
                        401,
                        f"令牌 {match.name} 已于 "
                        f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(match.expires_at))} 过期",
                        "authentication_error",
                        dialect,
                    )
                    return False, None
                return True, match
        if self.api_key and hmac.compare_digest(supplied, self.api_key):
            return True, None
        self._error(401, "凭证无效或已吊销", "authentication_error", dialect)
        return False, None


    def _record(
        self, identity: DownstreamToken | None, ok: bool, tokens_in: int = 0, tokens_out: int = 0
    ) -> None:
        """按令牌记账。master 凭证与未启用鉴权的请求不记（它们不是设备流量）。"""
        if identity is None:
            return
        # 客户端身份速览：写进 usage（运行时状态，指纹已排除，不触发重载）。
        # 只在身份可信（src 有值且无 bad）时落——bad 也记 ip，但设备字段留空。
        ident = getattr(self, "_ident", None) or {}
        if ident.get("src") and not ident.get("bad"):
            identity.usage.last_ip = self._client_ip()
            identity.usage.last_user = ident.get("user", "")
            identity.usage.last_ver = ident.get("ver", "")
            identity.usage.last_device = ident.get("dev", "")
            identity.usage.last_device_id = ident.get("did", "")
        token_store = self.tokens
        if token_store is None:
            return
        try:
            token_store.report(identity, ok, tokens_in, tokens_out)
        except OSError as exc:
            # 记账失败不该弄死正在返回的响应，但必须留痕
            self.log_error("令牌用量落盘失败：%r", exc)

    def _read_json(self, dialect: str = "anthropic") -> dict[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._error(400, "Content-Length 非法", dialect=dialect)
            return None
        raw = self.rfile.read(length) if length else b""
        try:
            parsed = json.loads(raw.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._error(400, f"请求体不是合法 JSON：{exc}", dialect=dialect)
            return None
        if not isinstance(parsed, dict):
            self._error(400, "请求体必须是 JSON 对象", dialect=dialect)
            return None
        return parsed

    # -- SSE -------------------------------------------------------------

    def _begin_sse(self) -> None:
        """用 chunked 编码，HTTP/1.1 下不依赖连接关闭来界定正文。"""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

    def _write_chunk(self, data: bytes) -> None:
        self.wfile.write(f"{len(data):X}\r\n".encode("ascii") + data + b"\r\n")
        self.wfile.flush()

    def _sse(self, event: str, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False)
        self._sse_raw(f"event: {event}\ndata: {body}\n\n")

    def _sse_raw(self, text: str) -> None:
        """写一段原始 SSE 文本并按 event_delay 节流（OpenAI 那种只有 data 行也走这里）。"""
        self._write_chunk(text.encode("utf-8"))
        if self.event_delay:
            time.sleep(self.event_delay)

    def _end_chunks(self) -> None:
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    # -- 路由 ------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        # 注意别对根路径做 rstrip("/")："/" 会被剥成空串，导致根路径判断失效
        path = self.path.split("?")[0]
        if path != "/":
            path = path.rstrip("/")
        if path == "/":
            # 落地页：给「在浏览器里打开域名看一眼」的人一个明确的回应。
            # 刻意不含模型清单与任何凭证线索——那些都在鉴权之后。
            self._send_html(
                "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
                "<title>relay-hub</title></head>"
                "<body style=\"font-family:sans-serif;max-width:640px;margin:60px auto;"
                "color:#333;line-height:1.7\">"
                "<h2>relay-hub 中转站在线</h2>"
                "<p>这是一个 OpenAI / Anthropic 兼容的 API 网关。</p>"
                "<p><a href=\"/panel\">用户面板</a>（登录/注册/兑换额度/API Key）</p>"
                "<p>可用端点（均需凭证）：</p>"
                "<ul><li><code>GET /v1/models</code></li>"
                "<li><code>POST /v1/chat/completions</code></li>"
                "<li><code>POST /v1/messages</code></li>"
                "<li><code>POST /v1/embeddings</code></li>"
                "<li><code>POST /v1/responses</code></li></ul>"
                "<p>健康检查：<code>GET /healthz</code>（无需凭证，供 Docker/负载均衡探活）。</p>"
                "<p style=\"color:#888\">凭证无效或缺失会返回 401；"
                "超过限额返回 429。拿测试密钥做连通性检查是正常用法。</p>"
                "</body></html>"
            )
            return
        if path == "/healthz":
            # 无需凭证的探活端点：Docker HEALTHCHECK / 负载均衡 / 监控用。
            # 刻意不泄露版本号与模型信息——探活只需要知道"活着"。
            self._send_json(200, {"ok": True, "server": "relay-hub"})
            return
        if path == "/panel":
            self._send_html(PANEL_HTML)
            return
        if path == "/api/user/me":
            user = self._session_user()
            if user is None or self.users is None:
                self._send_json(401, {"ok": False, "error": "请先登录"})
                return
            pool = self.users.pool
            fresh = pool.get(user.user_id)
            api_key_hint = ""
            for t in self.tokens.pool.tokens if self.tokens else []:
                if t.user_id == user.user_id:
                    api_key_hint = t.token_hint
                    break
            self._send_json(
                200,
                {
                    "ok": True,
                    "username": fresh.username if fresh else user.username,
                    "quota": fresh.quota if fresh else 0,
                    "used": fresh.used if fresh else 0,
                    "group": fresh.group if fresh else "default",
                    "allow_register": pool.allow_register,
                    "api_key_hint": api_key_hint,
                    "unlimited": bool(fresh and fresh.quota < 0),
                },
            )
            return
        if path == "/v1/toip/station":
            # 公开端点：与 /v1/whoami 同级的信息披露——只报「本站支不支持
            # TOIP、该往哪发口令、口令怎么算」。**不含种子、口令、令牌**，
            # 所以发现成本与一次 404 等价。
            self._handle_toip_station()
            return
        if path == "/v1/toip/session":
            # 已接入插件的自查：我是谁、还剩多久、我这个令牌用了多少。
            # 与 /v1/models 同鉴权口径（走令牌），但只读且不改任何状态。
            service = self.toip
            if service is None:
                self._error(404, "本网关未启用 TOIP 接入", "not_found_error")
                return
            authorized, identity = self._authenticate()
            if not authorized or identity is None:
                if authorized:
                    # master 凭证没有「插件身份」，自查没有主语可说；
                    # 明确 400 比回一份全零的假身份更省排查时间。
                    self._error(
                        400,
                        "TOIP 自查需要下游令牌（master 凭证没有插件身份）",
                        "invalid_request_error",
                    )
                return
            self._send_json(200, service.describe_session(identity))
            return
        if path == "/v1/whoami":
            # 官方站自动识别（App 填个网址就能探测）：公开、只报协议身份与
            # 能力开关，不含模型清单、凭证线索与计数——探测成本与 404 相同。
            self._send_json(
                200,
                {
                    "server": "relay-hub",
                    "version": relayhub_version,
                    "pairing_open": bool(
                        getattr(self.server, "pairing", None)
                        and self.server.pairing.window_open()
                    ),
                    "services": {
                        "llm": True,
                    },
                    "pair_mode": str(
                        getattr(self.server, "pair_mode", "code")
                    ),
                },
            )
            return
        if path != "/v1/models":
            self._error(404, f"未知路径 {self.path}", "not_found_error")
            return
        authorized, identity = self._authenticate()
        if not authorized:
            return
        created = int(time.time())
        data = []
        for model, window in sorted(self.router.models().items()):
            # 令牌级模型白名单同步到列表：限了模型的令牌不该看到用不了的模型
            # （one-api 同语义；master 凭证 identity=None，不受限）。
            if identity is not None and identity.models and model not in identity.models:
                continue
            item: dict[str, Any] = {
                "id": model,
                "object": "model",
                "created": created,
                "owned_by": "relay-hub",
            }
            if window:
                item["context_window"] = window
            data.append(item)
        self._send_json(200, {"object": "list", "data": data})

    def do_POST(self) -> None:  # noqa: N802
        try:
            self._post()
        except Exception as exc:  # noqa: BLE001
            # 兜底：handler 里抛未捕获异常时，socketserver 只会静默掐断连接，
            # 客户端看到的是 RemoteDisconnected（像网络问题），排查方向会被带偏。
            # 宁可回一个难看的 500，也让它带上真实错误。
            self.log_error("处理请求时未捕获异常：%r", exc)
            fragment = self.path.split("?")[0].rstrip("/")
            dialect = "openai" if fragment == "/v1/chat/completions" else "anthropic"
            try:
                self._error(500, f"中转站内部错误：{type(exc).__name__}: {exc}", "api_error", dialect)
            except OSError:
                pass

    def _post(self) -> None:
        path = self.path.split("?")[0].rstrip("/")
        if path == "/v1/pair":
            # 配对端点在鉴权之前：来配对的设备本来就还没有凭证。
            # 暴露面由配对窗口守着——没有活跃窗口时直接拒绝，常态下这个
            # 路径等价于不存在（pairing.py 的安全模型）。
            self._handle_pair()
            return
        if path in ("/v1/toip/join", "/v1/toip/enroll"):
            # TOIP 接入端点同样在鉴权之前：来接入的插件还没有令牌。
            # 两个路径的区别只是「拿什么换令牌」——join 收动态口令或登记口令，
            # enroll 只收一次性登记口令。暴露面由口令窗口 + 爆破闸门守着。
            self._handle_toip_join(path)
            return
        if path == "/v1/embeddings":
            self._handle_embeddings()
            return
        if path.startswith("/api/auth/") or path.startswith("/api/user/"):
            self._handle_panel_api(path)
            return
        if path not in ("/v1/messages", "/v1/chat/completions", "/v1/responses"):
            self._error(404, f"未知路径 {self.path}", "not_found_error")
            return
        started = time.monotonic()
        # 入站协议决定出站编码：两个口共用同一套路由，只有「怎么说话」不同。
        dialect = ("openai" if path == "/v1/chat/completions"
                   else "responses" if path == "/v1/responses" else "anthropic")

        # 单 IP 限流：放在鉴权之前——刷请求的人不带有效凭证也一样占带宽。
        # 鉴权失败的请求同样计入（这正是要防的：拿垃圾凭证打接口探测）。
        # 拉黑（IP）更靠前：被拉黑的来源连限流计数都不进，策略文件改完即生效。
        client_ip = self._client_ip()
        if self.policy is not None and self.policy.is_ip_blocked(client_ip):
            self._error(
                403,
                "来源已被中转站管理员拉黑，如有疑问请联系管理员",
                "permission_error",
                dialect,
            )
            self._log_request(
                started=started, dialect=dialect, identity=None,
                ok=False, status=403, reason="ip blacklisted",
            )
            return
        if self.ip_rpm > 0:
            if not self.ip_limiter.check(client_ip, self.ip_rpm):
                self._error(
                    429,
                    f"来源 {client_ip} 超过每分钟 {self.ip_rpm} 请求的 IP 限额，请稍后再试",
                    "rate_limit_error",
                    dialect,
                )
                self._log_request(
                    started=started, dialect=dialect, identity=None,
                    ok=False, status=429, reason="ip rate limit",
                )
                return

        # 链路标识（入口侧）：Via 含本站实例标记 或 Hops 已到上限 → 判环拒绝。
        # 比 LoopGuard 的内容指纹更强：就算上游改写了请求内容也拦得住；
        # 两者叠加是纵深防御（第三方网关会丢头，但不会改内容）。
        instance = self.server.instance_id  # type: ignore[attr-defined]
        inbound_via = self.headers.get("Via") or ""
        try:
            inbound_hops = int(self.headers.get("X-Relay-Hub-Hops") or 0)
        except ValueError:
            inbound_hops = 0
        request_id = (self.headers.get("X-Request-ID") or uuid.uuid4().hex)[:64]
        self._current_request_id = request_id
        if inbound_hops >= 4 or instance in inbound_via:
            self._error(
                508,
                "检测到转发环路：Via/Hops 链路标识显示本请求已经过本站。"
                "请检查上游配置是否把本站指回了自己。",
                "api_error",
                dialect,
            )
            self._log_request(
                started=started, dialect=dialect, identity=None,
                ok=False, status=508, reason="relay loop via headers",
            )
            return
        trace_headers = {
            "Via": (inbound_via + ", " + instance).strip(", "),
            "X-Relay-Hub-Hops": str(inbound_hops + 1),
            "X-Request-ID": request_id,
        }

        authorized, identity = self._authenticate(dialect)
        if not authorized:
            self._log_request(
                started=started, dialect=dialect, identity=None,
                ok=False, status=401, reason="unauthorized",
            )
            return
        # 客户端身份：鉴权成功后立即解——身份头的密钥是令牌哈希，
        # 必须先知道是哪枚令牌才验得了。解不出不拒请求（只标 bad）：
        # 管理是目的，不是新的墙。扩展包不在时整段跳过。
        self._ident: dict[str, str] = {}
        if identity is not None and ident_module is not None:
            self._ident = self._parse_identity(identity)
            # 拉黑（设备）：按 设备 ID，其次令牌名（后台管理两处都能填）。
            # 放在身份解析后：没有身份头的旧客户端仍有 IP 拉黑兜着。
            if self.policy is not None and self.policy.is_device_blocked(
                self._ident.get("did", ""), identity.name
            ):
                self._error(
                    403,
                    "该设备已被中转站管理员拉黑，如有疑问请联系管理员",
                    "permission_error",
                    dialect,
                )
                self._log_request(
                    started=started, dialect=dialect, identity=identity,
                    ok=False, status=403, reason="device blacklisted",
                )
                return
        # 优先队列判定：VIP 设备/IP 在并发闸门里插队（见 ConcurrencyGate.acquire）
        gate_priority = self.policy is not None and (
            self.policy.is_ip_priority(client_ip)
            or (
                identity is not None
                and self.policy.is_device_priority(
                    self._ident.get("did", ""), identity.name
                )
            )
        )
        body = self._read_json(dialect)
        if body is None:
            self._log_request(
                started=started, dialect=dialect, identity=identity,
                ok=False, status=400, reason="invalid json",
            )
            return
        # body 身份块兜底：有身份头时也要把块摘掉（不漏给上游、不进缓存指纹）；
        # 没有身份头时它就是唯一身份来源。头部身份优先，body 只兜底。
        if ident_module is not None:
            body_block = ident_module.extract_body_identity(body)
            if body_block is not None and not self._ident:
                self._ident = body_block
        model = str(body.get("model") or "")
        # stream 要在协议翻译前取走：翻译后的 Anthropic 形态里没有这个字段。
        streaming = bool(body.get("stream"))
        if not model:
            self._error(400, "缺少 model", dialect=dialect)
            self._log_request(
                started=started, dialect=dialect, identity=identity,
                ok=False, status=400, reason="missing model",
            )
            return

        # 测试密钥走合成应答：任意模型名都接，不查清单、不受令牌模型白名单约束。
        is_test = identity is not None and identity.scope == SCOPE_TEST

        # 模型存在性在这一层拦。理由：这是「网关给不给这个模型」的契约，
        # 不该等发到上游才由上游报 404 —— 那时已经白烧一次配额，
        # 而且池子里的模型名和上游的模型名本来就不是一回事（要经过映射）。
        # 测试密钥例外：任意模型名都接（性能压测不在乎模型存不存在）。
        if not is_test:
            known = self.router.models()
            if model not in known:
                self._error(
                    404,
                    f"模型 {model} 不在中转站的可用列表里。可用：{sorted(known)}",
                    "not_found_error",
                    dialect,
                )
                self._log_request(
                    started=started, dialect=dialect, model=model, identity=identity,
                    ok=False, status=404, reason="unknown model",
                )
                return

        # 令牌级模型白名单：one-api 令牌的「可用模型」语义。
        # 放在 404 之后，这样「模型不存在」和「令牌无权用」的报错不会互相掩盖。
        if identity is not None and not is_test and not identity.allows(model):
            allowed = list(identity.models)
            self._error(
                403,
                f"令牌 {identity.name} 无权使用模型 {model}。该令牌可用：{allowed}",
                "permission_error",
                dialect,
            )
            self._log_request(
                started=started, dialect=dialect, model=model, identity=identity,
                ok=False, status=403, reason="token model restriction",
            )
            return

        # 限额准入（日配额 + RPM）。对所有令牌身份生效——公网上被打得最狠的
        # 恰恰是 test 令牌，它们最需要限流。放在模型校验之后：打错模型名的请求
        # 不该消耗配额；放在 relay 之前：超限请求不该触达上游。
        if identity is not None:
            ok_daily, reason = self.tokens.admit(identity) if self.tokens else (True, "")
            if not ok_daily:
                self._record(identity, False)
                self._error(429, f"令牌 {identity.name} {reason}", "rate_limit_error", dialect)
                self._log_request(
                    started=started, dialect=dialect, model=model, identity=identity,
                    ok=False, status=429, reason="daily quota exceeded",
                )
                return
            if not self.rate_limiter.check(
                identity.token_hash or identity.token, identity.rpm
            ):
                self._error(
                    429,
                    f"令牌 {identity.name} 超过每分钟 {identity.rpm} 请求的限额",
                    "rate_limit_error",
                    dialect,
                )
                self._log_request(
                    started=started, dialect=dialect, model=model, identity=identity,
                    ok=False, status=429, reason="rpm limit exceeded",
                )
                return

            # 用户额度与预扣费：绑定用户的令牌在 _finish_relay 里做
            # （预扣要在应答缓存查询之后——命中缓存不该被预扣冻结）。

        # 转发环路检测：内容指纹 + 在飞计数（对「上游又指回我们」的拓扑环兜底，
        # 中间哪怕隔着 new-api 这类不改内容的第三方网关也能命中）。
        # test 令牌走本地合成应答，不触上游，无环风险，不计数。
        fp = None
        if not is_test:
            fp = _request_fingerprint(model, body)
            if not self.loop_guard.acquire(fp):
                self._error(
                    508,
                    "检测到转发环路：同一请求内容在飞次数超限。请检查上游是否指回了本站。",
                    "api_error",
                    dialect,
                )
                self._log_request(
                    started=started, dialect=dialect, model=model, identity=identity,
                    ok=False, status=508, reason="relay loop detected",
                )
                return
        try:
            # 并发闸门：在飞满员时排队而不是硬拒（搜题场景体验），队满/超时才 429。
            # 优先名单里的设备/IP 排 VIP 队，名额一释放先轮到他们。
            gate = self.conc_gate
            if gate is not None and not gate.acquire(priority=gate_priority):
                self._error(
                    429,
                    "系统繁忙：请求已进入排队但未能在限时内轮到，请稍后重试",
                    "rate_limit_error",
                    dialect,
                )
                self._log_request(
                    started=started, dialect=dialect, identity=identity,
                    ok=False, status=429, reason="concurrency queue timeout",
                )
                return
            try:
                self._finish_relay(
                    started, dialect, model, body, streaming, identity, is_test, trace_headers, fp
                )
            finally:
                if gate is not None:
                    gate.release()
        finally:
            if fp:
                self.loop_guard.release(fp)


    def _handle_embeddings(self) -> None:
        """/v1/embeddings：RAG/文本工具的向量端点（OpenAI 协议形态）。

        中文：复用 chat 的鉴权 / 令牌模型白名单 / 日配额 / RPM 四道闸；
        非流式、请求体不进缓存与环路指纹（向量请求便宜且无环路拓扑价值）。
        test 令牌回本地合成向量，绝不触上游——与 chat 的测试密钥语义一致。

        English: /v1/embeddings with the same auth / model-whitelist / quota /
        RPM gates as chat. Non-streaming; bypasses cache & loop fingerprint.
        Test tokens get a locally synthesized embedding, never touching upstream.
        """
        started = time.monotonic()
        dialect = "openai"
        authorized, identity = self._authenticate(dialect)
        if not authorized:
            self._log_request(
                started=started, dialect=dialect, identity=None,
                ok=False, status=401, reason="unauthorized",
            )
            return
        body = self._read_json(dialect)
        if body is None:
            self._log_request(
                started=started, dialect=dialect, identity=identity,
                ok=False, status=400, reason="invalid json",
            )
            return
        model = str(body.get("model") or "")
        if not model:
            self._error(400, "缺少 model", dialect=dialect)
            self._log_request(
                started=started, dialect=dialect, identity=identity,
                ok=False, status=400, reason="missing model",
            )
            return
        is_test = identity is not None and identity.scope == SCOPE_TEST
        if identity is not None and not is_test and not identity.allows(model):
            self._error(
                403,
                f"令牌 {identity.name} 无权使用模型 {model}。该令牌可用：{list(identity.models)}",
                "permission_error",
                dialect,
            )
            self._log_request(
                started=started, dialect=dialect, model=model, identity=identity,
                ok=False, status=403, reason="token model restriction",
            )
            return
        if identity is not None:
            ok_daily, reason = self.tokens.admit(identity) if self.tokens else (True, "")
            if not ok_daily:
                self._record(identity, False)
                self._error(429, f"令牌 {identity.name} {reason}", "rate_limit_error", dialect)
                self._log_request(
                    started=started, dialect=dialect, model=model, identity=identity,
                    ok=False, status=429, reason="daily quota exceeded",
                )
                return
            if not self.rate_limiter.check(
                identity.token_hash or identity.token, identity.rpm
            ):
                self._error(
                    429,
                    f"令牌 {identity.name} 超过每分钟 {identity.rpm} 请求的限额",
                    "rate_limit_error",
                    dialect,
                )
                self._log_request(
                    started=started, dialect=dialect, model=model, identity=identity,
                    ok=False, status=429, reason="rpm limit exceeded",
                )
                return

        if is_test:
            inp = body.get("input")
            n = len(inp) if isinstance(inp, list) else 1
            if isinstance(inp, str):
                n = 1
            n = max(1, min(n, 2048))
            tokens_in = max(1, len(str(inp)) // 4)
            dim = 8
            data = {
                "object": "list",
                "model": model,
                "data": [
                    {
                        "object": "embedding",
                        "index": i,
                        "embedding": [round(((i * dim + j) % dim + 1) / dim, 4) for j in range(dim)],
                    }
                    for i in range(n)
                ],
                "usage": {"prompt_tokens": tokens_in, "total_tokens": tokens_in},
            }
            self._send_json(200, data)
            self._log_request(
                started=started, dialect=dialect, model=model, identity=identity,
                ok=True, tokens_in=tokens_in, channel=self.test_router.LABEL,
            )
            return

        try:
            data, label, tokens_in = self.router.relay_embeddings(model, body)
        except RouterError as exc:
            kind = "not_found_error" if exc.status == 404 else "api_error"
            self._record(identity, False)
            self._error(exc.status, str(exc), kind, dialect)
            self._log_request(
                started=started, dialect=dialect, model=model, identity=identity,
                ok=False, status=exc.status, reason=str(exc)[:120],
            )
            return
        self._send_json(200, data)
        self._log_request(
            started=started, dialect=dialect, model=model, identity=identity,
            ok=True, tokens_in=tokens_in, channel=label,
        )

    def _finish_relay(
        self,
        started: float,
        dialect: str,
        model: str,
        body: dict[str, Any],
        streaming: bool,
        identity: DownstreamToken | None,
        is_test: bool,
        trace_headers: dict[str, str],
        fp: str | None,
    ) -> None:
        router = self.test_router if is_test else self.router

        if dialect == "responses":
            # Responses 请求先翻译成 OpenAI chat 形态，再统一归一化为 Anthropic IR。
            body = responses_to_chat(body)
        if dialect in ("openai", "responses"):
            # 网关内部只认 Anthropic 形态，OpenAI 请求先归一化，
            # 否则「OpenAI 客户端 + Anthropic 上游」会把错的请求体转过去。
            try:
                body = to_anthropic_request(body)
            except UpstreamError as exc:
                self._error(400, exc.detail, "invalid_request_error", dialect)
                self._log_request(
                    started=started, dialect=dialect, model=model, identity=identity,
                    ok=False, status=400, reason=exc.detail[:120],
                )
                return

        try:
            # 应答缓存（非流式）：命中即回缓存，不上游、不计费、不预扣（cache 是激励机制）
            pre = 0
            cache_key = None
            if not streaming and not is_test:
                if identity is not None and identity.user_id:
                    tenant = identity.user_id
                elif identity is not None or self.api_key:
                    tenant = "master"
                else:
                    tenant = "anon"
                cache_key = f"{tenant}:{fp}"
                cached = self.response_cache.get(cache_key)
                if cached is not None:
                    usage = cached.get("usage") or {}
                    self._record(
                        identity, True,
                        int(usage.get("input_tokens") or 0),
                        int(usage.get("output_tokens") or 0),
                    )
                    self._log_request(
                        started=started, dialect=dialect, model=model, identity=identity,
                        ok=True, stream=False, status=200,
                        tokens_in=int(usage.get("input_tokens") or 0),
                        tokens_out=int(usage.get("output_tokens") or 0),
                        channel="cache", reason="cache hit",
                    )
                    if dialect == "openai":
                        self._send_json(200, openai_completion(model, cached))
                    elif dialect == "responses":
                        self._send_json(200, responses_completion(model, cached))
                    else:
                        self._send_json(200, cached)
                    return

            # 用户额度预扣（对标 new-api 的 input pre-consume）：按输入体量估算先冻结，
            # 完工后按实际用量多退少补——堵「发大 prompt 中途断开白嫖上游」的洞。
            # 放在缓存查询之后：命中缓存不该被预扣冻结。
            if not is_test and identity is not None and identity.user_id and self.users:
                fresh = self.users.pool.get(identity.user_id)
                if fresh is None or not fresh.enabled:
                    self._error(
                        401, f"令牌所属用户 {identity.user_id[:8]}… 不存在或已禁用",
                        "authentication_error", dialect,
                    )
                    self._log_request(
                        started=started, dialect=dialect, model=model, identity=identity,
                        ok=False, status=401, reason="panel user disabled",
                    )
                    return
                est_input = len(extract_prompt(body)) // 4
                est_cost = self.users.pool.cost_of(fresh, est_input, 0)
                if fresh.quota == 0 or (est_cost > 0 and fresh.quota < est_cost):
                    self._error(
                        429,
                        f"用户 {fresh.username} 额度不足：本请求预估 {est_cost} 点，"
                        f"余额 {fresh.quota} 点。请兑换或联系管理员",
                        "rate_limit_error",
                        dialect,
                    )
                    self._log_request(
                        started=started, dialect=dialect, model=model, identity=identity,
                        ok=False, status=429, reason="quota exhausted (pre-consume)",
                    )
                    return
                if self.users.pre_consume(identity.user_id, est_cost):
                    pre = est_cost

            try:
                outcome = router.relay(
                    model, body, streaming, trace_headers=trace_headers, fp=fp
                )
            except TypeError as exc:
                # 第三方路由器（测试/扩展）可能还是旧签名：不认 trace 参数就退回旧调用
                if "unexpected keyword" not in str(exc):
                    raise
                outcome = router.relay(model, body, streaming)
        except RouterError as exc:
            # 走到这里说明还没往客户端写过字节，可以正常回错误码
            if pre and identity is not None and identity.user_id and self.users:
                self.users.settle(identity.user_id, pre, 0)  # 上游失败：预扣全退
            kind = "not_found_error" if exc.status == 404 else "api_error"
            self._record(identity, False)
            self._error(exc.status, str(exc), kind, dialect)
            self._log_request(
                started=started, dialect=dialect, model=model, identity=identity,
                ok=False, status=exc.status, reason=str(exc)[:120],
            )
            return

        if streaming:
            ok = self._emit_stream(outcome, dialect)
            usage = outcome.usage
            # usage 在流尾才被填充，_emit_stream 消费完生成器后这里才读得到
            tokens_in, tokens_out = (usage.input, usage.output) if usage else (0, 0)
            cache_read = getattr(usage, "cache_read", 0) if usage else 0
            cache_creation = getattr(usage, "cache_creation", 0) if usage else 0
            cost = 0
            if identity is not None and identity.user_id and self.users:
                fresh = self.users.pool.get(identity.user_id)
                if fresh is not None:
                    if ok:
                        cost = self.users.pool.cost_of(fresh, tokens_in, tokens_out)
                        self.users.settle(identity.user_id, pre, cost)  # 多退少补
                    else:
                        # 流中断：上游已消费整段输入，按预扣额结清（不上浮也不退还）
                        # ——这才是预扣防刷的本意；真实网络抖动的损失由预扣上限封顶。
                        self.users.settle(identity.user_id, pre, pre)
                        cost = pre
            self._record(identity, ok, tokens_in, tokens_out)
            self._log_request(
                started=started, dialect=dialect, model=model, identity=identity,
                ok=ok, stream=True, status=200,
                tokens_in=tokens_in, tokens_out=tokens_out,
                cache_read=cache_read, cache_creation=cache_creation,
                cost=cost, channel=outcome.label,
                reason="" if ok else "stream interrupted",
            )
            return
        if outcome.message is None:
            if pre and identity is not None and identity.user_id and self.users:
                self.users.settle(identity.user_id, pre, 0)  # 空结果：预扣全退
            self._record(identity, False)
            self._error(502, "路由返回了空结果", "api_error", dialect)
            self._log_request(
                started=started, dialect=dialect, model=model, identity=identity,
                ok=False, status=502, reason="empty relay outcome",
            )
            return
        usage = (outcome.message.get("usage") or {}) if outcome.message else {}
        cache_read, cache_creation = cache_from_usage(usage)
        tokens_in = int(usage.get("input_tokens") or 0)
        tokens_out = int(usage.get("output_tokens") or 0)
        cost = 0
        if identity is not None and identity.user_id and self.users:
            fresh = self.users.pool.get(identity.user_id)
            if fresh is not None:
                cost = self.users.pool.cost_of(fresh, tokens_in, tokens_out)
                self.users.settle(identity.user_id, pre, cost)  # 多退少补
        # 记账赶在写响应之前：响应字节一出去，客户端就可能立刻断开，
        # 账还没落盘就被读到旧值（测试里表现为偶发丢一次）。
        self._record(identity, True, tokens_in, tokens_out)
        if cache_key:
            self.response_cache.put(cache_key, outcome.message)
        self._log_request(
            started=started, dialect=dialect, model=model, identity=identity,
            ok=True, stream=False, status=200,
            tokens_in=tokens_in, tokens_out=tokens_out,
            cache_read=cache_read, cache_creation=cache_creation,
            cost=cost, channel=outcome.label,
        )
        if dialect == "openai":
            self._send_json(200, openai_completion(model, outcome.message))
        elif dialect == "responses":
            self._send_json(200, responses_completion(model, outcome.message))
        else:
            self._send_json(200, outcome.message)

    def _emit_stream(self, outcome: RelayOutcome, dialect: str = "anthropic") -> bool:
        """写整条流。返回 False 表示中途出错（调用方据此记令牌失败，不再补状态码）。"""
        self._begin_sse()
        try:
            if dialect == "openai":
                for item in openai_chunks(outcome.model, outcome.events or ()):
                    self._sse_raw(f"data: {json.dumps(item, ensure_ascii=False)}\n\n")
                self._sse_raw("data: [DONE]\n\n")
            elif dialect == "responses":
                for name, payload in responses_chunks(outcome.model, outcome.events or ()):
                    self._sse(name, payload)
            else:
                for event, payload in outcome.events or ():
                    self._sse(event, payload)
        except (RouterError, OSError, RuntimeError) as exc:
            # 响应头已发出，改不了状态码；只能发一个 error 事件再收尾。
            # 上游失败已在 router 里记过账，这里不重复计。
            message = str(exc)
            try:
                if dialect == "openai":
                    error = {"error": {"message": message, "type": "api_error", "code": None}}
                    self._sse_raw(f"data: {json.dumps(error, ensure_ascii=False)}\n\n")
                    self._sse_raw("data: [DONE]\n\n")
                elif dialect == "responses":
                    err = {"type": "error", "code": "api_error",
                           "message": message, "param": None, "sequence_number": -1}
                    self._sse_raw(
                        "event: error\ndata: "
                        + json.dumps(err, ensure_ascii=False) + "\n\n"
                    )
                else:
                    payload = {
                        "type": "error",
                        "error": {"type": "api_error", "message": message},
                    }
                    self._sse_raw(
                        f"event: error\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
                    )
            except OSError:
                pass
            return False
        finally:
            try:
                self._end_chunks()
            except OSError:
                pass
        return True


class LoopGuard:
    """转发环路检测：同一内容指纹的在飞请求计数。

    为什么用内容指纹而不是跳数头：中间隔一层 new-api 这类第三方网关，
    自定义头会被丢掉；但**请求内容原样透传**是所有中转站的共性。
    正常请求在飞时同指纹最多 1-2 个（并发重试），环路上每跳都会 +1，
    超过阈值判环。代价：三个客户端同时发一模一样的请求会误伤第三个——
    阈值 3 下概率可忽略，换来的确定性终止是值的。
    """

    def __init__(self, limit: int = 3) -> None:
        self._limit = max(2, limit)
        self._lock = threading.Lock()
        self._inflight: dict[str, int] = {}

    def acquire(self, fingerprint: str) -> bool:
        with self._lock:
            count = self._inflight.get(fingerprint, 0)
            if count >= self._limit:
                return False
            self._inflight[fingerprint] = count + 1
            return True

    def release(self, fingerprint: str) -> None:
        with self._lock:
            count = self._inflight.get(fingerprint, 0) - 1
            if count <= 0:
                self._inflight.pop(fingerprint, None)
            else:
                self._inflight[fingerprint] = count


def _loop_fingerprint(model: str, body: dict[str, Any]) -> str:
    """环指纹：模型 + 消息内容 + max_tokens。转发链上每一跳内容不变。"""
    material = json.dumps(
        {
            "model": model,
            "messages": body.get("messages"),
            "max_tokens": body.get("max_tokens"),
        },
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _request_fingerprint(model: str, body: dict[str, Any]) -> str:
    """请求内容指纹：环路检测与应答缓存共用的键。

    键设计规范（刻意为之）：
      * **包含**语义参数：模型、规范化 messages、tools/tool_choice、
        temperature/top_p/max_tokens/stop、stream——这些变了语义就变了；
      * **绝不包含**：X-Request-ID/Via/Hops 等链路标识、Authorization、
        时间戳、nonce、客户端 IP、User-Agent——它们每跳都变，进了键
        就永远不命中，环路检测也随之失效；
      * `v` 是键版本号：指纹算法升级时递增，旧缓存自然过期，
        升级不会造成语义错配，也不该让命中率永久归零。
    """
    material = json.dumps(
        {
            "v": 1,
            "model": model,
            "messages": body.get("messages"),
            "tools": body.get("tools"),
            "tool_choice": body.get("tool_choice"),
            "temperature": body.get("temperature"),
            "top_p": body.get("top_p"),
            "max_tokens": body.get("max_tokens"),
            "stop": body.get("stop"),
            "stream": bool(body.get("stream")),
        },
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class ResponseCache:
    """非流式应答缓存：命中即免上游调用、免计费。

    隔离维度：键前缀带调用者身份（user_id / master / anon）——公网多用户
    场景下不做跨用户共享（A 付费的答案不能白给 B，也避免响应串户）。
    只缓存非流式 200 应答；流式的产出依赖逐事件透传，缓存收益为负。
    进程内存态，重启清零；TTL 300s、上限 512 条（超出淘汰最旧）。
    """

    TTL = 300.0
    MAX_ENTRIES = 512

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, tuple[float, dict[str, Any]]] = {}

    def get(self, key: str) -> dict[str, Any] | None:
        now = time.time()
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            ts, message = item
            if now - ts > self.TTL:
                self._items.pop(key, None)
                return None
            return message

    def put(self, key: str, message: dict[str, Any]) -> None:
        with self._lock:
            if len(self._items) >= self.MAX_ENTRIES:
                oldest = min(self._items, key=lambda k: self._items[k][0])
                self._items.pop(oldest, None)
            self._items[key] = (time.time(), message)


class RelayServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request: Any, client_address: tuple[str, int]) -> None:
        """客户端半途掐连接（探活/负载器常见）只值得一行日志，不值得整段堆栈刷屏。"""
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, TimeoutError)):
            if getattr(self, "verbose", False):
                self.log_message("客户端断开 %s: %r", client_address, exc)
            return
        super().handle_error(request, client_address)


    def __init__(
        self,
        address: tuple[str, int],
        router: Any,
        api_key: str | None = None,
        event_delay: float = 0.0,
        verbose: bool = False,
        tokens: TokenStore | None = None,
        pairing: Any = None,
        request_log: Any = None,
        users: UserStore | None = None,
        redeem: RedeemStore | None = None,
        loop_limit: int = 3,
        ip_rpm: int = 60,
        max_concurrency: int = 4,
        queue_size: int = 16,
        queue_wait: float = 30.0,
        policy: Any = None,
        pair_mode: str = "code",
        toip: Any = None,
        plugin_log_home: Path | None = None,
    ) -> None:
        if event_delay < 0:
            raise ValueError("event_delay 不能为负")
        if pair_mode not in ("code", "auto-lan"):
            raise ValueError("pair_mode 只能是 code 或 auto-lan")
        # 先查接口再绑端口。漏了这步的后果很误导：请求打进来时在 handler 里抛
        # AttributeError，表现是「连接被直接掐断」（RemoteDisconnected），
        # 看起来像网络问题而不是「参数传错了」。
        for method in ("relay", "models"):
            if not callable(getattr(router, method, None)):
                raise TypeError(
                    f"router 必须是实现了 relay()/models() 的路由器，"
                    f"收到 {type(router).__name__}（缺 {method}）。"
                    "只想用演示渠道池的话，请包一层 DemoRouter。"
                )
        if pairing is not None and not callable(getattr(pairing, "redeem", None)):
            raise TypeError("pairing 必须实现 redeem()（用 pairing.PairingService）")
        super().__init__(address, RelayHandler)
        self.router = router
        self.api_key = api_key
        self.event_delay = event_delay
        self.verbose = verbose
        self.tokens = tokens
        self.pairing = pairing
        # 配对模式：code（默认，带外配对码）/ auto-lan（局域网免码，幂等复用）
        self.pair_mode = pair_mode
        self.request_log = request_log
        # 测试密钥路由与限流器：网关自持，无需外部注入
        self.test_router = TestRouter()
        self.rate_limiter = RateLimiter()
        # 单 IP 限流：防「一个出口 IP 上跑一堆设备刷请求」。与令牌 RPM 互补——
        # 令牌限的是每台设备的凭证，IP 限的是共享出口（教室 NAT）整体频率。
        self.ip_limiter = RateLimiter()
        self.ip_rpm = max(0, ip_rpm)  # 0 = 关闭
        # 并发闸门 + 排队：搜题场景突发并发时排队而非硬拒（见 ConcurrencyGate）。
        self.conc_gate = (
            ConcurrencyGate(max_concurrency, queue_size, queue_wait)
            if max_concurrency > 0
            else None
        )
        # 转发环路检测：内容指纹 + 在飞计数（阈值 3）
        self.loop_guard = LoopGuard(loop_limit)
        # 链路标识：本站实例标记（进 Via 头，环路检测的最强信号）
        self.instance_id = f"relayhub-{uuid.uuid4().hex[:8]}"
        # 接入策略（拉黑 + 优先名单）：后台管理改文件即时生效（指纹热加载）。
        # 传 None = 无策略文件（全放行、全普通队），测试与单机自用零负担。
        self.policy = policy
        # 非流式应答缓存（按调用者隔离，TTL 300s）
        self.response_cache = ResponseCache()
        # 用户体系（公网面板 + 额度计费）。默认挂标准数据根；
        # users.json 不存在时是「未开放注册的空池」，面板功能自然降级。
        self.users = users if users is not None else UserStore(paths.users_path())
        self.redeem = redeem if redeem is not None else RedeemStore(paths.redeem_codes_path())
        # 登录会话（内存态）：sid -> (user_id, expires)。重启全员下线，对面板是特性。
        self.sessions: dict[str, tuple[str, float]] = {}
        self.session_lock = threading.Lock()
        # TOIP 接入服务（toip.py）。None = 本网关未启用 TOIP，/v1/toip/* 全 404。
        # 服务本身按需从数据根读 station/tickets 文件，所以 CLI 只需传一个
        # ToipService 实例，不必把两个路径散到构造签名里。
        self.toip = toip
        # 插件日志根（pluginlogs/ 的父目录）。None = 用默认数据根；
        # 测试传 tmp_path 让插件日志不落进真实数据根。
        self.plugin_log_home = plugin_log_home

    @property
    def base_url(self) -> str:
        host, port = self.server_address[0], self.server_address[1]
        return f"http://{host}:{port}"

    def toip_summary(self) -> dict[str, Any]:
        """给发现应答器用的 TOIP 能力块（放 UDP 包里的那一小份）。

        刻意比 `GET /v1/toip/station` 更瘦：UDP 应答要挤进 4096 字节的
        接收缓冲，而且发现阶段只需要「支不支持 + 往哪问」。细节让客户端
        发现之后再走 HTTP 拿——这也让应答包不会随端点增多而膨胀。
        """
        service = self.toip
        if service is None:
            return {"enabled": False}
        public = service.station_public()
        if not public.get("enabled"):
            return {"enabled": False}
        return {
            "enabled": True,
            "protocol": public.get("protocol", toip_module.PROTOCOL),
            "version": public.get("version", toip_module.PROTOCOL_VERSION),
            "station_id": public.get("station_id", ""),
            "join": "/v1/toip/join",
            "station": "/v1/toip/station",
        }


def demo_pool() -> ChannelPool:
    """演示用渠道池：一个坏渠道在前，用于验证故障切换。"""
    models = {"glm-5.2": 1000000, "deepseek-v4-pro": 1000000, "deepseek-v4-flash": 1000000}
    return ChannelPool(
        [
            Channel(name="primary-down", models=dict(models), broken=True),
            Channel(name="secondary", models=dict(models)),
        ]
    )


def demo_router() -> DemoRouter:
    return DemoRouter(demo_pool())
