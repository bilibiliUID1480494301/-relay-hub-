"""真实上游调用 + 协议转换。

为什么必须有协议转换：上游可能是 OpenAI 形态的自托管模型/网关，也可能是
**Anthropic Messages** 形态的渠道。所以中转站要能：
    入站 anthropic-messages  →  上游 anthropic-messages   （原样透传）
    入站 anthropic-messages  →  上游 openai-chat          （双向翻译，含流式）
第二条是号池能覆盖到 OpenAI 生态的关键。

支持：Anthropic ⇄ OpenAI 的 `tools` / `tool_use` / `tool_calls` 互译（参考 OneAPI
`relay-convert.go` 的 Inbound→IR→Outbound 思路：网关内部只认 Anthropic 一种 IR，
出站/入站各做一次协议适配）。多模态块仍然显式报 400，避免半对翻译把问题藏到难排查处。
"""

from __future__ import annotations

import json
import re
import ssl
import threading
import time
import uuid
from dataclasses import dataclass
from http.client import HTTPConnection, HTTPSConnection
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

from .pool import (
    AUTH_MODE_BEARER,
    PROTOCOL_ANTHROPIC,
    UpstreamKey,
)

ANTHROPIC_VERSION = "2023-06-01"

# OpenAI 客户端基本不传 max_tokens，而 Anthropic 的 max_tokens 是必填字段。
# 与其让上游回一句 "max_tokens: field required"，不如给个保守默认值。
DEFAULT_MAX_TOKENS = 4096

_FINISH_REASON_MAP = {
    "stop": "end_turn",
    "length": "max_tokens",
    "content_filter": "end_turn",
    "tool_calls": "tool_use",
}


class UpstreamError(RuntimeError):
    """上游调用失败。retryable 决定是否计入熔断。"""

    def __init__(self, status: int, message: str, retryable: bool) -> None:
        super().__init__(f"HTTP {status}: {message}" if status else message)
        self.status = status
        self.detail = message
        self.retryable = retryable


@dataclass
class UpstreamReply:
    message: dict[str, Any]
    tokens_in: int
    tokens_out: int
    # 缓存命中（Anthropic cache_read/creation；OpenAI cached_tokens 折进 read）
    cache_read: int = 0
    cache_creation: int = 0


def cache_from_usage(usage: dict[str, Any]) -> tuple[int, int]:
    """从 usage 提取缓存命中量。Anthropic 有原生字段；
    OpenAI 的 cached_tokens 藏在 prompt_tokens_details 里，折进 read 侧。"""
    read = int(usage.get("cache_read_input_tokens") or 0)
    creation = int(usage.get("cache_creation_input_tokens") or 0)
    if not read:
        details = usage.get("prompt_tokens_details") or {}
        read = int(details.get("cached_tokens") or 0) if isinstance(details, dict) else 0
    return read, creation


# ---------------------------------------------------------------- 基础工具


def normalize_base(base_url: str) -> str:
    """与常见客户端一致：不以 /v1 结尾就补 /v1。"""
    trimmed = base_url.strip().rstrip("/")
    if not trimmed:
        raise ValueError("base_url 为空")
    return trimmed if trimmed.lower().endswith("/v1") else f"{trimmed}/v1"


def _open(key: UpstreamKey, path: str, timeout: float) -> tuple[HTTPConnection, str]:
    parts = urlsplit(key.base_url)
    scheme = parts.scheme.lower() or "http"
    if scheme not in ("http", "https"):
        raise UpstreamError(0, f"不支持的 scheme：{key.base_url}", retryable=False)
    host = parts.hostname or "127.0.0.1"
    port = parts.port or (443 if scheme == "https" else 80)
    if scheme == "https":
        connection: HTTPConnection = HTTPSConnection(host, port, timeout=timeout)
    else:
        connection = HTTPConnection(host, port, timeout=timeout)
    # 请求目标用 origin-form（仅路径）：http.client 对绝对 URL 会原样发出
    # 「POST http://host/... HTTP/1.1」，严格的 origin server 会回 404 空响应体。
    base_path = parts.path.rstrip("/")
    if not re.search(r"/v\d+$", base_path, re.IGNORECASE):
        # base_url 没带版本段才补 /v1：显式写了 /v1、/v4（智谱）等就尊重原样，
        # 否则智谱的 /api/paas/v4 会被改写成 /api/paas/v4/v1 直接 404。
        base_path = f"{base_path}/v1"
    target = f"{base_path}{path}"
    if parts.query:
        # base_url 自带的 query 必须原样带到上游（如 ?app_version=…、
        # 各家网关的 ?api-version=）。这里曾经只取 parts.path，query 被静默丢掉——
        # 上游要么按缺参报 400，要么走默认分支，排查时完全看不出问题出在拼 URL。
        target = f"{target}{'&' if '?' in target else '?'}{parts.query}"
    return connection, target


def _auth_headers(
    key: UpstreamKey,
    accept_sse: bool,
    access_token: str | None = None,
    trace_headers: dict[str, str] | None = None,
) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if key.auth_mode == AUTH_MODE_BEARER:
        # ANTHROPIC_AUTH_TOKEN 风格的上游：协议是 Anthropic 但凭证是 Bearer
        headers["Authorization"] = f"Bearer {key.api_key}"
    elif key.protocol == PROTOCOL_ANTHROPIC:
        headers["x-api-key"] = key.api_key
        headers["anthropic-version"] = ANTHROPIC_VERSION
    else:
        headers["Authorization"] = f"Bearer {key.api_key}"
    if key.extra_headers:
        # 渠道级额外头（Claude Code OAuth 的 anthropic-beta 等）最后合并，可覆盖默认
        headers.update(key.extra_headers)
    if trace_headers:
        # 链路标识（Via / X-Relay-Hub-Hops / X-Request-ID）最后合并：
        # 让转发链路可观测，也是环路检测的最强信号
        headers.update(trace_headers)
    headers["Accept"] = "text/event-stream" if accept_sse else "application/json"
    return headers


def _retryable(status: int) -> bool:
    """计入分级冷却的上游失败：429（soft 档）、5xx/连不上（err 档）、
    401/403（disable 档——重试同一个 Key 没有意义，但也不能让它装作健康
    继续接流量，必须熔断等人工处理）。其余 4xx 是请求本身的问题（不计）。"""
    if status == 0:
        return True
    if status in (401, 403):
        return True
    return status == 429 or status >= 500


def _iter_lines(response: Any) -> Iterator[bytes]:
    while True:
        line = response.readline()
        if not line:
            return
        yield line


def _read_error(response: Any) -> str:
    try:
        raw = response.read()
    except OSError:
        return "<读取错误响应失败>"
    text = raw.decode("utf-8", errors="replace").strip()
    return text[:400] or "<空响应体>"


# ---------------------------------------------------------------- 请求翻译

# Anthropic ⇄ OpenAI 的工具 schema 是公开标准（OneAPI 的 relay-convert.go 也是这套），
# 这里照着它实现：
#   Anthropic tools:[{name,description,input_schema}]   ⇄
#   OpenAI   tools:[{type:"function",function:{name,description,parameters}}]
#   Anthropic content tool_use:{type,id,name,input}     ⇄
#   OpenAI   message.tool_calls:[{id,type:"function",function:{name,arguments(JSON 串)}}]
#   Anthropic content tool_result:{type,tool_use_id,content} ⇄
#   OpenAI   message(role:"tool"):{tool_call_id,content}


def _anthropic_text(content: Any) -> str:
    """从 Anthropic 的 content（str 或块数组）里抽出纯文本；忽略 tool_use/tool_result 等块。"""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    return "".join(
        part.get("text", "")
        for part in content
        if isinstance(part, dict) and part.get("type") == "text"
    )


def _anthropic_tools_to_openai(tools: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for tool in tools or []:
        if not isinstance(tool, dict):
            continue
        # 服务端工具（web_search_*/computer_* 等）不是 function 调用，别硬翻译成
        # 空参数的 function——那会让 OpenAI 上游收到一个必然误触发的假工具。
        # 它们由调用方（to_openai_request）映射成 web_search_options 之类的原生开关。
        if tool.get("type") not in (None, "", "custom"):
            continue
        params = tool.get("input_schema") or {"type": "object", "properties": {}}
        out.append(
            {
                "type": "function",
                "function": {
                    "name": tool.get("name"),
                    "description": tool.get("description", ""),
                    "parameters": params,
                },
            }
        )
    return out


def _anthropic_image_to_openai(source: Any) -> dict[str, Any] | None:
    """Anthropic image 块的 source → OpenAI image_url part；无法识别返回 None。"""
    if not isinstance(source, dict):
        return None
    if source.get("type") == "base64":
        media = str(source.get("media_type") or "image/png")
        data = str(source.get("data") or "")
        if not data:
            return None
        return {"type": "image_url", "image_url": {"url": f"data:{media};base64,{data}"}}
    if source.get("type") == "url":
        url = str(source.get("url") or "")
        if not url:
            return None
        return {"type": "image_url", "image_url": {"url": url}}
    return None


def _openai_image_to_anthropic(image_url: Any) -> dict[str, Any] | None:
    """OpenAI image_url part → Anthropic image 块；无法识别返回 None。

    data URL 拆成 base64 source；http(s) URL 走 Anthropic 的 url source。
    """
    url = ""
    if isinstance(image_url, dict):
        url = str(image_url.get("url") or "")
    elif isinstance(image_url, str):
        url = image_url
    if not url:
        return None
    if url.startswith("data:"):
        head, _, data = url.partition(",")
        media = head[5:].split(";", 1)[0] or "image/png"
        if not data:
            return None
        return {"type": "image", "source": {"type": "base64", "media_type": media, "data": data}}
    if url.startswith(("http://", "https://")):
        return {"type": "image", "source": {"type": "url", "url": url}}
    return None


def _openai_functions_to_anthropic(specs: Any) -> list[dict[str, Any]]:
    """OpenAI 的 tools 或 legacy functions → Anthropic tools。

    tools 里每项包了一层 {function:{...}}；legacy functions 里直接是 {name,...}，
    用 `spec.get("function", spec)` 两种都兜住。
    """
    out: list[dict[str, Any]] = []
    for spec in specs or []:
        if not isinstance(spec, dict):
            continue
        func = spec.get("function", spec)
        params = func.get("parameters") or {"type": "object", "properties": {}}
        out.append(
            {
                "name": func.get("name"),
                "description": func.get("description", ""),
                "input_schema": params,
            }
        )
    return out


def _parse_arguments(raw: Any) -> dict[str, Any]:
    """OpenAI 的 arguments 是 JSON 字符串；宽松解析：坏 JSON 当空对象，别让整条请求 500。"""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        if not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return {}


def to_openai_request(payload: dict[str, Any]) -> dict[str, Any]:
    """Anthropic Messages 请求 → OpenAI Chat Completions 请求（含 tools/tool_use/tool_result 互译）。"""
    messages: list[dict[str, Any]] = []
    system_text = _anthropic_text(payload.get("system"))
    if system_text.strip():
        messages.append({"role": "system", "content": system_text})

    for message in payload.get("messages") or []:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        content = message.get("content")
        if role == "user":
            text_parts: list[str] = []
            image_parts: list[dict[str, Any]] = []
            tool_results: list[dict[str, Any]] = []
            if isinstance(content, str):
                text_parts.append(content)
            elif isinstance(content, list):
                for part in content:
                    if not isinstance(part, dict):
                        continue
                    ptype = part.get("type")
                    if ptype == "text":
                        text_parts.append(part.get("text", ""))
                    elif ptype == "image":
                        image = _anthropic_image_to_openai(part.get("source"))
                        if image is not None:
                            image_parts.append(image)
                    elif ptype == "tool_result":
                        tool_results.append(part)
            # 有图时 content 必须用块数组（OpenAI 多模态格式），纯文本保持字符串
            if image_parts:
                parts: list[dict[str, Any]] = []
                if "".join(text_parts).strip():
                    parts.append({"type": "text", "text": "".join(text_parts)})
                parts.extend(image_parts)
                messages.append({"role": "user", "content": parts})
            elif text_parts:
                messages.append({"role": "user", "content": "".join(text_parts)})
            for tr in tool_results:
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tr.get("tool_use_id"),
                        "content": _anthropic_text(tr.get("content")),
                    }
                )
        elif role == "assistant":
            text_parts = []
            tool_uses: list[dict[str, Any]] = []
            if isinstance(content, str):
                text_parts.append(content)
            elif isinstance(content, list):
                for part in content:
                    if not isinstance(part, dict):
                        continue
                    ptype = part.get("type")
                    if ptype == "text":
                        text_parts.append(part.get("text", ""))
                    elif ptype == "tool_use":
                        tool_uses.append(
                            {
                                "id": part.get("id"),
                                "type": "function",
                                "function": {
                                    "name": part.get("name"),
                                    "arguments": json.dumps(
                                        part.get("input") or {}, ensure_ascii=False
                                    ),
                                },
                            }
                        )
            msg: dict[str, Any] = {"role": "assistant", "content": "".join(text_parts)}
            if tool_uses:
                # OpenAI 要求带 tool_calls 时 content 必须是字符串（可空）
                msg["content"] = msg["content"] or ""
                msg["tool_calls"] = tool_uses
            messages.append(msg)

    out: dict[str, Any] = {"model": payload.get("model"), "messages": messages}
    atools = payload.get("tools")
    converted_tools = _anthropic_tools_to_openai(atools) if atools else []
    has_server_search = bool(atools) and any(
        isinstance(t, dict) and str(t.get("type") or "").startswith("web_search")
        for t in atools
    )
    if has_server_search:
        # Anthropic 的联网搜索是服务端工具（web_search_*），OpenAI 侧对应
        # web_search_options 开关——两个方言各自的原生搜索入口互译。
        out["web_search_options"] = payload.get("web_search_options") or {}
    elif payload.get("web_search_options") is not None:
        out["web_search_options"] = payload["web_search_options"]
    if converted_tools:
        out["tools"] = converted_tools
    for source, target in (
        ("max_tokens", "max_tokens"),
        ("temperature", "temperature"),
        ("top_p", "top_p"),
        ("stop_sequences", "stop"),
    ):
        if payload.get(source) is not None:
            out[target] = payload[source]
    return out


def _flatten_openai_content(content: Any) -> str:
    """OpenAI 的 content 可能是字符串，也可能是 [{type:text,text:...}] 块数组。"""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    pieces: list[str] = []
    for part in content:
        if not isinstance(part, dict):
            continue
        kind = part.get("type")
        if kind in (None, "text", "input_text"):
            pieces.append(str(part.get("text") or ""))
        elif kind in ("image_url", "input_image"):
            # 用户消息里的图片由 _openai_user_content_to_anthropic 走块翻译；
            # 走到这里的都是 system/assistant/tool 等纯文本语境，直接忽略图块
            # （而不是像旧版那样 400 拒绝——搜题带图是正常用法）。
            continue
        elif kind in ("audio", "input_audio"):
            raise UpstreamError(
                400, f"本版本不支持 OpenAI 多模态块 {kind} 的翻译", retryable=False
            )
    return "".join(pieces)


def _openai_user_content_to_anthropic(content: Any) -> Any:
    """OpenAI 用户消息 content → Anthropic 形态（纯文本或 text+image 块数组）。

    图片识别（搜题拍照）走这里：image_url 的 data URL 拆成 base64 source、
    http(s) URL 转 Anthropic 的 url source；纯文本消息保持字符串不变。
    """
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    blocks: list[dict[str, Any]] = []
    has_image = False
    for part in content:
        if not isinstance(part, dict):
            continue
        kind = part.get("type")
        if kind in (None, "text", "input_text"):
            text = str(part.get("text") or "")
            if text:
                blocks.append({"type": "text", "text": text})
        elif kind in ("image_url", "input_image"):
            image = _openai_image_to_anthropic(part.get("image_url") or part)
            if image is not None:
                blocks.append(image)
                has_image = True
        elif kind in ("audio", "input_audio"):
            raise UpstreamError(
                400, f"本版本不支持 OpenAI 多模态块 {kind} 的翻译", retryable=False
            )
    if not has_image:
        # 无图退回纯文本（拼接顺序与旧版一致），避免无谓的块数组
        return "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
    if not any(b.get("type") == "text" for b in blocks):
        blocks.insert(0, {"type": "text", "text": ""})
    return blocks


def to_anthropic_request(payload: dict[str, Any]) -> dict[str, Any]:
    """OpenAI Chat Completions 请求 → Anthropic Messages 请求（含 tools/functions/tool 角色互译）。

    **为什么必须做这一步**：网关对外同时开两个口（`/v1/messages` 与
    `/v1/chat/completions`），但内部只认一种规范形态。少了这层翻译，
    「客户端说 OpenAI、上游也是 Anthropic」这条路径会把 OpenAI 的请求体原样
    怼给 `/messages`——上游要么直接报错，要么把 `messages` 里的 system 角色
    当成普通对话轮次处理。这类 bug 不报错、只是答得不对，最难查。
    """
    system_parts: list[str] = []
    messages: list[dict[str, Any]] = []
    for message in payload.get("messages") or []:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        if role == "system":
            text = _flatten_openai_content(message.get("content"))
            if text.strip():
                system_parts.append(text)
            continue
        if role == "tool":
            # OpenAI 的 tool 角色 → Anthropic 的 tool_result 块（放在一条 user 消息里）
            messages.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": message.get("tool_call_id"),
                            "content": _flatten_openai_content(message.get("content")),
                        }
                    ],
                }
            )
            continue
        if role == "assistant":
            text = _flatten_openai_content(message.get("content"))
            content_blocks: list[dict[str, Any]] = []
            if text.strip():
                content_blocks.append({"type": "text", "text": text})
            for tc in message.get("tool_calls") or []:
                if not isinstance(tc, dict):
                    continue
                func = tc.get("function") or {}
                content_blocks.append(
                    {
                        "type": "tool_use",
                        "id": tc.get("id"),
                        "name": func.get("name"),
                        "input": _parse_arguments(func.get("arguments")),
                    }
                )
            messages.append({"role": "assistant", "content": content_blocks})
            continue
        if role == "user":
            messages.append(
                {"role": "user", "content": _openai_user_content_to_anthropic(message.get("content"))}
            )

    out: dict[str, Any] = {
        "model": payload.get("model"),
        "messages": messages,
        "max_tokens": int(payload.get("max_tokens") or DEFAULT_MAX_TOKENS),
    }
    if system_parts:
        # Anthropic 的 system 是顶层字段，不是一条消息。
        out["system"] = "\n\n".join(system_parts)
    otools = payload.get("tools")
    if otools:
        out["tools"] = _openai_functions_to_anthropic(otools)
    ofunctions = payload.get("functions")
    if ofunctions:
        out.setdefault("tools", []).extend(_openai_functions_to_anthropic(ofunctions))
    # OpenAI 的联网搜索开关 → Anthropic 的 web_search 服务端工具（原生搜索入口互译）。
    if payload.get("web_search_options") is not None:
        opts = payload["web_search_options"] if isinstance(payload["web_search_options"], dict) else {}
        out.setdefault("tools", []).append(
            {
                "type": "web_search_20250305",
                "name": "web_search",
                "max_uses": int(opts.get("max_uses") or 3),
            }
        )
    for source, target in (("temperature", "temperature"), ("top_p", "top_p")):
        if payload.get(source) is not None:
            out[target] = payload[source]
    stop = payload.get("stop")
    if stop:
        out["stop_sequences"] = [stop] if isinstance(stop, str) else list(stop)
    return out


def to_anthropic_message(data: dict[str, Any], model: str) -> tuple[dict[str, Any], int, int]:
    """OpenAI Chat Completions 响应 → Anthropic Messages 响应（含 tool_calls → tool_use 互译）。"""
    choices = data.get("choices") or []
    choice = choices[0] if isinstance(choices, list) and choices else {}
    raw_message = choice.get("message") or {}
    text = _flatten_openai_content(raw_message.get("content"))
    content_blocks: list[dict[str, Any]] = []
    if text.strip():
        content_blocks.append({"type": "text", "text": text})
    for tc in raw_message.get("tool_calls") or []:
        if not isinstance(tc, dict):
            continue
        func = tc.get("function") or {}
        content_blocks.append(
            {
                "type": "tool_use",
                "id": tc.get("id"),
                "name": func.get("name"),
                "input": _parse_arguments(func.get("arguments")),
            }
        )
    if not content_blocks:
        content_blocks.append({"type": "text", "text": ""})
    usage = data.get("usage") or {}
    tokens_in = int(usage.get("prompt_tokens") or 0)
    tokens_out = int(usage.get("completion_tokens") or 0)
    message = {
        "id": f"msg_{uuid.uuid4().hex[:24]}",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content_blocks,
        "stop_reason": _FINISH_REASON_MAP.get(str(choice.get("finish_reason")), "end_turn"),
        "stop_sequence": None,
        "usage": {"input_tokens": tokens_in, "output_tokens": tokens_out},
    }
    return message, tokens_in, tokens_out




# ---------------------------------------------------------------- 非流式


def call_once(
    key: UpstreamKey,
    payload: dict[str, Any],
    timeout: float = 120.0,
    trace_headers: dict[str, str] | None = None,
) -> UpstreamReply:
    anthropic_side = key.protocol == PROTOCOL_ANTHROPIC
    path = "/messages" if anthropic_side else "/chat/completions"
    connection, url = _open(key, path, timeout)
    try:
        if anthropic_side:
            outbound = {**payload, "stream": False}
        else:
            outbound = {**to_openai_request(payload), "stream": False}
        body = json.dumps(outbound, ensure_ascii=False).encode("utf-8")
        headers = _auth_headers(key, accept_sse=False, trace_headers=trace_headers)
        headers["Content-Length"] = str(len(body))
        connection.request("POST", url, body=body, headers=headers)
        response = connection.getresponse()
        if response.status != 200:
            raise UpstreamError(response.status, _read_error(response), _retryable(response.status))
        raw = response.read()
    except (OSError, ssl.SSLError) as exc:
        raise UpstreamError(0, f"连接上游失败：{exc}", retryable=True) from exc
    finally:
        connection.close()

    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpstreamError(0, f"上游返回的不是合法 JSON：{exc}", retryable=True) from exc

    if anthropic_side:
        usage = data.get("usage") or {}
        cache_read, cache_creation = cache_from_usage(usage)
        return UpstreamReply(
            message=data,
            tokens_in=int(usage.get("input_tokens") or 0),
            tokens_out=int(usage.get("output_tokens") or 0),
            cache_read=cache_read,
            cache_creation=cache_creation,
        )
    message, tokens_in, tokens_out = to_anthropic_message(data, str(payload.get("model") or ""))
    cache_read, cache_creation = cache_from_usage(data.get("usage") or {})
    return UpstreamReply(
        message=message,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        cache_read=cache_read,
        cache_creation=cache_creation,
    )


def call_embeddings(
    key: UpstreamKey,
    payload: dict[str, Any],
    timeout: float = 120.0,
    trace_headers: dict[str, str] | None = None,
) -> tuple[dict[str, Any], int]:
    """调用上游的 /v1/embeddings（OpenAI 协议）。

    中文：embeddings 只有 OpenAI 协议形态（Anthropic 没有此 API），所以
    Anthropic 协议的渠道在路由层就会被跳过。返回 (上游 JSON, tokens_in)；
    tokens_in 取 usage.prompt_tokens（缺失时按 total_tokens / 文本长度估算）。

    English: embeddings only exists in the OpenAI dialect (Anthropic has no
    such API), so Anthropic-protocol channels are skipped at the router
    level. Returns (upstream JSON, tokens_in).
    """
    connection, url = _open(key, "/embeddings", timeout)
    try:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = _auth_headers(key, accept_sse=False, trace_headers=trace_headers)
        headers["Content-Length"] = str(len(body))
        connection.request("POST", url, body=body, headers=headers)
        response = connection.getresponse()
        if response.status != 200:
            raise UpstreamError(
                response.status, _read_error(response), _retryable(response.status)
            )
        raw = response.read()
    except (OSError, ssl.SSLError) as exc:
        raise UpstreamError(0, f"连接上游失败：{exc}", retryable=True) from exc
    finally:
        connection.close()

    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpstreamError(0, f"上游返回的不是合法 JSON：{exc}", retryable=True) from exc

    usage = data.get("usage") or {}
    tokens_in = int(usage.get("prompt_tokens") or usage.get("total_tokens") or 0)
    if not tokens_in:
        inp = payload.get("input")
        chars = len(inp) if isinstance(inp, str) else sum(
            len(x) for x in inp if isinstance(x, str)
        ) if isinstance(inp, list) else 1
        tokens_in = max(1, chars // 4)
    return data, tokens_in


# ---------------------------------------------------------------- 流式


def stream_events(
    key: UpstreamKey,
    payload: dict[str, Any],
    timeout: float = 300.0,
    on_usage: Callable[[int, int], None] | None = None,
    trace_headers: dict[str, str] | None = None,
) -> Iterator[tuple[str, dict[str, Any]]]:
    """产出 Anthropic 形态的 (event, payload) 序列。

    上游是 anthropic 协议时原样透传；是 openai 协议时边收边翻译。
    连不上 / 非 200 会在第一次 next() 时抛出，因此调用方可以先 peek 再决定是否放弃这个 Key。
    """
    if key.protocol == PROTOCOL_ANTHROPIC:
        yield from _stream_anthropic(key, payload, timeout, on_usage, trace_headers)
    else:
        yield from _stream_openai_as_anthropic(key, payload, timeout, on_usage, trace_headers)


def _stream_anthropic(
    key: UpstreamKey,
    payload: dict[str, Any],
    timeout: float,
    on_usage: Callable[[int, int], None] | None,
    trace_headers: dict[str, str] | None = None,
) -> Iterator[tuple[str, dict[str, Any]]]:
    connection, url = _open(key, "/messages", timeout)
    tokens_in = tokens_out = 0
    try:
        body = json.dumps({**payload, "stream": True}, ensure_ascii=False).encode("utf-8")
        headers = _auth_headers(key, accept_sse=True, trace_headers=trace_headers)
        headers["Content-Length"] = str(len(body))
        connection.request("POST", url, body=body, headers=headers)
        response = connection.getresponse()
        if response.status != 200:
            raise UpstreamError(response.status, _read_error(response), _retryable(response.status))

        current_event: str | None = None
        data_lines: list[str] = []
        for raw in _iter_lines(response):
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if not line:
                if data_lines:
                    text = "\n".join(data_lines)
                    try:
                        parsed = json.loads(text)
                    except json.JSONDecodeError:
                        parsed = {"type": current_event or "message", "raw": text}
                    name = current_event or str(parsed.get("type", "message"))
                    usage = parsed.get("usage") or {}
                    if name == "message_start":
                        # Anthropic 的 message_start 把 usage 嵌在 message 里，
                        # 顶层 usage 只出现在 message_delta。读错位置的话
                        # tokens_in 永远是 0——不报错，只是账悄悄记少。
                        start_usage = (parsed.get("message") or {}).get("usage") or usage
                        tokens_in = int(start_usage.get("input_tokens") or 0)
                        tokens_out = int(start_usage.get("output_tokens") or 0)
                    elif name == "message_delta":
                        tokens_out = max(tokens_out, int(usage.get("output_tokens") or 0))
                    yield (name, parsed)
                current_event, data_lines = None, []
                continue
            if line.startswith(":"):
                continue
            if line.startswith("event:"):
                current_event = line[len("event:") :].strip()
            elif line.startswith("data:"):
                data_lines.append(line[len("data:") :].lstrip())

        # 上游若在最后一个事件后没补空行，这里补发，避免丢掉收尾事件
        if data_lines:
            text = "\n".join(data_lines)
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = {"type": current_event or "message", "raw": text}
            yield (current_event or str(parsed.get("type", "message")), parsed)
    except (OSError, ssl.SSLError) as exc:
        raise UpstreamError(0, f"连接上游失败：{exc}", retryable=True) from exc
    finally:
        connection.close()
    if on_usage:
        on_usage(tokens_in, tokens_out)


def _stream_openai_as_anthropic(
    key: UpstreamKey,
    payload: dict[str, Any],
    timeout: float,
    on_usage: Callable[[int, int], None] | None,
    trace_headers: dict[str, str] | None = None,
) -> Iterator[tuple[str, dict[str, Any]]]:
    model = str(payload.get("model") or "")
    connection, url = _open(key, "/chat/completions", timeout)
    tokens_in = tokens_out = 0
    try:
        outbound = to_openai_request(payload)
        # 只有带上 include_usage 上游才会在流尾给 usage，拿不到就记 0，不瞎估。
        outbound["stream"] = True
        outbound["stream_options"] = {"include_usage": True}
        body = json.dumps(outbound, ensure_ascii=False).encode("utf-8")
        headers = _auth_headers(key, accept_sse=True, trace_headers=trace_headers)
        headers["Content-Length"] = str(len(body))
        connection.request("POST", url, body=body, headers=headers)
        response = connection.getresponse()
        if response.status != 200:
            raise UpstreamError(response.status, _read_error(response), _retryable(response.status))

        yield (
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": f"msg_{uuid.uuid4().hex[:24]}",
                    "type": "message",
                    "role": "assistant",
                    "model": model,
                    "content": [],
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 0, "output_tokens": 0},
                },
            },
        )

        text_opened = False
        # OpenAI 把 tool_calls 切成带 index 标记的碎片流过来；这里按 index 聚合。
        # 每个 OpenAI tool_call 对应一个 Anthropic content 块，块索引 = index + 1（文本占 0）。
        tools: dict[int, dict[str, Any]] = {}
        finish_reason = "stop"
        for raw in _iter_lines(response):
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if not line or not line.startswith("data:"):
                continue
            data = line[len("data:") :].strip()
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
            except json.JSONDecodeError:
                continue
            usage = chunk.get("usage") or {}
            if usage:
                tokens_in = int(usage.get("prompt_tokens") or tokens_in)
                tokens_out = int(usage.get("completion_tokens") or tokens_out)
            for choice in chunk.get("choices") or []:
                delta = choice.get("delta") or {}
                piece = delta.get("content")
                if isinstance(piece, str) and piece:
                    if not text_opened:
                        text_opened = True
                        yield (
                            "content_block_start",
                            {
                                "type": "content_block_start",
                                "index": 0,
                                "content_block": {"type": "text", "text": ""},
                            },
                        )
                    yield (
                        "content_block_delta",
                        {
                            "type": "content_block_delta",
                            "index": 0,
                            "delta": {"type": "text_delta", "text": piece},
                        },
                    )
                for tc in delta.get("tool_calls") or []:
                    if not isinstance(tc, dict):
                        continue
                    idx = tc.get("index")
                    if not isinstance(idx, int):
                        idx = 0
                    entry = tools.setdefault(idx, {"id": None, "name": None, "opened": False})
                    func = tc.get("function") or {}
                    if tc.get("id") or func.get("id"):
                        entry["id"] = tc.get("id") or func.get("id")
                    if func.get("name"):
                        entry["name"] = func.get("name")
                    argument = func.get("arguments")
                    if argument:
                        argument = str(argument)
                    if not entry["opened"]:
                        entry["opened"] = True
                        yield (
                            "content_block_start",
                            {
                                "type": "content_block_start",
                                "index": idx + 1,
                                "content_block": {
                                    "type": "tool_use",
                                    "id": entry["id"],
                                    "name": entry["name"],
                                    "input": {},
                                },
                            },
                        )
                        if argument:
                            yield (
                                "content_block_delta",
                                {
                                    "type": "content_block_delta",
                                    "index": idx + 1,
                                    "delta": {
                                        "type": "input_json_delta",
                                        "partial_json": argument,
                                    },
                                },
                            )
                    elif argument:
                        yield (
                            "content_block_delta",
                            {
                                "type": "content_block_delta",
                                "index": idx + 1,
                                "delta": {
                                    "type": "input_json_delta",
                                    "partial_json": argument,
                                },
                            },
                        )
                if choice.get("finish_reason"):
                    finish_reason = str(choice["finish_reason"])

        if text_opened:
            yield ("content_block_stop", {"type": "content_block_stop", "index": 0})
        for idx in sorted(tools):
            if tools[idx]["opened"]:
                yield ("content_block_stop", {"type": "content_block_stop", "index": idx + 1})
        if not text_opened and not any(t["opened"] for t in tools.values()):
            # 兜底：上游偶尔回一个空响应；补一个空文本块避免 content 为空被客户端拒。
            yield (
                "content_block_start",
                {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
            )
            yield ("content_block_stop", {"type": "content_block_stop", "index": 0})
        yield (
            "message_delta",
            {
                "type": "message_delta",
                "delta": {
                    "stop_reason": _FINISH_REASON_MAP.get(finish_reason, "end_turn"),
                    "stop_sequence": None,
                },
                "usage": {"output_tokens": tokens_out},
            },
        )
        yield ("message_stop", {"type": "message_stop"})
    except (OSError, ssl.SSLError) as exc:
        raise UpstreamError(0, f"连接上游失败：{exc}", retryable=True) from exc
    finally:
        connection.close()
    if on_usage:
        on_usage(tokens_in, tokens_out)


def peek_first(events: Iterator[tuple[str, dict[str, Any]]]) -> tuple[tuple[str, dict[str, Any]], Iterator[tuple[str, dict[str, Any]]]]:
    """取出第一个事件用于「先探再决定放弃哪个 Key」，再把剩余事件接回迭代器。

    流式中途出错无法再切换渠道，所以能切换的唯一时机就是这里。
    """
    first = next(events)

    def rest() -> Iterator[tuple[str, dict[str, Any]]]:
        yield first
        yield from events

    return first, rest()
