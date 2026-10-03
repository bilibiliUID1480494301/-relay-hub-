"""中转站一致性探测器。

用途：把「客户端要求中转站做到什么」变成可执行断言，指到任意 base URL 上跑一遍。
先对着已知正确的参考实现跑（`relayhub.gateway.service`）证明探测器有效，
再指向 New API 之类的真实网关，用结果替代「应该支持吧」的猜测。

检查项：
    auth.reject_missing        无凭证必须被拒（401），不能裸奔
    models.list                GET /v1/models 可列出模型（用于自动填 personalModelIds）
    anthropic.non_stream       POST /v1/messages 非流式，必需字段齐全
    anthropic.stream           POST /v1/messages 流式，事件序列与字段名严格正确
    anthropic.stream.incremental  流式是否真增量（首字节远早于末字节）
    openai.non_stream          POST /v1/chat/completions 非流式
    openai.stream              流式 + [DONE] 终止
    error.unknown_model        未知模型返回 4xx，而不是 200 或 5xx
"""

from __future__ import annotations

import argparse
import http.client
import json
import ssl
import sys
import time
from dataclasses import dataclass
from typing import Any, Iterable, Iterator
from urllib.parse import urlsplit

ANTHROPIC_EVENT_ORDER = [
    "message_start",
    "content_block_start",
    "content_block_delta",
    "content_block_stop",
    "message_delta",
    "message_stop",
]
ANTHROPIC_MESSAGE_FIELDS = ("id", "type", "role", "model", "content", "stop_reason", "usage")


def valid_anthropic_sequence(names: list[str]) -> bool:
    """状态机校验事件序列，取代单块模板的严格相等。

    真实流（尤其推理模型）会有**多个 content 块**（思维链一块、正文一块），
    每块内 delta 连发多次。合法形状：
        message_start
        → (content_block_start → content_block_delta+ → content_block_stop)+
        → message_delta → message_stop
    """
    if not names or names[0] != "message_start":
        return False
    i = 1
    blocks = 0
    while i < len(names) and names[i] == "content_block_start":
        blocks += 1
        i += 1
        if i >= len(names) or names[i] != "content_block_delta":
            return False
        while i < len(names) and names[i] == "content_block_delta":
            i += 1
        if i >= len(names) or names[i] != "content_block_stop":
            return False
        i += 1
    if blocks == 0:
        return False
    if i >= len(names) or names[i] != "message_delta":
        return False
    i += 1
    return i == len(names) - 1 and names[i] == "message_stop"


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class RawResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    first_byte_at: float
    last_byte_at: float


class Probe:
    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        timeout: float = 15.0,
        insecure: bool = False,
    ) -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https"):
            raise ValueError(f"base_url 必须以 http/https 开头：{base_url}")
        self.scheme = parts.scheme
        self.host = parts.hostname or "127.0.0.1"
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.prefix = parts.path.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.insecure = insecure

    # -- 传输 ------------------------------------------------------------

    def _connection(self, stream: bool) -> http.client.HTTPConnection:
        if self.scheme == "https":
            context = ssl.create_default_context()
            if self.insecure:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            return http.client.HTTPSConnection(
                self.host, self.port, timeout=self.timeout, context=context
            )
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def _headers(self, with_auth: bool, streaming: bool) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if with_auth and self.api_key:
            headers["x-api-key"] = self.api_key
            headers["Authorization"] = f"Bearer {self.api_key}"
        if streaming:
            headers["Accept"] = "text/event-stream"
            headers["anthropic-version"] = "2023-06-01"
        return headers

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        with_auth: bool = True,
        streaming: bool = False,
        read_stream: bool = False,
    ) -> tuple[RawResponse, list[bytes]]:
        """发一个请求。read_stream=True 时返回逐行读到的原始块（用于流式增量断言）。"""
        connection = self._connection(streaming)
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        headers = self._headers(with_auth, streaming)
        if payload is not None:
            headers["Content-Length"] = str(len(payload))
        started = time.monotonic()
        connection.request(method, f"{self.prefix}{path}", body=payload, headers=headers)
        response = connection.getresponse()
        first = time.monotonic()

        lines: list[bytes] = []
        if read_stream:
            while True:
                line = response.readline()
                if not line:
                    break
                lines.append(line)
            collected = b"".join(lines)
        else:
            collected = response.read()
        last = time.monotonic()
        connection.close()

        header_map = {key.lower(): value for key, value in response.getheaders()}
        return (
            RawResponse(
                status=response.status,
                headers=header_map,
                body=collected,
                first_byte_at=first - started,
                last_byte_at=last - started,
            ),
            lines,
        )

    def get(self, path: str, **kwargs: Any) -> RawResponse:
        return self.request("GET", path, **kwargs)[0]

    def post(self, path: str, body: dict[str, Any], **kwargs: Any) -> tuple[RawResponse, list[bytes]]:
        return self.request("POST", path, body, **kwargs)


# ---------------------------------------------------------------- SSE 解析


def parse_sse(lines: Iterable[bytes]) -> list[tuple[str | None, str]]:
    """把 SSE 行流解析成 [(event, data)]。忽略注释与空 data。"""
    events: list[tuple[str | None, str]] = []
    current_event: str | None = None
    data_lines: list[str] = []
    for raw in lines:
        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        if not line:
            if data_lines:
                events.append((current_event, "\n".join(data_lines)))
            current_event, data_lines = None, []
            continue
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            current_event = line[len("event:") :].strip()
        elif line.startswith("data:"):
            data_lines.append(line[len("data:") :].lstrip())
    if data_lines:
        events.append((current_event, "\n".join(data_lines)))
    return events


def _pick_model(probe: Probe) -> tuple[str | None, str]:
    listing = probe.get("/v1/models")
    if listing.status != 200:
        return None, f"GET /v1/models 返回 {listing.status}"
    try:
        payload = json.loads(listing.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"/v1/models 不是合法 JSON：{exc}"
    items = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(items, list) or not items:
        return None, "/v1/models 的 data 为空"
    first = items[0]
    model = first.get("id") if isinstance(first, dict) else None
    if not model:
        return None, "模型条目缺少 id"
    return str(model), ""


# ---------------------------------------------------------------- 各项检查


def run_checks(
    base_url: str,
    api_key: str | None = None,
    model: str | None = None,
    timeout: float = 15.0,
    insecure: bool = False,
) -> list[CheckResult]:
    probe = Probe(base_url, api_key, timeout, insecure)
    results: list[CheckResult] = []

    # 1. 无凭证必须被拒
    if api_key:
        try:
            response = probe.post(
                "/v1/messages", {"model": "x", "max_tokens": 1, "messages": []}, with_auth=False
            )[0]
            results.append(
                CheckResult(
                    "auth.reject_missing",
                    response.status == 401,
                    f"无凭证请求返回 {response.status}（期望 401）",
                )
            )
        except OSError as exc:
            results.append(CheckResult("auth.reject_missing", False, f"连接失败：{exc}"))
            return results

    # 2. 模型列表
    model, note = _pick_model(probe)
    chosen = model or "__probe_unknown_model__"
    if model is None:
        # 不 early-return：真实网关常见「有 /v1/messages 但没有 /v1/models」，
        # 那样只报一条失败会把协议层的真实情况全掩盖掉。
        note = f"{note}；后续协议检查改用占位模型名 {chosen}，结果仅供参考"
    results.append(CheckResult("models.list", model is not None, note or f"首个模型 {model}"))

    # 3. Anthropic 非流式
    try:
        response, _ = probe.post(
            "/v1/messages",
            {"model": chosen, "max_tokens": 64, "messages": [{"role": "user", "content": "ping"}]},
        )
        missing = _missing_anthropic_fields(response)
        results.append(
            CheckResult(
                "anthropic.non_stream",
                response.status == 200 and not missing,
                f"HTTP {response.status}"
                + (f"，缺字段 {missing}" if missing else "，字段齐全"),
            )
        )
    except OSError as exc:
        results.append(CheckResult("anthropic.non_stream", False, f"连接失败：{exc}"))

    # 4. Anthropic 流式
    try:
        response, lines = probe.post(
            "/v1/messages",
            {
                "model": chosen,
                "max_tokens": 64,
                "stream": True,
                "messages": [{"role": "user", "content": "ping"}],
            },
            streaming=True,
            read_stream=True,
        )
        content_type = response.headers.get("content-type", "")
        events = parse_sse(lines)
        names = [name for name, _ in events]
        # 状态机校验：允许多 content 块 + 连发 delta（真实推理流的形状）
        sequence_ok = valid_anthropic_sequence([n for n in names if n != "ping"])
        payload_ok = True
        for name, data in events:
            if name in (None, "ping"):
                continue
            try:
                parsed = json.loads(data)
            except json.JSONDecodeError:
                payload_ok = False
                break
            if parsed.get("type") != name:
                payload_ok = False
                break
        results.append(
            CheckResult(
                "anthropic.stream",
                response.status == 200
                and "text/event-stream" in content_type
                and sequence_ok
                and payload_ok,
                f"HTTP {response.status}, content-type={content_type or '缺失'}, "
                f"事件={names}, 顺序{'正确' if sequence_ok else '错误'}, "
                f"data.type{'匹配' if payload_ok else '不匹配'}",
            )
        )
        # 5. 增量性：首字节若几乎等于末字节，说明被整包缓冲了
        if response.status == 200 and len(names) > 2:
            results.append(
                CheckResult(
                    "anthropic.stream.incremental",
                    response.last_byte_at - response.first_byte_at > 0.005,
                    f"首字节 {response.first_byte_at * 1000:.1f}ms，"
                    f"末字节 {response.last_byte_at * 1000:.1f}ms"
                    f"（若两者几乎相同，说明被缓冲成整包，SSE 就不是真流式）",
                )
            )
    except OSError as exc:
        results.append(CheckResult("anthropic.stream", False, f"连接失败：{exc}"))

    # 6. OpenAI 非流式
    try:
        response, _ = probe.post(
            "/v1/chat/completions",
            {"model": chosen, "messages": [{"role": "user", "content": "ping"}]},
        )
        detail = f"HTTP {response.status}"
        ok = response.status == 200
        if ok:
            try:
                payload = json.loads(response.body.decode("utf-8"))
                choices = payload.get("choices")
                if not isinstance(choices, list) or not choices:
                    ok, detail = False, "choices 为空"
                elif "message" not in choices[0]:
                    ok, detail = False, "choices[0] 缺 message"
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                ok, detail = False, f"响应不是合法 JSON：{exc}"
        results.append(CheckResult("openai.non_stream", ok, detail))
    except OSError as exc:
        results.append(CheckResult("openai.non_stream", False, f"连接失败：{exc}"))

    # 7. OpenAI 流式
    try:
        response, lines = probe.post(
            "/v1/chat/completions",
            {"model": chosen, "stream": True, "messages": [{"role": "user", "content": "ping"}]},
            streaming=True,
            read_stream=True,
        )
        events = parse_sse(lines)
        payloads = [data for _, data in events if data]
        has_done = payloads[-1].strip() == "[DONE]" if payloads else False
        chunks_ok = all(_is_openai_chunk(p) for p in payloads[:-1]) if len(payloads) > 1 else False
        results.append(
            CheckResult(
                "openai.stream",
                response.status == 200 and has_done and chunks_ok,
                f"HTTP {response.status}, 数据块 {len(payloads)} 个, "
                f"[DONE] {'有' if has_done else '缺失'}, "
                f"chunk 结构{'正确' if chunks_ok else '错误'}",
            )
        )
    except OSError as exc:
        results.append(CheckResult("openai.stream", False, f"连接失败：{exc}"))

    # 8. 未知模型错误语义
    try:
        response, _ = probe.post(
            "/v1/messages",
            {
                "model": "definitely-not-a-real-model-xyz",
                "max_tokens": 8,
                "messages": [{"role": "user", "content": "ping"}],
            },
        )
        results.append(
            CheckResult(
                "error.unknown_model",
                400 <= response.status < 500,
                f"返回 {response.status}（期望 4xx；返回 200 说明它不校验模型）",
            )
        )
    except OSError as exc:
        results.append(CheckResult("error.unknown_model", False, f"连接失败：{exc}"))

    return results


def _missing_anthropic_fields(response: RawResponse) -> list[str]:
    if response.status != 200:
        return []
    try:
        payload = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ["<响应不是合法 JSON>"]
    if not isinstance(payload, dict):
        return ["<响应不是 JSON 对象>"]
    return [field for field in ANTHROPIC_MESSAGE_FIELDS if field not in payload]


def _is_openai_chunk(data: str) -> bool:
    try:
        payload = json.loads(data)
    except json.JSONDecodeError:
        return False
    return isinstance(payload, dict) and "choices" in payload


# ---------------------------------------------------------------- CLI


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="中转站一致性探测")
    parser.add_argument("--base-url", required=True, help="如 http://127.0.0.1:8799 或 https://gw.local")
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--model", default=None, help="不传则用 /v1/models 的第一个")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--insecure", action="store_true", help="跳过 TLS 校验（自签证书时用）")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出")
    args = parser.parse_args(argv)

    try:
        results = run_checks(
            args.base_url, args.api_key, args.model, args.timeout, args.insecure
        )
    except (OSError, ValueError) as exc:
        print(f"探测失败：{exc}", file=sys.stderr)
        return 2

    if args.json:
        print(
            json.dumps(
                [{"name": r.name, "ok": r.ok, "detail": r.detail} for r in results],
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print(f"目标：{args.base_url}")
        for result in results:
            print(f"  [{'通过' if result.ok else '失败'}] {result.name}  {result.detail}")
        passed = sum(1 for r in results if r.ok)
        print(f"\n{passed}/{len(results)} 项通过")

    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
