"""路由层：号池 × 上游调用 × 失败切换。

这里解决三个真问题：

1. **失败切换的时机**。非流式很简单，失败就换下一个 Key。流式不行——响应头一发出去就
   无法再改 HTTP 状态码，所以唯一能切换的时机是「连上并且确认状态码 OK」的那一刻。
   `peek_first` 就是干这个的：先把第一个事件拉出来，成功了才把控制权交给调用方。

2. **哪些失败该计入熔断**。429/5xx/连不上是渠道的问题，要熔断；400/404 是我们请求本身
   写得不对（比如模型名错、协议翻译不了），把它算成渠道故障会让整个池子被无辜熔断。

3. **用量记账的完整性**。流式的 usage 在流尾才到，所以不能在返回时就记成功，
   要在流真正跑完后由 `_guard` 补记；客户端中途断开则既不记成功也不记失败。
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from . import upstream
from .pool import KeyPool, UpstreamKey
from .pool import PROTOCOL_ANTHROPIC
from .upstream import UpstreamError, call_embeddings


class RouterError(RuntimeError):
    """无可用渠道。status 区分「客户端要了个不存在的模型」和「上游全挂了」。

    这个区分有实际意义：模型名不在池里是 404（客户端的错，别去熔断任何 Key），
    所有渠道故障才是 502/503（上游的错）。混成一个会让排查方向完全跑偏。
    """

    def __init__(self, message: str, attempts: list[str] | None = None, status: int = 502) -> None:
        super().__init__(message)
        self.attempts = attempts or []
        self.status = status


@dataclass
class RelayOutcome:
    """一次成功的转发结果。二选一：非流式给 message，流式给 events。

    `model` 是本次实际服务的模型名：HTTP 层要用它把 Anthropic 形态的结果
    编码成 OpenAI 形态（chunk 里必须回填 model），这一步不能靠猜。

    `usage` 是流式场景下的用量承接器（`_TokenSink`）：usage 在流尾才到，
    HTTP 层要在流跑完后读它做按令牌记账。非流式没有这个值——直接读 message 的 usage。
    """

    label: str
    model: str = ""
    message: dict[str, Any] | None = None
    events: Iterator[tuple[str, dict[str, Any]]] | None = None
    attempts: list[str] = field(default_factory=list)
    usage: _TokenSink | None = None


class _TokenSink:
    """承接流式流尾才到达的 usage（缓存命中在 message_start 里就位）。"""

    def __init__(self) -> None:
        self.input = 0
        self.output = 0
        self.cache_read = 0
        self.cache_creation = 0

    def __call__(self, tokens_in: int, tokens_out: int) -> None:
        self.input = tokens_in
        self.output = tokens_out


class ExitGuard:
    """出口查重：同一内容指纹在时间窗内对同一上游的发送次数上限。

    与入口 LoopGuard 配对：入口拦「回来的」，出口拦「发出去的」——
    即使入口因内容差异漏判（上游改写了部分参数），同一指纹对同一
    上游的高频重发也会在这里被跳过，候选直接当不可用处理。
    进程内存态，重启清零；窗口 60s、上限 4 次。
    """

    WINDOW = 60.0
    LIMIT = 4

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sends: dict[tuple[str, str], list[float]] = {}

    def allow(self, fingerprint: str, upstream: str) -> bool:
        now = time.monotonic()
        with self._lock:
            key = (fingerprint, upstream)
            hits = [t for t in self._sends.get(key, ()) if now - t < self.WINDOW]
            if len(hits) >= self.LIMIT:
                self._sends[key] = hits
                return False
            hits.append(now)
            self._sends[key] = hits
            if len(self._sends) > 4096:
                self._sends = {k: v for k, v in self._sends.items() if v}
            return True


_EXIT_GUARD = ExitGuard()


class KeyPoolRouter:
    """把请求分发给号池里的真实上游 Key。"""

    def __init__(
        self,
        pool: KeyPool,
        *,
        timeout: float = 120.0,
        stream_timeout: float = 300.0,
        persist_path: Path | None = None,
    ) -> None:
        self.pool = pool
        self.timeout = timeout
        self.stream_timeout = stream_timeout
        self.persist_path = persist_path

    # -- 对外 ------------------------------------------------------------

    def models(self) -> dict[str, int]:
        """模型 → 上下文长度（0 表示该 Key 没声明，不要当成真的 0）。"""
        windows = self.pool.model_windows()
        return {model: windows.get(model, 0) for model in self.pool.all_models()}

    def relay(
        self,
        model: str,
        payload: dict[str, Any],
        stream: bool,
        trace_headers: dict[str, str] | None = None,
        fp: str | None = None,
    ) -> RelayOutcome:
        candidates = self.pool.candidates(model)
        if not candidates:
            declared = any(key.supports(model) for key in self.pool.keys)
            raise RouterError(
                self._no_candidate_reason(model),
                status=503 if declared else 404,
            )

        attempts: list[str] = []
        last: UpstreamError | None = None
        # retries：同一渠道的尝试次数（对标 new-api 的可配重试）。
        # 1 = 现状（失败就换下一家）；>1 = 先在本渠道快速重试 N 次再切换，
        # 适合「上游偶发抖动」比「切渠道成本高」的场景。
        for key in candidates:
            if fp is not None and not _EXIT_GUARD.allow(fp, key.label):
                # 出口查重：同指纹对同上游高频重发 → 跳过该候选（疑似环路）
                continue
            for attempt in range(max(1, self.pool.retries)):
                attempts.append(key.label if attempt == 0 else f"{key.label}#{attempt + 1}")
                try:
                    if stream:
                        return self._relay_stream(key, model, payload, attempts, trace_headers)
                    return self._relay_once(key, model, payload, attempts, trace_headers)
                except UpstreamError as exc:
                    last = exc
                    self.pool.report_failure(key, exc, trip=exc.retryable)
                    self._persist()
                    continue
        raise RouterError(f"全部 {len(attempts)} 个渠道都失败，最后一个错误：{last}", attempts)

    def relay_embeddings(
        self,
        model: str,
        payload: dict[str, Any],
        trace_headers: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], str, int]:
        """转发 /v1/embeddings（非流式，与 chat 的协议翻译无关）。

        中文：embeddings 只有 OpenAI 协议形态，Anthropic 协议渠道直接跳过。
        返回 (上游 JSON, 渠道 label, tokens_in)；失败渠道按 chat 同一套熔断
        规则记账（连败进冷却），成功按 prompt_tokens 记用量。

        English: forward /v1/embeddings (non-streaming). Anthropic-protocol
        channels are skipped. Returns (JSON, channel label, tokens in).
        Failures feed the same circuit-breaker accounting as chat.
        """
        candidates = [
            key
            for key in self.pool.candidates(model)
            if key.protocol != PROTOCOL_ANTHROPIC
        ]
        if not candidates:
            declared = any(key.supports(model) for key in self.pool.keys)
            raise RouterError(
                self._no_candidate_reason(model),
                status=503 if declared else 404,
            )

        attempts: list[str] = []
        last: UpstreamError | None = None
        for key in candidates:
            attempts.append(key.label)
            try:
                data, tokens_in = call_embeddings(
                    key, {**payload, "model": key.map_to_upstream(model)},
                    self.timeout, trace_headers=trace_headers,
                )
            except UpstreamError as exc:
                last = exc
                self.pool.report_failure(key, exc, trip=exc.retryable)
                self._persist()
                continue
            self.pool.report_success(key, tokens_in, 0, 0, 0)
            self._persist()
            if isinstance(data.get("model"), str):
                data["model"] = model  # 响应里的模型名翻回对外名
            return data, key.label, tokens_in
        raise RouterError(
            f"全部 {len(attempts)} 个渠道都失败，最后一个错误：{last}", attempts
        )

    # -- 内部 ------------------------------------------------------------

    def _relay_once(
        self,
        key: UpstreamKey,
        model: str,
        payload: dict[str, Any],
        attempts: list[str],
        trace_headers: dict[str, str] | None = None,
    ) -> RelayOutcome:
        # 模型映射：客户端发对外名，上游收真名
        upstream_model = key.map_to_upstream(model)
        reply = upstream.call_once(
            key, {**payload, "model": upstream_model}, self.timeout, trace_headers=trace_headers
        )
        self.pool.report_success(
            key, reply.tokens_in, reply.tokens_out, reply.cache_read, reply.cache_creation
        )
        self._persist()
        if isinstance(reply.message, dict) and reply.message.get("model"):
            reply.message["model"] = model  # 响应里的模型名翻回对外名
        return RelayOutcome(
            label=key.label, model=model, message=reply.message, attempts=list(attempts)
        )

    def _relay_stream(
        self,
        key: UpstreamKey,
        model: str,
        payload: dict[str, Any],
        attempts: list[str],
        trace_headers: dict[str, str] | None = None,
    ) -> RelayOutcome:
        sink = _TokenSink()
        upstream_model = key.map_to_upstream(model)
        events = upstream.stream_events(
            key,
            {**payload, "model": upstream_model},
            self.stream_timeout,
            on_usage=sink,
            trace_headers=trace_headers,
        )
        # peek 会真正发起连接并检查状态码；这一步失败才能安全地换 Key，
        # 因为此时我们还没向客户端写过任何字节。
        #
        # 注意必须接住返回的「剩余迭代器」：peek_first 已经把第一个事件从原生成器里
        # 取走了，原生成器上再也拿不到它。丢掉返回值 = 静默吞掉 message_start，
        # 客户端会因为事件序列不全而整个拒绝这条流。
        _first, events = upstream.peek_first(events)
        return RelayOutcome(
            label=key.label,
            model=model,
            events=self._guard(key, self._public_model(events, model, sink), sink),
            attempts=list(attempts),
            usage=sink,
        )

    def _public_model(
        self,
        events: Iterator[tuple[str, dict[str, Any]]],
        model: str,
        sink: _TokenSink | None = None,
    ) -> Iterator[tuple[str, dict[str, Any]]]:
        """流式事件里的模型名翻回对外名（message_start 内嵌 model 字段）；
        顺带从 message_start 的 usage 里收缓存命中量。"""
        for name, payload in events:
            if name == "message_start":
                message = payload.get("message")
                if isinstance(message, dict):
                    if message.get("model"):
                        message["model"] = model
                    if sink is not None:
                        cache_read, cache_creation = upstream.cache_from_usage(
                            message.get("usage") or {}
                        )
                        sink.cache_read = cache_read
                        sink.cache_creation = cache_creation
            yield name, payload

    def _guard(
        self,
        key: UpstreamKey,
        events: Iterator[tuple[str, dict[str, Any]]],
        sink: _TokenSink,
    ) -> Iterator[tuple[str, dict[str, Any]]]:
        """流式收尾时补记用量；中途断裂则记失败（此时已无法切换渠道）。"""
        try:
            yield from events
        except GeneratorExit:
            # 客户端主动断开：既不算成功也不算失败
            raise
        except UpstreamError as exc:
            self.pool.report_failure(key, exc, trip=exc.retryable)
            self._persist()
            raise
        except OSError as exc:
            self.pool.report_failure(key, UpstreamError(0, str(exc), True), trip=True)
            self._persist()
            raise
        else:
            self.pool.report_success(
                key,
                sink.input,
                sink.output,
                getattr(sink, "cache_read", 0),
                getattr(sink, "cache_creation", 0),
            )
            self._persist()

    def _persist(self) -> None:
        if self.persist_path:
            self.pool.save(self.persist_path)

    def _no_candidate_reason(self, model: str) -> str:
        if not self.pool.keys:
            return "号池是空的，先用 `relayhub.gateway pool add` 添加上游 Key"
        matched = [k.label for k in self.pool.keys if k.supports(model)]
        if not matched:
            return (
                f"没有任何 Key 声明支持模型 {model}。已配置的模型有："
                f"{sorted({m for k in self.pool.keys for m in k.models})}"
            )
        # 「不可用」有两种，排查方向完全不同，所以分开报：
        # 你手动禁用的是一个意思，熔断闸跳了是另一个意思。
        now = self.pool.now()
        disabled = [k.label for k in self.pool.keys if k.supports(model) and not k.enabled]
        cooling = [
            k.label
            for k in self.pool.keys
            if k.supports(model) and k.enabled and not k.is_available(now)
        ]
        reasons = []
        if disabled:
            reasons.append(f"已禁用：{disabled}")
        if cooling:
            reasons.append(f"熔断冷却中：{cooling}")
        tier_text = "/".join(
            f"{name}:{seconds:g}s" for name, seconds in self.pool.cooldown_tiers.items()
        )
        return (
            f"模型 {model} 的 {len(matched)} 个渠道全部不可用（{'；'.join(reasons)}；"
            f"阈值 {self.pool.failure_threshold} 次 / 冷却档位 {tier_text}）"
        )


# ---------------------------------------------------------------- 号池热加载

# 这些字段只反映「服务过程中的状态」，不参与选路配置。
# credits 不在其中：它是人/脚本记录的选路输入（most_credits 策略用），改了必须触发 reload。
_RUNTIME_ONLY_FIELDS = (
    "usage",
    "consecutive_failures",
    "disabled_until",
    "cooldown_tier",
    "last_error",
)


def config_fingerprint(path: Path) -> str | None:
    """号池文件的「配置指纹」——只算影响选路的字段。

    **刻意排除 usage / 熔断状态**。因为中转站每服务一个请求就会把用量落盘；
    若把运行时字段算进指纹，就退化成「每个请求 reload 一次」，round-robin 游标
    被反复重置，轮询直接变成「永远挑第一个 Key」。这个坑很隐蔽：
    测试里单请求都能过，只有连续请求才暴露。
    """
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    stripped: dict[str, Any] = {k: v for k, v in raw.items() if k != "keys"}
    stripped["keys"] = [
        {k: v for k, v in item.items() if k not in _RUNTIME_ONLY_FIELDS}
        for item in raw.get("keys") or []
        if isinstance(item, dict)
    ]
    blob = json.dumps(stripped, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class ReloadingRouter:
    """包住 KeyPoolRouter：号池文件被外部改动（比如刚跑了一次 `pool add`）就重新加载。

    为什么不干脆重启中转站：重启会掐掉正在答题的客户端手上的在途请求。
    老师机上加一个上游 Key 不该有这个副作用。
    """

    def __init__(self, pool_path: Path, **kwargs: Any) -> None:
        self.pool_path = Path(pool_path)
        self._kwargs = kwargs
        self._lock = threading.Lock()
        # 先记指纹再构建：万一构建期间文件变了，最坏是多 reload 一次（无害）；
        # 反过来则会「拿着旧 router 配着新指纹」，从此永不刷新。
        self._fingerprint = config_fingerprint(self.pool_path)
        self._router = self._build()

    @property
    def pool(self) -> KeyPool:
        return self._current().pool

    def stats(self) -> dict:
        return self._current().pool.stats()

    def _build(self) -> KeyPoolRouter:
        return KeyPoolRouter(
            KeyPool.load(self.pool_path), persist_path=self.pool_path, **self._kwargs
        )

    def _current(self) -> KeyPoolRouter:
        fingerprint = config_fingerprint(self.pool_path)
        if fingerprint != self._fingerprint:
            with self._lock:
                fingerprint = config_fingerprint(self.pool_path)
                if fingerprint != self._fingerprint:
                    self._router = self._build()
                    self._fingerprint = fingerprint
        return self._router

    # -- 与 KeyPoolRouter 同形 -------------------------------------------

    def models(self) -> dict[str, int]:
        return self._current().models()

    def relay(
        self,
        model: str,
        payload: dict[str, Any],
        stream: bool,
        trace_headers: dict[str, str] | None = None,
        fp: str | None = None,
    ) -> RelayOutcome:
        return self._current().relay(model, payload, stream, trace_headers=trace_headers, fp=fp)

    def relay_embeddings(
        self,
        model: str,
        payload: dict[str, Any],
        trace_headers: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], str, int]:
        """与 KeyPoolRouter.relay_embeddings 同形（热加载包装）。/ Same shape as KeyPoolRouter.relay_embeddings."""
        return self._current().relay_embeddings(model, payload, trace_headers=trace_headers)
