"""中转站层：号池 + 路由 + 参考实现 + 一致性探测器。

真跑中转站用 `KeyPoolRouter`（发真实上游请求）；
`DemoRouter` 只返回固定文本，是测试靶子。
"""

from .conformance import CheckResult, Probe, run_checks
from .pool import (
    PROTOCOL_ANTHROPIC,
    PROTOCOL_OPENAI_CHAT,
    KeyPool,
    PoolError,
    UpstreamKey,
    key_from_spec,
)
from .router import KeyPoolRouter, RelayOutcome, RouterError
from .service import Channel, ChannelPool, DemoRouter, RelayServer, demo_pool, demo_router
from .upstream import (
    UpstreamError,
    UpstreamReply,
    call_once,
    normalize_base,
    stream_events,
    to_anthropic_request,
)

__all__ = [
    "PROTOCOL_ANTHROPIC",
    "PROTOCOL_OPENAI_CHAT",
    "Channel",
    "ChannelPool",
    "CheckResult",
    "DemoRouter",
    "KeyPool",
    "KeyPoolRouter",
    "PoolError",
    "Probe",
    "RelayOutcome",
    "RelayServer",
    "RouterError",
    "UpstreamError",
    "UpstreamKey",
    "UpstreamReply",
    "call_once",
    "demo_pool",
    "demo_router",
    "key_from_spec",
    "normalize_base",
    "run_checks",
    "stream_events",
    "to_anthropic_request",
]
