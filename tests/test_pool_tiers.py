"""分级冷却状态机 + credit 感知调度测试。

档位语义的核心断言：恢复路径不同的故障不能共享同一种冷却。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from relayhub.gateway.pool import (
    TIER_DISABLE,
    TIER_ERR,
    TIER_PLAN,
    TIER_SOFT,
    KeyPool,
    PoolError,
    UpstreamKey,
    classify_failure,
)
from relayhub.gateway.router import config_fingerprint
from relayhub.gateway.upstream import UpstreamError


def _key(label: str, credits: int = -1) -> UpstreamKey:
    return UpstreamKey(
        key_id=label,
        label=label,
        base_url=f"http://{label}",
        api_key="k",
        models=("glm-5.2",),
        model_windows={"glm-5.2": 1000},
        credits=credits,
    )


# ---------------------------------------------------------------- 分诊


@pytest.mark.parametrize(
    ("status", "message", "expected"),
    [
        (401, "unauthorized", TIER_DISABLE),
        (403, "forbidden", TIER_DISABLE),
        (429, "rate limited", TIER_SOFT),
        (500, "internal error", TIER_ERR),
        (503, "unavailable", TIER_ERR),
        (0, "connection refused", TIER_ERR),
        (400, "max_tokens required", None),  # 请求写错，不熔断
        (404, "model not found", None),
        # 4xx 但带额度语义：是账号的事，不是请求的事（1005 是实测配额码）
        (400, "error 1005: credit exhausted", TIER_PLAN),
        (402, "insufficient balance", TIER_PLAN),
        (400, "配额已用完", TIER_PLAN),
    ],
)
def test_classify_failure(status: int, message: str, expected: str | None) -> None:
    assert classify_failure(status, message) == expected


# ---------------------------------------------------------------- 档位时长


def test_tiers_engage_after_threshold_with_tier_duration() -> None:
    clock = {"now": 1000.0}
    keys = [_key("a")]
    pool = KeyPool(keys, failure_threshold=2, cooldown_tiers={"soft": 45.0}, clock=lambda: clock["now"])

    pool.report_failure(keys[0], UpstreamError(429, "rate limited", True))
    assert keys[0].is_available(1000.0), "偶发一次限流不该立刻冷却整个渠道"
    pool.report_failure(keys[0], UpstreamError(429, "rate limited", True))
    assert keys[0].cooldown_tier == TIER_SOFT
    assert keys[0].disabled_until == 1045.0, "soft 档用 soft 的时长，不是全局默认"


def test_auth_failure_disables_immediately_and_requires_manual_enable() -> None:
    """401/403 没有「等一会儿就好」的恢复路径：跳过阈值直接禁用。"""
    keys = [_key("a")]
    pool = KeyPool(keys, failure_threshold=3, clock=lambda: 1000.0)
    pool.report_failure(keys[0], UpstreamError(401, "token expired", True))

    assert keys[0].enabled is False
    assert keys[0].cooldown_tier == TIER_DISABLE
    assert keys[0].disabled_until == 0.0
    assert pool.candidates("glm-5.2") == []

    # 恢复路径是人工 enable，且要连档位标记一起清
    assert pool.set_enabled("a", True) is True
    assert keys[0].enabled is True
    assert keys[0].cooldown_tier == ""
    assert [k.label for k in pool.candidates("glm-5.2")] == ["a"]


def test_plan_tier_defaults_to_twelve_hours() -> None:
    keys = [_key("a")]
    pool = KeyPool(keys, failure_threshold=1, clock=lambda: 1000.0)
    pool.report_failure(keys[0], UpstreamError(400, "1005 credit exhausted", True))
    assert keys[0].cooldown_tier == TIER_PLAN
    assert keys[0].disabled_until == 1000.0 + 43200.0


def test_success_clears_tier_mark() -> None:
    keys = [_key("a")]
    pool = KeyPool(keys, failure_threshold=1, clock=lambda: 1000.0)
    pool.report_failure(keys[0], UpstreamError(503, "down", True))
    assert keys[0].cooldown_tier == TIER_ERR
    pool.report_success(keys[0])
    assert keys[0].cooldown_tier == ""
    assert keys[0].disabled_until == 0.0


def test_unknown_tier_name_is_rejected_at_construction() -> None:
    with pytest.raises(PoolError, match="未知冷却档位"):
        KeyPool([_key("a")], cooldown_tiers={"whatever": 5.0})


# ---------------------------------------------------------------- credit 调度


def test_most_credits_orders_by_credits_unknown_last() -> None:
    keys = [_key("low", credits=10), _key("unknown"), _key("high", credits=900)]
    pool = KeyPool(keys, strategy="most_credits")
    ordered = [k.label for k in pool.candidates("glm-5.2")]
    assert ordered == ["high", "low", "unknown"], "没记录过额度的排最后但仍在候选里"


def test_most_credits_keeps_unknown_keys_usable() -> None:
    """只有一个「没填额度」的渠道时不能因为它没填额度就被排除。"""
    keys = [_key("only")]
    pool = KeyPool(keys, strategy="most_credits")
    assert [k.label for k in pool.candidates("glm-5.2")] == ["only"]


def test_credit_is_config_and_triggers_hot_reload(tmp_path: Path) -> None:
    """credits 是选路输入：改它必须让 serve 的热加载看见；运行时档位必须相反。"""
    path = tmp_path / "pool.json"
    pool = KeyPool([_key("a")], strategy="most_credits")
    pool.save(path)
    baseline = config_fingerprint(path)

    # 纯运行时字段：档位标记与签到时间戳变了，指纹必须不动
    pool.keys[0].cooldown_tier = TIER_PLAN
    pool.save(path)
    assert config_fingerprint(path) == baseline, "档位/签到时间戳不该触发 reload"

    # credits 是选路配置：变了必须触发 reload
    pool.keys[0].credits = 77
    pool.save(path)
    assert config_fingerprint(path) != baseline, "记录额度后 serve 必须重新加载"


# ---------------------------------------------------------------- 落盘


def test_new_fields_roundtrip_through_disk(tmp_path: Path) -> None:
    path = tmp_path / "pool.json"
    key = _key("a", credits=42)
    key.cooldown_tier = TIER_SOFT
    key.disabled_until = 999.0
    pool = KeyPool([key])
    pool.save(path)

    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["cooldown_tiers"] == {TIER_PLAN: 43200.0, TIER_SOFT: 60.0, TIER_ERR: 600.0}

    restored = KeyPool.load(path).keys[0]
    assert restored.credits == 42
    assert restored.cooldown_tier == TIER_SOFT
    assert restored.disabled_until == 999.0
