"""请求明细：一次推理请求一行（JSONL），只记元数据，永不记对话内容。

「用量统计」和「请求记录」是两回事，都需要：
  * 号池/令牌文件里的累计数（requests/ok/tokens）——回答「用了多少」；
  * 本文件的一行行明细——回答「什么时候、谁、用的哪个模型、哪个渠道、
    成没成、多快」。排查「昨晚谁在刷 deepseek」这类问题只能靠明细。

按天轮转：实际落盘文件是 `<stem>.<YYYYMMDD>.jsonl`（path 参数是基准名），
单天一个文件，不再无限膨胀；tail/summarize 自动聚合所有天的文件。

隐私边界（刻意的）：不落 prompt/completion 文本，只落其规模与元数据。
中转站能看到内容是事实，但日志文件是最容易被随手翻/随手拷的东西，
把内容写进去等于把所有用户的对话明文摊在磁盘上。

写失败不炸请求路径（与 audit 同纪律）：宁可丢一行日志打 stderr，不 500。
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any


def _daily_path(path: Path, ts: float) -> Path:
    """按天切分的实际落盘路径：<stem>.<YYYYMMDD>.jsonl。"""
    stamp = time.strftime("%Y%m%d", time.localtime(ts))
    return path.with_name(f"{path.stem}.{stamp}{path.suffix}")


# 日志保留天数（0 = 永久保留 / keep forever）。serve 启动时经 set_retention 注入。
_RETENTION_DAYS = 0
_last_prune = 0.0


def set_retention(days: int) -> None:
    """设置保留天数 / set log retention in days (0 = keep forever)."""
    global _RETENTION_DAYS
    _RETENTION_DAYS = max(0, int(days))


def _prune_old(path: Path, now: float) -> None:
    """删除超过保留天数的按日明细文件（每小时至多跑一次）。"""
    global _last_prune
    if _RETENTION_DAYS <= 0 or now - _last_prune < 3600:
        return
    _last_prune = now
    cutoff = time.strftime("%Y%m%d", time.localtime(now - _RETENTION_DAYS * 86400))
    for f in _all_files(path):
        stamp = f.stem.rsplit(".", 1)[-1]
        if stamp.isdigit() and stamp < cutoff:
            try:
                f.unlink()
            except OSError:
                pass


def _all_files(path: Path) -> list[Path]:
    """所有按天切分的明细文件，按文件名（即日期）正序。"""
    parent = Path(path).parent
    if not parent.is_dir():
        return []
    return sorted(parent.glob(f"{Path(path).stem}.*{Path(path).suffix}"))


def record(
    path: Path,
    *,
    ts: float | None = None,
    token: str = "-",
    dialect: str = "",
    model: str = "",
    channel: str = "",
    ok: bool,
    stream: bool = False,
    status: int = 0,
    tokens_in: int = 0,
    tokens_out: int = 0,
    cache_read: int = 0,
    cache_creation: int = 0,
    cost: int = 0,
    request_id: str = "",
    ip: str = "",
    # 客户端身份（协议解出 / body 块兜底）。元数据，仍不含内容；
    # 缺省不写键——老日志行和新日志行保持同构。
    ident_user: str = "",
    ident_ver: str = "",
    ident_dev: str = "",
    ident_did: str = "",
    ident_src: str = "",
    latency_ms: float = 0.0,
    reason: str = "",
) -> None:
    """追加一条请求明细。reason 用于失败时的简短归因（不含请求体）。"""
    ts = ts if ts is not None else time.time()
    _prune_old(path, ts)
    entry = {
        "ts": round(ts, 3),
        "token": token,
        "dialect": dialect,
        "model": model,
        "channel": channel,
        "ok": bool(ok),
        "stream": bool(stream),
        "status": int(status),
        "tokens_in": int(tokens_in),
        "tokens_out": int(tokens_out),
        "latency_ms": round(float(latency_ms), 1),
    }
    if request_id:
        entry["req_id"] = request_id
    if ip:
        entry["ip"] = ip  # 调用方 IP：公网模式的审计与滥用追溯需要（仍是元数据，不含内容）
    # 客户端身份：日志页 / 用户管理按「谁、哪台设备」追得下去（解出后传入）
    for key, value in (
        ("ident_user", ident_user),
        ("ident_ver", ident_ver),
        ("ident_dev", ident_dev),
        ("ident_did", ident_did),
        ("ident_src", ident_src),
    ):
        if value:
            entry[key] = value
    if cache_read or cache_creation:
        entry["cache_read"] = int(cache_read)
        entry["cache_creation"] = int(cache_creation)
    if cost:
        entry["cost"] = int(cost)  # 用户面板计费扣点（-1 = 扣费时余额已尽）
    if reason:
        entry["reason"] = str(reason)[:120]
    try:
        daily = _daily_path(Path(path), ts)
        daily.parent.mkdir(parents=True, exist_ok=True)
        with open(daily, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as exc:
        print(f"警告：请求明细写入失败（{exc}）", file=sys.stderr)


def tail(path: Path, limit: int = 200) -> list[dict[str, Any]]:
    """按时间正序读最后 limit 条（聚合所有按天文件）；坏行跳过。"""
    lines: list[str] = []
    for file in _all_files(Path(path)):
        try:
            lines.extend(file.read_text(encoding="utf-8").splitlines())
        except OSError:
            continue
    out: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            out.append(parsed)
    return out


def summarize(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """把明细聚合成用量视图：总量 + 按令牌/模型/渠道/日。"""

    def _bucket(key: str) -> dict[str, dict[str, int]]:
        buckets: dict[str, dict[str, int]] = {}

        def bump(name: str, e: dict[str, Any]) -> None:
            slot = buckets.setdefault(str(name), {"requests": 0, "ok": 0, "failed": 0, "tokens_in": 0, "tokens_out": 0, "cache_read": 0})
            slot["requests"] += 1
            slot["ok" if e.get("ok") else "failed"] += 1
            slot["tokens_in"] += int(e.get("tokens_in") or 0)
            slot["tokens_out"] += int(e.get("tokens_out") or 0)
            slot["cache_read"] += int(e.get("cache_read") or 0)

        for e in entries:
            bump(e.get(key) or "-", e)
        return buckets

    day_buckets: dict[str, dict[str, int]] = {}
    for e in entries:
        day = time.strftime("%Y-%m-%d", time.localtime(float(e.get("ts") or 0)))
        slot = day_buckets.setdefault(day, {"requests": 0, "ok": 0, "failed": 0, "tokens_in": 0, "tokens_out": 0, "cache_read": 0})
        slot["requests"] += 1
        slot["ok" if e.get("ok") else "failed"] += 1
        slot["tokens_in"] += int(e.get("tokens_in") or 0)
        slot["tokens_out"] += int(e.get("tokens_out") or 0)
        slot["cache_read"] += int(e.get("cache_read") or 0)

    ok_count = sum(1 for e in entries if e.get("ok"))
    latencies = [float(e["latency_ms"]) for e in entries if e.get("ok") and e.get("latency_ms")]
    return {
        "window": {
            "requests": len(entries),
            "ok": ok_count,
            "failed": len(entries) - ok_count,
            "tokens_in": sum(int(e.get("tokens_in") or 0) for e in entries),
            "tokens_out": sum(int(e.get("tokens_out") or 0) for e in entries),
            "cache_read": sum(int(e.get("cache_read") or 0) for e in entries),
            "avg_latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else 0.0,
        },
        "by_token": _bucket("token"),
        "by_model": _bucket("model"),
        "by_channel": _bucket("channel"),
        "by_day": dict(sorted(day_buckets.items())),
    }
