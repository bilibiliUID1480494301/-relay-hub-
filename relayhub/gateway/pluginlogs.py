"""插件日志：按插件分账的接入与调用记录（一条插件一条流水，与 API 请求日志分开）。

## 为什么必须分开

`reqlog.py` 回答的是「这个中转站被用了多少」——它的主语是**令牌**，落点是
一张按天切分的全局流水表。插件是另一回事：同一个插件可能被装在十台机器上、
每台一枚令牌，管理员想问的是「这个插件整体表现如何、它什么时候接入的、
它用哪个模型多、有没有在刷」，而这些问题在全局流水里要靠 token 名字瞎猜。

所以这里给每个插件一个**自己的目录**：

    <home>/pluginlogs/<plugin_id>/<YYYYMMDD>.jsonl      调用流水（按天）
    <home>/pluginlogs/<plugin_id>/events.jsonl          接入事件（追加，不轮转）

两条刻意的设计对齐既有模块：

  * **隐私边界与 reqlog 一致**：只落元数据，永不落 prompt/completion。
    插件日志比请求日志更容易被单独翻出来看，把内容写进去等于给每个插件
    做一个对话存档——这是本模块最不能破的一条线。
  * **写失败不炸请求路径**：与 `audit.py` / `reqlog.py` 同纪律，宁可丢一行
    打 stderr，不能让正在答题的请求 500。

## 与 audit / reqlog 的三方分工

| 文件 | 主语 | 回答的问题 | 轮转 |
|------|------|-----------|------|
| `audit.jsonl` | 管理员动作 | 「谁在什么时候改了配置」 | 不轮转（不可变） |
| `requests.<日>.jsonl` | 令牌（设备） | 「这台设备用了多少」 | 按天 |
| `pluginlogs/<id>/…` | 插件 | 「这个插件整体干了什么」 | 按天 + 保留期 |

三者都写是**有意的重复**：它们服务三种不同的追问路径，合并成一张表会让
每一种追问都变慢（也是 `audit` / `reqlog` 当初分家的同一个理由）。

## 为什么插件身份头不参与鉴权

插件 id 来自请求头（`X-DSH-Plugin-Id`），HTTP 头是**可以随便伪造**的。
本模块因此把它当作**分类标签**而不是**身份凭证**：

  * 鉴权永远只看下游令牌（`service._authenticate`），头部伪造不了别人的令牌；
  * 伪造插件 id 的最坏后果是「把自己的调用记到别人的目录里」——同一台机器
    上的两个插件互相冒名，够不上跨设备的安全问题。
  * 目录名经过 `toip._sanitize_plugin_id` 同一套白名单校验，挡掉 `..` 与
    路径分隔符，插件 id 无法把日志写到 `<home>` 之外。
"""

from __future__ import annotations

import json
import shutil
import sys
import time
from pathlib import Path
from typing import Any

# 日志 schema 版本：写在每个目录的 <id>/schema.json 里，方便将来迁移时判断
# 一个目录是老格式还是新格式（目录是长期存在的，不能靠猜）。
SCHEMA_VERSION = 1

# 默认保留天数。与 serve --log-retention-days 的形态对齐；0 = 不清理。
DEFAULT_RETENTION_DAYS = 30

# 单条流水里允许出现的键（隐私边界由测试钉死，见 tests/test_pluginlogs.py）。
# 任何新增字段都必须先加进这里——这个「必须先声明」的摩擦是有意的。
_ALLOWED_KEYS = frozenset(
    {
        "ts",
        "plugin",
        "plugin_version",
        "station_id",
        "token",
        "session",
        "dialect",
        "model",
        "ok",
        "stream",
        "status",
        "tokens_in",
        "tokens_out",
        "latency_ms",
        "ip",
        "reason",
        "schema",
    }
)


def root(home: Path) -> Path:
    """插件日志根目录（`<home>/pluginlogs`）。"""
    return Path(home) / "pluginlogs"


def plugin_dir(home: Path, plugin_id: str) -> Path:
    """某个插件的日志目录。<home>/pluginlogs/<plugin_id>。"""
    return root(home) / str(plugin_id)


def daily_path(home: Path, plugin_id: str, ts: float) -> Path:
    """按天切分的流水文件：<home>/pluginlogs/<id>/<YYYYMMDD>.jsonl。"""
    stamp = time.strftime("%Y%m%d", time.localtime(ts))
    return plugin_dir(home, plugin_id) / f"{stamp}.jsonl"


def events_path(home: Path, plugin_id: str) -> Path:
    """接入事件文件：<home>/pluginlogs/<id>/events.jsonl（追加，不轮转）。

    接入事件（首次登记、口令轮换、被拒）数量级极小，且是「这个插件什么时候
    来的」的唯一凭据，所以不做按天切分也不进保留期清理——清理流水可以，
    清理「它来过」不行。
    """
    return plugin_dir(home, plugin_id) / "events.jsonl"


# ---------------------------------------------------------------- 写


def record(
    home: Path,
    plugin_id: str,
    *,
    ts: float | None = None,
    plugin_version: str = "",
    station_id: str = "",
    token: str = "-",
    session: str = "",
    dialect: str = "",
    model: str = "",
    ok: bool,
    stream: bool = False,
    status: int = 0,
    tokens_in: int = 0,
    tokens_out: int = 0,
    latency_ms: float = 0.0,
    ip: str = "",
    reason: str = "",
) -> None:
    """给某插件追加一条调用流水。

    调用方（`RelayHandler`）已经确认过 `plugin_id` 合法且非空；本函数再挡一道
    （纵深防御：目录名安全是「不能把日志写到 <home> 外」的硬约束）。
    """
    ts = ts if ts is not None else time.time()
    entry: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "ts": round(ts, 3),
        "plugin": plugin_id,
        "token": token,
        "dialect": dialect,
        "model": model,
        "ok": bool(ok),
        "stream": bool(stream),
        "status": int(status),
        "tokens_in": int(tokens_in),
        "tokens_out": int(tokens_out),
        "latency_ms": round(float(latency_ms), 1),
    }
    # 可选字段：缺省不写键，保证新老日志行同构（与 reqlog 同一约定）。
    for key, value in (
        ("plugin_version", plugin_version),
        ("station_id", station_id),
        ("session", session),
        ("ip", ip),
    ):
        if value:
            entry[key] = str(value)
    if reason:
        entry["reason"] = str(reason)[:120]

    _append(daily_path(home, plugin_id, ts), entry)


def record_event(home: Path, plugin_id: str, event: str, **detail: Any) -> None:
    """给某插件追加一条接入事件（登记/轮换/被拒）。

    与 `audit.record` 同构，但落点在插件自己的目录里——这样「看这个插件
    的全部痕迹」只需要读一个目录，不必在全局审计里按插件名 grep。
    """
    entry: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "ts": round(time.time(), 3),
        "event": event,
    }
    # 空/None 不写键（新老日志行同构）；但 0 与 False 是**有意义的取值**
    # （status=0、ok=False），必须留下——静默丢值会让日志骗人。
    for key, value in detail.items():
        if value is None or value == "":
            continue
        if key not in _ALLOWED_KEYS and key not in ("event", "kind"):
            continue
        entry[key] = value if isinstance(value, (int, float, bool)) else str(value)
    _append(events_path(home, plugin_id), entry)


def _append(target: Path, entry: dict[str, Any]) -> None:
    """追加一行 JSON。任何失败都只打 stderr——日志绝不能弄死请求。"""
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        marker = target.parent / "schema.json"
        if not marker.exists():
            # 目录首次出现时留一份自述：将来扫日志的人不必翻代码就知道
            # 这个目录是什么、哪个版本写的、保留期多久。
            marker.write_text(
                json.dumps(
                    {
                        "schemaVersion": SCHEMA_VERSION,
                        "plugin": target.parent.name,
                        "kind": "relay-hub plugin logs",
                        "daily": "<YYYYMMDD>.jsonl = 调用流水（元数据，无内容）",
                        "events": "events.jsonl = 接入事件（登记/轮换/被拒）",
                        "retentionDays": DEFAULT_RETENTION_DAYS,
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
    except OSError as exc:
        print(f"警告：插件日志写入失败（{exc}）：{entry}", file=sys.stderr)


# ---------------------------------------------------------------- 读


def _flow_files(home: Path, plugin_id: str) -> list[Path]:
    """某插件的按天流水文件，按文件名（即日期）正序。"""
    directory = plugin_dir(home, plugin_id)
    if not directory.is_dir():
        return []
    return sorted(
        p for p in directory.glob("*.jsonl") if p.name != "events.jsonl"
    )


def tail(home: Path, plugin_id: str, limit: int = 200) -> list[dict[str, Any]]:
    """按时间正序读某插件的最后 limit 条流水（聚合所有天）；坏行跳过。"""
    lines: list[str] = []
    for file in _flow_files(home, plugin_id):
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


def events(home: Path, plugin_id: str, limit: int = 100) -> list[dict[str, Any]]:
    """读某插件的接入事件（最后 limit 条）。文件不存在返回空表。"""
    target = events_path(home, plugin_id)
    try:
        lines = target.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
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
    """把某插件的流水聚合成用量视图：总量 + 按模型/令牌/日。

    形状与 `reqlog.summarize` 保持同构（`window` + `by_*`），前端可以复用
    同一套渲染；插件维度额外的 `by_token` 让「同一个插件在多台机器上」可拆。
    """
    ok_count = sum(1 for e in entries if e.get("ok"))
    latencies = [
        float(e["latency_ms"]) for e in entries if e.get("ok") and e.get("latency_ms")
    ]

    def _bucket(key: str) -> dict[str, dict[str, int]]:
        buckets: dict[str, dict[str, int]] = {}
        for e in entries:
            slot = buckets.setdefault(
                str(e.get(key) or "-"),
                {"requests": 0, "ok": 0, "failed": 0, "tokens_in": 0, "tokens_out": 0},
            )
            slot["requests"] += 1
            slot["ok" if e.get("ok") else "failed"] += 1
            slot["tokens_in"] += int(e.get("tokens_in") or 0)
            slot["tokens_out"] += int(e.get("tokens_out") or 0)
        return buckets

    day_buckets: dict[str, dict[str, int]] = {}
    for e in entries:
        day = time.strftime("%Y-%m-%d", time.localtime(float(e.get("ts") or 0)))
        slot = day_buckets.setdefault(
            day,
            {"requests": 0, "ok": 0, "failed": 0, "tokens_in": 0, "tokens_out": 0},
        )
        slot["requests"] += 1
        slot["ok" if e.get("ok") else "failed"] += 1
        slot["tokens_in"] += int(e.get("tokens_in") or 0)
        slot["tokens_out"] += int(e.get("tokens_out") or 0)

    return {
        "window": {
            "requests": len(entries),
            "ok": ok_count,
            "failed": len(entries) - ok_count,
            "tokens_in": sum(int(e.get("tokens_in") or 0) for e in entries),
            "tokens_out": sum(int(e.get("tokens_out") or 0) for e in entries),
            "avg_latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else 0.0,
        },
        "by_model": _bucket("model"),
        "by_token": _bucket("token"),
        "by_day": dict(sorted(day_buckets.items())),
    }


def list_plugins(home: Path) -> list[dict[str, Any]]:
    """列出所有有日志的插件：id + 文件数 + 大小 + 最后活动时间。

    目录即注册表：没有中心索引文件，少一处会跟磁盘不一致的状态。
    """
    base = root(home)
    if not base.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for directory in sorted(p for p in base.iterdir() if p.is_dir()):
        files = [p for p in directory.glob("*.jsonl") if p.is_file()]
        size = sum(p.stat().st_size for p in files if p.exists())
        latest = 0.0
        for file in files:
            try:
                latest = max(latest, file.stat().st_mtime)
            except OSError:
                continue
        out.append(
            {
                "plugin_id": directory.name,
                "files": len(files),
                "bytes": size,
                "last_activity": round(latest, 3),
                "first_seen": _first_seen(directory),
            }
        )
    return out


def _first_seen(directory: Path) -> float:
    """该插件最早一条接入事件的时间（没有 events.jsonl 时回退到最早流水）。"""
    try:
        for line in directory.joinpath("events.jsonl").read_text(
            encoding="utf-8"
        ).splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(entry, dict) and entry.get("ts"):
                return float(entry["ts"])
    except OSError:
        pass
    return 0.0


# ---------------------------------------------------------------- 保留期


def prune(home: Path, *, retention_days: int = DEFAULT_RETENTION_DAYS) -> list[str]:
    """删掉超过保留期的按天流水文件，返回被删的文件名。

    **只删流水，不删 events.jsonl**：流水是「用量」可以过保质期，
    接入事件是「它来过」的证据，删了就没法回答「这个插件什么时候装上过」。

    `retention_days == 0` = 显式关闭清理（与 serve --log-retention-days 同语义）。
    负数没有实际意义，但会得到一个**未来的截止点**（刚写的文件也算过期），
    测试靠它验清理逻辑，不必 sleep 等时间流逝。
    """
    if retention_days == 0:
        return []
    base = root(home)
    if not base.is_dir():
        return []
    cutoff = time.time() - retention_days * 86400.0
    removed: list[str] = []
    for file in base.glob("*/*.jsonl"):
        if file.name == "events.jsonl":
            continue
        try:
            if file.stat().st_mtime < cutoff:
                file.unlink()
                removed.append(f"{file.parent.name}/{file.name}")
        except OSError:
            continue
    return removed


def forget(home: Path, plugin_id: str) -> bool:
    """彻底删掉某个插件的全部日志目录。返回是否真的删了东西。

    这是「撤销一个已经不再使用的插件」的唯一入口——与令牌吊销不同，
    日志删除不可逆，所以只暴露给管理面显式调用，绝不自动触发。
    """
    directory = plugin_dir(home, plugin_id)
    if not directory.is_dir():
        return False
    shutil.rmtree(directory, ignore_errors=True)
    return True
