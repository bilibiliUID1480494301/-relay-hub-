"""控制面操作审计：谁在什么时候做了什么管理动作（JSONL 追加写）。

README「五」管理面缺口的第三条：出事之前只有「当前状态」，渠道被误删、
令牌被吊销、配对窗口被打开之后无法回溯是谁干的。审计不解决问题，
但让「什么时候开始的」有据可查。

覆盖的事件：管理面的全部写操作（经 `_mutate` 单一咽喉）、下游令牌的发放/吊销/
启停、配对窗口的开启与兑换成败。号池 CLI（pool add/rm…）暂不记录——它是
本机操作，没有跨设备的信任问题。

两个刻意的取舍：
  * **追加写，不改不删**：审计的价值在不可变性，回滚/整理都交给文件级备份。
  * **写失败不炸主流程**：审计挂在请求路径（配对）和控制面（admin/token），
    磁盘抖动时宁可丢一条日志并打 stderr 警告，不能让答题的请求 500。
    这个妥协写在这里，别当成疏忽。

密钥纪律：调用方传入 detail 之前必须先把 api_key/token 之类的明文剥掉
（admin 侧已剥，见 `admin._mutate` 的测试）。
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any


def record(event: str, *, path: Path | None = None, **detail: Any) -> None:
    """追加一条审计事件。event 用点分小写（pair.begin / pool.delete / token.revoke）。"""
    target = Path(path) if path else _default_path()
    entry = {"ts": round(time.time(), 3), "event": event, **detail}
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
    except OSError as exc:
        print(f"警告：审计写入失败（{exc}）：{entry}", file=sys.stderr)


def tail(path: Path | None = None, limit: int = 50) -> list[dict[str, Any]]:
    """按时间正序读最后 limit 条。文件不存在返回空表（还没发生过任何事件）。"""
    target = Path(path) if path else _default_path()
    try:
        lines = target.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            # 半截行（崩溃残留）：跳过但不吞掉其余历史
            continue
        if isinstance(parsed, dict):
            out.append(parsed)
    return out


def _default_path() -> Path:
    from .. import paths

    return paths.audit_path()
