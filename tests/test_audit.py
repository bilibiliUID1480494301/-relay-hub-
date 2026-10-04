"""审计日志测试：追加、读取、容错。"""

from __future__ import annotations

import json
from pathlib import Path

from relayhub.gateway import audit


def test_record_then_tail_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    audit.record("pair.begin", path=path, client_id="app", ttl=300)
    audit.record("pair.success", path=path, device="laptop")

    entries = audit.tail(path)
    assert [e["event"] for e in entries] == ["pair.begin", "pair.success"]
    assert entries[0]["client_id"] == "app"
    assert isinstance(entries[0]["ts"], float)
    # 文件必须是合法 JSONL
    lines = path.read_text(encoding="utf-8").splitlines()
    assert all(isinstance(json.loads(line), dict) for line in lines)


def test_tail_returns_empty_for_missing_file(tmp_path: Path) -> None:
    assert audit.tail(tmp_path / "nope.jsonl") == []


def test_tail_skips_corrupt_lines(tmp_path: Path) -> None:
    """进程崩溃可能留下半截行：跳过它，不吞掉其余历史。"""
    path = tmp_path / "audit.jsonl"
    path.write_text(
        '{"ts":1,"event":"a"}\n{"ts":2,"event":"\n{"ts":3,"event":"c"}\n',
        encoding="utf-8",
    )
    events = [e["event"] for e in audit.tail(path)]
    assert events == ["a", "c"]


def test_tail_limit_keeps_most_recent(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    for index in range(10):
        audit.record("e", path=path, index=index)
    assert [e["index"] for e in audit.tail(path, limit=3)] == [7, 8, 9]
