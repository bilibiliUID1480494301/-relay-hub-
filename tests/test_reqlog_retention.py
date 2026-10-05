"""请求明细按日清理 / daily request-log retention."""

from __future__ import annotations

import time
from pathlib import Path

from relayhub.gateway import reqlog


def test_retention_prunes_old_days(tmp_path):
    log = tmp_path / "requests.jsonl"
    now = time.time()
    # 手工造三天的按日文件：今天、3 天前、40 天前
    for age, body in ((0, '{"ts":1}'), (3 * 86400, '{"ts":2}'), (40 * 86400, '{"ts":3}')):
        p = reqlog._daily_path(log, now - age)
        Path(p).write_text(body, encoding="utf-8")

    reqlog.set_retention(30)
    try:
        reqlog.record(log, ts=now, ok=True)  # record 内部触发清理
        files = [f.name for f in reqlog._all_files(log)]
        today = reqlog._daily_path(log, now).name
        d3 = reqlog._daily_path(log, now - 3 * 86400).name
        d40 = reqlog._daily_path(log, now - 40 * 86400).name
        assert today in files and d3 in files and d40 not in files
    finally:
        reqlog.set_retention(0)


def test_retention_zero_keeps_everything(tmp_path):
    log = tmp_path / "requests.jsonl"
    now = time.time()
    old = reqlog._daily_path(log, now - 400 * 86400)
    old.write_text("{}", encoding="utf-8")
    reqlog.set_retention(0)
    reqlog.record(log, ts=now, ok=True)
    assert old.exists()
