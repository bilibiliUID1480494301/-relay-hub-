"""CLI 帮助面回归：所有子命令 --help 不得崩溃（v0.2.7 的 %LOCALAPPDATA% 教训）。"""

from __future__ import annotations

import subprocess
import sys

SUBCOMMANDS = [
    "serve", "admin", "pool", "scan", "requests", "usage",
    "token", "clients", "pair", "audit", "check", "doctor",
]


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "relayhub.gateway", *args],
        capture_output=True, text=True, timeout=60,
    )


def test_all_subcommand_help_no_crash():
    for sub in SUBCOMMANDS:
        r = _run(sub, "--help")
        assert r.returncode == 0, f"{sub} --help rc={r.returncode}: {r.stderr[-300:]}"
        assert "Traceback" not in r.stderr, f"{sub} --help crashed"


def test_serve_help_word_alias():
    """「serve help」应等价于 serve --help，而不是 argparse 报错。"""
    r = _run("serve", "help")
    assert r.returncode == 0
    assert "usage:" in r.stdout.lower()


def test_top_level_version():
    r = _run("--version")
    assert r.returncode == 0
    assert r.stdout.strip().endswith("0.2.12") or "hubrelay" in r.stdout
