"""环境自检 / Environment self-check (`hubrelay doctor`).

中文：
    一条命令体检建站环境：Python 版本、数据目录可写、号池/令牌状态、
    本机推理服务（Ollama / LM Studio / vLLM / llama.cpp）、端口占用、
    Windows 防火墙提示。每项给出 ✓/✗ 与可执行的修复建议。

English:
    One-shot environment doctor: Python version, data-root writability,
    pool/token status, local inference servers, port availability, and a
    Windows firewall hint. Every check returns ok/detail/fix fields so the
    result is machine-readable as well as human-friendly.
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path
from typing import Any

from relayhub.gateway.localscan import scan as _scan_local
from relayhub.paths import pool_path, relayhub_home, tokens_path

__all__ = ["run_checks", "doctor"]


def _check_python() -> dict[str, Any]:
    ok = sys.version_info >= (3, 10)
    ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    return {
        "name": "python",
        "ok": ok,
        "detail": ver,
        "fix": None if ok else "升级到 Python ≥ 3.10 / upgrade to Python 3.10+",
    }


def _check_home() -> dict[str, Any]:
    root = relayhub_home()
    try:
        root.mkdir(parents=True, exist_ok=True)
        probe = root / ".doctor_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return {
            "name": "data_root",
            "ok": True,
            "detail": str(root),
            "fix": None,
        }
    except OSError as exc:
        return {
            "name": "data_root",
            "ok": False,
            "detail": str(root),
            "fix": f"目录不可写：{exc}；用 RELAYHUB_HOME 换个根 / set RELAYHUB_HOME",
        }


def _check_pool() -> dict[str, Any]:
    p = pool_path()
    if not p.exists():
        return {
            "name": "pool",
            "ok": True,
            "detail": "empty（尚未创建 / not created yet）",
            "fix": "hubrelay pool add / st.add_upstream(...) 添加第一个上游 Key",
        }
    try:
        import json

        data = json.loads(p.read_text(encoding="utf-8"))
        n = len(data) if isinstance(data, list) else len(data.get("keys", data))
        return {"name": "pool", "ok": n > 0, "detail": f"{p}（{n} 个渠道 / channels）",
                "fix": None if n else "号池为空：pool add 或 scan_and_import()"}
    except Exception as exc:  # noqa: BLE001
        return {"name": "pool", "ok": False, "detail": str(p), "fix": f"号池文件损坏：{exc}"}


def _check_tokens() -> dict[str, Any]:
    p = tokens_path()
    if not p.exists():
        return {"name": "tokens", "ok": True, "detail": "empty（尚未发令牌 / no tokens yet）",
                "fix": "token add <name> / st.create_token(...) 给设备发凭证"}
    try:
        import json

        data = json.loads(p.read_text(encoding="utf-8"))
        n = len(data) if isinstance(data, list) else len(data.get("tokens", data))
        return {"name": "tokens", "ok": True, "detail": f"{p}（{n} 枚令牌 / tokens）", "fix": None}
    except Exception as exc:  # noqa: BLE001
        return {"name": "tokens", "ok": False, "detail": str(p), "fix": f"令牌文件损坏：{exc}"}


def _check_local_inference(timeout: float) -> dict[str, Any]:
    try:
        servers = _scan_local(timeout=timeout)
    except Exception:  # noqa: BLE001
        servers = []
    detail = ", ".join(f"{s.kind}@{s.base_url.rsplit(':', 1)[-1]}({len(s.models)}模型)" for s in servers) \
        if servers else "未发现 / none found"
    return {
        "name": "local_inference",
        "ok": True,  # 找不到不算故障，只是提示
        "detail": detail,
        "fix": None if servers else "先启动 Ollama / LM Studio 等，再 hubrelay scan",
    }


def _check_port(port: int) -> dict[str, Any]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.bind(("127.0.0.1", port))
        return {"name": f"port:{port}", "ok": True, "detail": "可用 / free", "fix": None}
    except OSError:
        return {"name": f"port:{port}", "ok": False, "detail": "已被占用 / in use",
                "fix": f"换个端口：serve --port {port + 1} 或停掉占用进程"}
    finally:
        s.close()


def _check_firewall_hint() -> dict[str, Any]:
    hint = None
    if sys.platform == "win32":
        hint = ("Windows 首次监听会弹防火墙授权，点「允许访问」；"
                "错过弹窗到 Windows 安全中心→防火墙→允许应用 勾选 Python")
    return {"name": "firewall_hint", "ok": True, "detail": hint or "n/a", "fix": hint}


def run_checks(*, port: int = 8799, scan_timeout: float = 1.5) -> list[dict[str, Any]]:
    """跑全部体检项。/ Run all checks. 返回 [{name, ok, detail, fix}]。"""
    return [
        _check_python(),
        _check_home(),
        _check_pool(),
        _check_tokens(),
        _check_local_inference(scan_timeout),
        _check_port(port),
        _check_firewall_hint(),
    ]


def doctor(*, port: int = 8799, scan_timeout: float = 1.5) -> list[dict[str, Any]]:
    """`run_checks` 的别名（API 层导出名）。/ Alias of `run_checks` for the API layer."""
    return run_checks(port=port, scan_timeout=scan_timeout)
