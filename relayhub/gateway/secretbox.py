# -*- coding: utf-8 -*-
"""落盘凭证的加密保险箱：上游 Key、TOIP 口令种子不再明文躺在本机磁盘上。

威胁模型（用户拍板的默认假设）：**本机环境不可信**。
  * 文件被拷走（备份同步、访客账号、恶意软件扫盘）不该直接得到可用凭证；
  * 同机其他账号不该顺手读到（0600 只挡君子，挡不了提权）。

方案按平台分两档，都是纯标准库：
  * Windows（本项目目标平台）：DPAPI（CryptProtectData，CurrentUser 域）。
    密钥由 Windows 登录账户派生——文件拷到任何别的机器/别的账户都解不开，
    改密码由 OS 决定是否作废。这就是「加密落盘」而不是「混淆」。
  * 其他平台：没有可用的标准库 KMS，**诚实降级**为明文 + 0600 + 头部标记
    `"enc": "plain"`，并在读侧打印一次性警告。不假装安全（自研 XOR/CTR
    流密码是把安全当儿戏），README 明确建议放可信环境或整盘加密。

文件格式：整个 JSON 文档加密成 {"enc": "<scheme>", "data": "<base64>"}。
读侧兼容历史：解析出 "enc" 字段走解密；否则按旧明文文档处理，下次 save
自动升级为加密——已部署站点无需迁移脚本。
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

SCHEME_DPAPI = "dpapi"
SCHEME_PLAIN = "plain"

_WARNED = False


def _dpapi_protect(data: bytes) -> bytes:
    """CryptProtectData（CurrentUser）：只在本机本 Windows 账户下可解。"""
    import ctypes.wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    src = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = BLOB()
    # CRYPTPROTECT_UI_FORBIDDEN：服务/无人值守场景必须；不弹任何 UI。
    if not ctypes.windll.crypt32.CryptProtectData(  # type: ignore[attr-defined]
        ctypes.byref(src), None, None, None, None, 0x1, ctypes.byref(out)
    ):
        raise OSError("CryptProtectData failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)  # type: ignore[attr-defined]


def _dpapi_unprotect(data: bytes) -> bytes:
    import ctypes.wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    src = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(  # type: ignore[attr-defined]
        ctypes.byref(src), None, None, None, None, 0x1, ctypes.byref(out)
    ):
        raise OSError("CryptUnprotectData failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)  # type: ignore[attr-defined]


def _platform_scheme() -> str:
    return SCHEME_DPAPI if sys.platform == "win32" else SCHEME_PLAIN


def _warn_plain_once() -> None:
    global _WARNED
    if _WARNED:
        return
    _WARNED = True
    print(
        "警告：本平台没有可用的标准库加密后端，凭证仍以明文（0600）落盘。"
        "请把 RELAYHUB_HOME 放在可信环境，或启用整盘加密。",
        file=sys.stderr,
    )


def seal(payload: dict[str, Any], *, path: Path) -> None:
    """payload 加密落盘（平台不支持则明文 + 0600 + 头部标记，不假装安全）。"""
    scheme = _platform_scheme()
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if scheme == SCHEME_DPAPI:
        blob = {"enc": SCHEME_DPAPI, "data": base64.b64encode(_dpapi_protect(raw)).decode("ascii")}
    else:
        blob = {"enc": SCHEME_PLAIN, "data": base64.b64encode(raw).decode("ascii")}
    _warn_plain_once() if scheme == SCHEME_PLAIN else None
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.seal.tmp")
    tmp.write_text(json.dumps(blob, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    harden(path)


def unseal(path: Path) -> dict[str, Any] | None:
    """读加密文档。文件不存在返回 None；解密失败按「文件不可用」处理。

    兼容历史明文：文档里没有 enc 字段就按旧格式直接解析（下次 save 升级）。
    DPAPI 解密失败（换机器/换账户/文件损坏）不抛——返回 None 让调用方走
    「凭证不存在」的既有路径，绝不回退到把密文当明文猜。
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        blob = json.loads(text)
    except ValueError:
        return None
    if not isinstance(blob, dict) or "enc" not in blob:
        # 历史明文文档
        return blob if isinstance(blob, dict) else None
    scheme = str(blob.get("enc"))
    try:
        data = base64.b64decode(str(blob.get("data") or ""))
    except (ValueError, TypeError):
        return None
    if scheme == SCHEME_DPAPI:
        try:
            raw = _dpapi_unprotect(data)
        except OSError as exc:
            print(f"警告：加密凭证解密失败（{exc}），视为不存在：{path}", file=sys.stderr)
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
    if scheme == SCHEME_PLAIN:
        _warn_plain_once()
        try:
            return json.loads(base64.b64decode(str(blob.get("data") or "")).decode("utf-8"))
        except (ValueError, TypeError):
            return None
    return None


def harden(path: Path) -> None:
    """尽力把权限收到 0600（Windows 的 chmod 语义有限，失败不阻断）。"""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:  # pragma: no cover - 平台相关
        pass
