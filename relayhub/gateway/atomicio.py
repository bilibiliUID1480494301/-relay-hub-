"""原子 JSON 落盘：同目录临时文件 + os.replace。

为什么必须原子：网关数据面每个请求都会重写 tokens/pool/users 等共享状态
文件，管理面（另一进程）与测试又在并发读它们。非原子写会让读者「撕读」——
读到空文件或半截 JSON（CI 上 Python 3.10 的
test_streaming_usage_reaches_the_token 因此挂过：轮询读到正在重写的
tokens.json）。

os.replace 在同一文件系统内是原子的：读者要么看到完整的旧文件，
要么看到完整的新文件，永远看不到中间态。
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    """JSON 原子落盘：先写同目录临时文件，再 os.replace 顶替正式文件。

    临时文件名带 pid + 线程 id：管理面与网关是两个进程，都可能保存同一份
    文件，固定临时名会让两个进程互相写坏对方的中间态。
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident():x}.tmp")
    try:
        tmp.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        os.replace(tmp, path)
    finally:
        # replace 成功后 tmp 已不存在；写失败时清理，避免残留垃圾
        if tmp.exists():
            tmp.unlink()
