"""写入前的带时间戳备份与回滚。

约定（与 oj 项目一致）：时间戳文件名不含冒号，避免 WinError 123。
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

STAMP_FMT = "%Y%m%dT%H%M%S"
MANIFEST_NAME = "manifest.json"


@dataclass(frozen=True)
class Snapshot:
    snapshot_id: str
    root: Path

    @property
    def manifest_path(self) -> Path:
        return self.root / self.snapshot_id / MANIFEST_NAME

    def read_manifest(self) -> dict:
        return json.loads(self.manifest_path.read_text(encoding="utf-8"))


def make_snapshot(paths: list[Path], root: Path) -> Snapshot:
    """把 paths 里存在的文件复制到 <root>/<stamp>/，返回快照句柄。"""
    stamp = datetime.now().strftime(STAMP_FMT)
    target = root / stamp
    # 同一秒内重复快照时避免互相覆盖
    suffix = 1
    while target.exists():
        suffix += 1
        target = root / f"{stamp}-{suffix}"

    target.mkdir(parents=True, exist_ok=False)
    entries = []
    for src in paths:
        if not src.is_file():
            entries.append({"path": str(src), "existed": False})
            continue
        dst = target / src.name
        shutil.copy2(src, dst)
        entries.append({"path": str(src), "existed": True, "bytes": dst.stat().st_size})

    manifest = {"created_at": datetime.now().isoformat(timespec="seconds"), "files": entries}
    (target / MANIFEST_NAME).write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return Snapshot(snapshot_id=target.name, root=root)


def list_snapshots(root: Path) -> list[Snapshot]:
    if not root.is_dir():
        return []
    items = [p for p in root.iterdir() if p.is_dir() and (p / MANIFEST_NAME).is_file()]
    return [Snapshot(snapshot_id=p.name, root=root) for p in sorted(items, reverse=True)]


def latest_snapshot(root: Path) -> Snapshot | None:
    found = list_snapshots(root)
    return found[0] if found else None


def restore(snapshot: Snapshot, dry_run: bool = False) -> list[str]:
    """把快照里的文件写回原位。返回人类可读的操作说明。"""
    lines: list[str] = []
    manifest = snapshot.read_manifest()
    for entry in manifest["files"]:
        dst = Path(entry["path"])
        if not entry.get("existed"):
            if dst.is_file():
                lines.append(f"删除 {dst}（快照时不存在）")
                if not dry_run:
                    dst.unlink()
            else:
                lines.append(f"跳过 {dst}（快照时不存在，当前也不存在）")
            continue
        src = snapshot.root / snapshot.snapshot_id / dst.name
        if not src.is_file():
            lines.append(f"缺少备份文件 {src}，跳过")
            continue
        lines.append(f"还原 {dst}")
        if not dry_run:
            shutil.copy2(src, dst)
    return lines
