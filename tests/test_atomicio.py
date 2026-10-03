"""atomicio.write_json_atomic：共享状态文件必须原子落盘。

背景：网关数据面每请求重写 tokens/pool/users，管理面与测试并发读。
非原子写（直接 write_text）会让读者撕读到空文件/半截 JSON——CI 的
test_streaming_usage_reaches_the_token 就因此挂过一次（3.10 慢机放大窗口）。
"""

from __future__ import annotations

import json

from relayhub.gateway.atomicio import write_json_atomic


def _tmp_residues(path) -> list[str]:
    return [p.name for p in path.parent.glob(path.name + ".*.tmp")]


def test_atomic_write_leaves_no_tmp_residue_and_valid_json(tmp_path) -> None:
    target = tmp_path / "tokens.json"
    for i in range(3):
        write_json_atomic(target, {"n": i})
        # 读回即合法 JSON，且内容是最近一次的
        assert json.loads(target.read_text(encoding="utf-8")) == {"n": i}
        assert _tmp_residues(target) == []


def test_atomic_write_replaces_old_content_atomically(tmp_path) -> None:
    target = tmp_path / "pool.json"
    write_json_atomic(target, {"v": "old", "keys": [1, 2, 3]})
    first = target.read_text(encoding="utf-8")
    assert first.endswith("\n")  # 与手写 save 的格式保持一致（便于 diff/人工查看）
    write_json_atomic(target, {"v": "new", "keys": []})
    assert json.loads(target.read_text(encoding="utf-8")) == {"v": "new", "keys": []}
    # 首行写入失败或中断时旧文件必须完好：模拟 tmp 残留不影响正式文件
    (tmp_path / "pool.json.999.abc.tmp").write_text("{半截", encoding="utf-8")
    assert json.loads(target.read_text(encoding="utf-8")) == {"v": "new", "keys": []}
