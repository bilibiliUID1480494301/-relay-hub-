"""Product-level leak scanner: unpacks whl/sdist and greps for internal project strings.

用法：python scripts/scan_leak.py dist/*.whl dist/*.tar.gz
"""
import re
import sys
import tarfile
import zipfile

PATTERN = re.compile(
    r"学伴|studymate|workbuddy|元宝|claw|zcode|"
    r"E:[/\]dev|[Uu]sers[/\]ws|ws@|LAPTOP-[0-9A-Za-z]+|"
    r"NoBook|翼鸥|relayhub[0-9]|py-internal",
    re.I,
)


def scan(path: str) -> int:
    ctx = zipfile.ZipFile(path) if path.endswith(".whl") else tarfile.open(path)
    names = ctx.namelist() if path.endswith(".whl") else ctx.getnames()
    read = ctx.read if path.endswith(".whl") else ctx.extractfile
    hits = 0
    for n in names:
        if not n.endswith((".py", ".md", ".toml", ".txt", ".json", ".cfg", ".cfg", ".yml", ".yaml")):
            continue
        try:
            fh = read(n)
            text = (fh.read() if hasattr(fh, "read") else b"").decode("utf-8", "ignore")
        except Exception:
            continue
        for m in PATTERN.finditer(text):
            hits += 1
            line = text[: m.start()].count("\n") + 1
            print(f"  LEAK {path}:{n}:{line} {m.group(0)!r}")
    print(f"{path}: {'CLEAN' if hits == 0 else str(hits) + ' HITS'}")
    return hits


if __name__ == "__main__":
    bad = sum(scan(p) for p in sys.argv[1:])
    print("VERDICT:", "CLEAN" if bad == 0 else "BLOCK")
    raise SystemExit(1 if bad else 0)
