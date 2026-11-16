#!/usr/bin/env bash
# 一把梭验收：单元测试 + 回归语料 + 打包元数据 + 关键不变量。
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== python =="; python3 -V

echo "== unit tests =="
python3 -m unittest discover -s tests -t . 2>&1 | tail -3

echo "== corpus =="
python3 -m blastradius selftest

echo "== inventory =="
python3 -m blastradius version

echo "== packaging =="
python3 - <<'PY'
import importlib, tomllib
data = tomllib.load(open("pyproject.toml", "rb"))
proj = data["project"]
assert proj.get("readme") and __import__("os").path.exists(proj["readme"]), "readme missing"
for name, target in proj["scripts"].items():
    mod, fn = target.split(":")
    obj = getattr(importlib.import_module(mod), fn)
    assert callable(obj), f"{name} -> {target} is not callable"
    print(f"  entry point {name} -> {target} ok")
pkgs = data["tool"]["setuptools"]["packages"]
for p in pkgs:
    importlib.import_module(p)
print(f"  packages {pkgs} import ok")
PY

echo "== safety invariants =="
python3 - <<'PY'
import ast, pathlib
banned = {"os.system", "os.popen", "os.execv", "os.execve", "os.spawnv", "os.fork",
          "subprocess.run", "subprocess.call", "subprocess.Popen", "eval", "exec"}
hits = []
for f in pathlib.Path("blastradius").glob("*.py"):
    tree = ast.parse(f.read_text())
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            parts, cur = [], n.func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr); cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            name = ".".join(reversed(parts))
            if name in banned:
                hits.append(f"{f.name}:{n.lineno} {name}")
print("  no execution primitives" if not hits else f"  FOUND {hits}")
raise SystemExit(1 if hits else 0)
PY

echo "== ok =="
