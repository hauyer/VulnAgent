# -*- coding: utf-8 -*-
"""Redo assembly: download quickjs tarball -> extract -> vulnerable quickjs.c
(from quickjs-git) -> libbf (from libbf tarball dir) -> build qjs."""
import tarfile
import shutil
import subprocess
import sys
from pathlib import Path

root = Path(r"D:\课程设计小学期\VulnAgent\third_party")
qdir = root / "quickjs-2023-12-09"
tarball = root / "quickjs-src.tar"

# 1. tarball
subprocess.run(
    ["curl", "-L", "-o", str(tarball),
     "https://bellard.org/quickjs/quickjs-2023-12-09.tar.xz"],
    capture_output=True, check=True,
)
with tarfile.open(tarball) as t:
    t.extractall(root)
if not (qdir / "list.h").exists():
    print("FAIL: tarball extract incomplete")
    sys.exit(1)
print("tarball extracted")

# 2. vulnerable quickjs.c
vuln = root / "quickjs-git" / "quickjs.c"
shutil.copyfile(vuln, qdir / "quickjs.c")
txt = (qdir / "quickjs.c").read_text(encoding="utf-8", errors="replace")
print("vuln signature (FALSE, FALSE):", "vd->var_name, FALSE, FALSE," in txt)

# 3. libbf
bf_src = [d for d in root.iterdir() if d.is_dir() and d.name.startswith("libbf")]
if not bf_src:
    print("FAIL: libbf source missing")
    sys.exit(1)
dest = qdir / "libbf"
if not (dest / "libbf.c").exists():
    shutil.copytree(bf_src[0], dest, dirs_exist_ok=True)
print("libbf present:", (dest / "libbf.c").exists())
print("READY")
