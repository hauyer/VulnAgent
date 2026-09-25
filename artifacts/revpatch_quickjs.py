# -*- coding: utf-8 -*-
"""Reverse-apply the official QuickJS fix patch (ExploitGym task data) to the
2023-12-09 tarball quickjs.c, producing the vulnerable variant for discovery."""
import subprocess
import sys
from pathlib import Path

root = Path(r"D:\课程设计小学期\VulnAgent\third_party")
qdir = root / "quickjs-2023-12-09"
patch = root / "exploitgym" / "data" / "tasks" / "user" / "nofuzz" / "CVE-2023-48183" / "patch.diff"

# init a throwaway git repo so git apply works
subprocess.run(["git", "init", "-q"], cwd=qdir)
subprocess.run(["git", "add", "quickjs.c"], cwd=qdir)
check = subprocess.run(
    ["git", "apply", "--check", "-R", str(patch)], cwd=qdir,
    capture_output=True, text=True,
)
if check.returncode != 0:
    print("FAIL: reverse patch does not apply cleanly:", check.stderr[:300])
    sys.exit(1)
subprocess.run(["git", "apply", "-R", str(patch)], cwd=qdir, check=True)
txt = (qdir / "quickjs.c").read_text(encoding="utf-8", errors="replace")
print("reverse-applied; vulnerable again (is_lexical in fix hunk):", "vd->is_lexical" in txt)
print("VULNERABLE TREE READY")
