# -*- coding: utf-8 -*-
import tarfile
from pathlib import Path

root = Path(r"D:\课程设计小学期\VulnAgent\third_party")
with tarfile.open(root / "quickjs-src.tar") as t:
    names = t.getnames()
print("count:", len(names))
print(names[:15])
print("...")
print(names[-5:])
