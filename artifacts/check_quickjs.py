import tarfile, os, re

root = r"D:\课程设计小学期\VulnAgent\third_party"
with tarfile.open(os.path.join(root, "quickjs-src.tar")) as t:
    t.extractall(root)
dirs = [d for d in os.listdir(root) if d.startswith("quickjs") and os.path.isdir(os.path.join(root, d))]
q = os.path.join(root, "quickjs-2023-12-09")
print("using:", q)
src = os.path.join(q, "quickjs.c")
txt = open(src, encoding="utf-8", errors="replace").read()
print("has fix (is_lexical):", "vd->is_lexical" in txt)
print("has libbf dir:", os.path.isdir(os.path.join(q, "libbf")))
m = re.search(r'CONFIG_VERSION\s*"([0-9-]+)"', txt)
print("version:", m.group(1) if m else "?")
