from pathlib import Path

p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\main\app\assets\run.sh")
t = p.read_text(encoding="utf-8")
old = """       grep -q '^KASLR_ANCHORS=' "$D/kaslr.txt" 2>/dev/null &&
       grep -q '^KASLR_VOTES=' "$D/kaslr.txt" 2>/dev/null; then"""
new = """       grep -q '^KASLR_ANCHORS=' "$D/kaslr.txt" 2>/dev/null &&
       grep -q '^KASLR_VOTES=' "$D/kaslr.txt" 2>/dev/null &&
       grep -q '^KASLR_BYTES=' "$D/kaslr.txt" 2>/dev/null; then"""
if old not in t:
    raise SystemExit("anchor missing")
p.write_text(t.replace(old, new, 1), encoding="utf-8", newline="\n")
print("cache format gate added")
