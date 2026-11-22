import re
import zipfile
from pathlib import Path

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
pat = re.compile(rb"(?i)(slab|stale|leak_limit|leak limit|runaway|posix_timers|SAFE_)")

print("=== APK ===")
apk = WS / "release" / "apk" / "MagicRoot-1.0.3.apk"
with zipfile.ZipFile(apk) as z:
    for n in z.namelist():
        if n.endswith("/"):
            continue
        b = z.read(n)
        hits = sorted({m.group(0).decode("ascii", "ignore") for m in pat.finditer(b)})
        if hits:
            print(n, len(b), hits[:20])

print("=== SOURCE ASSETS ===")
root = WS / "main" / "app" / "assets"
for p in root.iterdir():
    if p.is_file():
        b = p.read_bytes()
        hits = sorted({m.group(0).decode("ascii", "ignore") for m in pat.finditer(b)})
        if hits:
            print(p.name, p.stat().st_size, hits[:20])
