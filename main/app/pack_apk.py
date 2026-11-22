import os
import sys
import zipfile

root, out = sys.argv[1], sys.argv[2]
src = os.path.join(out, "base.apk")
dst = os.path.join(out, "unsigned.apk")

with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
    for item in zin.infolist():
        zout.writestr(item, zin.read(item.filename))
    zout.write(os.path.join(out, "dex", "classes.dex"), "classes.dex")
    stellar2 = os.path.join(root, "libs", "stellar-classes2.dex")
    if os.path.exists(stellar2):
        zout.write(stellar2, "classes2.dex")
    assets = os.path.join(root, "assets")
    # Recurse: assets/98260/ (second-chain binaries + scripts) must be packaged
    # as assets/98260/<name>; the legacy build is the only path that uses this
    # packer (the compose path packs sourceSets assets directly).
    for dirpath, _dirnames, filenames in os.walk(assets):
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, assets).replace(os.sep, "/")
            zout.write(path, "assets/" + rel)
print("unsigned", dst)
