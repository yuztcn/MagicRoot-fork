from pathlib import Path
p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\main\app\assets\run.sh")
t = p.read_text(encoding="utf-8")
old = '''if [ "${MAGICROOT_AB_STAGE:-}" = "fsuid" ]; then
    echo "AB_STAGE_OK stage=fsuid"
    exit 0
fi'''
new = '''if [ "${MAGICROOT_AB_STAGE:-}" = "fsuid" ]; then
    kill -9 "$CRED_PID" 2>/dev/null || true
    rm -f "$SYNC" 2>/dev/null || true
    echo "AB_STAGE_OK stage=fsuid"
    exit 0
fi'''
if old not in t:
    raise SystemExit("hook missing")
p.write_text(t.replace(old, new, 1), encoding="utf-8", newline="\n")
print("fsuid stage hook now kills pending cred_target")
