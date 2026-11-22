from pathlib import Path

p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\main\app\assets\run.sh")
t = p.read_text(encoding="utf-8")
old = '''[ "$(getenforce)" = "Permissive" ] || { echo "FAIL=permissive"; exit 4; }
mark PERMISSIVE_DONE
'''
new = '''[ "$(getenforce)" = "Permissive" ] || { echo "FAIL=permissive"; exit 4; }
mark PERMISSIVE_DONE
# Device A/B test hook: stop right after the permissive stage so presets can be
# compared without loading a module or touching creds.
if [ "${MAGICROOT_PERMISSIVE_ONLY:-0}" = "1" ]; then
    echo "PERMISSIVE_ONLY_OK tuning=$(cat "$D/ab_tuning" 2>/dev/null || echo unknown) attempts=$(grep -c '^attempt=' "$D/run.log" 2>/dev/null || echo 0)"
    exit 0
fi
'''
if old not in t:
    raise SystemExit("permissive-only anchor missing")
t = t.replace(old, new, 1)
p.write_text(t, encoding="utf-8", newline="\n")
print("permissive-only test mode added")
