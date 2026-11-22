from pathlib import Path

p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\main\app\assets\run.sh")
t = p.read_text(encoding="utf-8")
before = t
# Use the last fd= line: with the fallback sequence the first line may be fd=-1
# even when a later reboot magic or /dev/ksu fallback succeeded.
t = t.replace("sed -n 's/.*fd=\\([-0-9][0-9]*\\).*/\\1/p' \"$D/ksu_grant.log\" | head -1",
              "sed -n 's/.*fd=\\([-0-9][0-9]*\\).*/\\1/p' \"$D/ksu_grant.log\" | tail -1")
if t == before:
    raise SystemExit("fd parser anchor missing")
p.write_text(t, encoding="utf-8", newline="\n")
print("patched fd= extraction to tail -1")
