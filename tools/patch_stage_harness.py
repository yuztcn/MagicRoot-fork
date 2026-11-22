from pathlib import Path
import re

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")

# 1) production: more KASLR capture samples by default (stage A/B hit anchors=1
#    with 40 loops; 120 gives much more raw trace without meaningful boot cost).
p = WS / "main" / "app" / "assets" / "run.sh"
t = p.read_text(encoding="utf-8")
t = t.replace("GRAB_LOOPS=${MAGICROOT_GRAB_LOOPS:-40}",
              "GRAB_LOOPS=${MAGICROOT_GRAB_LOOPS:-120}")
t = t.replace("case \"$GRAB_LOOPS\" in ''|*[!0-9]*) GRAB_LOOPS=40 ;; esac",
              "case \"$GRAB_LOOPS\" in ''|*[!0-9]*) GRAB_LOOPS=120 ;; esac")
p.write_text(t, encoding="utf-8", newline="\n")
print("run.sh GRAB_LOOPS default -> 120")

# 2) device launcher writes the actual run.sh PID so the host harness can
#    distinguish "still in preflight" from "process exited without a marker".
lp = WS / ".probe" / "ab_launch_stage.sh"
lt = lp.read_text(encoding="utf-8")
lt = lt.replace('echo "LAUNCHED pid=$! log=$LOG"',
                'PID=$!\necho "$PID" > "/data/local/tmp/ab-$TAG.pid"\necho "LAUNCHED pid=$PID log=$LOG"')
lp.write_text(lt, encoding="utf-8", newline="\n")
print("ab_launch_stage.sh writes pid file")

# 3) host harness: use pid liveness instead of ps/grep process detection.
hp = WS / "tools" / "device" / "ab_stage.py"
ht = hp.read_text(encoding="utf-8")
old = '''        if not ab.device_has_run():
            time.sleep(3)
            full = ab.tail_log(tag, 40)'''
new = '''        pid_txt = ab.shell(f"cat /data/local/tmp/ab-{tag}.pid 2>/dev/null").stdout.strip()
        if pid_txt.isdigit():
            alive = ab.shell(f"kill -0 {pid_txt} 2>/dev/null; echo $?", timeout=20).stdout.strip()
        else:
            alive = "0"
        if alive.splitlines()[-1:] not in (["0"], []):
            # process was alive at the check; keep polling
            continue
        if alive.splitlines()[-1:] == ["0"]:
            time.sleep(3)
            full = ab.tail_log(tag, 40)'''
if old not in ht:
    raise SystemExit("harness process-check anchor missing")
ht = ht.replace(old, new, 1)
hp.write_text(ht, encoding="utf-8", newline="\n")
print("ab_stage.py uses pid liveness")
