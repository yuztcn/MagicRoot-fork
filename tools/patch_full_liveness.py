from pathlib import Path

p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\tools\device\ab_full.py")
t = p.read_text(encoding="utf-8")

old = '''        pid_txt = ab.shell(f"cat /data/local/tmp/ab-{tag}.pid 2>/dev/null").stdout.strip()
        if pid_txt.isdigit():
            rc = ab.shell(f"kill -0 {pid_txt} 2>/dev/null; echo $?", timeout=20).stdout.strip()
            rc = rc.splitlines()[-1] if rc.splitlines() else "1"
        else:
            rc = "1"
        if rc == "0":
            continue
        # process exited without a marker
        time.sleep(3)
        full = ab.tail_log(tag, 50)'''

new = '''        pid_txt = ab.shell(f"cat /data/local/tmp/ab-{tag}.pid 2>/dev/null").stdout.strip()
        alive_state = "UNKNOWN"
        if pid_txt.isdigit():
            r = ab.shell(f"kill -0 {pid_txt} 2>/dev/null && echo ALIVE || echo DEAD",
                         timeout=60)
            lines = [x.strip() for x in r.stdout.splitlines() if x.strip()]
            if lines:
                alive_state = lines[-1]
        if alive_state != "DEAD":
            # ALIVE or adb timeout: never declare the run dead on one probe
            continue
        # double-check DEAD to avoid transient adb/shell failures
        time.sleep(5)
        r2 = ab.shell(f"kill -0 {pid_txt} 2>/dev/null && echo ALIVE || echo DEAD",
                      timeout=60)
        lines2 = [x.strip() for x in r2.stdout.splitlines() if x.strip()]
        if not lines2 or lines2[-1] != "DEAD":
            continue
        # process really exited without a marker
        time.sleep(3)
        full = ab.tail_log(tag, 50)'''
if old not in t:
    raise SystemExit("pid block anchor missing")
t = t.replace(old, new, 1)
p.write_text(t, encoding="utf-8", newline="\n")
print("ab_full.py robust ALIVE/DEAD double-check installed")
