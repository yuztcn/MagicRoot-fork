from pathlib import Path

p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\tools\device\ab_permissive.py")
t = p.read_text(encoding="utf-8")
t = t.replace("def one_trial(preset: str, index: int):",
              "def one_trial(preset: str, index: int, do_reboot: bool = True):")
old = '''    if not reboot_and_wait(tag):
        return {"tag": tag, "preset": preset, "outcome": "boot_timeout"}'''
new = '''    if do_reboot:
        if not reboot_and_wait(tag):
            return {"tag": tag, "preset": preset, "outcome": "boot_timeout"}
    else:
        if not wait_online(60):
            return {"tag": tag, "preset": preset, "outcome": "offline"}
        time.sleep(2)'''
if old not in t:
    raise SystemExit("anchor missing")
t = t.replace(old, new, 1)
p.write_text(t, encoding="utf-8", newline="\n")
print("ab_permissive one_trial(do_reboot) fixed")
