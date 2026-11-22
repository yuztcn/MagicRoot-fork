from pathlib import Path

p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\tools\device\ab_permissive.py")
t = p.read_text(encoding="utf-8")
t = t.replace("def one_trial(preset: str, index: int):", "def one_trial(preset: str, index: int, do_reboot: bool = True):")
t = t.replace(
'''    if not reboot_and_wait(tag):
        return {"tag": tag, "preset": preset, "outcome": "boot_timeout"}''',
'''    if do_reboot:
        if not reboot_and_wait(tag):
            return {"tag": tag, "preset": preset, "outcome": "boot_timeout"}
    else:
        if not wait_online(60):
            return {"tag": tag, "preset": preset, "outcome": "offline"}
        # keep a little margin for the preflight; run.sh itself waits for
        # uptime>=120s / load<=20 / mem>=1GB.
        time.sleep(2)''')
p.write_text(t, encoding="utf-8", newline="\n")
print("one_trial gained do_reboot flag")
