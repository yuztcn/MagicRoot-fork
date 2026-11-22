from pathlib import Path

p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\tools\device\ab_stage.py")
t = p.read_text(encoding="utf-8")
t = t.replace('''        if "DONE" in out:
            outcome = "done"
            break''', '''        if re.search(r"^DONE\\s*$", out, re.M):
            outcome = "done"
            break''')
t = t.replace('''            elif "DONE" in full:
                outcome = "done"''', '''            elif re.search(r"^DONE\\s*$", full, re.M):
                outcome = "done"''')
p.write_text(t, encoding="utf-8", newline="\n")
print("stage DONE detection tightened (exact line only)")
