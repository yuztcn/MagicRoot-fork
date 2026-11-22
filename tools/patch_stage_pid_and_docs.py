from pathlib import Path

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")

# Fix the inverted kill -0 result: 0 means ALIVE -> keep polling; non-zero -> gone.
p = WS / "tools" / "device" / "ab_stage.py"
t = p.read_text(encoding="utf-8")
old = '''        pid_txt = ab.shell(f"cat /data/local/tmp/ab-{tag}.pid 2>/dev/null").stdout.strip()
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
new = '''        pid_txt = ab.shell(f"cat /data/local/tmp/ab-{tag}.pid 2>/dev/null").stdout.strip()
        if pid_txt.isdigit():
            rc = ab.shell(f"kill -0 {pid_txt} 2>/dev/null; echo $?", timeout=20).stdout.strip()
            rc = rc.splitlines()[-1] if rc.splitlines() else "1"
        else:
            rc = "1"
        if rc == "0":
            # still alive (possibly in preflight); keep polling
            continue
        if rc != "0":
            time.sleep(3)
            full = ab.tail_log(tag, 40)'''
if old not in t:
    raise SystemExit("pid-liveness anchor missing")
t = t.replace(old, new, 1)
p.write_text(t, encoding="utf-8", newline="\n")
print("fixed kill -0 liveness logic")

# Record the conceptual correction.
doc = WS / "docs/reference/reference-parameter-research.md"
dt = doc.read_text(encoding="utf-8")
if "cred stage 不能独立运行" not in dt:
    dt = dt.rstrip() + """

### 补充修正：cred stage 不能独立 A/B

cred 阶段依赖前序 permissive/fsuid 以及目标 cred/候选进程状态，**不能单独拉起来做
A/B**。因此后续阶段只能做**整链 A/B**（从干净 boot 跑完整 run.sh，比较整链
成功/阶段到达/耗时），或者在同一 permissive 状态内做全链变体；`MAGICROOT_AB_STAGE`
钩子只用于“跑到某阶段即停”的整链对比，不能把 cred 阶段当作独立可执行单元。
"""
    doc.write_text(dt, encoding="utf-8", newline="\n")
    print("documented cred-stage correction")

dv = WS / "docs/DEVICE-VERIFY.md"
dvt = dv.read_text(encoding="utf-8")
if "cred stage 不能独立 A/B" not in dvt:
    dvt = dvt.rstrip() + """

**修正（2026-10-25 21:20）**：cred stage 依赖 permissive/fsuid/候选 cred，不能独立
A/B；后续如继续，只做整链 A/B（fresh boot 跑完整 run.sh），不再拆分 cred 阶段。
"""
    dv.write_text(dvt, encoding="utf-8", newline="\n")
    print("recorded DEVICE-VERIFY correction")
