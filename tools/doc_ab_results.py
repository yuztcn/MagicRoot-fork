from pathlib import Path

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
doc = WS / "docs/reference/reference-parameter-research.md"
t = doc.read_text(encoding="utf-8")
if "## 8. 真机 A/B 初步结果" not in t:
    t = t.rstrip() + """

---

## 8. 真机 A/B 初步结果（2026-10-25 20:38）

设备：Honor Magic9 `<SERIAL>`；adb：**SDK 37 platform-tools 37.0.1**；
测试只跑 permissive 阶段（`MAGICROOT_PERMISSIVE_ONLY=1`），不加载模块、不写 cred。
每轮之间只做**受控的一次 reboot**（把 SELinux 从 Permissive 复位到 Enforcing）；
reference-2 的第二次重启是**漏洞竞态导致的设备重启**，不是 adb 命令。

| trial | preset | 结果 | 落地 attempt | 总耗时 | KASLR anchors/votes | 备注 |
|---|---|---|---:|---:|---:|---|
| current-1 | current (32/500) | OK | 35 | 352.3 s | 6 / 505 | boot d0a87 |
| current-2 | current (32/500) | OK | 9 | 107.1 s | 6 / ? | boot 06d2 |
| reference-1 | reference (24/200) | OK | 8 | 139.3 s | 6 / ? | boot 06ef，含约 60 s preflight 等待 |
| reference-2 | reference (24/200) | **设备重启** | 13（中断） | 199.3 s | — | boot b51ff，attempt 13 后设备重启 |

关键日志：

```text
current-1: LANDED attempt=35  PERMISSIVE_DONE  host_elapsed=352.3 s
current-2: LANDED attempt=9   PERMISSIVE_DONE  host_elapsed=107.1 s
reference-1: LANDED attempt=8 PERMISSIVE_DONE  host_elapsed=139.3 s
reference-2: attempt=13 landed=0 之后设备重启（无 FAIL、无 DONE）
```

观察：

- current 2/2 成功（attempt 35、9）；reference 1/2 成功（attempt 8），另一次在
  attempt 13 后重启；
- reference 单次成功的耗时并不显著优于 current（139.3 s vs 107.1 s，且包含 preflight 等待）；
- 两个档位在成功轮次里落地都很快（8/9/35），说明 attempts 500 的冗余确实很大；
- **样本量太小**（每档 2 次），且 reference 出现 1 次重启，不能据此把默认切到 reference。

当前结论：

```text
1. 默认保持 current（32 victims / 500 attempts），不切换到 reference；
2. reference 只作为 opt-in 低压力档（$D/tuning-reference），继续观察；
3. 若要确认“最优”，每档至少需要再积累 2-3 次成功/重启样本；
4. reference-2 的重启是竞态风险，不是 adb 版本或命令问题。
```

设备当前状态：Permissive（current-2 成功后），NO_MODULE；需要重启才能恢复 Enforcing。
"""
    doc.write_text(t, encoding="utf-8", newline="\n")
    print("parameter research A/B section appended")

dv = WS / "docs/DEVICE-VERIFY.md"
dt = dv.read_text(encoding="utf-8")
if "## 24. victims 参数真机 A/B" not in dt:
    dt = dt.rstrip() + """

---

## 24. victims 参数真机 A/B 初步结果（2026-10-25 20:38）

设备 `<SERIAL>`；adb SDK 37.0.1；测试仅 permissive 阶段：

| 档位 | trial | 结果 | 落地 attempt | 总耗时 |
|---|---|---|---:|---:|
| current (32/500) | 1 | OK | 35 | 352.3 s |
| current (32/500) | 2 | OK | 9 | 107.1 s |
| reference (24/200) | 1 | OK | 8 | 139.3 s |
| reference (24/200) | 2 | **设备重启** | 13（中断） | 199.3 s |

结论：current 2/2 成功；reference 1/2 成功且有一次竞态重启，样本不足，**默认保持
current**，reference 继续作为 `$D/tuning-reference` opt-in 档。
reference-2 的重启是漏洞竞态，不是 adb 命令（日志在 attempt 13 后直接中断，
无 FAIL/DONE；adb 命令只发送过一次 reboot，在测试开始前）。
"""
    dv.write_text(dt, encoding="utf-8", newline="\n")
    print("DEVICE-VERIFY §24 appended")
else:
    print("§24 already present")
