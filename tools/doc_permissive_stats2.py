from pathlib import Path

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
doc = WS / "docs/reference/reference-parameter-research.md"
t = doc.read_text(encoding="utf-8")
if "## 9. 扩充 permissive 统计" not in t:
    t = t.rstrip() + """

---

## 9. 扩充 permissive 统计（2026-10-25 21:16）

在 §8 基础上继续用 permissive-only 测试；每轮开始前一次受控 reboot。
`current` 4 轮全部成功；`reference` 4 轮仅 1 轮成功，另有 2 次设备重启和 1 次
43 attempts 未落地（人工终止）。

| preset | trial | 结果 | 落地 attempt | 总耗时 |
|---|---|---:|---:|---:|
| current | 1 | OK | 35 | 352.3 s |
| current | 2 | OK | 9 | 107.1 s |
| current | 3 | OK | 10 | 164.2 s |
| current | 4 | OK | 19 | 262.0 s |
| reference | 1 | OK | 8 | 139.3 s |
| reference | 2 | **设备重启** | 13 中断 | 199.3 s |
| reference | 3 | **设备重启/无结果** | — | 232.7 s |
| reference | 4 | 43 attempts 未落地，人工终止 | — | — |

统计结论：

```text
current : 4/4 成功，落地 attempt 9~35，无重启
reference: 1/4 成功，2 次竞态重启，1 次 43 attempts 未落地
```

在这个 6.12.58 设备上，**reference（24/200）并不优于 current（32/500）**；
reference 反而更不稳定。默认应保持 current；reference 仅作低压力实验档。
样本仍偏小（4 vs 4），但方向已经比较明确。

## 10. 后续阶段 A/B 尝试（未完成）

新增了 `MAGICROOT_AB_STAGE=fsuid|module` 停止钩子，并尝试对
`cred-current` / `cred-reference` / `fsuid-current` / `fsuid-reference` 做 A/B。
本轮尝试**没有产生有效数据**，原因：

1. 第一版 harness 把 `GRAB_DONE`/`PATCH_DONE` 误判为最终 `DONE`，在 run.sh 仍
   在运行时进入下一轮 reboot（已修复为只匹配整行 `DONE`）；
2. `device_has_run` 在 preflight 阶段误判进程消失，产生 `no_result`；
3. 其中一轮 KASLR 只抓到 1.1 MB / 1 anchor，`FAIL=kaslr_anchors`；
4. 测试被人工取消。

因此后续阶段（fsuid/cred/module）的 A/B 结论仍待补测；permissive 结论不受影响。
"""
    doc.write_text(t, encoding="utf-8", newline="\n")
    print("appended full permissive stats + stage blocker")

dv = WS / "docs/DEVICE-VERIFY.md"
dt = dv.read_text(encoding="utf-8")
if "## 25. 扩充 permissive 统计" not in dt:
    dt = dt.rstrip() + """

---

## 25. 扩充 permissive 统计与后续阶段（2026-10-25 21:16）

permissive-only 扩充样本：

| preset | 成功/总 | 落地 attempts | 备注 |
|---|---|---|---|
| current (32/500) | **4/4** | 35, 9, 10, 19 | 无重启 |
| reference (24/200) | 1/4 | 8 | 2 次竞态重启 + 1 次 43 attempts 未落地 |

结论：该设备上 current 明显更稳，**默认保持 current**，不切 reference。

后续 fsuid/cred/module 阶段 A/B 的第一次尝试因 harness 误判 `DONE`、进程探测误判
和一次 KASLR anchors 不足而作废，测试被人工取消；`MAGICROOT_AB_STAGE` 钩子已加入
run.sh，后续修好 harness 后可继续。设备当前已回到 Enforcing，无残留 run。
"""
    dv.write_text(dt, encoding="utf-8", newline="\n")
    print("appended DEVICE-VERIFY §25")
else:
    print("§25 already present")
