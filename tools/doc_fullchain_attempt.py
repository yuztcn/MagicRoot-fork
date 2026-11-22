from pathlib import Path

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")

doc = WS / "docs/reference/reference-parameter-research.md"
t = doc.read_text(encoding="utf-8")
if "## 11. 整链 A/B 尝试" not in t:
    t = t.rstrip() + """

---

## 11. 整链 A/B 尝试（2026-10-25 21:34，未完成）

cred 不能独立运行，因此按整链方式测试：fresh boot 后跑完整 run.sh
（permissive→fsuid→cred→module→root），测试时临时设置
`MAGICROOT_ALLOW_SHELL=1`，否则 root_stage 的 grant 必然被 allow_shell 默认关闭拦住。

| variant | 结果 | 说明 |
|---|---|---|
| full-current-1 | **设备重启（reboot）** | KASLR/patch 成功，permissive attempt 9 后设备重启 |
| full-reference-1 | `FAIL=kaslr_anchors anchors=1 min=2` | 抓取字节 3.39 MB、votes 701，但 anchors 只有 1；未进入 permissive |

结论：

```text
1. 整链 A/B 没有产生有效对比：current 出现一次 full-chain 重启，reference 未过 KASLR；
2. permissive 单独测试 current 4/4、reference 1/4（2 次竞态重启）仍是最强证据；
3. 默认继续保留 current；reference 不切默认；
4. 整链稳定性、cred/module 阶段仍未有可靠 A/B 数据；
5. KASLR anchors 偶发=1，即使把 GRAB_LOOPS 提高到 120 也会出现；后续需要
   KASLR 重抓/放宽 anchors 门槛策略后才能稳定跑整链 A/B。
```

整链 A/B 的 `MAGICROOT_ALLOW_SHELL=1` 只用于测试，生产默认仍是 0（信息提示已显示）。
"""
    doc.write_text(t, encoding="utf-8", newline="\n")
    print("appended full-chain attempt")

dv = WS / "docs/DEVICE-VERIFY.md"
dt = dv.read_text(encoding="utf-8")
if "## 26. 整链 A/B 尝试" not in dt:
    dt = dt.rstrip() + """

---

## 26. 整链 A/B 尝试（2026-10-25 21:34）

| variant | 结果 | 说明 |
|---|---|---|
| full-current-1 (allow_shell=1) | **设备重启** | permissive attempt 9 后重启，未进入 cred/module |
| full-reference-1 (allow_shell=1) | `FAIL=kaslr_anchors anchors=1` | raw 3.39 MB/votes 701，但 anchors 只有 1 |

整链 A/B 未得到有效对比。permissive 结论不变：current 4/4，reference 1/4（2 次
竞态重启），默认保留 current。KASLR 抓取偶发 anchors=1，后续需重抓/放宽门槛后才能
稳定做整链测试。设备当前 Enforcing、无残留 run。
"""
    dv.write_text(dt, encoding="utf-8", newline="\n")
    print("appended DEVICE-VERIFY §26")
else:
    print("§26 already present")
