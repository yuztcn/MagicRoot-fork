from pathlib import Path
import re

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
size = "3,823,582 B"
sha = "1401d384ca4b8052b39cf17da6f2842ad2c2495d74bf024b5cc85ae4cf1179a3"

doc = WS / "docs/reference/kernel-adaptation-61258-61238.md"
t = doc.read_text(encoding="utf-8")
t = re.sub(r"size = `[^`]+`", f"size = `{size}`", t)
t = re.sub(r"sha256 = `[0-9a-f]{64}`", f"sha256 = `{sha}`", t)
doc.write_text(t, encoding="utf-8", newline="\n")
print("adaptation doc hash updated")

dv = WS / "docs/DEVICE-VERIFY.md"
dt = dv.read_text(encoding="utf-8")
if "## 23. 参考参数研究" not in dt:
    dt = dt.rstrip() + """

---

## 23. 参考项目 victims 等参数研究（2026-10-25 19:55）

研究一加16 v2.7.0 `core.sh` / `perm.bin` / `writer.bin` / `t64560_v36.c` /
`t64560_v42.c` 与 HyperBreak Enhanced `Pipeline.java` 的默认/实测参数：

```text
OP16 v2.7.0 core.sh:
  perm   : 180 400 16 6000 12000 4500
  writer : 90 90 400 16 6000 12000 (min 4500)
  capture: loadgen.bin 2 30 x300
参考二进制缺省 (perm.bin/t64560_v36):
  120 400 16 6000 20000 4500
HyperBreak Enhanced 实测通过:
  perm/fsuid: 200 400 24 12000 12000 4500
  cred      : 200 300 400 24 12000 10000 3500 + pid
MagicRoot 当前默认:
  perm/fsuid: 500 400 32 12000 12000 4500
  cred      : 400/500 400 24 12000 15000/15000 3500
```

结论：我们当前比两个参考都更激进（victims 32 vs 16/24；attempts 500 vs
90~200；cred drain 15000 vs 10000）。按 Enhanced 的 hit 模型，24 victims +
200 attempts 的未落地概率约 0.12%，500 attempts 属于过度冗余；32 victims 的
每 attempt 计时器数为 12,800（OP16 6,400 / Enhanced 9,600），内核压力更高。

**默认值暂不改**（无设备无法 A/B），但 run.sh 已加入 opt-in 档位：

```text
$D/tuning-reference   -> 24/200/300/12000/10000/3500 (推荐日常)
$D/tuning-op16        -> 16/180/90/6000/12000/4500 (最保守对照)
MAGICROOT_TUNING / MAGICROOT_ATTEMPTS_* / ... 可单独覆盖
```

日志会输出 `TUNING=reference ...` 与最终 `ATTEMPTS_PERMISSIVE=...`。
详见 `docs/reference/reference-parameter-research.md`。

构建：APK 3,823,582 B
sha256 `1401d384ca4b8052b39cf17da6f2842ad2c2495d74bf024b5cc85ae4cf1179a3`
（`tools/verify_apk.py` 通过；未安装，真机 A/B 待设备连接）。
"""
    dv.write_text(dt, encoding="utf-8", newline="\n")
    print("DEVICE-VERIFY §23 appended")
else:
    print("§23 already present")
