from pathlib import Path
import re

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
size = "3,824,410 B"
sha = "f0b7082de4aab69d39a8680544d2ddd00eb56befa2dafc3fb4c1661e82b93450"

# 1) verify marker
vp = WS / "tools/verify_apk.py"
vt = vp.read_text(encoding="utf-8")
if 'b"KASLR_REGRAB"' not in vt:
    vt = vt.replace('b"KASLR_CROSS_CHECK", b"KO_PATCH_SELF_CHECK",',
                    'b"KASLR_CROSS_CHECK", b"KASLR_REGRAB", b"KO_PATCH_SELF_CHECK",')
    vp.write_text(vt, encoding="utf-8", newline="\n")
    print("verify_apk marker KASLR_REGRAB added")

# 2) build hash in kernel adaptation doc
kp = WS / "docs/reference/kernel-adaptation-61258-61238.md"
kt = kp.read_text(encoding="utf-8")
kt = re.sub(r"size = `[^`]+`", f"size = `{size}`", kt)
kt = re.sub(r"sha256 = `[0-9a-f]{64}`", f"sha256 = `{sha}`", kt)
kp.write_text(kt, encoding="utf-8", newline="\n")
print("kernel adaptation hash updated")

# 3) research doc: KASLR regrab section
rp = WS / "docs/reference/reference-parameter-research.md"
rt = rp.read_text(encoding="utf-8")
if "## 12. KASLR 重抓策略" not in rt:
    rt = rt.rstrip() + """

---

## 12. KASLR 重抓策略（2026-10-25 21:40）

问题：整链测试中 KASLR 偶发 `anchors=1` / bytes 偏低（例如 raw 3.39 MB、votes 701
但 anchors=1），原逻辑只在字段缺失时 fallback，并且**在验证前就写 cache**；结果
同 boot 重试会复用不合格 cache，继续失败。

修复（`run.sh`）：

```text
1. 把 KASLR 字段校验抽成 kaslr_fields_ok()，只有
   anchors>=profile_min、votes>=profile_min、bytes>=profile_min、无 KASLR_ERROR
   才算通过；
2. cache 命中先校验，不达标输出 KASLR_CACHE_REJECT 并强制重抓；
3. 最多 KASLR_GRAB_TRIES=3（可由 MAGICROOT_KASLR_GRAB_TRIES 覆盖）：
   第1次 grab.sh 120 loops；
   第2次 grab.sh 240 loops（上限 MAGICROOT_KASLR_GRAB_MAX_LOOPS=300）；
   第3次 grab_legacy.sh 8s + 文本锚点；
   每次重新跑 KASLR_BIN，失败输出 KASLR_REGRAB …，通过才 break；
4. 只有通过 gate 的 capture 才写入 kaslr.cache；失败时删除旧 cache；
5. GRAB_LOOPS 默认从 40 提到 120，降低首轮 anchors 不足概率。
```

真机验证（强制低 loops，KASLR_ONLY）：

```text
KASLR_GRAB_TRY=1 loops=10
KASLR_REGRAB attempt=1 anchors=1 votes=285 bytes=1425408
KASLR_GRAB_TRY=2 loops=20
KASLR_REGRAB attempt=2 anchors=1 votes=272 bytes=1081344
KASLR_GRAB_TRY=3 legacy=1 loops=30
KASLR_ANCHORS=3 votes=668 bytes=2301952
KASLR_CROSS_CHECK=ok
KASLR_ACCEPTED slide=0x28b3a00000
KASLR_ONLY_DONE
```

即低质量抓取会被自动淘汰，legacy 文本锚点兜底成功；整链不再因为一次
anchors=1 就 `FAIL=kaslr_anchors`。
"""
    rp.write_text(rt, encoding="utf-8", newline="\n")
    print("research doc KASLR regrab appended")

# 4) DEVICE-VERIFY section
dp = WS / "docs/DEVICE-VERIFY.md"
dt = dp.read_text(encoding="utf-8")
if "## 27. KASLR 重抓策略" not in dt:
    dt = dt.rstrip() + f"""

---

## 27. KASLR 重抓策略（2026-10-25 21:40）

`run.sh` 现在：

- cache 命中先校验，不达标 `KASLR_CACHE_REJECT` 并重抓；
- 最多 3 次：120 loops → 240 loops → `grab_legacy.sh` 8s；
- 只有通过 anchors/votes/bytes gate 才写 `kaslr.cache`，失败删除旧 cache；
- 新增 `MAGICROOT_KASLR_GRAB_TRIES`（默认 3）和
  `MAGICROOT_KASLR_GRAB_MAX_LOOPS`（默认 300）。

真机强制低 loops 验证成功：

```text
KASLR_GRAB_TRY=1 loops=10 → anchors=1, votes=285, bytes=1425408 → KASLR_REGRAB
KASLR_GRAB_TRY=2 loops=20 → anchors=1, votes=272, bytes=1081344 → KASLR_REGRAB
KASLR_GRAB_TRY=3 legacy=1 → anchors=3, votes=668, bytes=2301952
KASLR_CROSS_CHECK=ok; KASLR_ACCEPTED slide=0x28b3a00000; KASLR_ONLY_DONE
```

构建：APK {size} sha256 `{sha}`；`verify_apk` 通过。
"""
    dp.write_text(dt, encoding="utf-8", newline="\n")
    print("DEVICE-VERIFY §27 appended")
