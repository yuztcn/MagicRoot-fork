from pathlib import Path

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")

# run.sh current preset: cred defaults 260/320, 16 victims, 6000 nfrag,
# 12000 drain, 4500 min for both phases.
p = WS / "main" / "app" / "assets" / "run.sh"
t = p.read_text(encoding="utf-8")
t = t.replace("        DEF_VICTIMS_PERMISSIVE=32; DEF_VICTIMS_FSUID=32; DEF_VICTIMS_CRED=24\n"
              "        DEF_ATTEMPTS_PERMISSIVE=500; DEF_ATTEMPTS_FSUID=500\n"
              "        DEF_ATTEMPTS_CRED1=400; DEF_ATTEMPTS_CRED2=500\n"
              "        DEF_FRAG_PERMISSIVE=12000; DEF_DRAIN_PERMISSIVE=12000; DEF_MIN_PERMISSIVE=4500\n"
              "        DEF_FRAG_CRED=12000; DEF_DRAIN_CRED1=15000; DEF_MIN_CRED1=3500\n"
              "        DEF_DRAIN_CRED2=15000; DEF_MIN_CRED2=3500",
              "        DEF_VICTIMS_PERMISSIVE=32; DEF_VICTIMS_FSUID=32; DEF_VICTIMS_CRED=16\n"
              "        DEF_ATTEMPTS_PERMISSIVE=500; DEF_ATTEMPTS_FSUID=500\n"
              "        DEF_ATTEMPTS_CRED1=260; DEF_ATTEMPTS_CRED2=320\n"
              "        DEF_FRAG_PERMISSIVE=12000; DEF_DRAIN_PERMISSIVE=12000; DEF_MIN_PERMISSIVE=4500\n"
              "        DEF_FRAG_CRED=6000; DEF_DRAIN_CRED1=12000; DEF_MIN_CRED1=4500\n"
              "        DEF_DRAIN_CRED2=12000; DEF_MIN_CRED2=4500")
p.write_text(t, encoding="utf-8", newline="\n")

# Compose UI default victimCred = 16
p = WS / "main" / "compose-app" / "app" / "src" / "main" / "kotlin" / "com" / "aoki" / "magicroot" / "UiState.kt"
t = p.read_text(encoding="utf-8")
t = t.replace('var victimCred by mutableIntStateOf(validCredVictim(victimPrefs.getInt("cred_24", 24), 24))',
              'var victimCred by mutableIntStateOf(validCredVictim(victimPrefs.getInt("cred_24", 16), 16))')
p.write_text(t, encoding="utf-8", newline="\n")

# Old Java UI default victimCred = 16
p = WS / "main" / "app" / "src" / "com" / "aoki" / "magicroot" / "MainActivity.java"
t = p.read_text(encoding="utf-8")
t = t.replace("private int victimCred = 24;", "private int victimCred = 16;")
t = t.replace('victimCred = validCredVictim(victimPrefs.getInt("cred_24", 24), 24);',
              'victimCred = validCredVictim(victimPrefs.getInt("cred_24", 16), 16);')
p.write_text(t, encoding="utf-8", newline="\n")
print("default cred parameters updated")

# docs
p = WS / "docs" / "DEVICE-VERIFY.md"
t = p.read_text(encoding="utf-8")
t = t.replace("cred      : 400/500 400 24 12000 15000/15000 3500",
              "cred      : 260/320 400 16 6000 12000 4500")
t = t.replace("cred      : 200 300 400 24 12000 10000 3500 + pid",
              "cred      : 200 300 400 24 12000 10000 3500 + pid")  # reference preset unchanged
p.write_text(t, encoding="utf-8", newline="\n")

p = WS / "docs" / "reference" / "reference-parameter-research.md"
t = p.read_text(encoding="utf-8")
t = t.replace("| cred phase1/2 | 400 / 500 | 400 | **24** | 12000 | 15000 / 15000 | 3500 / 3500 |",
              "| cred phase1/2 | **260 / 320** | 400 | **16** | **6000** | 12000 / 12000 | 4500 / 4500 |")
t = t.replace("`UiState.kt` 默认：`victimPerm=32`、`victimFsuid=32`、`victimCred=24`；",
              "`UiState.kt` 默认：`victimPerm=32`、`victimFsuid=32`、`victimCred=16`；")
t = t.replace("3. **attempts**：参考 180/90、Enhanced 200/300，我们 500/500/400/500。",
              "3. **attempts**：参考 180/90、Enhanced 200/300，我们 500/500/260/320。")
t = t.replace("| current（现有默认） | 32 / 32 / 24 | 500 / 500 | 400 / 500 | 12000 / 12000 | 12000 | 15000 | 4500 / 3500 |",
              "| current（现有默认） | 32 / 32 / 16 | 500 / 500 | 260 / 320 | 12000 / 6000 | 12000 | 12000 | 4500 / 4500 |")
p.write_text(t, encoding="utf-8", newline="\n")

# append a short record
p = WS / "docs" / "DEVICE-VERIFY.md"
t = p.read_text(encoding="utf-8")
if "## 32. 默认 cred 参数对齐" not in t:
    t = t.rstrip() + """

---

## 32. 默认 cred 参数对齐（2026-10-25 23:05）

默认 cred 参数调整为：

```text
attempts = 260 / 320
timers   = 400
victims  = 16
nfrag    = 6000
drain    = 12000 / 12000
min      = 4500 / 4500
```

对应 `t64560_cred <cred> 260 320 400 16 6000 12000 4500`。
UI cred 默认档位同步为 16；可选档位仍为 8/12/16/24/32。
"""
    p.write_text(t, encoding="utf-8", newline="\n")
    print("appended DEVICE-VERIFY §32")
