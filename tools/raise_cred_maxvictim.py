from pathlib import Path
import hashlib
import shutil

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
NEW = WS / ".probe" / "fina120" / "t64560_cred_max32"
ASSET = WS / "main" / "app" / "assets" / "t64560_cred"
OLD = WS / ".probe" / "fina120" / "t64560_cred_max24"
shutil.copy2(ASSET, OLD)
shutil.copy2(NEW, ASSET)
h = hashlib.sha256(ASSET.read_bytes()).hexdigest()
print("cred binary", ASSET.stat().st_size, h)

# Native source default + Makefile explicit flag
p = WS / "refs" / "mly-61258" / "src_cred32" / "t64560_cred.c"
t = p.read_text(encoding="utf-8")
t = t.replace("#define MAXVICTIM 24", "#define MAXVICTIM 32", 1)
p.write_text(t, encoding="utf-8", newline="\n")

p = WS / "main" / "host" / "native" / "Makefile"
t = p.read_text(encoding="utf-8")
t = t.replace("$(BIN)/t64560_cred: $(GEN_DIR)/t64560_cred.c | $(BIN)\n\t$(CC) $(CFLAGS) -o $@ $<",
              "$(BIN)/t64560_cred: $(GEN_DIR)/t64560_cred.c | $(BIN)\n\t$(CC) $(CFLAGS) -DMAXVICTIM=32 -o $@ $<")
p.write_text(t, encoding="utf-8", newline="\n")

# run.sh validation
p = WS / "main" / "app" / "assets" / "run.sh"
t = p.read_text(encoding="utf-8")
t = t.replace("case \"$VICTIMS_CRED\" in 8|12|16|24) ;; *) VICTIMS_CRED=$DEF_VICTIMS_CRED ;; esac",
              "case \"$VICTIMS_CRED\" in 8|12|16|24|32) ;; *) VICTIMS_CRED=$DEF_VICTIMS_CRED ;; esac")
p.write_text(t, encoding="utf-8", newline="\n")

# compose UiState cycle/validation
p = WS / "main" / "compose-app" / "app" / "src" / "main" / "kotlin" / "com" / "aoki" / "magicroot" / "UiState.kt"
t = p.read_text(encoding="utf-8")
t = t.replace("""        victimCred = when (victimCred) {
            8 -> 12
            12 -> 16
            16 -> 24
            else -> 8
        }""", """        victimCred = when (victimCred) {
            8 -> 12
            12 -> 16
            16 -> 24
            24 -> 32
            else -> 8
        }""")
t = t.replace("if (value == 8 || value == 12 || value == 16 || value == 24) value else fallback",
              "if (value == 8 || value == 12 || value == 16 || value == 24 || value == 32) value else fallback")
p.write_text(t, encoding="utf-8", newline="\n")

# Old Java UI path (kept in sync if used by another target)
p = WS / "main" / "app" / "src" / "com" / "aoki" / "magicroot" / "MainActivity.java"
t = p.read_text(encoding="utf-8")
t = t.replace("Victim 档位（SELinux/fsuid: 16/24/32，cred: 8/12/16/24）",
              "Victim 档位（SELinux/fsuid: 16/24/32，cred: 8/12/16/24/32）")
t = t.replace("""        if (value == 8) return 12;
        if (value == 12) return 16;
        if (value == 16) return 24;
        return 8;""", """        if (value == 8) return 12;
        if (value == 12) return 16;
        if (value == 16) return 24;
        if (value == 24) return 32;
        return 8;""")
t = t.replace("return (value == 8 || value == 12 || value == 16 || value == 24) ? value : fallback;",
              "return (value == 8 || value == 12 || value == 16 || value == 24 || value == 32) ? value : fallback;")
p.write_text(t, encoding="utf-8", newline="\n")

# Miuix label: no longer "three tiers"
p = WS / "main" / "compose-app" / "app" / "src" / "main" / "kotlin" / "com" / "aoki" / "magicroot" / "MiuixHost.kt"
t = p.read_text(encoding="utf-8")
t = t.replace('StatusPill("三档 Victim"', 'StatusPill("Victim 档位"')
p.write_text(t, encoding="utf-8", newline="\n")

# verify_apk: pin cred binary
p = WS / "tools" / "verify_apk.py"
t = p.read_text(encoding="utf-8")
if '("t64560_cred",' not in t:
    t = t.replace('    ("t64560_v36", None, "6.12 permissive writer"),\n' if '("t64560_v36"' in t else '    ("run.sh", None, "flavor-aware chain"),',
                  '    ("t64560_v36", None, "6.12 permissive writer"),\n    ("t64560_cred", "%s", "6.12 cred writer MAXVICTIM=32"),\n' % h[:16])
p.write_text(t, encoding="utf-8", newline="\n")

# docs tooling README
p = WS / "tools" / "README.md"
t = p.read_text(encoding="utf-8")
t = t.replace("`t64560_cred` (MAXVICTIM=24)", "`t64560_cred` (MAXVICTIM=32)")
p.write_text(t, encoding="utf-8", newline="\n")
print("patched source/UI/config")
