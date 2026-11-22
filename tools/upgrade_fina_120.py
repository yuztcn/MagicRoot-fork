from pathlib import Path
import hashlib
import zipfile

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
BUNDLE = Path(r"<LOCAL_USER>user\Downloads\FinaSU_v1.2.0_kernel-bundle.zip")
TMP = WS / ".probe" / "fina120"
TMP.mkdir(parents=True, exist_ok=True)
ASSET = WS / "main" / "app" / "assets" / "ksu-template-fina.ko"

with zipfile.ZipFile(BUNDLE) as z:
    new = z.read("arm64/android16-6.12_kernelsu.ko")
old = ASSET.read_bytes()
(TMP / "old-ksu-template-fina.ko").write_bytes(old)
ASSET.write_bytes(new)
print("template old", len(old), hashlib.sha256(old).hexdigest())
print("template new", len(new), hashlib.sha256(new).hexdigest())

# kernel_profiles: version table + comment
p = WS / "main" / "app" / "assets" / "kernel_profiles.sh"
t = p.read_text(encoding="utf-8")
t = t.replace("#        fina     = FinaSU 1.0.10           kernel 33034 / uapi 6",
              "#        fina     = FinaSU 1.2.0             kernel 33071 / uapi 6")
t = t.replace("        fina)     echo \"33034\" ;;", "        fina)     echo \"33071\" ;;")
p.write_text(t, encoding="utf-8", newline="\n")
print("kernel_profiles updated")

# root_stage fallback expectation
p = WS / "main" / "app" / "assets" / "root_stage.sh"
t = p.read_text(encoding="utf-8")
t = t.replace("        EXPECT_KVER=33034; EXPECT_UAPI=6 ;;",
              "        EXPECT_KVER=33071; EXPECT_UAPI=6 ;;")
p.write_text(t, encoding="utf-8", newline="\n")
print("root_stage expectation updated")

# verify_apk: description + new template hash pin
p = WS / "tools" / "verify_apk.py"
t = p.read_text(encoding="utf-8")
t = t.replace('("ksu-template-fina.ko", None, "FinaSU 1.0.10 native 6.12 LKM (MultiSU bundle)")',
              '("ksu-template-fina.ko", "31fdd7b03de9524d", "FinaSU 1.2.0 native 6.12 LKM (MultiSU bundle)")')
p.write_text(t, encoding="utf-8", newline="\n")
print("verify_apk updated")

# DEVICE-VERIFY: current asset table + fina note
p = WS / "docs" / "DEVICE-VERIFY.md"
t = p.read_text(encoding="utf-8")
t = t.replace("| fina | `ksu-template-fina.ko`（FinaSU 1.0.10 bundle 590848 B） | 33034 | `syms_61258_fina.txt` | 尚未生成 → fail-closed |",
              "| fina | `ksu-template-fina.ko`（FinaSU 1.2.0 bundle 590848 B） | 33071 | `syms_61258_fina.txt` | `syms_6138_fina.txt` |")
t = t.replace("- FinaSU 同步升级到 v1.0.10（33034），`ksud_fina` 取自该 APK 的 `libksud.so`\n  （`ksud 1.0.10 (uapi: 6)`）。",
              "- FinaSU 升级到 v1.2.0（33071），`ksud` 取自已安装管理器的 `libksud.so`\n  （`ksud 1.2.0 (uapi: 6)`）；内置 6.12 模板同步替换为 1.2.0 版本。")
p.write_text(t, encoding="utf-8", newline="\n")
print("DEVICE-VERIFY updated")
