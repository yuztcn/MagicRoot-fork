#!/usr/bin/env bash
# MagicRoot 一键静态门禁与单元测试套件
# 覆盖：Shell 语法 + LF 行尾 + 资产注册对账 + Java 纯逻辑单测 + 全链路回归审计
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== [1/7] Shell 语法与 LF 行尾检查 =="
sh_count=0
while IFS= read -r -d '' f; do
    sh_count=$((sh_count + 1))
    bash -n "$f"
    if [ -x /system/bin/sh ]; then
        /system/bin/sh -n "$f"
    fi
    if LC_ALL=C grep -q $'\r' "$f"; then
        echo "FAIL CRLF detected in $f" >&2
        exit 1
    fi
done < <(find main/app/assets -type f -name "*.sh" -print0)
echo "PASS $sh_count shell scripts syntax & LF clean"

echo "== [2/7] 资产注册表、磁盘文件与内核 Profile 表多端对账 =="
python3 -I - <<'PY'
import json, os, re, sys

src = open("main/compose-app/app/src/main/java/com/aoki/magicroot/MainActivity.java", encoding="utf-8").read()
helper = open("main/compose-app/app/src/main/java/com/aoki/magicroot/KernelLogHelper.java", encoding="utf-8").read()
run_sh = open("main/app/assets/run.sh", encoding="utf-8").read()
run6157 = open("main/app/assets/98260/run6157_full.sh", encoding="utf-8").read()
kprof_sh = open("main/app/assets/kernel_profiles.sh", encoding="utf-8").read()
table = json.load(open("tools/kernel_profiles.json", encoding="utf-8"))

m1 = re.search(r"ASSETS\s*=\s*\{(.*?)\};", src, re.S)
m2 = re.search(r"ASSETS_98260\s*=\s*\{(.*?)\};", src, re.S)
if not m1 or not m2:
    print("FAIL cannot parse ASSETS / ASSETS_98260 in MainActivity.java", file=sys.stderr)
    sys.exit(1)

reg = set()
for m in (m1, m2):
    reg |= set(s.strip('"') for s in re.findall(r'"([^"]+)"', m.group(1)))

disk = set()
for root, _, files in os.walk("main/app/assets"):
    for f in files:
        disk.add(os.path.relpath(os.path.join(root, f), "main/app/assets").replace("\\", "/"))

unreg = sorted(disk - reg)
missing = sorted(reg - disk)
if unreg or missing:
    for p in unreg:
        print(f"FAIL unregistered asset on disk: {p}", file=sys.stderr)
    for p in missing:
        print(f"FAIL registered asset missing on disk: {p}", file=sys.stderr)
    sys.exit(1)

# Verify tools/kernel_profiles.json against Java and shell dispatch
for p in table["profiles_61x"]:
    pid = p["id"]
    rel = p["release_prefix"]
    pdir = p["payload_dir"]
    cga = p["cga_base"]
    if pid != "g19a":
        if f'"{rel}"' not in helper or f'"{pdir}"' not in helper:
            print(f"FAIL 6.1 profile {pid} missing from KernelLogHelper.java", file=sys.stderr)
            sys.exit(1)
        if f"{rel}*" not in run_sh or f"{rel}" not in run6157:
            print(f"FAIL 6.1 profile {pid} missing from run.sh / run6157_full.sh", file=sys.stderr)
            sys.exit(1)
    if cga and cga not in reg:
        print(f"FAIL 6.1 profile {pid} CGA base {cga} not registered in ASSETS", file=sys.stderr)
        sys.exit(1)

for p in table["profiles_98260"]:
    pid = p["id"]
    pdir = p["dir"]
    rel = p["release_prefix"]
    if f'"{pdir}"' not in helper or f'"{rel}"' not in helper:
        print(f"FAIL 98260 profile {pid} ({pdir}) missing from KernelLogHelper.java", file=sys.stderr)
        sys.exit(1)
    if pid != "61821h1c" and rel not in kprof_sh:
        print(f"FAIL 98260 profile {pid} ({rel}) missing from kernel_profiles.sh", file=sys.stderr)
        sys.exit(1)

if "r612 && KernelLogHelper.is6157OnlyAsset(name)" not in src:
    print("FAIL 6.12 deployment does not exclude 6.1-only assets", file=sys.stderr)
    sys.exit(1)
if "pruneUnused6157AssetsOn612(legacyRelease)" not in src:
    print("FAIL 6.12 stale 6.1 asset cleanup is not wired into staging", file=sys.stderr)
    sys.exit(1)

import hashlib
manifest_entries = 0
for rel in sorted(disk):
    if not rel.endswith("/SHA256SUMS.txt"):
        continue
    manifest_path = os.path.join("main/app/assets", rel)
    for line_no, line in enumerate(open(manifest_path, encoding="utf-8"), 1):
        parts = line.split()
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            continue
        target_rel = os.path.normpath(os.path.join(os.path.dirname(rel), parts[1])).replace("\\", "/")
        target_path = os.path.join("main/app/assets", target_rel)
        if target_rel not in disk:
            print(f"FAIL manifest {rel}:{line_no} missing target {target_rel}", file=sys.stderr)
            sys.exit(1)
        actual_sha = hashlib.sha256(open(target_path, "rb").read()).hexdigest()
        if actual_sha != parts[0].lower():
            print(f"FAIL manifest {rel}:{line_no} hash mismatch for {target_rel}", file=sys.stderr)
            sys.exit(1)
        manifest_entries += 1
print(f"PASS per-profile SHA256SUMS ({manifest_entries} entries)")

dedup_doc = json.load(open("tools/asset_dedup_map.json", encoding="utf-8"))["duplicates"]
for dup, meta in dedup_doc.items():
    canon = meta["canonical"]
    sha = meta["sha256"]
    dup_path = os.path.join("main/app/assets", dup)
    canon_path = os.path.join("main/app/assets", canon)
    if not os.path.isfile(dup_path) or not os.path.isfile(canon_path):
        print(f"FAIL dedup file missing: {dup} or {canon}", file=sys.stderr)
        sys.exit(1)
    h1 = hashlib.sha256(open(dup_path, "rb").read()).hexdigest()
    h2 = hashlib.sha256(open(canon_path, "rb").read()).hexdigest()
    if h1 != sha or h2 != sha:
        print(f"FAIL dedup hash mismatch for {dup} -> {canon}", file=sys.stderr)
        sys.exit(1)
    if f'm.put("{dup}", "{canon}");' not in helper:
        print(f"FAIL dedup mapping {dup} -> {canon} missing from KernelLogHelper.java", file=sys.stderr)
        sys.exit(1)

print(f"PASS asset registry parity ({len(disk)} files = {len(reg)} registered) + {len(table['profiles_61x']) + len(table['profiles_98260'])} kernel profiles + {len(dedup_doc)} dedup mappings synced")

import zipfile
apk_path = os.environ.get("MAGICROOT_APK", "main/app/MagicRoot.apk")
if os.path.isfile(apk_path):
    with zipfile.ZipFile(apk_path) as apk:
        apk_names = set(apk.namelist())
        for rel in sorted(disk):
            disk_sha = hashlib.sha256(open(os.path.join("main/app/assets", rel), "rb").read()).hexdigest()
            entry = "assets/" + rel
            if entry not in apk_names:
                if rel not in dedup_doc:
                    print(f"FAIL asset {rel} missing from APK and not in dedup map", file=sys.stderr)
                    sys.exit(1)
                entry = "assets/" + dedup_doc[rel]["canonical"]
            apk_sha = hashlib.sha256(apk.read(entry)).hexdigest()
            if disk_sha != apk_sha:
                print(f"FAIL APK asset sha mismatch for {rel} via {entry}", file=sys.stderr)
                sys.exit(1)
    print(f"PASS MagicRoot.apk bit-for-bit asset equivalence ({len(disk)} assets verified)")
PY

echo "== [3/7] Java 纯逻辑单元测试 + g142 KASLR 合成捕获回归 =="
python3 -I - <<'PY'
import subprocess, sys, tempfile
from pathlib import Path

java_dir = Path("main/compose-app/app/src/main/java/com/aoki/magicroot")
test_dir = Path("tools/tests")
sources = [
    str(java_dir / "RunProgress.java"),
    str(java_dir / "KernelLogHelper.java"),
    str(java_dir / "SukisuLateLoadPatch.java"),
    str(java_dir / "LiveLogStore.java"),
    str(test_dir / "RunProgressTest.java"),
    str(test_dir / "KernelLogHelperTest.java"),
    str(test_dir / "SukisuLateLoadPatchTest.java"),
    str(test_dir / "LiveLogStoreTest.java"),
]
with tempfile.TemporaryDirectory(prefix="magicroot-javatest-") as td:
    cp = subprocess.run(["javac", "-encoding", "UTF-8", "-d", td, *sources],
                        text=True, capture_output=True)
    if cp.returncode != 0:
        print(cp.stdout + cp.stderr, file=sys.stderr)
        sys.exit(1)
    for cls in ("com.aoki.magicroot.RunProgressTest", "com.aoki.magicroot.KernelLogHelperTest",
                "com.aoki.magicroot.SukisuLateLoadPatchTest", "com.aoki.magicroot.LiveLogStoreTest"):
        run = subprocess.run(["java", "-cp", td, cls], text=True, capture_output=True)
        print(run.stdout.rstrip())
        if run.returncode != 0:
            print(run.stderr, file=sys.stderr)
            sys.exit(1)
PY
python3 -I tools/test_kaslr_g142.py

echo "== [4/7] Kernel Flavor 符号与模板矩阵审计 =="
bash tools/audit_kernel_flavors.sh >/dev/null
echo "PASS audit_kernel_flavors.sh"

echo "== [5/7] 6.1.x 98260 链路与新增 6.1.x profile 适配回归测试 =="
python3 -I tools/gen_6157_integrity.py --check >/dev/null
echo "PASS gen_6157_integrity.py"
python3 -I tools/gen_6157_syms_from_cga.py --check >/dev/null
echo "PASS gen_6157_syms_from_cga.py"
python3 -I tools/audit_6157_chain.py >/dev/null
echo "PASS audit_6157_chain.py"
python3 -I tools/test_61128_adaptation.py all
python3 -I tools/test_cga_feature_restore.py

echo "== [6/7] 98260 生命周期、收尾状态机与 H1C 引擎回归测试 =="
python3 -I tools/test_98260_uaf_lifecycle.py
python3 -I tools/test_init_cred_patch.py
python3 -I tools/test_runtime_syms.py
python3 -I tools/sync_manager_symbols.py --check
python3 -I tools/test_98260_finalize.py >/dev/null
echo "PASS test_98260_finalize.py"
python3 -I tools/test_h1c_flow.py 2>&1 | tail -n 3

echo "== [7/7] 清理结果与 Termux su_entry 回归测试 =="
python3 -I tools/test_cleanup_contract.py >/dev/null
echo "PASS test_cleanup_contract.py"
python3 -I tools/test_termux_su_entry.py >/dev/null
echo "PASS test_termux_su_entry.py"

echo "ALL CHECKS PASSED"
