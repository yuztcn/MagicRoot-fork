#!/usr/bin/env python3
"""Offline audit for MagicRoot 1.0.4 optional-98260 + KSU flavor matrix.

Checks (no device write):
  * flavor list sync UI <-> shell
  * per-flavor LKM template + syms for 61258 and 6138
  * syms key symbols match the two kernel ELFs (addresses embedded in files)
  * 98260 per-kernel target metadata / build marker / manifest hashes
  * feature env vars passed by Compose exist in shell
  * legacy fallback option coverage warnings
"""
import hashlib
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = ROOT
ASSETS = os.path.join(APP, "main", "app", "assets")
UI = os.path.join(APP, "main", "compose-app", "app", "src", "main", "kotlin", "com", "aoki", "magicroot", "UiState.kt")
LEGACY = os.path.join(APP, "main", "app", "src", "com", "aoki", "magicroot", "MainActivity.java")
COMPOSE = os.path.join(APP, "main", "compose-app", "app", "src", "main", "java", "com", "aoki", "magicroot", "MainActivity.java")
KP = os.path.join(ASSETS, "kernel_profiles.sh")
RUN = os.path.join(ASSETS, "run.sh")
RUN60 = os.path.join(ASSETS, "98260", "run98260.sh")

FAILS = []
WARNS = []
PASS_COUNT = [0]


def check(ok, msg):
    if ok: PASS_COUNT[0] += 1
    print(("PASS  " if ok else "FAIL  ") + msg)
    if not ok:
        FAILS.append(msg)


def warn(ok, msg):
    if not ok:
        print("WARN  " + msg)
        WARNS.append(msg)


def read(path):
    return open(path, "r", encoding="utf-8", errors="replace").read()


kp = read(KP)
ui = read(UI)
legacy = read(LEGACY)
compose = read(COMPOSE)
run = read(RUN)
run60 = read(RUN60)

# --- 1. flavor list sync ---------------------------------------------------
shell_list = re.search(r'KSU_FLAVORS="([^"]+)"', kp)
check(bool(shell_list), "kernel_profiles.sh defines KSU_FLAVORS")
shell_flavors = shell_list.group(1).split()
ui_list = re.search(r'KSU_FLAVOR_ORDER\s*=\s*listOf\(([^)]*)\)', ui)
check(bool(ui_list), "UiState.kt defines KSU_FLAVOR_ORDER")
ui_flavors = re.findall(r'"([a-z]+)"', ui_list.group(1)) if ui_list else []
check(set(shell_flavors) == set(ui_flavors) and len(shell_flavors) == 6,
      "UI/shell flavor sets match: %s vs %s" % (ui_flavors, shell_flavors))

expected_pkgs = {
    "kernelsu": "me.weishu.kernelsu",
    "resukisu": "com.resukisu.resukisu",
    "next": "com.rifsxd.ksunext",
    "sukisu": "com.sukisu.ultra",
    "fina": "me.yuki.fina",
    "nova": "com.sukisu.nova",
}
for f, pkg in expected_pkgs.items():
    check(pkg in kp and pkg in ui and pkg in compose,
          "flavor %-8s manager package %s present in shell+UI" % (f, pkg))

check("ksu_flavor_ksud()" in kp, "kernel_profiles.sh has ksu_flavor_ksud()")

# --- 2. per-profile LKM/syms matrix ---------------------------------------
templates = {
    "resukisu": "ksu-template-bakasu.ko",
    "kernelsu": "ksu-template.ko",
    "next": "ksu-template-next.ko",
    "sukisu": "ksu-template-sukisu.ko",
    "fina": "ksu-template-fina.ko",
    # SukiSU Nova loads the LKM extracted from the manager APK; the generic
    # official template is only a routing placeholder for the static audit.
    "nova": "ksu-template.ko",
}
syms_suffix = {
    "resukisu": "_bakasu",
    "kernelsu": "",
    "next": "_next",
    "sukisu": "_sukisu",
    "fina": "_fina",
    "nova": "_nova",
}
for profile in ("61258", "6138"):
    for f in shell_flavors:
        ko = os.path.join(ASSETS, templates[f])
        sym = os.path.join(ASSETS, "syms_%s%s.txt" % (profile, syms_suffix[f]))
        check(os.path.isfile(ko) and os.path.getsize(ko) > 100000,
              "%s %-8s LKM template exists (%s)" % (profile, f, os.path.basename(ko)))
        check(os.path.isfile(sym) and os.path.getsize(sym) > 1000,
              "%s %-8s syms exists (%s)" % (profile, f, os.path.basename(sym)))

# --- 3. key symbol addresses ----------------------------------------------
expected_syms = {
    "61258": {
        "prepare_creds": "0xffffffc08019c448",
        "init_task": "0xffffffc08255dac0",
        "selinux_state": "0xffffffc0827e7a60",
    },
    "6138": {
        "prepare_creds": "0xffffffc080b8a21c",
        "init_task": "0xffffffc0823ecf00",
        "selinux_state": "0xffffffc0826663c8",
    },
}
for profile in ("61258", "6138"):
    for f in shell_flavors:
        sym = os.path.join(ASSETS, "syms_%s%s.txt" % (profile, syms_suffix[f]))
        data = read(sym)
        for name, addr in expected_syms[profile].items():
            m = re.search(r'^%s\s+(\S+)' % re.escape(name), data, re.M)
            check(bool(m and m.group(1).lower() == addr.lower()),
                  "%s %-8s %s == %s" % (profile, f, name, addr))

# --- 4. 98260 target metadata / build marker ------------------------------
target_meta = {
    "61258": {
        "dir": os.path.join(ASSETS, "98260"),
        "kernel": "6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k",
        "marker": b"6.12.58-android16-6",
    },
    "6138": {
        "dir": os.path.join(ASSETS, "98260-6138"),
        "kernel": "6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k",
        "marker": b"6.12.38-android16-5",
    },
}
for profile, m in target_meta.items():
    tgt = os.path.join(m["dir"], "target.sh")
    data = read(tgt)
    check(m["kernel"] in data, "%s target.sh kernel matches" % profile)
    check(m["marker"].decode() in data,
          "%s target.sh carries build marker" % profile)
    other = b"6.12.38-android16-5" if profile == "61258" else b"6.12.58-android16-6"
    check(other.decode() not in data,
          "%s target.sh does not carry wrong kernel marker" % profile)
    sums = read(os.path.join(m["dir"], "SHA256SUMS.txt")).splitlines()
    ok = True
    for line in sums:
        h, name = line.split()[:2]
        p = os.path.join(m["dir"], name)
        if not (os.path.isfile(p) and hashlib.sha256(open(p, "rb").read()).hexdigest() == h):
            ok = False
            break
    check(ok, "%s 98260 SHA256SUMS matches all assets" % profile)

check("6.12.58-android16-6" in run60 and "6.12.38-android16-5" in run60,
      "run98260.sh selects both 61258 and 6138 kernels")
check("target_kernel_mismatch" in run60, "run98260.sh fail-closes on target/kernel mismatch")
check('MAGICROOT_ENABLE_98260' in run and 'MAGICROOT_98260_PREFLIGHT' in run,
      "run.sh gates 98260 via opt-in + preflight")

# --- 5. option env coverage ------------------------------------------------
opts = [
    "MAGICROOT_SU_COMPAT", "MAGICROOT_SU_ENTRY",
    "MAGICROOT_ALLOW_SHELL", "MAGICROOT_ADB_ROOT", "MAGICROOT_KERNEL_UMOUNT",
    "MAGICROOT_SELINUX_HIDE", "MAGICROOT_REPAIR",
    "MAGICROOT_KSU_FLAVOR", "MAGICROOT_CHAIN", "MAGICROOT_ENABLE_98260",
    "MAGICROOT_98260_PREFLIGHT", "MAGICROOT_98260_KSU",
    "MAGICROOT_98260_CRED_MODE",
    "MAGICROOT_98260_ATTEMPTS", "MAGICROOT_98260_CHURN_ROUNDS",
    "MAGICROOT_98260_CHURN_PER_CPU", "MAGICROOT_98260_WAIT_CAP",
    "MAGICROOT_98260_CUSTOM_KO",
]
shell_all = "\n".join(read(os.path.join(ASSETS, n)) for n in os.listdir(ASSETS)
                      if n.endswith(".sh")) + read(os.path.join(ASSETS, "98260", "run98260.sh"))
for opt in opts:
    check(opt in compose, "Compose passes %s" % opt)
    check(opt in shell_all, "shell consumes/handles %s" % opt)

legacy_opts = [o for o in opts if o in legacy]
missing_legacy = [o for o in opts if o not in legacy]
warn(not missing_legacy,
     "legacy fallback does not pass: %s (Compose is the shipped UI)" % ", ".join(missing_legacy))

# 98260 must not require KSU flavor/syms: run.sh returns in chain block before
# the 64560 KSU selection path.
chain_pos = run.find('CHAIN=${MAGICROOT_CHAIN:-64560}')
ksu_pos = run.find('KSU_FLAVOR=$(ksu_flavor_normalize')
check(0 <= chain_pos < ksu_pos,
      "98260 chain dispatch precedes 64560 KSU/flavor deployment (chain isolated)")

# --- 6. manager packages (optional, from device if adb present) -----------
adb = os.environ.get("ADB", "adb")
if os.path.isfile(adb):
    import subprocess
    try:
        out = subprocess.check_output([adb, "-s", "SERIAL", "shell", "pm list packages"],
                                      stderr=subprocess.DEVNULL, timeout=20).decode("utf-8", "replace")
        installed = set(re.findall(r'package:(\S+)', out))
        for f, pkg in expected_pkgs.items():
            print(("PASS  " if pkg in installed else "WARN  ") +
                  "flavor %-8s manager %s installed=%s" % (f, pkg, pkg in installed))
            if pkg not in installed:
                WARNS.append("manager not installed: %s (%s)" % (f, pkg))
    except Exception as e:
        print("WARN  manager package probe skipped:", e)
else:
    print("WARN  adb not found; manager-installed check skipped")


# --- 7. staged asset list must cover every flavor for both kernels -------
compose_src = read(COMPOSE)
assets_block = compose_src[compose_src.find("private static final String[] ASSETS = {"):
                          compose_src.find("};", compose_src.find("private static final String[] ASSETS = {"))]
required_base = ["ko_patch", "kernel_profiles.sh", "ksu_grant"]
for f in shell_flavors:
    required_base.append(templates[f])
    for profile in ("61258", "6138"):
        required_base.append("syms_%s%s.txt" % (profile, syms_suffix[f]))
for name in required_base:
    check(name in assets_block, "Compose ASSETS stages %s" % name)
check('"syms_6138_next.txt"' in assets_block and
      '"syms_6138_sukisu.txt"' in assets_block and
      '"syms_6138_fina.txt"' in assets_block,
      "Compose ASSETS stages full 6138 flavor syms set")

# --- 8. 98260 auto-KernelSU wiring -----------------------------------------
run60 = read(os.path.join(ASSETS, "98260", "run98260.sh"))
check('MAGICROOT_98260_KSU' in run60, "run98260.sh reads MAGICROOT_98260_KSU")
check('MAGICROOT_98260_KSU:-1' in run60, "98260 auto-KernelSU defaults ON")
check('insmod' in run60 and 'late-load' in run60,
      "98260 auto-KernelSU has insmod + ksud late-load path")
check('ksu_select_ko' in run60 and 'ko_patch' in run60,
      "98260 auto-KernelSU uses selected flavor KO template/syms")
ui_state = read(os.path.join(APP, "main", "compose-app", "app", "src", "main",
                             "kotlin", "com", "aoki", "magicroot", "UiState.kt"))
host = read(os.path.join(APP, "main", "compose-app", "app", "src", "main",
                         "kotlin", "com", "aoki", "magicroot", "MiuixHost.kt"))
check('chain98260Ksu' in ui_state and 'update98260Ksu' in ui_state,
      "98260 auto-KSU UI state exists")
check('自动加载 KernelSU' in host and 'update98260Ksu' in host,
      "98260 auto-KSU debug toggle exists")
check('MAGICROOT_98260_KSU' in compose_src, "Compose passes auto-KSU env")
check('MAGICROOT_98260_KSU' in legacy, "legacy passes auto-KSU env")

print("\nSUMMARY pass=%d warn=%d fail=%d" %
      (PASS_COUNT[0], len(WARNS), len(FAILS)))
if WARNS:
    print("WARNINGS:")
    for w in WARNS:
        print("  - " + w)
if FAILS:
    print("FAILURES:")
    for f in FAILS:
        print("  - " + f)
    sys.exit(1)
print("AUDIT_RESULT=PASS_WITH_WARNINGS" if WARNS else "AUDIT_RESULT=PASS")
