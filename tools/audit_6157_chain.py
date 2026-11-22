#!/usr/bin/env python3
"""Static audit for every supported 6.1.x 98260 handoff.

Never executes a payload or loads a module.  Checks the successful-payload
rebase, per-build CGA vermagic, restored g7d M6 assets, asset registration and
the runner's fail-closed branch ordering.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "main/app/assets"
BIN_SRC = ROOT / "binary-sources/61157-g264"
MAIN = ROOT / "main/compose-app/app/src/main/java/com/aoki/magicroot/MainActivity.java"
HELPER = ROOT / "main/compose-app/app/src/main/java/com/aoki/magicroot/KernelLogHelper.java"
RUNNER = ASSETS / "98260/run6157_full.sh"
RUN = ASSETS / "run.sh"
KERNELS = {
    "g264": "6.1.157-android14-11-g2646292297b1",
    "gaaa": "6.1.157-android14-11-gaaa383620ebf",
    "g3306": "6.1.157-android14-11-g3306a328b7be",
    "g84": "6.1.157-android14-11-g84ffa64b710b",
    "g77f": "6.1.157-android14-11-g77f76e323a02",
    "g8d6": "6.1.157-android14-11-g8d63307071ad",
    "gce849": "6.1.99-android14-11-gce84935796c9",
    "g5859": "6.1.99-android14-11-g5859fbdbad8c",
    "g54d": "6.1.99-android14-11-g54d40b4fb287",
    "g40b1": "6.1.128-android14-11-g40b1fd119d9b",
    "ge9da": "6.1.99-android14-11-ge9da27488f45",
    "g8a496": "6.1.128-android14-11-g8a4968670f1c",
    "g2e1f": "6.1.128-android14-11-g2e1f0741dafb",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def elf_header(path: Path) -> tuple[int, int, int, bool]:
    data = path.read_bytes()
    phoff = int.from_bytes(data[32:40], "little")
    phentsize = int.from_bytes(data[54:56], "little")
    phnum = int.from_bytes(data[56:58], "little")
    interp = any(int.from_bytes(data[phoff + i * phentsize:
                                   phoff + i * phentsize + 4], "little") == 3
                 for i in range(phnum))
    return data[4], int.from_bytes(data[16:18], "little"), \
        int.from_bytes(data[18:20], "little"), interp


def main() -> int:
    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        print(("PASS " if ok else "FAIL ") + name + ((" " + detail) if detail and not ok else ""))
        if not ok:
            failures.append(name + ((": " + detail) if detail else ""))

    profiles_doc = json.loads((BIN_SRC / "success-profiles.json").read_text())
    profiles = profiles_doc["profiles"]
    check("profile set", sorted(profiles) == sorted(KERNELS), str(sorted(profiles)))
    check("g264 restored from successful APK",
          digest(ASSETS / "98260-g264/exploit-android-key-ptr")
          == "cc0b9693dcdba564585c39dfe3eb386860f1cede4251d0d7aca63d1e51762843")

    for name, kernel in KERNELS.items():
        profile = profiles[name]
        payload = ASSETS / profile["directory"] / "exploit-android-key-ptr"
        check(name + " payload exists", payload.is_file(), str(payload))
        if not payload.is_file():
            continue
        check(name + " payload hash", digest(payload) == profile["generated_sha256"])
        check(name + " payload executable", bool(payload.stat().st_mode & 0o111))
        check(name + " static Android ELF", elf_header(payload) == (2, 2, 183, False),
              str(elf_header(payload)))
        check(name + " blind reclaim string",
              b"PC98260_G264_BLIND_RECLAIM" in payload.read_bytes())
        if name in ("g77f", "gce849", "g40b1"):
            check(name + " BTF layout corrected",
                  profile["layout_corrected"] and profile["task_cred"] == 0x840
                  and profile["kitimer_size"] == 0x118)
        base = ASSETS / "g264" / {"g264": "ksm-g264-base.ko"}.get(
            name, "ksm-" + name + "-base.ko")
        check(name + " CGA base exists", base.is_file(), str(base))
        if base.is_file():
            magic = base.read_bytes()
            check(name + " CGA vermagic", ("vermagic=" + kernel).encode() in magic)

    rebase = BIN_SRC / "rebase_success_payload.py"
    proc = subprocess.run(
        [sys.executable, "-I", str(rebase), "verify",
         "--base", str(ASSETS / "98260-g264/exploit-android-key-ptr"),
         "--profiles", str(BIN_SRC / "success-profiles.json"),
         "--output-root", str(ASSETS)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=120, check=False)
    check("deterministic payload rebase", proc.returncode == 0 and
          proc.stdout.count("OK ") == len(KERNELS), proc.stdout[-1000:])

    integrity_tool = ROOT / "tools/gen_6157_integrity.py"
    proc = subprocess.run([sys.executable, "-I", str(integrity_tool), "--check"],
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=120, check=False)
    check("integrity manifest deterministic", proc.returncode == 0, proc.stdout)
    integrity_rows = {}
    for line in (ASSETS / "6157-integrity.tsv").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        pid, path, expected = line.split("\t")
        integrity_rows.setdefault(pid, []).append((path, expected))
        check("integrity hash " + pid + "/" + path,
              not path.startswith("/") and ".." not in path
              and digest(ASSETS / path) == expected)
    for name in KERNELS:
        rows = dict(integrity_rows.get(name, []))
        profile = profiles[name]
        expected_count = 14 if name == "g264" else 11
        check(name + " integrity coverage", len(rows) == expected_count
              and profile["directory"] + "/exploit-android-key-ptr" in rows
              and profile["directory"] + "/pc98260-su" in rows
              and "g264/ksm-" + name + "-base.ko" in rows
              and "g264/syms-" + name + ".txt" in rows
              and "g264/ko_slide_patch" in rows)
    check("g7d integrity covers M6",
          len(integrity_rows.get("6157", [])) == 23
          and "g264/syms-g7d.txt" in dict(integrity_rows.get("6157", [])))
    runner_text = RUNNER.read_text()
    check("integrity check precedes UAF",
          "if ! verify_6157_integrity; then" in runner_text
          and runner_text.index("if ! verify_6157_integrity; then")
          < runner_text.index("UAF_STARTED=1", runner_text.index("if ! verify_6157_integrity; then")))

    m6_doc = json.loads((BIN_SRC / "m6-provenance.json").read_text())
    m6_dir = ASSETS / "ksu6157-m6"
    check("M6 file count", len(m6_doc["files"]) == 19 and
          len([p for p in m6_dir.iterdir() if p.is_file()]) == 19)
    for name, meta in m6_doc["files"].items():
        p = m6_dir / name
        check("M6 " + name, p.is_file() and p.stat().st_size == meta["size"]
              and digest(p) == meta["sha256"])
    m6_ok = (m6_dir / "kernelsu-os9-selx11.ko").read_bytes()
    check("M6 OS9 module vermagic",
          b"vermagic=6.1.157-android14-11-g7d3922fade43" in m6_ok)
    check("M6 has no 43499 assets", not any("43499" in p.name for p in m6_dir.iterdir()))
    post_root = (m6_dir / "post_root.sh").read_text()
    check("M6 FIFO eval service disabled",
          "persistent FIFO root service disabled" in post_root
          and "mkfifo" not in post_root and 'eval "$CMD"' not in post_root)

    main_text = MAIN.read_text()
    helper_text = HELPER.read_text()
    runner = RUNNER.read_text()
    run_text = RUN.read_text()
    assets_block = main_text.split("private static final String[] ASSETS = {", 1)[1].split("};", 1)[0]
    for name, kernel in KERNELS.items():
        directory = "98260-" + name
        ko = "g264/ksm-" + name + "-base.ko"
        check(name + " payload registered in ASSETS",
              '"' + directory + '/exploit-android-key-ptr"' in assets_block)
        check(name + " su registered in ASSETS",
              '"' + directory + '/pc98260-su"' in assets_block)
        check(name + " target registered in ASSETS",
              '"' + directory + '/target.sh"' in assets_block)
        check(name + " CGA registered in ASSETS", '"' + ko + '"' in assets_block)
        check(name + " shared Java profile route",
              'new Profile6157("' + name + '", "' + kernel + '", "' + directory
              + '", "' + ko + '")' in helper_text)
        check(name + " runner payload branch",
              "P6157=" + name + " ;;" in runner)
        check(name + " top-level 6.1 branch", kernel + "*" in run_text)
    check("runner derives per-profile CGA base",
          'G264_BASE=$D/g264/ksm-$P6157-base.ko' in runner
          and 'G264_KO=$D/ksm-$P6157.ko' in runner)
    check("runner derives blind reclaim for every non-g7d 6.1 profile",
          'if [ "$K6157" = "1" ] && [ "$G7D" = "0" ]; then\n    G264_BLIND=1' in runner)
    check("MainActivity delegates 6.1 asset staging",
          'return KernelLogHelper.shouldStage6157Asset(name, release);' in main_text)
    check("MainActivity delegates payload routing",
          'return KernelLogHelper.payloadDirFor6157(release);' in main_text)
    check("MainActivity delegates CGA routing",
          'return KernelLogHelper.cgaBaseFor6157(release);' in main_text)
    for name in m6_doc["files"]:
        check("registered " + name, f'"ksu6157-m6/{name}"' in assets_block)
    check("M6 filter g7d-only",
          'if (name.startsWith("ksu6157-m6/")) return m6;' in helper_text)
    check("g264 ksu6157 files not staged to g7d",
          'if (name.startsWith("ksu6157-g264/")) return g264;' in helper_text)
    for critical in ("ksu6157-m6/ksu_loader.sh", "ksu6157-m6/kernelsu-os9-selx11.ko",
                     "payloadDirFor6157", "cgaBaseFor6157"):
        check("critical/helper " + critical, critical in main_text)

    run_sh = RUN.read_text()
    for script in (RUN, RUNNER):
        for shell in ("bash", "/system/bin/sh"):
            p = subprocess.run([shell, "-n", str(script)], text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=30, check=False)
            check(script.name + " syntax " + shell, p.returncode == 0, p.stdout)
    idx_m6 = runner.index("98260_KSU_BACKEND=m6")
    idx_cga = runner.index("98260_KSU_BACKEND=g264-cga")
    idx_fail = runner.index("6157_handoff_unavailable")
    idx_existing = runner.index("98260_EXISTING_ROOT=verified")
    existing_block = runner[runner.rindex("# Reuse an already working", 0, idx_existing):
                            runner.index("# If a previous UAF failed", idx_existing)]
    check("existing root is verified before UAF",
          idx_existing < runner.index("parked_check", idx_existing)
          < runner.index("UAF_STARTED=1", idx_existing)
          and "timeout -k 1 6" in existing_block
          and "uid=0" in existing_block)
    check("existing root probe is 6.1-only and cannot mislabel KSU or hang a pipe",
          'if [ "$K6157" = "1" ]; then' in existing_block
          and '98260_KSU=loaded already' not in existing_block
          and '> "$_er_out" 2>/dev/null' in existing_block
          and "2>/dev/null | grep -q 'uid=0'" not in existing_block)
    check("M6 branch precedes CGA", idx_m6 < idx_cga)
    check("CGA native handoff is bounded",
          'timeout "$_insmod_timeout" "$SU" -c "insmod $_ko $_insmod_args"' in runner
          and 'timeout 45 "$KSUD" debug su' in runner
          and 'timeout 10 "$SU" -c' in runner)
    check("CGA patched module structure is enforced",
          '$_patch_abs" != "$_expect_abs' in runner
          and '$_patch_stubs" != "$_expect_stubs' in runner
          and 'ksm-g264-base.ko|ksm-gaaa-base.ko)' in runner
          and '_expect_abs=226' in runner and '_expect_stubs=221' in runner
          and '98260_G264_PATCH_INVALID' in runner
          and '98260_G264_KO=$_ko size=' in runner and 'sha256=${_ko_sha:-?}' in runner)
    check("CGA opens only selected manager",
          '_mgr_pkg=${MAGICROOT_KSU_PKG:-}' in runner
          and 'next) _mgr_pkg=com.rifsxd.ksunext' in runner
          and 'kqvdie.zeykvw.hpbcyd' not in runner
          and 'com.bakasu.bakasu' not in runner)
    check("6.1 generic fallback is blocked", idx_fail > idx_cga)
    check("legacy loader is g264-only",
          'KSU_HANDOFF_LEGACY=1' in runner.split("KSU_HANDOFF_LEGACY=0", 1)[1][:240])
    check("6.1 success emits preflight marker",
          'CHAIN=98260 PROFILE_6157=upstream' in run_sh
          and "CHAIN_98260_PREFLIGHT_OK=1" in run_sh)
    branch_6157 = run_sh.split('CHAIN=98260 PROFILE_6157=upstream', 1)[1][:2200]
    finalize_98260 = run_sh.split('finalize_98260() {', 1)[-1][:1200]
    check("6.1 success runs SUSFS",
          "finalize_98260" in branch_6157 and "susfs_load" in finalize_98260)
    check("SUSFS switch exported", "export SUSFS_ENABLE" in run_sh)

    print(f"\nSUMMARY failures={len(failures)}")
    if failures:
        for item in failures:
            print(" - " + item)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
