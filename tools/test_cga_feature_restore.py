#!/usr/bin/env python3
"""Static checks for the g264/gaaa KernelSU feature-restored CGA modules.

No payload is executed and no module is loaded.  Besides hashes, verify the
actual init/hook call sites so dormant upstream functions cannot be mistaken
for restored functionality.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "main/app/assets"
BIN_SRC = ROOT / "binary-sources/61157-g264"
BASE_SHA256 = "b44cc79de9196c65a0f2ffe1a6e5b23dff7713c68f8752c3fe861c627d78399a"
GAAA_SHA256 = "64ebb525f3f98c73a0cc648f27552b0e5792ee18aaf87c6b1fdade15a90bc377"
ENV = dict(os.environ, CGA_BASE_SHA256=BASE_SHA256, CGA_EXPECTED_ABS="226", CGA_EXPECTED_STUBS="221")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def disassemble(path: Path, symbol: str) -> str:
    proc = subprocess.run(
        ["llvm-objdump", "-dr", "--no-show-raw-insn", f"--disassemble-symbols={symbol}", str(path)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, timeout=60)
    require(proc.returncode == 0, f"objdump {symbol} failed: {proc.stdout}")
    return proc.stdout


def load_generator():
    os.environ.update(ENV)
    path = BIN_SRC / "rebase_cga_module.py"
    spec = importlib.util.spec_from_file_location("rebase_cga_feature_restore", path)
    require(spec is not None and spec.loader is not None, "cannot load CGA generator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> None:
    base = ASSETS / "g264/ksm-g264-base.ko"
    duplicate = ASSETS / "61157/g264/ksm-g264-base.ko"
    gaaa = ASSETS / "g264/ksm-gaaa-base.ko"
    require(sha256(base) == BASE_SHA256, "restored g264 base hash mismatch")
    require(sha256(duplicate) == BASE_SHA256, "61157 g264 duplicate is stale")
    require(sha256(gaaa) == GAAA_SHA256, "restored gaaa hash mismatch")
    require(b"vermagic=6.1.157-android14-11-g2646292297b1" in base.read_bytes(), "g264 vermagic")
    require(b"vermagic=6.1.157-android14-11-gaaa383620ebf" in gaaa.read_bytes(), "gaaa vermagic")

    doc = json.loads((BIN_SRC / "cga-feature-restore.json").read_text(encoding="utf-8"))
    require(doc["base_sha256"] == BASE_SHA256, "restore manifest base hash")
    require(set(doc["profiles"]) == {"gaaa"}, "restore manifest must only cover gaaa")
    profile = doc["profiles"]["gaaa"]
    require(profile["abs_count"] == 226 and profile["stub_count"] == 221, "restore counts")
    require(len(profile["symbols"]) == 226, "restore symbol map size")
    require("tracepoint_probe_register_prio" in profile["symbols"], "missing tracepoint registration")

    generator = load_generator()
    for path in (base, gaaa):
        data = path.read_bytes()
        elf = generator.Elf64(data)
        absolute = [symbol for symbol in elf.symbols()
                    if symbol.shndx == generator.SHN_ABS and symbol.value >= generator.KERNEL_START]
        by_name = {symbol.name: symbol for symbol in absolute}
        by_addr = {symbol.value: symbol.name for symbol in absolute}
        require(len(by_name) == 226, f"{path.name}: wrong absolute-symbol count")
        require(len(generator._stub_slots(data, elf, by_addr)) == 221,
                f"{path.name}: wrong live-stub count")
        require(b"L6a: syscall hooks SKIPPED" not in data, f"{path.name}: hooks still skipped")
        require(b"L6a: setuid/sucompat SKIPPED" not in data, f"{path.name}: sucompat still skipped")
        require(b"CGA-FEATURES: su_compat and kernel_umount registered" in data,
                f"{path.name}: restored registration log missing")

    init = disassemble(base, "kernelsu_init")
    require("ksu_selinux_hide_init" in init, "selinux_hide is not called by kernelsu_init")
    manager = disassemble(base, "ksu_syscall_hook_manager_init")
    for symbol in ("ksu_syscall_dispatcher_ready", "ksu_setuid_hook_init", "ksu_sucompat_init",
                   "__tracepoint_sys_enter"):
        require(symbol in manager, f"hook manager does not reference {symbol}")
    setresuid = disassemble(base, "setresuid_handler_pre")
    require("ksu_has_syscall_hook" in setresuid, "setresuid dispatcher duplicate guard missing")
    ready = disassemble(base, "ksu_syscall_dispatcher_ready")
    require("ksu_syscall_table" in ready and "ksu_dispatcher_nr" in ready,
            "dispatcher ready check is not implemented")

    runner = (ASSETS / "98260/run6157_full.sh").read_text(encoding="utf-8")
    require('ksm-g264-base.ko|ksm-gaaa-base.ko)' in runner, "restored runner profile gate")
    require('_expect_abs=226' in runner and '_expect_stubs=221' in runner, "restored runner counts")
    require('$_patch_abs" != "$_expect_abs' in runner, "runner does not enforce dynamic abs count")
    require('$_patch_stubs" != "$_expect_stubs' in runner, "runner does not enforce dynamic stubs")

    proc = subprocess.run(
        [sys.executable, "-I", str(BIN_SRC / "rebase_cga_module.py"), "verify",
         "--base", str(base), "--profiles", str(BIN_SRC / "cga-feature-restore.json"),
         "--output-root", str(ASSETS / "g264"), "--only", "gaaa"],
        cwd=ROOT, env=ENV, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=120, check=False)
    require(proc.returncode == 0 and "OK gaaa abs=226 stubs=221" in proc.stdout,
            f"gaaa deterministic verify failed:\n{proc.stdout}")
    print("PASS restored g264/gaaa: abs=226 stubs=221; selinux_hide/su_compat/kernel_umount call sites")
    print("PASS dispatcher readback, tracepoint registration, setresuid duplicate guard, gaaa rebase")


if __name__ == "__main__":
    main()
