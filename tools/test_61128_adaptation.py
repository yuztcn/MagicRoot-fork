#!/usr/bin/env python3
"""Static regression tests for the added 6.1.128 and 6.1.157 profiles.

These tests parse and rebuild assets; they never execute a payload or load a
kernel module.  Expected constants are hand-derived from the supplied boots.
"""
from __future__ import annotations

import copy
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
BASE_PAYLOAD_SHA256 = "cc0b9693dcdba564585c39dfe3eb386860f1cede4251d0d7aca63d1e51762843"
BASE_CGA_SHA256 = "6381ad16a904af8d7d2a702e04994ed22c3fd01c6e00229ec584634034a56c09"
OLD_PROFILES = {"g264", "g3306", "g84", "g77f", "gce849", "g5859", "g54d", "g40b1", "ge9da"}
COMMON = {
    "task_cred": 0x838,
    "real_cred": 0x830,
    "kitimer_size": 0x108,
    "selinux_minus7": 0xFFFFFFC00A6DA9E9,
    "sig_enforce": 0xFFFFFFC00A43DBA0,
    "user_ns": 0xFFFFFFC00A0B0708,
    "root_user": 0xFFFFFFC00A0B0998,
    "groups": 0xFFFFFFC00A0B1CB8,
    "ucounts": 0xFFFFFFC00A0B2228,
}
EXPECTED = {
    "g8a496": {
        **COMMON,
        "kernel": "6.1.128-android14-11-g8a4968670f1c",
        "timer_link": 0xFFFFFFC008380E70,
        "cred_link": 0xFFFFFFC008095FFC,
    },
    "g2e1f": {
        **COMMON,
        "kernel": "6.1.128-android14-11-g2e1f0741dafb",
        "timer_link": 0xFFFFFFC008381078,
        "cred_link": 0xFFFFFFC008095C98,
    },
    "gaaa": {
        "task_cred": 0x838,
        "real_cred": 0x830,
        "kitimer_size": 0x108,
        "kernel": "6.1.157-android14-11-gaaa383620ebf",
        "timer_link": 0xFFFFFFC0083C0A00,
        "cred_link": 0xFFFFFFC00808DE68,
        "selinux_minus7": 0xFFFFFFC00A6FDE39,
        "sig_enforce": 0xFFFFFFC00A45DC60,
        "user_ns": 0xFFFFFFC00A0D0748,
        "root_user": 0xFFFFFFC00A0D09D8,
        "groups": 0xFFFFFFC00A0D1CF8,
        "ucounts": 0xFFFFFFC00A0D2268,
    },
    "g8d6": {
        "task_cred": 0x840,
        "real_cred": 0x838,
        "kitimer_size": 0x118,
        "kernel": "6.1.157-android14-11-g8d63307071ad",
        "timer_link": 0xFFFFFFC0084A8D90,
        "cred_link": 0xFFFFFFC00804B790,
        "selinux_minus7": 0xFFFFFFC00A84B3A1,
        "sig_enforce": 0xFFFFFFC00A5A01A0,
        "user_ns": 0xFFFFFFC00A212910,
        "root_user": 0xFFFFFFC00A212BA0,
        "groups": 0xFFFFFFC00A213EC0,
        "ucounts": 0xFFFFFFC00A214430,
    },
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def load_json(path: Path) -> dict:
    require(path.is_file(), f"missing {path.relative_to(ROOT)}")
    return json.loads(path.read_text(encoding="utf-8"))


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=120, check=False)


def test_payload() -> None:
    doc = load_json(BIN_SRC / "success-profiles.json")
    profiles = doc["profiles"]
    for name in EXPECTED:
        require(name in profiles, f"missing profile {name}")
    require(OLD_PROFILES.issubset(profiles), "an old profile was removed")
    require(sha256(ASSETS / "98260-g264/exploit-android-key-ptr") == BASE_PAYLOAD_SHA256,
            "g264 successful payload changed")

    hashes = set()
    for name, expected in EXPECTED.items():
        profile = profiles[name]
        require(profile["directory"] == f"98260-{name}", f"{name}: wrong directory")
        for key in ("task_cred", "real_cred", "kitimer_size", "timer_link", "cred_link",
                    "selinux_minus7", "sig_enforce", "user_ns", "root_user", "groups", "ucounts"):
            require(profile.get(key) == expected[key],
                    f"{name}: {key}=0x{profile.get(key, 0):x}, expected 0x{expected[key]:x}")
        require(profile["neg_timer_link"] == (1 << 64) - expected["timer_link"],
                f"{name}: wrong negative timer link")
        payload = ASSETS / profile["directory"] / "exploit-android-key-ptr"
        require(payload.is_file(), f"{name}: payload missing")
        data = payload.read_bytes()
        require(data[:5] == b"\x7fELF\x02" and data[18:20] == b"\xb7\x00",
                f"{name}: not an AArch64 ELF64 payload")
        require(os.access(payload, os.X_OK), f"{name}: payload is not executable")
        require(b"PC98260_G264_BLIND_RECLAIM" in data, f"{name}: blind reclaim marker missing")
        require(sha256(payload) == profile["generated_sha256"], f"{name}: stale payload hash")
        hashes.add(profile["generated_sha256"])
        su = payload.parent / "pc98260-su"
        require(su.is_file() and os.access(su, os.X_OK), f"{name}: su client missing/not executable")
        require(sha256(su) == sha256(ASSETS / "98260-g264/pc98260-su"),
                f"{name}: unexpected su client")
        target = (payload.parent / "target.sh").read_text(encoding="utf-8")
        require(f'CHAIN_98260_KERNEL="{expected["kernel"]}"' in target,
                f"{name}: target does not pin the exact kernel")
        require('CHAIN_98260_MODELS=""' in target, f"{name}: model gate was added")
    require(len(hashes) == len(EXPECTED), "new payloads must not share one binary")

    proc = run([sys.executable, "-I", str(BIN_SRC / "rebase_success_payload.py"), "verify",
                "--base", str(ASSETS / "98260-g264/exploit-android-key-ptr"),
                "--profiles", str(BIN_SRC / "success-profiles.json"),
                "--output-root", str(ASSETS)])
    require(proc.returncode == 0, f"deterministic payload verify failed:\n{proc.stdout}")
    require(proc.stdout.count("OK ") == len(profiles) == 13,
            f"expected 13 verified profiles:\n{proc.stdout}")
    print("PASS payload profiles=13 old=9 new=4")


def expect_value_error(label: str, function, *args) -> None:
    try:
        function(*args)
    except ValueError:
        return
    raise AssertionError(f"{label}: expected ValueError")


def load_cga_generator():
    path = BIN_SRC / "rebase_cga_module.py"
    require(path.is_file(), f"missing {path.relative_to(ROOT)}")
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("rebase_cga_module", path)
    require(spec is not None and spec.loader is not None, "cannot load CGA generator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_cga() -> None:
    # The feature-restored g264/gaaa base intentionally has 226/221 entries.
    # The original 225/220 base was an audit-only precompiled copy and is no
    # longer stored in the public tree; the hash check stays optional for
    # local audit copies.  The runtime base is covered by
    # test_cga_feature_restore.py.
    base_path = BIN_SRC / "legacy-cga/ksm-g264-base.ko"
    if base_path.exists():
        require(sha256(base_path) == BASE_CGA_SHA256, "legacy g264 CGA base changed")
    doc = load_json(BIN_SRC / "cga-profiles.json")
    profiles = doc["profiles"]
    require(set(profiles) == set(EXPECTED), "CGA profile set is wrong")

    for name in ("g8a496", "g2e1f", "g8d6"):
        expected = EXPECTED[name]
        profile = profiles[name]
        require(profile["kernel"] == expected["kernel"], f"{name}: wrong CGA kernel")
        require(profile["boot_sha256"] == {
            "g8a496": "bebc28d515c2bdb2a11acba609dc3efee33e49730596e8e96d80c228fdbeb3a8",
            "g2e1f": "d5a085ec75f6864ddc9f9de4659959b02fed33b26ab1e7634cb673f4771bdba6",
            "g8d6": "b234993bcc2e0284184f8296f6965231934709d23fa3da29ac21868d0ad459f4",
        }[name], f"{name}: wrong boot hash")
        require(profile["output"] == f"ksm-{name}-base.ko", f"{name}: wrong output name")
        require(len(profile["symbols"]) == 225, f"{name}: expected 225 symbols")
        output = ASSETS / "g264" / profile["output"]
        require(output.is_file(), f"{name}: CGA output missing")
        require(sha256(output) == profile["generated_sha256"], f"{name}: stale CGA hash")
        require(("vermagic=" + expected["kernel"]).encode() in output.read_bytes(),
                f"{name}: wrong vermagic")
        if base_path.exists():
            proc = run([sys.executable, "-I", str(BIN_SRC / "rebase_cga_module.py"), "verify",
                        "--base", str(base_path), "--profiles",
                        str(BIN_SRC / "cga-profiles.json"), "--output-root", str(ASSETS / "g264"),
                        "--only", name])
            require(proc.returncode == 0 and proc.stdout.count("OK ") == 1,
                    f"{name}: CGA deterministic verify failed:\n{proc.stdout}")

    if base_path.exists():
        module = load_cga_generator()
        base = base_path.read_bytes()
        broken = copy.deepcopy(profiles["g8a496"])
        del broken["symbols"]["_printk"]
        expect_value_error("missing _printk", module.rebase_module, base, broken)

        old_by_addr = {0xFFFFFFC008002000: "real_symbol"}
        expect_value_error("unknown stub", module.resolve_stub,
                           0xFFFFFFC008999000, old_by_addr, {"real_symbol": 0xFFFFFFC008003000})
        require(module.resolve_stub(0xFFFFFFC008002000, old_by_addr,
                                    {"real_symbol": 0xFFFFFFC008003000})
                == 0xFFFFFFC008003000, "known stub did not map to its target")

        candidate = bytearray(module.rebase_module(base, profiles["g2e1f"])[0])
        candidate[0x100] ^= 1
        expect_value_error("unexplained byte", module.verify_module,
                           base, profiles["g2e1f"], bytes(candidate))
        print("PASS legacy cga profiles=2 abs=225 stubs=220 negatives=3; restored gaaa tested separately")
    else:
        print("SKIP legacy cga deterministic verify (audit-only base not stored)")


def test_routing() -> None:
    runner = (ASSETS / "98260/run6157_full.sh").read_text(encoding="utf-8")
    top = (ASSETS / "run.sh").read_text(encoding="utf-8")
    main = (ROOT / "main/compose-app/app/src/main/java/com/aoki/magicroot/MainActivity.java"
            ).read_text(encoding="utf-8")
    helper = (ROOT / "main/compose-app/app/src/main/java/com/aoki/magicroot/KernelLogHelper.java"
              ).read_text(encoding="utf-8")
    assets_block = main.split("private static final String[] ASSETS = {", 1)[1].split("};", 1)[0]
    for name, expected in EXPECTED.items():
        kernel = expected["kernel"]
        directory = f"98260-{name}"
        ko = f"g264/ksm-{name}-base.ko"
        require(f'"{directory}/exploit-android-key-ptr"' in assets_block,
                f"{name}: payload not registered in ASSETS")
        require(f'"{directory}/pc98260-su"' in assets_block, f"{name}: su not registered")
        require(f'"{directory}/target.sh"' in assets_block, f"{name}: target not registered")
        require(f'"{ko}"' in assets_block, f"{name}: CGA base not registered")
        require(f"P6157={name} ;;" in runner, f"{name}: runner payload dispatch missing")
        require(f"{kernel}*" in top, f"{name}: top-level 6.1 dispatch missing")
        require(f'"$D"/{directory}/*' in top, f"{name}: top-level chmod missing")
        require(f'new Profile6157("{name}", "{kernel}", "{directory}", "{ko}")' in helper,
                f"{name}: shared Java profile route missing")
        require(f"'/{directory}/* '" in main, f"{name}: deployment chmod missing")

    require('G264_BASE=$D/g264/ksm-$P6157-base.ko' in runner
            and 'G264_KO=$D/ksm-$P6157.ko' in runner,
            "runner no longer derives CGA paths from the exact profile")
    require('if [ "$K6157" = "1" ] && [ "$G7D" = "0" ]; then\n    G264_BLIND=1' in runner,
            "blind reclaim is not enabled uniformly for non-g7d 6.1 profiles")
    require('return KernelLogHelper.shouldStage6157Asset(name, release);' in main,
            "6.1 asset staging is not delegated to the shared profile planner")
    require('return KernelLogHelper.payloadDirFor6157(release);' in main
            and 'return KernelLogHelper.cgaBaseFor6157(release);' in main,
            "6.1 payload/CGA routing is not delegated")
    require('if (name.startsWith("ksu6157-m6/")) return m6;' in helper,
            "M6 staging is no longer g7d-only")
    require('if (name.startsWith("ksu6157-g264/")) return g264;' in helper,
            "legacy g264 handoff is no longer g264-only")
    require('echo "FAIL=kernel_unsupported' in runner, "unknown kernels no longer fail closed")
    print(f"PASS routing profiles={len(EXPECTED)} filters=exact fallback=closed")


def test_credit() -> None:
    about = (ROOT / "main/compose-app/app/src/main/kotlin/com/aoki/magicroot/MiuixHost.kt"
             ).read_text(encoding="utf-8")
    require('AboutSection(\n                "98260 适配致谢"' in about,
            "About page lacks the 98260 acknowledgement section")
    require('"GitHub / 酷安 Higanoneko"' in about, "About page lacks Higanoneko credit")
    for name, expected in EXPECTED.items():
        token = expected["kernel"].split("-", 1)[0] + " · g" + expected["kernel"].rsplit("g", 1)[1]
        require('"' + token + ' · 98260 · 静态适配"' in about,
                f"{name}: supported-kernel list not updated")
    print(f"PASS credit about=text kernels={len(EXPECTED)}")


def test_all() -> None:
    test_payload()
    test_cga()
    test_routing()
    test_credit()
    print("PASS all")


def main() -> int:
    tests = {"payload": test_payload, "cga": test_cga,
             "routing": test_routing, "credit": test_credit, "all": test_all}
    if len(sys.argv) != 2 or sys.argv[1] not in tests:
        print(f"usage: test_61128_adaptation.py {{{','.join(tests)}}}", file=sys.stderr)
        return 2
    try:
        tests[sys.argv[1]]()
    except (AssertionError, KeyError, TypeError, ValueError, OSError) as exc:
        print(f"FAIL {sys.argv[1]}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
