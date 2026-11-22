#!/usr/bin/env python3
"""Static regression for init_cred-aware ko_patch and late-load routing."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
KO_PATCH = os.environ.get("KO_PATCH", str(ROOT / "main/app/assets/ko_patch"))
K12 = "6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k"
K18 = "6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k"
K6658 = "6.6.58-android15-8-g6484937db664-abogki407459068-4k"
KG893 = "6.6.118-android15-8-g893e848657cc-4k"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run_patch(out: Path, template: str, syms: str, release: str,
              expect: str = "TRACK_THRONE=patched",
              input_path: Path | None = None) -> tuple[Path, str]:
    output = out / (template.replace("/", "_") + ".ko")
    source = input_path if input_path is not None else ROOT / template
    proc = subprocess.run(
        [KO_PATCH, str(source), str(output), str(ROOT / syms), "0", release],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=120, check=False)
    require(proc.returncode == 0, f"ko_patch failed {template}: {proc.stdout}")
    require(expect in proc.stdout, f"unexpected throne result {template}: {proc.stdout}")
    require("MISSING=0" in proc.stdout, f"unresolved symbol {template}: {proc.stdout}")
    return output, proc.stdout


def main() -> None:
    require(Path(KO_PATCH).is_file(), f"missing ko_patch {KO_PATCH}")
    with tempfile.TemporaryDirectory(prefix="init-cred-test-") as tmp:
        out = Path(tmp)
        cases = [
            ("main/app/assets/ksu-template.ko", "main/app/assets/syms_61258.txt", K12),
            ("main/app/assets/ksu-template-fina.ko", "main/app/assets/syms_61258_fina.txt", K12),
            ("main/app/assets/ksu-template-sukisu.ko", "main/app/assets/syms_61258_sukisu.txt", K12),
            ("main/app/assets/ksu-template-next.ko", "main/app/assets/syms_61258_next.txt", K12),
            ("main/app/assets/ksu-template-bakasu.ko", "main/app/assets/syms_61258_bakasu.txt", K12),
            ("main/app/assets/ksu-template-66118.ko", "main/app/assets/98260-6689/syms_6689_kernelsu.txt",
             "6.6.89-android15-8-g082e5a98dac1-abogki463734347-4k"),
            ("main/app/assets/ksu-template-66118.ko", "main/app/assets/98260-f171/syms_66118.txt",
             "6.6.118-android15-8-gf17133276a57-abogki518694926-4k"),
            ("main/app/assets/ksu-template-66118.ko", "main/app/assets/98260-ga812/syms_ga812_kernelsu.txt",
             "6.6.118-android15-8-ga812a1946391-abogki576098434-4k"),
            ("main/app/assets/ksu-template-66118.ko", "main/app/assets/98260-6658/syms_6658_kernelsu.txt", K6658),
            ("main/app/assets/ksu-template-66118-bakasu.ko", "main/app/assets/98260-6658/syms_6658_bakasu.txt", K6658),
            ("main/app/assets/ksu-template-66118-next.ko", "main/app/assets/98260-6658/syms_6658_next.txt", K6658),
            ("main/app/assets/ksu-template-66118-sukisu.ko", "main/app/assets/98260-6658/syms_6658_sukisu.txt", K6658),
            ("main/app/assets/ksu-template-66118-fina.ko", "main/app/assets/98260-6658/syms_6658_fina.txt", K6658),
            ("main/app/assets/ksu-template-66118.ko", "main/app/assets/98260-g893/syms_g893_kernelsu.txt", KG893),
            ("main/app/assets/ksu-template-66118-bakasu.ko", "main/app/assets/98260-g893/syms_g893_bakasu.txt", KG893),
            ("main/app/assets/ksu-template-66118-next.ko", "main/app/assets/98260-g893/syms_g893_next.txt", KG893),
            ("main/app/assets/ksu-template-66118-sukisu.ko", "main/app/assets/98260-g893/syms_g893_sukisu.txt", KG893),
            ("main/app/assets/ksu-template-66118-fina.ko", "main/app/assets/98260-g893/syms_g893_fina.txt", KG893),
        ]
        for template, syms, release in cases:
            patched, output = run_patch(out, template, syms, release)
            if release == K6658:
                symbols = subprocess.check_output(["readelf", "-sW", str(patched)], text=True)
                require(any(" ffffffc082170748 " in line and line.endswith(" init_cred")
                            for line in symbols.splitlines()),
                        f"6658 init_cred address missing for {template}: {output}")

        fina, _ = run_patch(out, "main/app/assets/ksu-template-fina.ko",
                            "main/app/assets/syms_61258_fina.txt", K12)
        rel = subprocess.check_output(["readelf", "-rW", str(fina)], text=True)
        require("000000000000b6a8" in rel and "init_cred" in rel,
                "Fina do_track_throne ADRP was not rewritten")
        require("000000000000b6ac" in rel and "R_AARCH64_ADD_ABS_LO12_NC" in rel,
                "Fina do_track_throne LDR was not converted to ADD")
        symbols = subprocess.check_output(["readelf", "-sW", str(fina)], text=True)
        require(symbols.count(" init_cred\n") == 1, "init_cred missing or duplicated")

        _, again = run_patch(out, "main/app/assets/ksu-template-fina.ko",
                             "main/app/assets/syms_61258_fina.txt", K12,
                             expect="TRACK_THRONE=already", input_path=fina)
        require("MISSING=0" in again, "idempotent Fina patch failed")

        run_patch(out, "main/app/assets/98260-61821/ksu-template.ko",
                  "main/app/assets/98260-61821/syms_61821_kernelsu.txt", K18,
                  expect="TRACK_THRONE=already")
        run_patch(out, "main/app/assets/98260-h1c/ksu-template-115.ko",
                  "main/app/assets/98260-61821-brm/syms_61821_brm.txt", K18,
                  expect="TRACK_THRONE=already")

        # Default keeps the proven init_cred rewrite (the 8384115b behavior).
        # MAGICROOT_THRONE_PATCH=0 must leave the module's own ksu_cred path.
        _, default_log = run_patch(out, "main/app/assets/ksu-template.ko",
                                   "main/app/assets/syms_61258.txt", K12)
        require("TRACK_THRONE=patched" in default_log,
                f"default throne patch missing: {default_log}")
        opt = out / "throne-opt-out.ko"
        env = os.environ.copy()
        env["MAGICROOT_THRONE_PATCH"] = "0"
        proc = subprocess.run(
            [KO_PATCH, str(ROOT / "main/app/assets/ksu-template.ko"),
             str(opt), str(ROOT / "main/app/assets/syms_61258.txt"), "0", K12],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=120, check=False, env=env)
        require(proc.returncode == 0, f"ko_patch opt-out failed: {proc.stdout}")
        require("TRACK_THRONE=disabled" in proc.stdout,
                f"opt-out did not disable throne patch: {proc.stdout}")
        require("MISSING=0" in proc.stdout,
                f"opt-out symbol failure: {proc.stdout}")
        require(opt.is_file(), "opt-out output missing")

        # An unproven address must not be guessed.  The legacy module remains
        # loadable, but is explicitly marked as init_cred-unavailable.
        donor = (ROOT / "main/app/assets/syms_61258_fina.txt").read_text()
        missing = out / "missing-init-cred.txt"
        missing.write_text("\n".join(line for line in donor.splitlines()
                                     if not line.startswith("init_cred ")) + "\n")
        bad = out / "missing.ko"
        proc = subprocess.run(
            [KO_PATCH, str(ROOT / "main/app/assets/ksu-template-fina.ko"),
             str(bad), str(missing), "0", K12],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=120, check=False)
        require("TRACK_THRONE=unavailable" in proc.stdout and "MISSING=0" in proc.stdout,
                f"missing init_cred was not marked unavailable: {proc.stdout}")

    runner = (ROOT / "main/app/assets/98260/run98260.sh").read_text()
    require("fake-cred-init-cred-insmod" in runner, "fake init-cred method missing")
    require("patch_init_cred_module_98260" in runner, "fake patch helper missing")
    require('98260_KSU_USERSLATE_RC=$_fake_ll_rc' in runner and
            '98260_KSU_USERSLATE_WARN=module_live_userspace_failed' in runner,
            "fake userspace late-load rc must be captured as a diagnostic")
    require('[ "$_fake_ll_rc" = "0" ] && ksu_loaded_98260' not in runner,
            "fake registration must not gate on the userspace late-load rc")
    require(runner.count('if ksu_loaded_98260; then\n                    # The init_cred-patched module is live') == 1,
            "fake module-live success criterion missing")
    require(runner.count('_fake_ll_rc=$?\n                echo "98260_FAKE_LATELOAD_RC=$_fake_ll_rc"') == 2,
            "fake late-load RC must be captured before tee changes $?")
    require("98260_INIT_CRED_PRIMARY_INSMOD_RC" in runner,
            "primary late-load still bypasses patched module")
    require('[ "$_primary_ll_rc" = "0" ] && grep -q' in runner and
            '_primary_ll_rc=$?\n                    echo "98260_KSU_LATELOAD_PRIMARY_RC=$_primary_ll_rc"' in runner,
            "98260 primary late-load must preserve and enforce the real RC")
    require("98260_INIT_CRED_FALLBACK=legacy_embedded" in runner,
            "unavailable-profile compatibility fallback is missing")
    require("TRACK_THRONE=no_reloc)" in runner and
            "98260_INIT_CRED_PATCH=skipped reason=no_ksu_reloc" in runner,
            "no_reloc manager LKM is not routed to the embedded fallback")
    require("TRACK_THRONE=disabled)" in runner,
            "runner does not accept the disabled throne result")
    require("98260_THRONE_PATCH=disabled" in runner,
            "runner does not log the disabled throne choice")
    runner6157 = (ROOT / "main/app/assets/98260/run6157_full.sh").read_text()
    require("98260_INIT_CRED_PRIMARY_INSMOD_RC" in runner6157,
            "6157 primary late-load still bypasses patched module")
    require('[ "$_primary_ll_rc" = "0" ] && ksu_live' in runner6157 and
            '_primary_ll_rc=$?\n                    echo "98260_KSU_LATELOAD_PRIMARY_RC=$_primary_ll_rc"' in runner6157,
            "6157 primary late-load must preserve and enforce the real RC")
    build = (ROOT / "build-binaries.ps1").read_text()
    require("throne_patch.c" in build, "native build omits throne_patch.c")
    print("PASS init_cred: five flavors + 6.6/6.18, 6658 all flavors, Fina wrapper, idempotency")
    print("PASS late-load: fake/primary consume patched KO and enforce RC; unavailable is explicit")


if __name__ == "__main__":
    main()
