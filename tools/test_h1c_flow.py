#!/usr/bin/env python3
"""Portable host-side control-flow tests for the H1C 98260 shell engine.

All native helpers and the KSU module list are fakes in a temporary directory.
No exploit, finit_module, device root command or real parked marker is run.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import dataclass
from pathlib import Path

WS = Path(__file__).resolve().parent.parent
SRC = WS / "main/app/assets/98260-h1c/run_h1c.sh"
TEST_SHELL = os.environ.get("H1C_TEST_SHELL") or shutil.which("bash")


@dataclass
class Result:
    returncode: int
    output: str
    h1c_log: str
    marker_exists: bool
    plant_started: bool
    elapsed: float
    full_stage_used: bool = False


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    path.chmod(0o755)


def run_engine(profile: str = "61821brm", plant_mode: str = "success",
               slide: str = "0x20000000", wait: int = 1,
               su_delay: int = 0, stage_mode: str = "ok",
               ksu_enable: int = 1, full_stage: bool = False) -> Result:
    if not TEST_SHELL:
        raise unittest.SkipTest("bash is not available; set H1C_TEST_SHELL")
    with tempfile.TemporaryDirectory(prefix="magicroot-h1c-test-") as tmp:
        base = Path(tmp)
        d = base / "data"
        h = d / "98260-h1c"
        sock_dir = d / "socks"
        h.mkdir(parents=True)
        sock_dir.mkdir(parents=True)
        shutil.copy2(SRC, h / "run_h1c.sh")

        write(h / "cve98260_plant", r"""#!/bin/sh
if [ "$1" = "--preflight" ]; then
    echo "[preflight] RESULT=OK"
    exit 0
fi
echo $$ > "$H1C_WORK/fake-plant.pid"
case "${FAKE_PLANT_MODE:-success}" in
    success)
        : > "$H1C_WORK/fake-root-ready"
        : > "$PC98260_SOCK" ;;
    parked)
        : > "$PC98260_SOCK"
        echo "[uaf] page miss; parking unsafe process"
        echo "[uaf] unsafe state; holding process until reboot" ;;
    exited)
        echo "[rootd] startup failed errno=13 (Permission denied)"
        exit 1 ;;
    timeout)
        : > "$PC98260_SOCK" ;;
esac
while [ -e "$PC98260_SOCK" ]; do sleep 1; done
""")
        write(h / "cve98260_slide", """#!/bin/sh
echo "[slide] raw cpu0 site=0xffffffc0a03e005c ptr=0xffffffc0a0001000"
""")
        write(h / "cve98260_su", r"""#!/bin/sh
if [ "${FAKE_SU_DELAY:-0}" != "0" ]; then sleep "$FAKE_SU_DELAY"; fi
if [ ! -f "$H1C_WORK/fake-root-ready" ]; then
    echo "connect root daemon: Connection refused" >&2
    exit 1
fi
case "$*" in
    *__PC98260_FINIT_EXIT__*) echo "FINIT_RC=0 ERRNO=0" ;;
    *id*) echo "uid=0(root) gid=0(root)" ;;
    *) exit 0 ;;
esac
""")
        write(h / "cve98260_module", "#!/bin/sh\necho MODULE_LOADED flags=0\n")
        write(h / "root_stage.sh", """#!/bin/sh
D=$1
if [ "$FAKE_STAGE_MODE" = "fail" ]; then
    echo ROOT_STAGE_FAIL=injected
    exit 20
fi
echo 'uid=0(root) gid=0(root) context=u:r:ksu:s0' > "$D/root_id"
echo ROOT_STAGE_OK
""")
        if full_stage:
            write(d / "root_stage.sh", """#!/bin/sh
D=/data/local/tmp/magic
echo full-stage > "$H1C_WORK/full-stage-used"
mkdir -p "$H1C_WORK/marks"
printf 'uid=0(root) gid=0(root) context=u:r:ksu:s0\\n' > "$H1C_WORK/marks/ROOT_ID"
echo ROOT_STAGE_OK
""")
        write(h / "addrcalc", "#!/bin/sh\nprintf '%s\\n' \"$FAKE_SLIDE\"\n")
        write(h / "template.ko", "fake")
        write(h / "syms.txt", "fake 0x1\n")
        write(d / "ko_patch", """#!/bin/sh
echo fake > "$2"
echo "PATCHED=226 MISSING=0 REPAIRED=14"
""")
        write(d / "ksud", "#!/bin/sh\nexit 0\n")
        write(d / "system-su", r"""#!/bin/sh
if [ "$1" = "-c" ] && [ "$2" = "id" ]; then
    echo "uid=0(root) gid=0(root) context=u:r:ksu:s0"
    exit 0
fi
[ "$1" = "-c" ] || exit 2
exec sh -c "$2"
""")
        write(d / "bin/pidof", r"""#!/bin/sh
[ "$1" = "cve98260_plant" ] || exit 1
[ -s "$H1C_WORK/fake-plant.pid" ] || exit 1
pid=$(cat "$H1C_WORK/fake-plant.pid")
kill -0 "$pid" 2>/dev/null || exit 1
echo "$pid"
""")
        modules = d / "modules"
        modules.write_text("kernelsu 376228 0 - Live 0x0\n", encoding="utf-8")
        marker = d / "parked-marker"
        env = os.environ.copy()
        env.update({
            "PATH": f"{d / 'bin'}:{env.get('PATH', '')}",
            "H1C_WORK": str(d),
            "H1C_DIR": str(h),
            "H1C_PROFILE": profile,
            "H1C_TEMPLATE": str(h / "template.ko"),
            "H1C_SYMS": str(h / "syms.txt"),
            "H1C_KSUD": str(d / "ksud"),
            "H1C_SYSTEM_SU": str(d / "system-su"),
            "H1C_SOCK_DIR": str(sock_dir),
            "H1C_PROC_MODULES": str(modules),
            "H1C_PARKED_MARKER": str(marker),
            "H1C_ROOTD_WAIT": str(wait),
            "H1C_KSU_ENABLE": str(ksu_enable),
            "FAKE_PLANT_MODE": plant_mode,
            "FAKE_STAGE_MODE": stage_mode,
            "FAKE_SLIDE": slide,
            "FAKE_SU_DELAY": str(su_delay),
        })
        started = time.monotonic()
        try:
            p = subprocess.run(
                [TEST_SHELL, str(h / "run_h1c.sh")], cwd=base, env=env,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=12, check=False)
            output = p.stdout
            rc = p.returncode
        except subprocess.TimeoutExpired as exc:
            output = exc.stdout or ""
            if isinstance(output, bytes):
                output = output.decode(errors="replace")
            output += "\nTEST_TIMEOUT"
            rc = 124
        elapsed = time.monotonic() - started
        h1c_log_path = d / "98260-h1c.log"
        h1c_log = h1c_log_path.read_text(encoding="utf-8", errors="replace") \
            if h1c_log_path.exists() else ""
        plant_started = (d / "fake-plant.pid").exists()
        marker_exists = marker.exists()
        full_stage_used = (d / "full-stage-used").exists()
        # Successful H1C unlinks the socket itself. Failure tests unlink only
        # the fake file so the temporary fake plant can exit; no process kill.
        for socket in sock_dir.glob("*.sock"):
            socket.unlink(missing_ok=True)
        return Result(rc, output, h1c_log, marker_exists, plant_started, elapsed,
                      full_stage_used)


class H1CFlowTest(unittest.TestCase):
    def test_each_run_resets_diagnostics_after_live_plant_guard(self) -> None:
        script = (WS / "main/app/assets/98260-h1c/run_h1c.sh").read_text(encoding="utf-8")
        guard = script.index('if pidof cve98260_plant')
        clear = script.index('for _diag in')
        self.assertLess(guard, clear,
                        "a guard-only invocation must preserve the old plant log")
        self.assertIn('if ! : > "$_diag"', script)
        self.assertIn('98260_H1C_FAIL=diagnostic_log_reset', script)
        for name in ("98260-h1c-ko-patch.log", "98260-h1c-root-stage.log"):
            self.assertIn(name, script)
        self.assertIn('h1c_log "98260_H1C_BEGIN', script)
        self.assertIn('run=${H1C_RUN_ID:-unknown}', script)
        self.assertIn('h1c_log "98260_H1C_PLANT_SHA256=', script)

    def test_legacy_brm_launch_is_guarded_from_h1c(self) -> None:
        """6.18.21 must never start the legacy exploit-android-key-ptr plant.

        The shared run98260.sh used to launch the legacy BRM UAF before the
        H1C dispatch, so g186 runs raced two engines and always left a parked
        process.  Keep the legacy launch, the pc98260-su requirement and the
        SUSFS preload inside the BRM-only block.
        """
        src = (WS / "main/app/assets/98260/run98260.sh").read_text(encoding="utf-8")
        start = src.index('if [ "$H1C_ONLY" != "1" ]; then')
        end = src.index("fi # legacy BRM chain only", start)
        legacy = src[start:end]
        self.assertIn('"$BIN" $REAL_CRED_ARG', legacy,
                      "legacy exploit launch must stay inside the BRM block")
        self.assertIn("SUSFS_PRELOAD_BEGIN", legacy)
        for needle in ('[ -x "$SU" ] || { echo "FAIL=asset_missing',
                       "pidof exploit-android-key-ptr",
                       "PC98260_MAX_ATTEMPTS"):
            self.assertIn(needle, legacy, f"{needle} must stay legacy-only")
        # The dispatch itself must remain outside the legacy block.
        self.assertNotIn("run_h1c.sh", legacy,
                         "H1C dispatch must not be nested in the BRM block")

    def test_builtin_profile_constants_match_honeclick(self) -> None:
        source = SRC.read_text(encoding="utf-8")
        profiles = {
            "61821": {
                "TIMER_LINK": "0xffffffc0803e005c",
                "CRED_LINK": "0xffffffc080147378",
                "SELINUX_LINK": "0xffffffc08299a6f0",
                "USER_NS": "0xffffffc0827110e0",
                "ROOT_USER": "0xffffffc082711390",
                "GROUPS": "0xffffffc082712a48",
                "UCOUNTS": "0xffffffc082712f08",
                "KITIMER_SIZE": "384", "KITIMER_NODE": "224",
                "TASK_CRED": "2312", "CRED_SIZE": "184",
                "SLAB_OBJECTS": "21", "SLAB_PAGES": "2",
                "SITE_LOW": "0x1e005c", "NEG_TIMER_LINK": "0x3f7fc1ffa4",
            },
            "61821h1c117": {
                "TIMER_LINK": "0xffffffc0803e0460",
                "CRED_LINK": "0xffffffc08014dca0",
                "SELINUX_LINK": "0xffffffc08299a6f0",
                "USER_NS": "0xffffffc0827110e0",
                "ROOT_USER": "0xffffffc082711390",
                "GROUPS": "0xffffffc082712a48",
                "UCOUNTS": "0xffffffc082712f08",
                "KITIMER_SIZE": "384", "KITIMER_NODE": "224",
                "TASK_CRED": "2312", "CRED_SIZE": "184",
                "SLAB_OBJECTS": "21", "SLAB_PAGES": "2",
                "SITE_LOW": "0x1e0460", "NEG_TIMER_LINK": "0x3f7fc1fba0",
            },
            "61821brm": {
                "TIMER_LINK": "0xffffffc0803e1fd0",
                "CRED_LINK": "0xffffffc08014cd90",
                "SELINUX_LINK": "0xffffffc08299a6f0",
                "USER_NS": "0xffffffc0827110e0",
                "ROOT_USER": "0xffffffc082711390",
                "GROUPS": "0xffffffc082712a48",
                "UCOUNTS": "0xffffffc082712f08",
                "KITIMER_SIZE": "384", "KITIMER_NODE": "224",
                "TASK_CRED": "2312", "CRED_SIZE": "184",
                "SLAB_OBJECTS": "21", "SLAB_PAGES": "2",
                "SITE_LOW": "0x1e1fd0", "NEG_TIMER_LINK": "0x3f7fc1e030",
            },
        }
        for profile, constants in profiles.items():
            with self.subTest(profile=profile):
                block = source.split(f"    {profile})", 1)[1].split(";;", 1)[0]
                for key, value in constants.items():
                    self.assertIn(f"{key}={value}", block)

    def assert_ok(self, result: Result) -> None:
        self.assertEqual(result.returncode, 0, result.output)
        self.assertIn("98260_H1C_ROOTD_READY=1", result.output)
        self.assertIn("98260_H1C_MODULE_LIVE=1", result.output)
        self.assertIn("98260_H1C_DIRECT_SU=ok", result.output)
        self.assertIn("98260_H1C_DONE=1", result.output)
        self.assertFalse(result.marker_exists)

    def test_success_flow_109_and_115(self) -> None:
        for profile in ("61821", "61821brm", "61821h1c117"):
            with self.subTest(profile=profile):
                result = run_engine(profile=profile)
                self.assert_ok(result)
                self.assertIn("98260_H1C_ROOT_STAGE_RC=0", result.h1c_log)

    def test_deployed_root_stage_is_used_and_not_overwritten(self) -> None:
        """The full deployed root_stage.sh owns manager registration.

        run_h1c.sh used to `cp -f "$H/root_stage.sh" "$D/root_stage.sh"`,
        replacing the manager-aware installer with the reduced H1C one and
        silently dropping signature registration.
        """
        result = run_engine(full_stage=True)
        self.assert_ok(result)
        self.assertTrue(result.full_stage_used,
                        "H1C must run the deployed root_stage.sh")
        self.assertIn("98260_H1C_ROOT_STAGE_RC=0", result.h1c_log)

    def test_rootd_only_success_does_not_write_parked_marker(self) -> None:
        result = run_engine(ksu_enable=0)
        self.assertEqual(result.returncode, 0, result.output)
        self.assertIn("98260_H1C_KSU=disabled rootd_only=1", result.output)
        self.assertIn("98260_H1C_DONE=1", result.output)
        self.assertFalse(result.marker_exists)

    def test_root_stage_failure_marks_same_boot(self) -> None:
        result = run_engine(stage_mode="fail")
        self.assertEqual(result.returncode, 85, result.output)
        self.assertIn("98260_H1C_FAIL=root_stage", result.output)
        self.assertTrue(result.plant_started)
        self.assertTrue(result.marker_exists)

    def test_parked_plant_fails_immediately_and_preserves_log(self) -> None:
        result = run_engine(plant_mode="parked", wait=30)
        self.assertEqual(result.returncode, 83, result.output)
        self.assertIn("98260_H1C_FAIL=uaf_parked", result.output)
        self.assertNotIn("98260_H1C_FAIL=rootd_timeout", result.output)
        self.assertIn("page miss; parking unsafe process", result.h1c_log)
        self.assertTrue(result.marker_exists)
        self.assertLess(result.elapsed, 8)

    def test_exited_plant_is_not_misreported_as_timeout(self) -> None:
        result = run_engine(plant_mode="exited", wait=30)
        self.assertEqual(result.returncode, 83, result.output)
        self.assertIn("98260_H1C_FAIL=plant_exited", result.output)
        self.assertIn("startup failed", result.h1c_log)
        self.assertTrue(result.marker_exists)

    def test_rootd_wait_uses_real_elapsed_seconds(self) -> None:
        result = run_engine(plant_mode="timeout", wait=1, su_delay=2)
        self.assertEqual(result.returncode, 83, result.output)
        self.assertIn("98260_H1C_FAIL=rootd_timeout", result.output)
        self.assertIn("rc=1 out=connect root daemon: Connection refused", result.output)
        self.assertTrue(result.marker_exists)
        self.assertLess(result.elapsed, 8)

    def test_invalid_slide_never_starts_plant(self) -> None:
        cases = {
            "0x0": "reason=zero",
            "0x20000001": "reason=unaligned",
            "0xnothex": "reason=non_hex",
            "0x": "reason=non_hex",
        }
        for slide, reason in cases.items():
            with self.subTest(slide=slide):
                result = run_engine(slide=slide)
                self.assertEqual(result.returncode, 81, result.output)
                self.assertIn("98260_H1C_FAIL=slide_invalid", result.output)
                self.assertIn(reason, result.output)
                self.assertFalse(result.plant_started)
                self.assertFalse(result.marker_exists)


if __name__ == "__main__":
    unittest.main(verbosity=2)
