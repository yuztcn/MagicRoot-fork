# Device runtime test runbook

All code/static checks are complete in this workspace.  These are the only
remaining tests; they need a USB/Wi-Fi ADB device.

## 0. Preconditions

- Device is bootloader-unlocked/root research device owned by the tester.
- USB debugging or wireless debugging is enabled.
- `adb devices` shows the device as `device`.
- Install the APK matching the current build:

```powershell
adb install -r C:\Users\HourG\Downloads\MagicRoot\APK\MagicRoot-1.0.5.apk
```

Record:

```powershell
adb shell getprop ro.product.model
adb shell getprop ro.build.display.id
adb shell uname -r
adb shell getprop ro.build.version.release
```

## 1. Provided 6.12.58 g42fcf008ff5c

Expected:

```text
Linux version 6.12.58-android16-6-g42fcf008ff5c-abogki504518581-4k
```

App steps:

1. Open MagicRoot.
2. Select `98260`.
3. Grant Shell through Stellar/Shizuku.
4. Deploy assets.
5. Start.
6. Save the full log.

Expected profile lines:

```text
98260_PROFILE_MATCH=1 profile=61258c
98260_CHAIN_BEGIN kernel=6.12.58-android16-6-g42fcf008ff5c-abogki504518581-4k
```

Capture:

```powershell
adb shell su -c 'uname -r; id; getenforce'
adb shell "cat /data/local/tmp/magic/run.log" > 61258c-run.log
```

## 2. 6.18.21 HOneClick 109/115

Kernels:

```text
6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k  (109)
6.18.21-android17-5-ge186062ea75f-abogki564062290-4k  (115)
```

Expected engine marker:

```text
98260_ENGINE=h1c
```

For g186 official Flavor, expected template:

```text
98260-h1c/ksu-template-115.ko
```

For g928 official Flavor, expected template:

```text
98260-61821/ksu-template.ko  (SU access fix, 86ed32a0...)
```

Capture:

```powershell
adb shell "cat /data/local/tmp/magic/98260-h1c.log" > h1c.log
adb shell "tail -200 /data/local/tmp/magic/98260-h1c-plant.log" > h1c-plant.log
```

The App's failure/success/previous-run exports also append these H1C logs under
`=== 98260-h1c*.log ===` headings.  After any log containing
`98260_H1C_PLANT_STARTED=1`, a failed run must not be retried in the same boot.
Preserve the exported first-run log before rebooting.

Expected rootd outcomes:

```text
98260_H1C_ROOTD_READY=1 ...                    # continue to module/root_stage
98260_H1C_FAIL=uaf_parked ...                  # native terminal state; reboot
98260_H1C_FAIL=plant_exited|plant_not_started # early startup failure; reboot
98260_H1C_FAIL=rootd_timeout waited=...        # real elapsed-time cap; reboot
98260_H1C_FAIL=slide_invalid ...               # rejected before plant; no reboot needed
```

A successful run still requires `98260_H1C_ROOT_STAGE_RC=0`, a root identity in
`u:r:ksu:s0`, and direct `/system/bin/su -c id` acceptance when su_compat and
allow_shell are enabled.  The shell-only regression below does not replace this
device validation:

```sh
python3 tools/test_h1c_flow.py
H1C_TEST_SHELL=/system/bin/sh python3 tools/test_h1c_flow.py
```

## 3. 64560 g928

Kernel must equal:

```text
6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k
```

Expected:

```text
64560_61821_MODULE=loaded
64560_61821_SU=... context=u:r:ksu:s0
64560_61821_DONE
```

Capture:

```powershell
adb shell "cat /data/local/tmp/magic/64560-61821.log" > 64560.log
```

## 4. 6.1.x 98260

Supported 98260 builds:

```text
6.1.157 g7d3922fade43, g2646292297b1, gaaa383620ebf, g3306a328b7be,
        g84ffa64b710b, g77f76e323a02
6.1.99  gce84935796c9, g5859fbdbad8c, g54d40b4fb287, ge9da27488f45
6.1.128 g40b1fd119d9b, g8a4968670f1c, g2e1f0741dafb
```

The last two 6.1.128 builds and 6.1.157 gaaa are static-only.  Before any authorized device
run, check their exact profile assets and deterministic outputs with:

```powershell
python3 -I tools/test_61128_adaptation.py all
python3 -I tools/audit_6157_chain.py
```

Expected CGA paths for the two 6.1.128 profiles are `g264/ksm-g8a496-base.ko` and
`g264/ksm-g2e1f-base.ko`; gaaa uses `g264/ksm-gaaa-base.ko`.  Never deploy
g84/g40b1's `0x840/0x118` module to these `0x838/0x108` builds.

g7d expected handoff:

```text
98260_KSU_BACKEND=m6
98260_KSU=loaded method=m6-loader-6157
98260_MANAGER_PRESENT=1
```

g264 and the other CGA builds expect:

```text
98260_KSU_BACKEND=g264-cga
98260_KSU=loaded method=g264-cga
98260_G264_KO=... vermagic=<exact target>
98260_SU_SETUP_BEGIN ksud=...
SU_OPTIONAL_MODE=overlay-system-ext-bin-tmpfs
SU_OPTIONAL_TERMUX=patched target=/system_ext/bin
SU_OPTIONAL_OK
98260_SU_SETUP_RC=0
```

2026-11-11 update: g264/gaaa use the feature-restored modules documented in
`docs/6157-CGA-FEATURE-RESTORE.md`; the following no-`su_compat` behavior is
now limited to the unchanged CGA profiles and to dispatcher-failure fallback.

These unchanged modules have no kernel su_compat by design, so KernelSU's
"traditional SU command support" stays greyed out with "kernel does not
support this feature".  `su` is `su_lkm` through the `/system_ext/bin`
overlay; the Termux `su` wrapper is patched to search that path.  Verify from
Termux (an already-running Termux is covered by a setns mount):

```sh
su -c id
# uid=0(root) ... context=u:r:su:s0
```

`SU_OPTIONAL_TERMUX=absent|unsupported|failed` means Termux is missing, has a
non-standard wrapper, or the write was denied; restarting Termux is only
needed when the patch succeeded but its namespace could not be entered.

All should include the successful bootstrap and static payload:

```text
98260_ROOTD_RETRY_DONE
[uaf] captured=... chosen=...
[blind] done writes=...
uid=0(root) ... context=u:r:ksu:s0
CHAIN_6157_RC=0
CHAIN_98260_DONE
98260_FINALIZE_BEGIN susfs=... load=...
SuSFS_LKM_LOAD=...
SOFT_REBOOT_REPAIR=...
98260_ROOTD_CLEANUP=...
98260_FINALIZE_END
DONE
```

`CHAIN_98260_DONE` → `DONE` is the optional SuSFS load and bounded rootd
cleanup.  With the SuSFS switch off expect
`SuSFS_LKM_LOAD=disabled reason=switch_off`, a finalize stage in the UI, and
still a final `DONE`.  A missing `DONE` here is a finalization failure, not a
KSU/root failure.

For preflight, expect `CHAIN_98260_PREFLIGHT_OK=1`.  If KSU is disabled, expect
`CHAIN_98260_DONE_ROOTD_ONLY=1`.

Capture:

```powershell
adb shell "cat /data/local/tmp/magic/run.log" > 6157-run.log
adb shell "cat /data/local/tmp/magic/98260.log" > 6157-uaf.log
adb shell "cat /data/local/tmp/magic/98260-ksu.log" > 6157-ksu.log
```

After a failure, reboot.  Do not start a second UAF in the same boot.  Run the
static gate before testing:

```powershell
python3 -I tools/audit_6157_chain.py
```

## 5. Failure logs

For any failure collect:

```powershell
adb shell "dmesg | tail -300"
adb shell "cat /proc/modules"
adb shell "getenforce"
adb logcat -d > logcat.txt
```

Do not rerun a 98260 failure in the same boot; reboot first.
