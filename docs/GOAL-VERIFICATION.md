# Goal adaptation verification

Generated during the active goal round.  No adb device was attached during this
run, so runtime pass/fail remains pending.

## Upstream reference

```text
https://github.com/superboyyy/HOneClick
HEAD 0ede55620b5fd782c4fbce296c0864897e347756 (2026-11-01)
```

Upstream profile IDs:

```text
honor-6.18.21-109  g928
honor-6.18.21-115  g186
```

## 98260 route

`98260/run98260.sh` default engine for the two 6.18.21 builds:

```text
MAGICROOT_98260_ENGINE=h1c
```

H1C assets:

```text
main/app/assets/98260-h1c/cve98260_plant
main/app/assets/98260-h1c/cve98260_slide
main/app/assets/98260-h1c/cve98260_su
main/app/assets/98260-h1c/cve98260_module
main/app/assets/98260-h1c/addrcalc
main/app/assets/98260-h1c/root_stage.sh
main/app/assets/98260-h1c/run_h1c.sh
```

Selected manager template and syms are passed from `ksu_select_ko`, preserving
KernelSU / BakaSU / Next / SukiSU / FinaSU.

For the g186 official Flavor the H1C path now uses upstream's exact 115 module:

```text
main/app/assets/98260-h1c/ksu-template-115.ko
375,616 B
sha256 f8dd188f3feb05998f145286c4093da2aaa944fca2cb226db561b1b784761f1e
```

It is used inside H1C.  The `98260-61821-brm/ksu-template-61821-kernelsu.ko`
fallback was replaced with this same 115 image on 2026-11-03; the old
6.12.76-based compatibility file is no longer shipped.  The g186 syms table
covers all 226 undefined symbols of the 115 module.

If preflight, slide or ko_patch fails before a UAF is started, the script falls
back to the legacy BRM route:

```text
98260_ENGINE_FALLBACK=brm reason=h1c_pre_uaf rc=81|82
```

After rootd startup the fallback is deliberately disabled; a parked
`cve98260_plant` requires reboot.

## 6.12.58 provided kernel

```text
image sha256   0385dbba2869c5669b676223d5d1101e500671415a1f3732ecf8c1e770453c99
kernel sha256  490d074be61dff039a937e404636bc19e04efdddf6665789505b8f82f9b5bf5e
release        6.12.58-android16-6-g42fcf008ff5c-abogki504518581-4k
profile        honor-61258c-98260
exploit sha256 92724e6a7976c11443a986e88f45b3bcc97db53217faab8ee53546b46f72a9d9
```

Five Flavor syms were regenerated from the provided vmlinux with 0 missing
undefined symbols.

Host verifier:

```text
python tools/verify_61258c_profile.py
```

Result: `RESULT PASS`

It re-reads the provided vmlinux `.symtab`, BTF layout, header constants and all
five syms tables:

```text
PASS LINK_SELINUX_STATE / INIT_USER_NS / ROOT_USER / INIT_GROUPS / INIT_UCOUNTS
PASS GEOM_MEMSTART_ADDR
PASS LINK_ALLOC_TIMER / LINK_ALLOC_CRED / LINK_ALLOC_TASK
PASS BTF task_struct.cred=0x900 real_cred=0x8f8 comm=0x910
PASS BTF k_itimer.it=0x78 cred.size=0xb8
PASS syms 61258c 225 + resukisu 233 + next 227 + sukisu 245 + fina 232
PASS exploit sha256 92724e6a...
```

## 6.1.157 g264

Static checks only:

```text
run61157.sh       bash -n 0
setup_su_app.sh   bash -n 0
su_optional.sh    bash -n 0
```

Runtime g264 CGA/root_stage remains untested because no device is attached.

## APK verification

```text
assets/98260-61258c/exploit-android-key-ptr 459184
assets/98260-61258c/target.sh                462
assets/syms_61258c.txt                      7824
assets/98260-h1c/run_h1c.sh                 7274
```

Version:

```text
versionCode 12
versionName 1.0.5
```

## Checksum integrity

The legacy `98260/SHA256SUMS.txt` and `98260-6138/SHA256SUMS.txt` still listed
pre-strip payloads and deleted helper files.  They were regenerated from the
files actually staged in the APK.

`tools/audit_adaptation_matrix.py` result after the fix:

```text
pass=131 warn=1 fail=1
```

The remaining failure is intentional: automatic `MAGICROOT_REPAIR` scheduling
was removed by the soft-reboot policy, so the audit's old `MAGICROOT_REPAIR`
consumer check no longer applies.

## H1C host control-flow test

`tools/test_h1c_flow.py` runs the actual `98260-h1c/run_h1c.sh` with fake native
helpers, exercising the complete non-device sequence:

```text
preflight -> slide -> ko_patch -> rootd -> module load -> root_stage
```

Result:

```text
98260_H1C_SLIDE=0x20000000
PATCHED=1 MISSING=0
98260_H1C_ROOTD_READY=1
98260_H1C_MODULE_LOAD_RC=0
98260_H1C_SUCOMPAT=1
ROOT_STAGE_OK
98260_H1C_DONE=1
H1C_FLOW_RESULT PASS
```

Production defaults are unchanged; `H1C_SYSTEM_SU` and `H1C_SOCK_DIR` are
test-only override points.
