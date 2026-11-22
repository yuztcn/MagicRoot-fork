# 98260 HOneClick engine

The 6.18.21 g928/g186 CVE-2026-98260 route uses the HOneClick 109/115 native
runtime.  It is selected by default for those two exact kernels:

```text
main/app/assets/98260-h1c/
  cve98260_plant       35,064 B  (rebuilt PIE, compound-page PFN fix)
  cve98260_slide      420,392 B
  cve98260_su         418,664 B
  cve98260_module     418,920 B
  addrcalc             25,000 B
  root_stage.sh           ~1 KB
  ksu-template-115.ko 438,096 B  (bootstrap creds patched)
  ko_patch (top-level asset, SHN_XINDEX repair)
  run_h1c.sh
```

`98260/run98260.sh` still performs the exact `uname -r` / profile gate and
`ksu_select_ko` first.  It then hands the selected `KO_TEMPLATE` and `SYMS` to
the HOneClick runtime, so the multi-manager Flavor selection is preserved.

6.18.21 is unconditionally H1C; the legacy BRM engine switch was removed.
`MAGICROOT_98260_ENGINE` is no longer read.

## Runtime sequence

```text
cve98260_plant --preflight          # also used by preflight-only mode
cve98260_slide --site-low
addrcalc add site (-timer_link)
ko_patch template patched.ko syms slide uname
cve98260_plant --slide
cve98260_su -c id
cve98260_module patched.ko 'allow_shell=... [force_feature=...]'
wait for kernelsu in /proc/modules
direct /system/bin/su or ksud debug su
root_stage.sh
direct /system/bin/su -c id acceptance when su_compat + allow_shell are on
```

`MAGICROOT_98260_PREFLIGHT=1` calls only the native H1C preflight and exits
without slide/ko_patch/plant.  It must never fall through to the legacy BRM
`--check` payload.

The module parameter string always includes `allow_shell`, taken from
`MAGICROOT_ALLOW_SHELL`; STP appends `force_feature=su_compat:0` as a second
token.  `cve98260_module` receives that whole string as one argv element.

The g928 official template is the upstream late-load SU-access-fixed 109
template.  The g186 + kernelsu path keeps the dedicated ge186/115 template;
other flavors use the manager-extracted LKM with the selected symbol table and
fall back to `ksud debug su` if direct sucompat is not ready.  The 115 template
now carries the same bootstrap-credential patch as 109:
`ksu_cred = prepare_kernel_cred(&init_task)` instead of `prepare_creds()`.
`patches/patch_ksu_bootstrap_creds_v331.py` (HOneClick upstream tree) accepts
both template hashes, and `syms_61821_brm.txt` gained the corresponding
`prepare_kernel_cred` symbol.  See `docs/61821-115-CHAIN-ANALYSIS.md`.

`ko_patch` includes upstream's `SHN_XINDEX (0xffff)` -> `.modinfo` repair; the
115 template reports `REPAIRED=14`.  `run_h1c.sh` now prefers the app-deployed
`/data/local/tmp/magic/root_stage.sh` (manager discovery, signature
registration, atomic `ksud` install) and only falls back to the reduced bundled
installer, copied to `root_stage_h1c.sh` so the deployed script is never
overwritten.  Accept either `root_id` or `marks/ROOT_ID` as the identity file.
`root_stage.sh` installs the selected
manager's userspace with `--libadbroot`/`--data-path` when available, applies
`su_compat`/`kernel_umount`/`selinux_hide`/`adb_root` features, runs the optional
`su_entry.sh`, and requires its own `id` to be `uid=0(root)`.  The runner also
requires `context=u:r:ksu:s0` from the `root_id` file and, in the normal
su_compat + allow_shell path, from a fresh direct `/system/bin/su -c id`.

When `MAGICROOT_KEEP_ROOTD=0` and su_compat is on, the H1C socket is unlinked
after successful acceptance; the parked parent is never killed.  The Tools
"stop rootd" action recognizes `/data/local/tmp/cve98260-h1c-*.sock` and
`cve98260_plant` listener children.

## Slide and rootd safeguards

As in HOneClick's Java `parseCve98260Slide`, a slide must be non-zero and
4-KiB aligned.  MagicRoot additionally rejects an empty or non-hex `addrcalc`
result.  `98260_H1C_FAIL=slide_invalid` is reported before plant starts; this
class of failure does not require a reboot.

The rootd wait uses the shell's monotonic `SECONDS` clock with a real 300-second
cap.  Each client probe still has a 5-second `timeout`, so a blocked request can
no longer multiply the intended wait by six.  Probe rc/output is logged on the
first attempt and then at most once every 30 seconds.  A native parking message,
plant exit, or missing plant process terminates the wait immediately with a
specific marker.  Once plant has started, every failure exit (including module
and root_stage failures) writes the same-boot marker, even if the process crashed
before printing its usual parking message.  Successful full-KSU and rootd-only
exits do not write it.  No second UAF is started and the PPID=1 parent is never
killed.

`tools/test_h1c_flow.py` exercises this control flow entirely with temporary
fake helpers.  It covers both built-in profiles, invalid slides, parked/exited
plant, real elapsed-time timeout, root_stage, and direct-su acceptance.  Set
`H1C_TEST_SHELL=/system/bin/sh` to run the same tests with Android mksh.

## Failure markers

```text
98260_H1C_FAIL=preflight
98260_H1C_FAIL=no_slide_site
98260_H1C_FAIL=slide_invalid reason=non_hex|zero|unaligned
98260_H1C_FAIL=ko_patch*
98260_H1C_FAIL=uaf_parked
98260_H1C_FAIL=plant_exited
98260_H1C_FAIL=plant_not_started
98260_H1C_FAIL=rootd_timeout
98260_H1C_FAIL=module_load
98260_H1C_FAIL=module_not_live
98260_H1C_FAIL=root_stage
98260_H1C_FAIL=root_id_invalid
98260_H1C_FAIL=direct_su_invalid
```

A failed 98260 run is not retried automatically; the plant/socket state must be
treated as parked until reboot.

## Log export and 2026-11-03 audit

Failure, success, and previous-run exports now append labelled sections for:

```text
98260-h1c.log
98260-h1c-ko-patch.log
98260-h1c-plant.log
98260-h1c-root-stage.log
```

This preserves the first failure even when a second attempt only reports the
same-boot plant guard.  The UI also treats any failure after
`98260_H1C_PLANT_STARTED=1` as reboot-required instead of offering a generic
retry message.

The upstream GitHub `main` commit was checked as
`0ede55620b5fd782c4fbce296c0864897e347756`; its 109/115 constants and the four
H1C native helper hashes match MagicRoot.  No native helper, symbol table, or
KernelSU template was changed in this follow-up.

The earlier g186 first-run log reached `PATCHED=226 MISSING=0 REPAIRED=14`, then
reported `page miss; parking unsafe process`.  The old runner misreported this
as `rootd_timeout`; the new runner reports `uaf_parked` and includes the plant
log.  The later same-boot `98260_plant_alive_same_boot` message is the
intended second-run guard, not the first failure cause.

2026-11-04 follow-up (`docs/61821-115-CHAIN-ANALYSIS.md`): the page miss was
traced to two independent causes, both now fixed in this repository:

1. `run98260.sh` launched the legacy `exploit-android-key-ptr` plant before the
   H1C dispatch.  On g186 that plant ran with 6.12-era k_itimer geometry, so the
   boot always carried two competing UAFs; the legacy block is now BRM-only.
2. `uaf_plant.c` `pfn_in_line()` required an exact head-PFN match.  Once
   `skb_page_frag_refill()` merged the freed order-1 slab into an order-2/3
   compound page, the trace recorded the compound head, so every write missed
   (`writes=480 hit=0`).  It now parses `order=<N>` and matches the whole
   compound range.  `cve98260_plant` was rebuilt from the patched source.

On-device exploit verification of these changes is still pending.
