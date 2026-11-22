# 6.1.157 support audit

Reference APKs inspected on 2026-11-02:

```text
MagicRoot-98260-1.0.35-6157.apk
MagicRoot-Pad3-1.0.10.apk
```

The Pad3 `43499-pd3x` route is **skipped** as requested.  No Pad3 / `gaaa383620ebf`
assets or kernel profile were imported.

2026-11-07 update: the user explicitly supplied a `gaaa383620ebf` boot and requested
support.  It now has its own 98260 static payload and remapped CGA base through the
existing `run6157_full.sh` route; this does **not** introduce the 43499/Pad3 route.
See `docs/61157-GAAA-ADAPT.md`.  No matching-device run has been performed.

2026-11-11 feature restoration: only g264 and gaaa now use 226-symbol/221-stub
CGA modules with `su_compat`, `kernel_umount` and `selinux_hide`.  The build and
static proof are in `docs/6157-CGA-FEATURE-RESTORE.md`; no device-side module
load has been performed.  Other profiles, including g19a's separate upstream
module, remain unchanged.

2026-11-13 g8d6: the supplied `boot_ota_1794143607737.img` is
`6.1.157-android14-11-g8d63307071ad`.  Its BTF layout is `0x840/0x118`
(cred `0xb0`), and its payload/CGA/syms were derived from that exact image;
the payload hash happens to match g84 because all seven patched addresses
and both layout constants coincide, while the CGA module and syms table are
build-specific.  No device run yet.  Details: `docs/6157-G8D6-ADAPT.md`.

2026-11-21 g08de: HyperBreak integration analysis confirmed
`6.1.157-android14-11-g08de1e2b38ba` is still vulnerable to the 98260
exec/timer bug, and its 98937 KASLR constants were added to
`main/app/assets/kaslr-98937/targets.conf`.  There is no payload or CGA
module for this build, so it is **not** dispatched by `run6157_full.sh`.
Details: `docs/6157-G08DE-ADAPT.md`.

6.1 retry profile: for exact 6.1 profiles the app now exports
`attempts=6`, `churn_per_cpu=32`, `wait_cap=8` (the runner's own tuned
values), instead of the 98260 UI defaults 12/256/25.  The other chains
(6.12/6.6/6.18) keep the UI values.

2026-11-07 unification: all 6.1 deployment now uses the profile-driven
`KernelLogHelper.shouldStage6157Asset`; the runner derives payload/CGA paths from
one `P6157` selector.  Deployed assets are checked against
`6157-integrity.tsv` before UAF, existing persistent root is verified before a
new attempt, and CGA handoff calls are bounded.  g7d M6 and g19a legacy remain
isolated backends.  Full reverse report and exact verification limits:
`docs/98260-EKROOT-1.67-REVERSE.md`.

## Current 6.1.x routes

`main/app/assets/run.sh` dispatches every supported 6.1.x build to
`98260/run6157_full.sh`:

| Kernel | Target | Root path | KSU handoff |
| --- | --- | --- | --- |
| `6.1.157-g7d3922fade43` | Magic6 系列 / ELP-AN00 / V3 | 98260 payload + M6 | `ksu6157-m6/` (OS9 module + `ko_patch2`/`load_ko`) |
| `6.1.157-g2646292297b1` | GT / 400Pro / 300 / VFlip2 | 98260 payload + CGA | `ksm-g264-base.ko` + manager ksud |
| `6.1.157-gaaa383620ebf` | supplied boot; no model gate | 98260 payload + CGA | `ksm-gaaa-base.ko` + manager ksud |
| `6.1.157-g3306a328b7be` | 400 Pro MagicOS 11 | 98260 payload + CGA | `ksm-g3306-base.ko` + manager ksud |
| `6.1.157-g84ffa64b710b` | Magic6 series MagicOS 11 | 98260 payload + CGA | `ksm-g84-base.ko` + manager ksud |
| `6.1.157-g77f76e323a02` | Magic V3 MagicOS 11 | 98260 payload + CGA | `ksm-g77f-base.ko` + manager ksud |
| `6.1.157-g8d63307071ad` | supplied boot; no model gate | 98260 payload + CGA | `ksm-g8d6-base.ko` + manager ksud |
| `6.1.99-gce84935796c9` | Magic6 series / V3 MagicOS 9 | 98260 payload + CGA | `ksm-gce849-base.ko` + manager ksud |
| `6.1.99-g5859fbdbad8c` | GT / 300 series MagicOS 9 | 98260 payload + CGA | `ksm-g5859-base.ko` + manager ksud |
| `6.1.99-g54d40b4fb287` | 400 Pro MagicOS 9 | 98260 payload + CGA | `ksm-g54d-base.ko` + manager ksud |
| `6.1.128-g40b1fd119d9b` | 200 Pro MagicOS 9 | 98260 payload + CGA | `ksm-g40b1-base.ko` + manager ksud |
| `6.1.128-g8a4968670f1c` | old X70 boot profile | 98260 payload + CGA | `ksm-g8a496-base.ko` + manager ksud |
| `6.1.128-g2e1f0741dafb` | old X70 Pro Max boot profile | 98260 payload + CGA | `ksm-g2e1f-base.ko` + manager ksud |
| `6.1.99-ge9da27488f45` | VFlip2 MagicOS 9 | 98260 payload + CGA | `ksm-ge9da-base.ko` + manager ksud |
| `6.1.157-g19a495a97bff` | MagicPad3 | 61157 route | 43499 route skipped |

There are no model/BTF/config gates on the CGA route.  The exact `uname -r`
selects the payload directory and `ksm-*-base.ko`; the runner fails closed for
unknown builds.  g7d uses the restored, historically proven M6 handoff; g264
keeps the g264 CGA/su inputs.  Every CGA build uses its own base module.

g7d's M6 handoff and g264's CGA/su route both have historical device closures.
The rebased g3306/g84/g77f/g8d6/gce849/g5859/g54d/g40b1/ge9da and the new
g8a496/g2e1f payloads are static adaptations until re-run on hardware.  See
`docs/6157-SUCCESS-CHAIN-REBASE.md`, `docs/61128-OLD-KERNELS-ADAPT.md` and
`docs/6157-G8D6-ADAPT.md`.

2026-11-04: g84 is now rebased from the proven 1.0.36 static blind payload.
Its BTF-audited layout remains `task_struct.cred=0x840`,
`k_itimer.size=0x118`, and its payload SHA-256 is
`6b118559a691f45d51cccb0815b623b1d03c5801df40f2beb34b995659bcc7d6`.
The same rebase also corrected g77f, gce849 and g40b1 to the audited
`0x840/0x118` family; their previous 34 KiB payloads still encoded
`0x838/0x108`.  The g84
KSU module's 57 task_struct field remaps and absolute symbols were audited
against the attached boot image previously.  No g84 device test exists yet;
see `docs/6157-SUCCESS-CHAIN-REBASE.md` and
`docs/6.1.157-G84-BOOT-VERIFY.md`.

## Reference route differences

`MagicRoot-98260-1.0.35-6157` contains a newer non-Pad3 route:

```text
assets/43499-6157/       (dc_ksu_run.sh and KSU handoff tooling)
assets/ksu6157/          (official 6.1.157 KSU module)
assets/ksu6157-g264/     (g264-specific KSU loader/prepare)
assets/g264/             (ksm-g264-base.ko, ko_slide_patch)
```

The reference Pad3 APK adds:

```text
assets/43499-pd3x/       (skipped)
```

The current app contains `61157` + `ksu6157` for the legacy ELP MyUse path,
and `ksu6157-g264` + `g264` for the CGA path.  The g264 CGA base and the
per-build remapped modules are third-party-derived binaries; their provenance
and hashes are recorded in `BINARY-SOURCES.md`.  They are not claimed to be
fully reproducible from this repository alone.

## Multi-manager status

| Kernel family | 5 Flavor asset selection | Actual manager matrix |
| --- | --- | --- |
| 6.12.58 / 6.12.38 / 6.12.23 | complete | all five flavors |
| 6.6.118 / 6.6.58 | complete | all five flavors |
| 6.18.21 98260 (g928/g186) | complete | all five flavors |
| 6.18.21 64560 (g928) | official single template | official KernelSU only |
| 6.1.157 / 6.1.99 / 6.1.128 CGA | per-build `ksm-*-base.ko` + manager-LKM test path | five flavors selectable; app-carved manager LKM is patched and tried first, CGA/M6 fallback |
| 6.1.157 MagicPad3 | skipped | skipped |

2026-11-13 test build: every 6.1.x CGA profile now first tries the selected
manager's own LKM (`ko-<flavor>.ko`, carved by the app).  It prefers a runtime
`/proc/kallsyms` table (`name 0xADDR`, slide=0) and falls back to the build's
`g264/syms-<build>.txt` + boot slide when kallsyms is masked; then rewrites the
vermagic and `insmod`s it.  Any patch/insmod/probe failure falls back to the
per-build CGA module (or M6 for g7d).  This is an on-device test path: the CGA
LKM remains the proven route, and non-official managers still need per-build
runtime verification.

gaaa run `20261113T081541` showed the CGA base `_printk` at link+slide
`0xffffffe4b2d82dbc` while the device kallsyms had `...1fbc` (0xE00 off), so
that base does not match the running gaaa build.  The manager-KO test path
therefore uses runtime kallsyms first; the CGA fallback remains fail-closed on
that device until its base is rebuilt from the correct image.

2026-11-13 19:51 gaaa + SukiSU 4.3.0-r2 (manager KO `6.1.166-dirty`):
runtime kallsyms 217,184 lines → `PATCHED=254 MISSING=0`, `insmod rc=0`,
`98260_KSUD_INSTALL_RC=0`, `98260_SU_PROVIDER=ready`, and
`98260_KSU=loaded method=manager-ko-patched`.  This confirms a 6.1.166 GKI
manager LKM can be relocated onto the 6.1.157 vendor kernel.  The runtime
table is now mandatory by default; the per-build `g264/syms-<build>.txt` is an
opt-in fallback (`MAGICROOT_6157_MANAGER_KO_ALLOW_CGA_SYMS=1`) because its
CGA base addresses can be stale.

Asset completeness for the flavor matrix is checked by:

```bash
tools/audit_kernel_flavors.sh
```

It reports 60/60 profile × flavor template/syms pairs present.  That does not
mean every path can actually initialize each manager.  For 6.1.x the runner
now extracts the selected manager's `ksud` and tries it first; the CGA module
is a KernelSU-compatible LKM, so non-official managers remain runtime
compatibility tests rather than guaranteed combinations.

## Binary source-buildability

| Binary group | Source / provenance |
| --- | --- |
| `binary-sources/61157-g264` | C sources for g264 loader/plant |
| `binary-sources/6157-g264` | g264 pipeline/deploy scripts, `ko_slide_patch.c`, `su_lkm.c`, CGA sources |
| `binary-sources/61821*`, `64560`, `66118`, `6658`, `98260-6.12` | existing source/build trees |
| `61157/kernelsu-honor.ko` | MyUse external build tree; no in-repo source copy |
| `61157/ksud` | manager-upstream binary; extracted from the installed manager |
| `61157/brm_plant*`, `ksu-loader*`, `pc98260_su` | reference/MyUse binaries; only partial in-repo sources |
| `ksu6157/*` | reference APK binaries; no in-repo source |
| `ksu-template*.ko` | upstream manager/MultiSU templates; provenance in `BINARY-SOURCES.md` |

The release still contains third-party binaries that cannot be rebuilt from
this repository alone.  They are documented as provenance-locked rather than
silently treated as reproducible.  No new opaque Pad3 binary was added.

## Remaining work

- Re-run the current APK on real hardware.  g7d M6 and g264 CGA/su have
  historical successful closures, but the rebuilt payloads/runner must be
  revalidated.  gaaa, g3306, g84, g77f, gce849, g5859, g54d, g40b1, g8a496,
  g2e1f and ge9da remain static-only CGA adaptations.
- Non-official manager compatibility on 6.1.x (the `ksud` extraction path is
  implemented; runtime protocol compatibility still needs a device).
- If complete MagicPad3 support is required, use the skipped `43499-pd3x`
  route; this is intentionally out of scope now.

## 2026-11-02 update: upstream 1.0.36 route

- g7d3922fade43 and g2646292297b1 now use `98260/run6157_full.sh`, imported
  from MagicRoot 1.0.36 source.  This removes the old 61157 path bugs
  (`$D/61157/61157/...`), the ELP-AN00-only model gate, and the BTF/config
  hash gates.
- The imported route uses:
  - `98260-6157` (g7d) / `98260-g264` (g264) payloads
  - `ksu6157` / `ksu6157-g264` KernelSU handoff
  - `g264` + `su-g264` CGA module/overlay for g264
- g19a495a97bff (MagicPad3) keeps the existing 61157 route; no new Pad3
  assets are required and 43499 is not introduced.
- `ksu6157/ksu-syms.txt` is stored with LF endings; no CRLF table.
- No model/BTF/build-hash restriction is added for g7d/g264; the exact
  `uname -r` prefix selects the upstream runner.

## 2026-11-03 asset deployment fix

6.1.157 g264 previously deployed `run6157_full.sh` but skipped the whole
`ASSETS_98260` loop for the release, so `98260/run98260.sh` was absent.
`run.sh`'s 98260 entry guard only accepted `run98260.sh`, producing:

```text
FAIL=chain_98260_assets_missing dir=/data/local/tmp/magic/98260
```

The guard now accepts any of:

```text
98260/run98260.sh
98260/run6157_full.sh
61157/run61157.sh
```

`buildStagePlan` explicitly stages `98260/run98260.sh` for every 6.1.x
release, `localDeploymentReady` accepts the g19a `61157/run61157.sh`
deployment, and `requireCriticalAssets` checks the route-specific script
(g19a → `61157/run61157.sh`, other 6.1.x → `98260/run6157_full.sh`).
No kernel/payload bytes or deployment filters for 6.12/6.18 were changed.

## 2026-11-13 per-build 6.1.x symbol table completion

- `tools/gen_6157_syms_from_cga.py` and `binary-sources/61157-g264/cga-profiles.json`
  now merge exact per-build symbols alongside the CGA `SHN_ABS` base symbols:
  - `g8d6`, `gaaa`, `g8a496`, `g2e1f`: full 108 extra symbols extracted from
    each build's exact `vmlinux.elf` (`363`/`369` symbols total; `ko_patch`
    `MISSING=0` and `TRACK_THRONE=patched` across all five flavors' 6.1
    manager LKMs and `kernelsu-honor.ko`).
  - `g7d`: 107 extra symbols from `61157/syms_elp_an00.txt` unbiased to raw
    link addresses (`357` symbols total; `MISSING=0` and
    `TRACK_THRONE=patched` across all five flavors' 6.1 manager LKMs and
    `kernelsu-honor.ko`).
  - `g264`: extra symbols from `61157/syms_g264.txt` + `success-profiles.json`
    (`269` symbols total; `MISSING=0` against `kernelsu-honor.ko` and
    `TRACK_THRONE=patched` across all five flavors).
  - Remaining 8 builds (`g3306`, `g84`, `g77f`, `gce849`, `g5859`, `g54d`,
    `g40b1`, `ge9da`): exact per-build `init_cred` (`groups + 8`),
    `init_groups`, `init_user_ns`, `root_user`, `init_ucounts`,
    `selinux_state`, and `sig_enforce` from `success-profiles.json` (`256`
    symbols total; `TRACK_THRONE=patched` across all five flavors, and full
    `commit_creds`/`init_cred` coverage for second-pass CGA fill).

