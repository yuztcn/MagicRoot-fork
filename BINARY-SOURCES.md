# Reproducible binary build sources

## Toolchain

- Android NDK **r28c** (`Pkg.Revision = 28.2.13676358`)
- clang wrapper: `aarch64-linux-android35-clang`
- flags: `-std=gnu11 -O2 -w -pthread -static`

## 98260 actual 6.12 binaries

The released 98260 binaries are **not** the early upstream reference binaries.
That reference binary lacks MagicRoot's 6.12 `--no-real-cred` option and fails
immediately when used by `run98260.sh`.

Source lineage: `binary-sources/98260-6.12/uaf_plant_61258.c` is a modified
derivative of `EAEdward/xiaomi9pmroot` (MIT, commit `b2dbd18d4327`); the local
header records that the logic is unchanged from `uaf_plant_v6.c` except the
marked PORT points.  `rootd.c` extends xiaomi9pmroot's `pc98260_rootd.c`, and
`su98260.c` is the same `pc98260_su.c` source with CRLF line endings.  An
earlier upstream project was a technical reference for target constants and
build parameters, not the source base; it is not redistributed or attributed
here.

Actual source:

```text
binary-sources/98260-6.12/
  uaf_plant_61258.c
  stubs.c
  rootd.c
  su98260.c
  pc98260_target.h / pc98260_target_61258.h / pc98260_target_6138.h
  build-98260-6.12.ps1
```

The 6.12 plant calls `prctl(PR_SET_CHILD_SUBREAPER, 1)` before any fork, so
helpers orphaned by a failed UAF attempt reparent to the exploit parent instead
of init.  This prevents init from reaping a timer-corrupted task; a later
`kill`/`waitpid` on such a task would itself panic.

Expected release hashes (verified by the build scripts):

```text
fe67a61d09393a7bdb3c0927a87947e66da166a6f38664ef1c5381ac76f28f73  exploit-android-key-ptr (6.12.58)
99fe9581a79fb2a5df80bf43c18a4e72025954c4cd63c854fc985369dcaba6bb  exploit-android-key-ptr (6.12.38)
696240ec583616d3677e693d1e5d3783b7f590b682ace8d7ca830bc757516ca5  pc98260-su
```

### 2026-11-05 6.12.58 payload update (compound-page reclaim)

The 6.12.58 payload shipped in 1.0.5 (asset hash `0b58827d…d377f65`) never
matched the `fe67a61d…` hash above; the asset in the 1.0.5 baseline was built
outside the checked-in PowerShell recipe.  The asset was therefore rebuilt from
the checked-in source for this fix:

- `uaf_plant_61258.c`: `find_page_free()` / `find_page_alloc()` /
  `pfn_in_line()` now match a `kmem` event whose `pfn` + `order=` range covers
  the victim, instead of comparing only the head PFN.  On 6.12,
  `skb_page_frag_refill()` allocates order-2/3 page_frags and buddy merging can
  fold the freed order-1 k_itimer slab into such a compound page; the old exact
  match then reported `page_freed=0` for the whole wait cap and the attempt was
  wasted (`writes=480 hit=0`).  This is the same defect class fixed for the H1C
  plant on 6.18.21.
- Built on-device with the Termux clang 21.1.8 driver
  (`clang -std=gnu11 -O2 -w -pthread -I binary-sources/98260-6.12`) as a
  **dynamically linked bionic PIE** (`interpreter /system/bin/linker64`).
  The Termux toolchain has no static bionic libc (`libc.a`/`crtbegin_static.o`
  are not shipped), so the `-static` recipe cannot be reproduced on-device.
  The kernel-side race (`execve("/proc/self/exe")` + `tgkill`) is unchanged;
  only the payload's userspace loader differs.

```text
788f53546a9b00527b9993792d5a43f64ad74881f1a4cf080c94f1b3ec580ee0  exploit-android-key-ptr (6.12.58, 2026-11-05, dynamic PIE, 58,552 B)
```

The `-static` PowerShell recipe in `build-98260-6.12.ps1` still checks the old
`fe67a61d…` hash; rebuilding with it requires re-running the hash gate after the
source change.  Other 6.12 profile payloads (61258b/61258c/6138/…) were **not**
rebuilt and keep their existing binaries.

### 2026-11-06 6.12.58 timer-UAF reaping fix

The on-device 6.12.58 payload now calls `prctl(PR_SET_CHILD_SUBREAPER, 1)` before
any UAF child is created and ignores ordinary session-teardown signals in the
parked parent.  Orphaned helper/victim zombies therefore stay with the exploit
parent instead of being reaped by init through the corrupted
`posix_cpu_timers` tree.  Stream reclaim also accepts an allocation hit only when
the trace task PID is the exploit itself; a PFN-only hit from a kworker/another
process is a miss, never a reason to reap an unproven node.  The successful,
deliberately controlled UAF reap is unchanged; a zygote-only restart remains
available for Zygisk Next/LSPosed.

The unchanged source first reproduced asset SHA-256
`788f53546a9b00527b9993792d5a43f64ad74881f1a4cf080c94f1b3ec580ee0`
bit-for-bit.  Rebuild with Termux clang 21.1.8 using the same dynamic PIE command
above.  The fixed asset is 59,048 bytes:

```text
53153702d10404a88a72194967bf8a8418776fb61046579d0cc782872beb4a8a  exploit-android-key-ptr (6.12.58, 2026-11-06)
```

Only `main/app/assets/98260/exploit-android-key-ptr` was replaced.  Other kernel
payloads retain their previous hashes.  `tools/test_98260_uaf_lifecycle.py` is
the offline regression gate; it does not replace an explicitly approved
on-device UAF/zygote test.

### 2026-11-07 6.12.58 armed-victim ledger + proven-reap fix

The remaining timer-UAF lifetime hole: a post-arm reclaim miss left its victim
child parked as an unreaped zombie, and the retry loop could then report
success in a session still carrying failed victims.  If that zombie's freed
slab page was later owned by a foreign allocation, the next `wait4` ->
`release_task` -> `posix_cpu_timers_exit` -> `timerqueue_del`/`rb_next` reaped
it through arbitrary rb_node contents (the fatal dumplog stack).

`uaf_plant_61258.c` now keeps a victim ledger.  Every armed child is recorded
with its slab halves (`mm_page_free`/`mm_page_alloc` trace timestamps order
the events).  On a miss the victim is classified:

- cover by a foreign allocation -> `UNPROVEN`, zombie stays parked;
- cover by our own spray -> proven, `waitpid` reaps it;
- freed but still in the buddy -> **zero-page repair**: bounded spray of
  all-zero pages (`{0,0,0}` rb_nodes unlink harmlessly in `timerqueue_del`)
  until the trace proves our allocation covers every needed half, then reap;
- no complete free observed -> stays `OPEN`, resolved by `victim_sweep()`.

`victim_sweep()` runs before success parks and before the failure hold, so a
successful session carries zero unproven victims; `[victim] summary` logs the
tally.  A post-arm error path that previously returned with an armed zombie
now kill+reaps it (the slab is still live at that point).

Built on-device with Termux clang (dynamic bionic PIE, same recipe as the
2026-11-05 build).  The fixed asset is 72,704 bytes:

```text
5091a36b08549832fa4818e7dab4aae2f20bc03368ff8d229c885ed259f1081a  exploit-android-key-ptr (6.12.58, 2026-11-07)
```

### 2026-11-07b lifetime hardening after two observed panics

Dumplog 20261107131212/20261107131613 showed the same fatal stack twice more
(`wait4 -> release_task -> posix_cpu_timers_exit -> rb_next`) while init reaped
armed exploit zombies — i.e. the ledger alone cannot prevent a panic whenever
the exploit parent dies (SIGKILL is unmaskable; init's stop/kill-all on
soft-reboot reaches it).  Two changes close the residual window:

- `victim_sweep()` now reaps OPEN victims whose slab never produced a
  complete free event, but only after a full untruncated rescan
  (`victim_scan_budgeted(v, SIZE_MAX)`).  A never-freed slab still contains
  valid k_itimer nodes, so reaping is the same benign unlink as the success
  path; parking it instead was a guaranteed bomb on any later parent death.
- The parked parent now runs `victim_watch_forever()` instead of `pause()`:
  every 5 s it rescans all OPEN/UNPROVEN victims and attempts a zero-page
  repair; a foreign-covered page that cycles back to the buddy is reclaimed
  and its zombie finally reaped.  Truly foreign-owned slabs stay UNPROVEN —
  that is the residual bomb userspace cannot remove (documented, not hidden).

```text
01d52e27be1a6dce0bf04467cd00f799ec309fb013df377b5e60a39e730ef691  exploit-android-key-ptr (6.12.58, 2026-11-07b)
```

All nine rebuildable payloads (61258b/61258c/6138/6123/6138y/g856/aph112/
6658/6689) were rebuilt again with the same source; current hashes:

```text
4333984cd477abde05611e560ae2762ebd07311a6c41e1b84c97ac3cde227396  98260-61258b
4333984cd477abde05611e560ae2762ebd07311a6c41e1b84c97ac3cde227396  98260-aph112
bdb6225fc19e94e253e6070e4294c929d9e391ae9d67d1c63eccddf34845854c  98260-61258c
c9449f1366cf525ac24a2cf3c495bd1655554a5e0d8ead7c3222d71ec3f4492b  98260-6138
03a84e055da8ce5a9fc8c7b3d541cafc770dc06131b99bdf5f6531b7d86d9ded  98260-6123
822898a9d343dd07a42609b7d1b5420d72eb675f43c5d54b9f571baaea86f1db  98260-6138y
47827a2c451ff1cf2e5519e827c41c40fb8afc89a3bb81cc7e1f73c3991c18ba  98260-g856
9b49c03c288ac1d0085ca7b1ccb6ffc326ac28ce88b21e0d4eed854d095c37f2  98260-6658
af1301dbd39975ea7aa2b1a13bcf8f7aef3469ef812028161b6a101a33622643  98260-6689
```

Only `main/app/assets/98260/exploit-android-key-ptr` was replaced; the other
6.12/6.6 payloads (61258b/61258c/6138/6123/6138y/g856/aph112, and the 6658 /
61821 source copies) still carry the pre-ledger lifetime behaviour and need a
matching rebuild with their own target headers before they can claim the same
guarantee.  `tools/test_98260_uaf_lifecycle.py` locks the ledger/sweep/reap
contract offline; on-device UAF runs remain an explicitly gated test.

### 2026-11-07 fleet rebuild (ledger payloads) + H1C session shield

All targets whose `pc98260_target_*.h` exists were rebuilt on-device with the
ledger source (dynamic bionic PIE, same recipe as 6.12.58):

```text
f80e1d47dbe9f2c6681efcb18d25e43ca9d1d480dead1b1cbc8a0b9cc621eaa9  98260-61258b
f80e1d47dbe9f2c6681efcb18d25e43ca9d1d480dead1b1cbc8a0b9cc621eaa9  98260-aph112 (same g459 kernel as 61258b)
c989cde290152753cfbf822f0abcf0e8bc32b9431f0948eebdeb36422b790b78  98260-61258c
7165046310ba1add45fa5a50e772e74be82e08cac1823aea5437eacacc90c8e0  98260-6138
d3d2d4e50a974d2b82d26390007492fbbab37fefe1ca7be6c81416667c668c34  98260-6123
8e105825b5f9d1b26d7ccdbe7acbd80325b384fbedb6f8283fb4e71f78c00621  98260-6138y
49c66623f2580f63f736f663119dd1e2fac3f2f6b65ec18828dd5a944b063c8c  98260-g856
83323c692a9fe78d24f2311ca1c8ef24a60f0f408724e3a349f6e6404871bd9c  98260-6658
d9f95eb0b1b05c87ad7b16018ec9337076020c255d54d7ec2efdd18a2979c752  98260-6689
```

6.6 builds: `binary-sources/6658/uaf_plant_61258.c` was refreshed to the ledger
source and `binary-sources/6689/` gained a shim `pc98260_target.h` plus the
source/stubs/rootd trio — both build with the same one-liner used for 61258.
Each binary's `--check` reports the correct `build_target` for its kernel.

Not rebuildable here (left at provenance-locked upstream binaries, same
pre-ledger miss semantics: the process parks on a miss — an improvement over
the 6.12 retry-loop, but without ledger/ledgered reaping):

- 98260-f171 / 98260-g554 (6.6.118): no `pc98260_target` header with the full
  `LINK_*` set exists locally; the shipped static payloads were supplied, not
  built from in-tree sources.  Deriving headers needs the f171/g554 vmlinux.
- All 6.1.x payloads (g264 family, g7d, g3306, g84, g77f, gce849, g5859, g54d,
  g40b1, ge9da, g8a496, g2e1f): the shipped binaries are upstream-derived
  static payloads rebased via `rebase_success_payload.py`; there is no source
  that compiles to these bytes.  `binary-sources/61157-g264/uaf_plant.c` is
  reference-only.
- 98260-61821* BRM payloads: dead at runtime (6.18.21 forces H1C).

`build-98260-6.12.ps1` now builds dynamic PIE (no `-static`), includes the
`g856`/`aph112` kernels, and its expected-hash table lists the ledger hashes;
the old `-static` Windows NDK recipe cannot reproduce them.

`binary-sources/98260-h1c/uaf_plant.c` gained the same session-teardown shield
the 6.12 plant already had (SIG_IGN for SIGHUP/SIGTERM/SIGINT/SIGQUIT): a
parked H1C parent is the UAF page holder and must survive userspace stop/start
so init never inherits its zombies.  H1C's existing `UAF_POISONED →
park_poisoned_process()` flow already satisfies "a successful session carries
no unproven victim" — it never retries a poisoned attempt.

```text
836a9ea5c153273c130dc34b154261458b8f5dd98d6a65961606d78deebc0c54  98260-h1c/cve98260_plant
```

`main/app/assets/run.sh` rootd-listener helper: parent discovery now starts
with init's `task/*/children` (the parked exploit parent is a direct child of
PID 1) instead of scanning every `/proc/*/comm`; the full scan remains as
fallback.  Per-phase `ROOTD_CLEAN_PHASE=` markers make a future timeout
pinpoint the stall; the default result wait is 8 s (was 5 s).

### SukiSU late-load workqueue fix (6.12.58)

SukiSU late-load skips `ksu_ksud_init()`, including
`INIT_WORK(stop_input_hook_work)`, but the first zygote `on_post_fs_data()` still
schedules that uninitialized work item.  This caused the recoverable
`__queue_work` WARNING seen before the independent fatal timer-UAF panic.
Upstream reference: SukiSU-Ultra `v4.3.0-r2`, commit
`645ef9860b9b7f900bb5d1b27e224f2c311d39c0`, kernel module license GPL-2.0.

For the late-load-only template, `ksu_stop_input_hook_runtime()` is semantically
a no-op because no input kprobe/work was installed.  The deterministic
`tools/patch_sukisu_lateload.py` verifies the input hash and ELF symbol, then
changes the third instruction (TBNZ at function+8) to `RET`.  The first ADRP and
second LDRB carry relocations and must remain intact because the kernel applies
them again at insmod; patching either would create a relocation/control-flow
overlap.  The tool rejects any patch target that still has an ELF relocation.
It does not patch arbitrary manager modules and does not alter Zygisk injection.

```text
input   9f999173fa65b3eb3a90e2becf2bf5ec42a5c5f7d58106802aaa9f8c16f71048  ksu-template-sukisu.ko (41150, 648,056 B)
output  bf41885860d1c01cef780dc5b31aabf01c8513f090aef264947f426c30f51442  ksu-template-sukisu-lateload.ko (648,056 B)
```

The input is the user-supplied SukiSU 41150 `android16-6.12` LKM with Build ID
`74ee27251faf31f5eb96c46069760689ea77a35d`.  It replaces the older 41100
built-in baseline.  The previous input/output hashes remain in git history.

Loading is controlled by the persistent UI switch **内置 SukiSU late-load 修复模块**
(default off).  When enabled for the exact 61258/SukiSU route, MainActivity skips
manager-LKM extraction and removes stale `ko-sukisu.ko`; run98260 uses only the
patched asset through `ksud insmod`, with direct `insmod $PATCHED` as the sole
fallback.  It never enters the manager-embedded late-load primary path.  The
manager still supplies its userspace `ksud`.

### 2026-11-07 cross-kernel verification + on-device auto-patch

The patch was verified to be **kernel-version agnostic**.  The SukiSU 41150
manager native library (`lib/arm64-v8a/libtqqfthevwb.so`) ships raw-deflate
compressed modules for several KMIs; `ksu_stop_input_hook_runtime` was located
by ELF symbol in each and the prologue compared:

| vermagic | prologue | TBNZ site | relocation |
|---|---|---|---|
| 6.6.127-4k | ADRP + LDRB + TBNZ | +8 | none (safe) |
| 6.12.76-4k | ADRP + LDRB + TBNZ | +8 | none (safe) |
| 6.18.32-4k | BTI + ADRP + LDRB + TBNZ | +12 | none (safe) |

The 6.12.76 variant is byte-identical to the built-in patch input
(`9f999173…`), confirming the built-in patched module equals "carved manager
KO + patch".  On 6.18 a BTI instruction precedes the sequence, so the TBNZ is
located by scanning for the ADRP+LDRB+TBNZ pattern, not by a fixed offset.

New `SukisuLateLoadPatch.java` implements this structural patch in the app:
find the symbol, scan for the sequence, verify the TBNZ, refuse if the site is
a relocation, then write RET.  `MainActivity.extractManagerLkm` now applies it
to every carved SukiSU KO and writes `ko-sukisu-lateload.ko` next to the raw
`ko-sukisu.ko`; run98260.sh prefers the auto-patched KO for the SukiSU
late-load path (`98260_KSU_AUTOPATCH=1`), so the per-kernel pre-patched
built-in template is no longer required.  The built-in switch remains as an
explicit alternative; if the prologue does not match (a different SukiSU
build), auto-patch returns null and the raw manager KO is used unchanged.

`tools/tests/SukisuLateLoadPatchTest.java` locks the contract: patching the
built-in input reproduces the built-in patched module byte-for-byte
(`bf418858…`), and junk/truncated inputs are refused.  It runs in check.sh.

The 41150 module added six imports not present in the old symbol table.  The
current B-slot boot image (SHA-256
`ae921fa30afe1554d32912716d869314827db495172748adda7d65aee45ad915`) was read
without modifying any partition and exported offline with
`tools/ExportKernelKallsyms.java`: kernel `6.12.58-android16-6-g3a7ac1674240…`,
129,131 symbols.  All 247 pre-existing `syms_61258_sukisu.txt` entries matched;
`bpf_get_btf_vmlinux`, `btf_find_by_name_kind`, `btf_name_by_offset`,
`btf_type_by_id`, `btf_type_skip_modifiers`, and `copy_from_kernel_nofault` were
then added from that exact image.

Offline `ko_patch` result for the 6.12.58 target is now
`PATCHED=251 MISSING=0`, with the exact target vermagic.  No module was loaded
during this static verification.

Build:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\build-binaries.ps1 `
  -NdkHome C:\path\to\android-ndk-r28c `
  -Install98260
```

The script builds both kernel profiles and verifies the exact hashes above.

## 6.18.21 g928 KernelSU template (HOneClick SU access fix)

Source of the change: HOneClick upstream `0ede556` + `docs/SU_ACCESS_FIX.md`.
The patched template is byte-identical to the upstream output:

```text
ksu-template.ko  492,728 bytes
sha256 86ed32a0946490736850d0c5d7a703c6e5bfde541e82864ed892b31e2b590563
input  e33b7c5dbbef2206571c99b13eadf1bc99a11d3182f6e5f3e2540c6ca9568003
```

It is used by both g928 paths:

```text
main/app/assets/64560-61821/ksu-template.ko
main/app/assets/98260-61821/ksu-template.ko
```

The input template's `prepare_creds()` bootstrap is replaced with
`prepare_kernel_cred(&init_task)`; the module symbol table is otherwise
unchanged. Audit: `docs/UPSTREAM-HONECLICK-20261101.md`.

## 6.18.21 boot profiles

```text
docs/6.18.21-BOOT-PROFILES.md
```

Records the g928/g186 boot image and kernel hashes, BTF/config sizes, and the
exact `uname -r` gates used by the profiles.

## HOneClick 98260 runtime

Source: HOneClick upstream `0ede556` (`native/cve98260/`), copied to
`main/app/assets/98260-h1c/` for the g928/g186 route.  Hashes:

```text
29d2d2507a14a630c4462646c5f3b17686541aaa8258b18a1d7411b2a4fc8b77  cve98260_plant (rebuilt 2026-11-04)
d6ab7421c3ee86894056e6d1821baad2f5c56e4fc09b289617071ac6a630987e  cve98260_slide
c63e4d87b2db4c1f86e0da919be744bc06172f01e0977867105c1f9fe32148f7  cve98260_su
20e144a5dd25556e21fafa4ac2cb7feba444e41d6a190631ee95b862ea393ca6  cve98260_module
```

`cve98260_plant` is the only helper rebuilt in this repository.  It is compiled
from `binary-sources/98260-h1c/uaf_plant.c` + `pc98260_rootd.c` (copied from
HOneClick upstream `native/cve98260/`) with the compound-page `pfn_in_line()`
fix documented in `docs/61821-115-CHAIN-ANALYSIS.md`:

```sh
sh binary-sources/98260-h1c/build-cve98260-plant.sh
```

The script is deterministic with clang 21 on this device and reproduces
`29d2d250…4fc8b77` exactly.

Upstream builds it statically with NDK r28c + `-static`; this checkout builds a
dynamic PIE (Termux clang 21, NDK r30 headers, Android 24+).  The app-level
strings match the upstream binary exactly apart from the added `order=` token,
which confirms the source correspondence.  The original upstream hash was
`2d1a106c5508c9d680cf72c9d0c0bc5e86e09a8173cf82bdcd4908dbd37f6c36` (441,608 B).

Official g186 HOneClick 115 template, bootstrap-credential patch applied
(2026-11-04; `prepare_kernel_cred(&init_task)` instead of `prepare_creds()`,
same patch as the 109 template):

```text
438,096 B
sha256 97022c36f9888469146b71a5917bc0fe95c28f2c4816ce8c601e3fe5a2fcdae0
main/app/assets/98260-h1c/ksu-template-115.ko
main/app/assets/98260-61821-brm/ksu-template-61821-kernelsu.ko
main/app/assets/98260-61821-brm/ksu-template.ko
```

Original upstream hash was
`f8dd188f3feb05998f145286c4093da2aaa944fca2cb226db561b1b784761f1e` (375,616 B).

H1C uses it for the g186 official Flavor.  On 2026-11-03 the stale
`98260-61821-brm/ksu-template-61821-kernelsu.ko` (built from a 6.12.76 base)
was replaced with this same upstream 115 image, so the pre-UAF/legacy path no
longer carries a foreign-vermagic template.

Engine contract: `docs/98260-H1C-ENGINE.md`.

## 6.12.58 g42fcf008ff5c (provided boot image)

`pc98260_target_61258c.h` is derived from the provided boot image; symbols and
all five Flavor syms tables were regenerated from its `vmlinux.elf`.  Details
and hashes: `docs/6.12.58-G42FC-ADAPTATION.md`.

```text
boot image sha256  0385dbba2869c5669b676223d5d1101e500671415a1f3732ecf8c1e770453c99
kernel sha256      490d074be61dff039a937e404636bc19e04efdddf6665789505b8f82f9b5bf5e
exploit sha256     92724e6a7976c11443a986e88f45b3bcc97db53217faab8ee53546b46f72a9d9
```

Rebuild:

```powershell
.\binary-sources\98260-6.12\build-98260-6.12.ps1 `
  -Kernel 61258c -NdkHome <ndk-r28c> -Install
```


The byte-identical reference copy `cve-98260-repo/` was removed on
2026-11-12; it was kept only for comparison and was never the source of the
released 6.12 binary.  xiaomi9pmroot is MIT (copyright
`yt-root-98260 contributors`), and its notice is retained in
`LICENSES/Xiaomi9pmroot-MIT.txt`.  The released 6.12 sources are a modified
derivative of xiaomi9pmroot with per-build and ledger changes, not an
independent rewrite.

## 64560 audit builds

The script also builds the available 64560 native sources into
`build/binaries/64560-audit/`.  It does not auto-install them because the
release APK uses the previously validated 64560 binaries.

| Asset | Source |
| --- | --- |
| addrcalc | `binary-sources/64560/native/addrcalc.c` |
| kaslr_slide_61258 | `binary-sources/64560/native/kaslr_slide_61258.c` |
| kaslr_slide_6138 | `binary-sources/64560/native/kaslr_slide_6138.c` |
| ko_patch | `binary-sources/64560/native/ko_patch.c` |
| ksu_grant | `binary-sources/64560/native/ksu_grant.c` |
| forker | `binary-sources/64560/native/forker.c` |
| wait_helper | `binary-sources/64560/native/wait_helper.c` (+ `futex_sync.h`) |
| t64560_v36 | `binary-sources/64560/upstream-honeclick/t64560_v36.c` |
| t64560_cred | `binary-sources/64560/upstream-honeclick/perf_cred_honor.c` |
| cred_target | `binary-sources/64560/native/cred_target.c` |

## Sources used by the release

- 98260: `binary-sources/98260-6.12/*` (actual released binary source).
- 98260 reference: upstream snapshot removed 2026-11-12; no upstream source copy is shipped.
- 64560: sources above plus upstream attribution in `THIRD_PARTY_NOTICES.md`.
- UI/Java/Kotlin: `main/`.

## 1.0.6 BRM compatibility module (superseded)

- Official KernelSU template: `main/app/assets/98260-61821-brm/ksu-template.ko`.
- Historical compatibility source and partial-link build: `binary-sources/61821-brm/`.
- The old generated compatibility image (`24840690...`, vermagic `6.12.76-4k`)
  has been replaced by the upstream g186 115 module
  (`f8dd188f...`, vermagic `6.18.21-android17-5-ge186062ea75f...`).
  `build-ksu-brm.py` remains as the historical recipe but is no longer the
  source of the shipped g186 KernelSU template.
- Exact target, offsets, SELinux checks and verification boundaries: `docs/BRM-6.6-INTEGRATION.md`.

## 6.6.89 g082e5a98dac1 adaptation (2026-11-04)

Target:

```text
6.6.89-android15-8-g082e5a98dac1-abogki463734347-4k
boot_ota SHA-256 91315bd8bba64ea312c79cfdd736e0846d8116ed5209be8cd7474523ee23b2ff
kernel Image SHA-256 fc802bb8925a8ce831977d6f2fe042d028c43aafd1171da36e7c172d64384400
```

- Target header: `binary-sources/6689/pc98260_target_6689.h`.
- Payload: `main/app/assets/98260-6689/exploit-android-key-ptr`,
  built from the 6.6 `uaf_plant_61258.c` source, dynamic PIE:
  `48240d9bc493f04518bb3b11326115488f4ba05ce3e8be2956d8692d8ef1a1ff`.
- rootd client: `98260-6689/pc98260-su`, reused 6.6.58 client
  (`8838ab17e38252492df3761b74126855bde8a77ed5ab02255b67ebef81376ab1`).
- KSU templates: existing `ksu-template-66118-*`; five new
  `syms_6689_*.txt` tables map every template import to 6.6.89 addresses.
- BTF: task cred 0x820, real_cred 0x818, k_itimer 0x108, cred 0xb8.
- Link calls: timer `do_timer_create+0x94`, cred `prepare_creds+0x20`,
  task `copy_process+0x13c`; `begin_new_exec` cleanup order verified.
- Details: `docs/6.6.89-ADAPT.md`.
- No physical device test exists; static adaptation only.

## 6.6 profiles

- 6658 source: `binary-sources/6658/`.
- 6.6.118 layout/source records: `binary-sources/66118/`.
- The supplied 6.6 exploit binaries and per-flavor syms were checked against their own vmlinux images. The 6658 profile selector is fixed in `main/app/assets/98260/run98260.sh`.

## 1.0.33 6.1.157 g264 CGA / su overlay

- Source, pipeline and CGA reference sources: `binary-sources/6157-g264/`.
- Runtime assets: `main/app/assets/61157/ (flattened as 61157/*.ko and helper binaries).
- Integration/report: `docs/6157-G264-CGA.md`.
- The g264 path uses `ksm-g264-base.ko` + per-boot `ko_slide_patch`, then
  `su_lkm` / `su_overlay_helper` for the non-sucompat KSU module.

## 6.1.157 support audit (2026-11-02)

- Reference APKs analyzed: `MagicRoot-98260-1.0.35-6157.apk`,
  `MagicRoot-Pad3-1.0.10.apk`.
- MagicPad3 / `43499-pd3x` is skipped by request; no Pad3 assets or profile were
  added.
- Current ELP-AN00 route is `61157/run61157.sh` + `ksu6157` and is documented
  in `docs/6157-SUPPORT-AUDIT.md`.
- Reference `ksu6157-g264` / `g264` assets are not imported because they are
  opaque third-party binaries with no in-repo build recipe.
- `61157/kernelsu-honor.ko`, `61157/ksud`, `ksu6157/*` remain
  provenance-locked upstream/reference artifacts; do not describe the whole
  APK as fully reproducible from this repository alone.

## Built-in manager ksud fallbacks (2026-11-02)

Historical note: this section documented five bundled manager `ksud_*`
fallbacks.  They were removed from the APK in the size-optimization pass
(2026-11-02).  The deployment path now relies on extracting `ksud` from the
installed manager; there is no bundled manager fallback.  The hashes below
are retained only as provenance for the removed files:

```text
4f7d5fd65631915ea579ff406bd9cbe58217f2c91dac6527f5b2f28ad4508171  ksud_kernelsu (4,990,848)
21dd59d95c35f7309d1f000dcc7c3872f67f3b43881d1d045f17ecb7a459e389  ksud_bakasu   (5,954,016)
8967e8b309293335354734600ae0725a6d3d9a81a0382907f656d376f52dff29  ksud_fina     (7,561,328)
36d260c9442ac55432880bd35efd7d55b7d30782631186615ecec83f359e842  ksud_next     (7,059,288)
3f04ece47a64814703af7f50362802ea9ed27ca7d52b989af07d4d028e0040cf  ksud_sukisu   (6,093,280)
```

They are used only when extraction from the selected installed manager fails.
Prefer manager extraction at runtime.  The 6.1.x route additionally falls back
to the bundled `ksu6157-g264/ksud` (not a per-flavor manager binary) when the
extracted manager ksud cannot talk to the CGA LKM.

## 6.18.21 adaptive profile (2026-11-02)

`KernelProfileGenerator.java` is ported from HOneClick
(`superboyyy/HOneClick`, package `com.aiden.honoroneclick`) with only the
package name changed.  It parses a user-selected `boot.img` locally and emits
the 98260 profile/symbol table.  No remote profile is downloaded.

Generated profiles are tied to the exact `uname -r` string found in the
imported image and are rejected by the H1C preflight if they do not match.

## 6.1.157 assets imported from MagicRoot 1.0.36 source

The following binary directories are imported unchanged from the supplied
`MagicRoot-98260-1.0.36-source.tar.gz`:

```text
98260-g264/        (upstream g264 98260 payload)
g264/              (CGA LKM patch base)
su-g264/           (CGA su overlay)
ksu6157-g264/      (g264 KSU loader/prepare/symbols)
98260/run6157_full.sh  (upstream 6.1 chain runner)
```

These are upstream Honor adaptation binaries, not first-party builds.
6.1 g7d/g264 now route through `run6157_full.sh`; g19a (MagicPad3) keeps the
existing 61157 route.  43499 is not introduced.

## 6.1.157 g3306 / g84 / g77f adaptation (2026-11-03)

Derived from the confirmed g264 chain using boot images from
`荣耀boot对照_20261103.zip`:

```text
source: boot.img raw ARM64 Image + vmlinux-to-elf reconstructed kallsyms
base:   raw link base 0xffffffc008000000 (calibrated against g264)
root:   uaf_plant.c + pc98260_rootd.c rebuilt per kernel with clang
KSU:    g264/ksm-g264-base.ko remapped (ABS + ksustub) and vermagic patched;
        g84/g77f additionally patch 57 task_struct field-offset instructions
```

Hashes:

```text
98260-g3306/exploit-android-key-ptr   3145b71471c06d2bc225b68eea25ac5c3f0e1b44ef3360a0fac5a516262dadc5
98260-g84/exploit-android-key-ptr     67359c952ce7c80e9edcb637e1f79b91f6d04d9079d5a55d4b2d9db95c5ef3d3
98260-g77f/exploit-android-key-ptr    4213e08ce321d0022c876678cd51ac6abecaa727d8afbeb9eb899f87869202f8
g264/ksm-g3306-base.ko                8237b456ca92704272f2e839a435e3a8756d344527f2cb7bc9b789b0a4c640c8
g264/ksm-g84-base.ko                  7777803ad2002752d45447f5f29d4321860925bb45b691a237d4eb5955161881
g264/ksm-g77f-base.ko                 39dd11bd5447feda6ee5f24b41bc00a22563eb72ce1c539b81b7304187e00cbd
```

g84/g77f KSU modules are experimental (no matching physical device tested).
The 34 KiB payload series above did **not** actually contain
`blind_reclaim_stream` despite this section's earlier claim; it was replaced
on 2026-11-04 by the proven static engine.  The hashes in this historical
section are superseded by `docs/6157-SUCCESS-CHAIN-REBASE.md`.  6.1.99/6.1.128
were later added separately, as described below.

2026-11-03 g84 boot revalidation: the attached g84 `boot.img` (kernel SHA-256
`a3e71193f879fee06baa332483c812ae42977aa773bdff5b318b54f0a5d8b618`)
has `task_struct.cred=0x840` and `k_itimer.size=0x118`.  The previously
shipped g84 payload still carried g264's `TASK_CRED=0x838` /
`KITIMER_SIZE=0x108`; it was corrected by eight in-place AArch64 immediate
patches (one cred destination, four trace-size comparisons, three timer
allocation-site constants), changing the payload SHA-256 from
`f5290228...aaa7` to `67359c95...f3d3`.  The timer link moved from
`do_timer_create+0x94` to `+0xb8`, the actual `kmem_cache_alloc` return
address in this image.  All other
instructions and the g186 route are unchanged.  See
`docs/6.1.157-G84-BOOT-VERIFY.md`.

## 6.1.x extension: 6.1.99 / 6.1.128 + g7d CGA (2026-11-03)

Boot images for the remaining 6.1.x builds were extracted from
`荣耀boot对照_20261103.zip` (unique kernels only):

```text
6.1.99-android14-11-gce84935796c9   BVL-AN00/AN16/AN20/AN20HP, FCP-AN10
6.1.99-android14-11-g5859fbdbad8c   AMG-AN00, AMP-AN00, AMP-AN10
6.1.99-android14-11-g54d40b4fb287   DNP-AN00
6.1.128-android14-11-g40b1fd119d9b  ELP-AN00
6.1.99-android14-11-ge9da27488f45   CLE-AN00 / CLE-AN00D
6.1.157-android14-11-g7d3922fade43  BVL-AN00/AN16/AN20/AN20HP, ELP-AN00, FCP-AN10
```

Derivation:

- kallsyms via `vmlinux-to-elf --base-address 0xffffffc080000000`, then the
  raw link addresses (`0xffffffc008…`) converted to the payload's
  `0xffffffc080…` link bias (+0x78000000).
- BTF layout families:
  - `0x838 / 0x108` (`task_struct.cred`, `k_itimer.size`): g5859, g54d, ge9da.
  - `0x840 / 0x118`: g7d, g77f, gce849, g40b1.
- `uaf_plant.c` rebuilt per kernel with clang (PIE, dynamic bionic), with
  `TASK_CRED`/`KITIMER_SIZE` set from BTF, `COPY_ALLOC_LINK` set to
  `copy_process + 0x160`, `SIG_ENFORCE_LINK` set to that kernel's
  `sig_enforce`, and a read-only `--check` JSON preflight.  These two anchors
  are per-build; the source defaults are g7d-specific.  The g264 CGA base module is remapped per kernel; the
  `0x840/0x118` family also patches 55 task-struct field instructions.
- Historical 2026-11-03 change: g7d was moved to the g264 CGA route and the M6
  handoff was removed.  2026-11-04 reverses that regression: the upstream
  `ksu6157-m6/` suite is restored and is the only default g7d handoff.
- The 6.1.x runner extracts `ksud` from the currently selected manager
  (`kernelsu` / `resukisu` / `fina` / `sukisu` / `next`) and falls back to the
  bundled `ksu6157-g264/ksud` only if that component cannot talk to the LKM.
- STP compat loads the CGA LKM with `force_feature=su_compat:0` (module
  parameter parsed by `ksu_feature_init`) and skips the `su-g264` userspace
  overlay; 6.12/6.6 uses `ksud insmod ... force_feature=su_compat:0` when
  su_compat is disabled.

Hashes:

```text
98260-gce849/exploit-android-key-ptr  f788e30e68ce454e2ce5a7b68f15fe3daf223a8686963c332638091775862752
98260-g5859/exploit-android-key-ptr   93636300d297020528db2d8c10042bd53df8a6588956c92c065ee0e9dd107e52
98260-g54d/exploit-android-key-ptr    043c81235273476b5fb3a3eb7fb3627282d3e91543fbc3c1d904c1b6e2141eb1
98260-g40b1/exploit-android-key-ptr   9370e5c82b8f3ecc8876fd13de0de881cca2090565a2394a4e7c4c2a400448ac
98260-ge9da/exploit-android-key-ptr   815f1155cd348780191c9c949e03a5c03437763ba8aed00b0e3d1e79346789e3
g264/ksm-g7d-base.ko                  9cab6ff6f0bfd61341f7167822fa166ac380061babff50e472fc76306ddeca02
g264/ksm-gce849-base.ko               d1ca5cb177ccd4a68caa140a420d5456bfc1ccfb164ee0d5ce3e852a0b8dff7d
g264/ksm-g5859-base.ko                bb4a39f19f697b4ea828dd5276de80cae2462a35ddd4358bd30bf3c49f22dad0
g264/ksm-g54d-base.ko                 644297299708ce7c6f46255d72122df7d63520dad6df6e0441703b5b74fac85b
g264/ksm-g40b1-base.ko                4040c5a24981f64c829675af146b7a9f6a6a797da3f9c73b6b39708974f9fdd8
g264/ksm-ge9da-base.ko                44e6366f0d6ffa04a64aa303cf49e752f6cb851d95c7fdc156c76c16715b6f83
```

Historical status for this 2026-11-03 series: all six were static adaptations.
g7d's **CGA** route was never device-validated; its proven route is M6, which
was restored on 2026-11-04.  g264 had the only full CGA root/KSU closure in
this series.  The 2026-11-04 rebase supersedes all payload hashes above; see
the last section.  No physical device exists for 6.1.99 / 6.1.128.

## 2026-11-03 6.1.x manager LKM extraction + g264 payload refresh

- Historical proposal: the app extracts the selected manager's embedded LKM
  to `ko-<flavor>.ko` for 6.1.x.  The 2026-11-04 audit found that only g264 has
  a matching `ksu6157-g264` absolute symbol table.  Therefore only g264 may
  enter the legacy `ksu_prepare`/`ksu-loader` branch; every other 6.1 build is
  forced to its own CGA base and fails closed if it is missing.
- g7d's old `ksu6157-m6/` M6 handoff (29 MB) was removed from assets and all
  registration/deployment paths on 2026-11-03.  It was restored on 2026-11-04
  from the supplied 1.0.36 APK because it is the only proven g7d handoff; see
  `docs/6157-SUCCESS-CHAIN-REBASE.md` and `m6-provenance.json`.
- g264 payload `98260-g264/exploit-android-key-ptr` was rebuilt with the same
  anchor discipline as the other 6.1.x builds:
  `COPY_ALLOC_LINK=0xffffffc08019f5fc`,
  `SIG_ENFORCE_LINK=0xffffffc08245dc60`,
  `TASK_CRED=0x838`, `KITIMER_SIZE=0x108`, read-only `--check`.
  SHA-256 `26287204cb15b58ffd95103f3c33554ac8d734bc7ab6195028c13498fa083562`.
  This 34 KiB rebuild is **retired**: it lacked the proven blind-reclaim
  engine.  On 2026-11-04 g264 was restored to `cc0b9693…2843`; the CGA base and
  `ksu6157-g264/` remain unchanged.

## 2026-11-03 HOneClick 6.18.21 upstream cross-check

- Upstream source: `https://github.com/superboyyy/HOneClick`, cloned locally
  under the build environment; `KernelProfileGenerator.java` matches this
  repository (package name only), and the `98260-h1c/` helper binaries plus
  `ksu-template-115.ko` hash-match upstream.
- `ko_patch` was missing upstream's `SHN_XINDEX (0xffff) -> .modinfo`
  section-index repair.  It now repairs those symbols and prints
  `REPAIRED=N`.  The 115 template reports 14 repaired symbols.
- Updated `ko_patch` SHA-256:
  `aa7727abd2132568a239da74a14177bc857c06d30b6875ab5b983654ceb4afca`.
- H1C `root_stage.sh` now installs the selected manager's userspace with
  `--libadbroot`/`--data-path` when available, falling back to plain
  `ksud install`, and respects `MAGICROOT_SU_COMPAT` (STP sets 0).
- 6.18.21 manager LKM/ksud extraction is the existing app extraction path;
  g928 uses the extracted manager LKM with the selected flavor's symbol table,
  while g186 + kernelsu keeps the upstream official 115 module.

## 2026-11-03 6.12.23 gd85666d7884 adaptation

Source image: `20261103131649-boot_ota_1793682544248.img` (100,663,296 B).
Boot header v4, kernel 39,815,680 B, SHA-256
`146721ce67fbe5d16fbb7c2d41db2fbf9ff30f8ffb85b2ae0ee83bb316159053`.

Kernel release:

```text
6.12.23-android16-5-gcd85666d7884-abogki452537391-4k
```

Derived values (see `binary-sources/98260-6.12/pc98260_target_g856.h`):

```text
do_timer_create+0xac  = 0xffffffc080cb8b60  (timer alloc site)
prepare_creds+0x2c    = 0xffffffc080df5358  (cred alloc site)
copy_process task alloc = 0xffffffc080d03ae4
begin_new_exec        = 0xffffffc080cffbb0
selinux_state         = 0xffffffc082656570
init_user_ns          = 0xffffffc0823f1360
task_struct.cred      = 0x900, k_itimer = 0x100, cred = 0xb8
task cache            = 0x1440, 6 objects / 8-page slab
memstart_addr         = 0xffffffc0817e5cd8
```

Assets:

```text
98260-g856/exploit-android-key-ptr  1cc31dd934712dc9b0178df581b2f31769c3c8b3d4a494d7f7aeab62cec52d7f
syms_g856.txt                       588cfaae1e2db48fccaf101899a464768ee727f26e117cb8098281578fa8c85d
syms_g856_bakasu.txt                7b606cd45fc2f74d37fb97eb96e2af89c4535b3aca3291719f2a6f7c0f022245
syms_g856_next.txt                  fe79570421d1afd88b9ab801759df760ff762c001e7df64ebe4fd2fe08814683
syms_g856_sukisu.txt                2b6a0c8ad05009b6ac64e2a40cfbda683faa7679f36000d5de896fe0913fb76d
syms_g856_fina.txt                  f340ad3dbd019be9c33a1f0e38b2126061df13bff78d9e9eeba105842bb3408d
```

All five `ksu-template*` modules patch with `MISSING=0` and target vermagic.
The route is `98260` with the in-process KASLR sampler; no 64560 KASLR
helper is claimed for this build.  No physical device is available, so the
runtime UAF/KSU handoff remains static-only.

## 2026-11-04 6.1.x rebase on the proven 1.0.36 payload

Input APK:

```text
MagicRoot-98260-1.0.36-6157.apk.1
cce10cb3ca64c4152f9c73c9b60f6a27bd9053dd3a919a708c7eb13de831bb0d
```

Input archive:

```text
MagicRoot-6157-全量归档-20261102.tar.gz
6f0fd7cf03bfbc52bc3cfa0c1c964f9445a75221d62b4792210ac15d45320d21
```

The g264 payload is restored exactly from the APK:

```text
base executable      static AArch64, 2,327,648 B, NDK r29, debug_info
sha256               cc0b9693dcdba564585c39dfe3eb386860f1cede4251d0d7aca63d1e51762843
blind env            PC98260_G264_BLIND_RECLAIM=1
```

The old 34,192-byte dynamic rebuild (hash `26287204…`) is retired: it had no
`blind_reclaim_stream()` and is not equivalent to the proven chain.

`binary-sources/61157-g264/rebase_success_payload.py` reproducibly derives the
extended static payloads from the proven base.  It maps the audited kernel
addresses into the payload's raw `0xffffffc008…` link bias, patches 11 address
materializations, 3 cred + 3 real_cred immediates, 2 `k_itimer` comparisons and
4 `.rodata` namespace pointers, then re-disassembles every result.  The
machine-readable inputs and output hashes are in `success-profiles.json`.
No other bytes differ.

Current extended payload hashes:

```text
g264   cc0b9693dcdba564585c39dfe3eb386860f1cede4251d0d7aca63d1e51762843
g3306  bba7b7e57f823f361073e89d2b986c91869a74cdfa31e3ad5d9c28a69f634a57
g84    6b118559a691f45d51cccb0815b623b1d03c5801df40f2beb34b995659bcc7d6
g77f   f1fff50a313fb5f63bc68f657628f5c7d08a0038837d7ef5e0a55e0e8dff85ba
gce849 318c2ba312a7c461cd09146fd3fc3dab24d42890591e64a5a6fd2e276e0996e6
g5859  25678da88f3769c63c6866f4d61700bb0126279f2033b3b3823eb945da323ba5
g54d   0c5a86ab31057685a5583c6fbdb41051cfc7031ee327b8ec84fb53f105ebe48a
g40b1  801f332954de365f8bc06b0c23794ff1f6e1a293b7be5bfb10a88aaba5895cd0
ge9da  e6a44461c6d5fff39a62f1c993caf6579c94bce4e846ff84e8c3a3a0e6d12090
```

g77f, gce849 and g40b1 are corrected from the stale `0x838/0x108` encoding to
the BTF-audited `0x840/0x118` family.

Restored g7d M6 suite:

```text
main/app/assets/ksu6157-m6/  (19 files, 29 MB)
source APK sha256           cce10cb3…bb0d
source archive sha256       6f0fd7cf…5d21
file hashes                 binary-sources/61157-g264/m6-provenance.json
```

The archive is stored as `-text` in `.gitattributes` to keep byte-locked helper
and symbol files unchanged.  The OS9/KSU331 modules carry g7d vermagic.  No
43499/Pad3 asset from either supplied file was imported.

The M6 suite is a first-party local handoff package (own artifact), not a
third-party component; it is intentionally not registered in the third-party
license inventory.

See `docs/6157-SUCCESS-CHAIN-REBASE.md` for the full static proof, runner
fixes and unverified boundaries.

## 2026-11-04 6.1.128 g8a496 / g2e1f static adaptation

Inputs are two unique old boots from `荣耀boot对照_20261103_旧版本.zip`:

```text
6.1.128-android14-11-g8a4968670f1c
  boot sha256 bebc28d515c2bdb2a11acba609dc3efee33e49730596e8e96d80c228fdbeb3a8
6.1.128-android14-11-g2e1f0741dafb
  boot sha256 d5a085ec75f6864ddc9f9de4659959b02fed33b26ab1e7634cb673f4771bdba6
```

Both are the `task_struct.cred=0x838`, `real_cred=0x830`,
`k_itimer.size=0x108` family.  `prepare_creds` displacement and
`init_posix_timers`' `kmem_cache_create` size were checked directly.  These
are not g84/g40b1 modules and must not receive the `0x840/0x118` field patch.

Payloads are deterministic rewrites of the locked g264 success payload:

```text
98260-g8a496/exploit-android-key-ptr  1db586a3f787a35d7f8872537470783397f2fbd9680a9877dd26beb2ca410f35
98260-g2e1f/exploit-android-key-ptr   e681569bcf6b51fa36e59622e6361b19653eeca2079c8b081f0b9a9ae2d47d27
```

CGA modules are produced by `binary-sources/61157-g264/rebase_cga_module.py`
from the g264 base `6381ad16…6c09` and the compact
`cga-profiles.json`.  It rewrites 225 named absolute symbols and 220 live
`strcpy`/cache/timer jump-stub qwords (204 unique targets), then patches the
single vermagic release.  Unknown symbols, ambiguous stubs and unexplained
byte changes fail closed.  Outputs:

```text
g264/ksm-g8a496-base.ko  450b242ba93e085de4545184882230980addefb336bd6922885b285863c19dfa
g264/ksm-g2e1f-base.ko   5b8f95453fa73e3c23aa0ffd071a2f354eb089358f4e13c2461fc87524075549
```

Both are static adaptations with no physical-device run.  Full method,
routing and tests: `docs/61128-OLD-KERNELS-ADAPT.md`.

### 2026-11-07 新内核 payload（g142 / ga812）

```text
20b166ce53c13d3f06214490556fd5019d1f504c6722cd0b615851633f6950ea  98260-g142/exploit-android-key-ptr  (6.12.58 g142ddad31e60, draft+61258 模板合成, 动态 PIE)
095d9af075fdaaf3678ed8710cccc53b1c209210773cbb02b2d4fb8c198d2371  98260-ga812/exploit-android-key-ptr (6.6.118 ga812a1946391, draft+6658 模板合成, 动态 PIE)
```

- 两内核均用 `tools/Chain98260TargetDraft.java` 从 boot.img 派生 target 头
  （kallsyms + BTF + do_timer_create/prepare_creds 反汇编），偏移量与各自
  家族已知模式一致（6.12=+0xac/+0x2c，6.6=+0x94/+0x20）。
- 五 Flavor 符号表 100% 映射（ga812 必须用 6.6 模板 ksu-template-66118-*，
  6.12 模板引用 6.6 没有的 `*_noprof` 符号会误判 missing）。
- 静态适配，无对应真机验证。

### 2026-11-07 6.1.157 gaaa383620ebf 静态适配

用户提供的 `boot_ota_1794058115581.img` SHA-256 为
`a41aa37fc83e39334a1805bcd3f510c860d76e6dd02e44db762012f6caf9e524`，
实际 release 为 `6.1.157-android14-11-gaaa383620ebf`。从镜像恢复 106799 个
kallsyms，并通过 `prepare_creds` / `do_timer_create` / `init_posix_timers`
反汇编确认 `0x838/0x830/0x108` 布局和两个分配返回点。

产物沿用锁定的 g264 成功型 payload 与 CGA base 确定性派生，不改旧资产：

```text
98260-gaaa/exploit-android-key-ptr  67cedbc21f3bd6c761291183dac054c5711407485fbff8c24a7d577409ee1fae
g264/ksm-gaaa-base.ko               64ebb525f3f98c73a0cc648f27552b0e5792ee18aaf87c6b1fdade15a90bc377
```

2026-11-11 恢复版 CGA 映射 226 个绝对符号、221 个活跳板并更新精确 vermagic；
旧 225/220 输入曾保存在 `legacy-cga/`；该审计副本已从公开树移除
（SHA-256 `6381ad16a904af8d7d2a702e04994ed22c3fd01c6e00229ec584634034a56c09`），
运行资产不受影响。`pc98260-su`
与其他 6.1 CGA profile 相同，由 `tools/asset_dedup_map.json` 去重。完整证据、
复现命令和未验证边界见 `docs/61157-GAAA-ADAPT.md`。本次没有引入
43499/Pad3 路线，也没有对应真机 root/KSU 验证。

### 2026-11-07 6.1.x 统一运行资产

本轮没有导入 ek-root 参考包的原生载荷、KO 或 rootd。现有 6.1.x payload/CGA
字节保持不变，只统一 Java 部署规划、runner 路径派生和交接前检查。

`ksu6157-m6/post_root.sh` 保留诊断快照，移除无人消费的常驻 FIFO `eval`
服务；本地修改后的 SHA-256 为
`f3c48e4f0561098a84f4816b63ba88309b8dacf03427bb56c47295f4a146b1d0`，
并同步记录在 `binary-sources/61157-g264/m6-provenance.json`。

新增 `6157-integrity.tsv` 由 `python3 -I tools/gen_6157_integrity.py`
从已注册运行资产确定性生成，SHA-256 为
`716bff07d37682e24f34e0422702c67debbe068dbb2fda811a6c6959087f8bc9`。
可用同一命令的 `--check` 复核；该清单不包含外部参考 APK 或设备数据。
以上脚本和状态机改动尚未做 6.1.x 真机复验。

### 2026-11-07 98260 trace-scan reclaim fix (6.12.58 g142 FAIL=80 root cause)

The v17-117r1 reference failure log (`prev-run-1794059690090.txt`) showed
12/12 attempts ending in `[stream] writes=480 hit=0` / `[half] miss` ->
`FAIL code=80` on kernel `6.12.58-...-g3a7ac1674240` (g142ddad).  Root cause
was in `binary-sources/98260-6.12/uaf_plant_61258.c` (identical copies also
under `binary-sources/6658/` and `binary-sources/6689/`):

- `TRACE_SCAN_BUDGET` (4 MiB) was a **single shared budget** across every
  `per_cpu/cpuN/trace` file, scanned cpu0 -> cpuN **forward** (oldest ->
  newest within each dump).  Under load (~25 on the failing run), cpu0's dump
  alone exceeded the budget, so cpu>=1 dumps were never scanned.
- `find_page_free` succeeded early (dumps still small) and `page_freed=1`
  was logged, but all `mm_page_alloc` events landed on cpu2/cpu3
  (`free_cpu=2,2,3` in the log) -> deterministic miss on every attempt.
  This is a **load-sensitive detection bug, not g142-specific**; verified
  61258 passed earlier only because dumps stayed under the budget.

Fix (applied to all three identical source copies):

- `struct trace_tail` + `trace_tail_open/close/next`: read each per-cpu
  trace file once into a malloc'd buffer (cap 128 MiB) and iterate lines
  **newest -> oldest**; our events are always the newest entries.
- `find_page_free`: per-cpu `TRACE_FREE_TAIL_BUDGET` (1 MiB) tail scan —
  hot path stays bounded.
- `find_page_alloc(uint64_t pfn, int prefer_cpu)`: `prefer_cpu` (the free
  cpu) scanned first, then the rest; per-cpu `TRACE_SCAN_BUDGET` (4 MiB);
  match still requires `mm_page_alloc` covering the PFN **and**
  `trace_task_is_self`.
- New diagnostic `g_alloc_cover`: counts `mm_page_alloc` lines covering the
  PFN *before* the task filter.  `cover=0` in a miss means our writes never
  allocated the page; `cover>0` means allocated but task-match failed.
  `[half] miss` now prints `cover=%lu`; `[stream] writes=...` prints
  `cover8k=%lu cover=%lu`.
- `reclaim_stream_half` / `reclaim_stream` call sites updated to pass
  `free_cpu`.

Runner knobs added to `main/app/assets/98260/run98260.sh` (opt-in only, off
by default):

- `CHAIN_98260_ENABLE_FALLBACK=1` or `MAGICROOT_98260_FALLBACK=1` ->
  `PC98260_ENABLE_FALLBACK=1` (enables the weaker pipe/AIO fallback paths;
  kept off by default because `reclaim_pipe` lacks `task_is_self` — a
  false hit could `rb_erase` foreign content, cf. the 2026-11-02 21:00
  `page_request` panic — and `reclaim_and_plant` plants into every AIO
  ring blindly).
- `MAGICROOT_98260_STREAM_BUF_KB=<n>` -> `PC98260_STREAM_BUF_KB=<n>`.

All 12 rebuildable payloads were rebuilt on-device with Termux clang 21.1.8
(dynamic bionic PIE, same recipe as the ledger build — pre-change rebuilds
were verified byte-identical to shipped assets).  At that rebuild every binary
was 75,696 B; subsequent engine changes changed the sizes, so the table below
is authoritative for current assets.  `exploit-61258b` and `exploit-aph112`
remain byte-identical and
`98260-aph112/exploit-android-key-ptr` is deduped to
`98260-61258b/exploit-android-key-ptr` in `tools/asset_dedup_map.json`.

Current shipped hashes (98260* dirs, 6.6/6.12 family):

```text
0fd3ff76cce3288252a2cf6f8ad64463f21542ab29f007fcdfda1dd36a0c0b4d  98260/exploit-android-key-ptr (104,816 B, 6.12.58)
5c76d21c012c000241c4716563da13b323a015d5b0f93902f717eba42b7ac10b  98260-61258b/exploit-android-key-ptr (104,816 B)
f203ce9e58323e44155354e945e480bcec4267e3f9ec57f4f68611814a13513e  98260-61258c/exploit-android-key-ptr (92,072 B, -s)
6c7126208ab4e139df3614519160da17dff8f5265d4c1d3177fab8442c3eda7a  98260-6138/exploit-android-key-ptr (104,816 B)
fecaa9c7c58b5b0da03c90c3c3a3af5232504967d685fda4528179249ba2d29c  98260-6123/exploit-android-key-ptr (104,816 B)
0f7c58b031e6e2bce059febe445576ef4a06b99ec380a9e2f5805901f3a867f0  98260-6138y/exploit-android-key-ptr (104,816 B)
38444791c48c63a8e09343d893d20a934c9daa3caaa38c1415db583f2f906c79  98260-g856/exploit-android-key-ptr (104,816 B)
36dc9e61224ae3dce3961a607949af5f114368507c2bb5d2a361f50810b39523  98260-g142/exploit-android-key-ptr (104,816 B, 2026-11-13 64 KiB slide align)
5c76d21c012c000241c4716563da13b323a015d5b0f93902f717eba42b7ac10b  98260-aph112/exploit-android-key-ptr (104,816 B, 与 61258b 相同)
ae7c08311b367cc066dae9dc3ef43c1904cc274930616fc8fcb35be05a5850d8  98260-6658/exploit-android-key-ptr (98,968 B)
0a62e2c06095d0a2a75622a0f9650ba07dfbd978133c6af19c6f1de1e96bab72  98260-6689/exploit-android-key-ptr (98,968 B)
095d9af075fdaaf3678ed8710cccc53b1c209210773cbb02b2d4fb8c198d2371  98260-ga812/exploit-android-key-ptr (98,968 B)
```

`98260/SHA256SUMS.txt` was updated for `exploit-android-key-ptr` and the
edited `run98260.sh`; the other per-profile `SHA256SUMS.txt` files were
updated likewise.  `build-98260-6.12.ps1` `$expect` now lists these hashes.

2026-11-13: 全部可重编的 98260 payload（9 个 6.12、6658/6689/ga812、H1C）
统一用本机 clang 21.1.8 重编，包含 trace 尾窗流式读取、raw 事件 id 自校准、
churn 每轮单次扫描、watcher 成功交接后 hold-only（H1C 为 1024 KiB 窗口）。
`98260-61821*` 仍是旧 payload（6.18.21 强制 H1C，运行时不用）；6.1 派生
payload 与 f171/g554 provenance-locked 资产未改字节。

### 2026-11-12 6.6 fake-cred 引擎恢复

旧 1.0.5 源码包 SHA-256
`d6469d33ab390e76f722413220210df49a0dc48154380f2a4a8fcc705c0c7b09`。
以其中 fake-cred 的 task/cred 安装语义为基准，将当前 6.12 已修复的完整实现
移植到 `binary-sources/6658/uaf_plant_61258.c` 并同步到 `6689`：页内 FULLCAP
cred、SELinux 零页、task->cred 指针、tile/blob 重叠过滤、fake 专用主分支，
以及成功后保留 cred 所在页。real-cred 的 direct-finit 与既有 victim 台账不变。

三者均用本机 Termux clang 21.1.8 按
`clang -std=gnu11 -O2 -w -pthread -I<source-dir> [target define] uaf_plant_61258.c stubs.c rootd.c`
重编；ga812 额外使用 `-DPC98260_TARGET_GA812`。新二进制均为 87,384 B，
动态 bionic PIE。9 个 6.12 payload 同步重编且哈希与上表保持不变。

`g554` / `f171` 仍是 provenance-locked 的旧静态 fake-cred payload（分别为
`3d0b64b2c080cb8bfcc3d49900b6627867e333a585e071bbd957ee2854f94815` 与
`c0b96ae2204b6131a9b718c6aeeba8578452f716e31046b137c37ac29dd98dd8`）；
本轮只恢复 runner 的 fake 入口，未改二进制字节。6.1 的既有 fake-cred
资产未改字节。

H1C 先按旧 1.0.5 的 fake 布局恢复，随后 2026-11-12 17:xx 按真机日志修正：
旧布局（rb_node 与 cred 同在 node_off、`cred[2]=task+task_cred`）在 6.18.21
上不会把 cred 指针写进 `task->cred`。现改为 6.12 已验证的 PLANT_PTR 形状
`{pc=task+task_cred-8, rb_right=cred_kva, rb_left=0}`，cred 体位于
`node_off+0x20`，并保留 `PAGE_OFFSET+(base<<12)` 地址公式、`FULLCAP`、
fake 子进程直接 rootd、成功保页与 victim 生命周期。

同一轮还加入：raw trace 先排空、`task_struct` 对象大小从 slabfs 读取、
最多 8 个 task 候选并逐个取证、通道自检、整块 8 KiB 双半页自有分配才判命中、
每次尝试前清 trace、socket 轮转喷洒。用
`binary-sources/98260-h1c/build-cve98260-plant.sh` 重编，产物 48,600 B，
SHA-256 `edde1a5657847951f65e15c931258712e38a354bd92506b0db26b8c8cde9566a`
（2026-11-13 watcher 窗口修复后重编，仍为 48,600 B）。

所有 6.6 新 payload 与恢复后的 H1C 尚未真机验证。

### 2026-11-12 ko_patch：throne 开关与字节可复现

`main/app/assets/ko_patch`
`238b49b83e03373a41f56812d34191d45bd63bfa71fb198537f782594e4dad79`。
新增 `MAGICROOT_THRONE_PATCH` 环境开关：默认仍执行 init_cred 改写（工作版
8384115b 的行为，已验证官方 KernelSU 3.3.1 注册与 su 正常）；设为
`0|off|false|no` 时跳过改写并输出 `TRACK_THRONE=disabled`。

复现配方（与工作版 `fe3f9832…` 逐字节一致，需先链接再 `llvm-strip`）：

```sh
clang -std=gnu11 -O2 -pthread -o ko_patch.unstripped ko_patch.c throne_patch.c
llvm-strip --strip-all ko_patch.unstripped -o ko_patch
```

工作版完整源码/资产/配方备份：
`/data/user/0/cc.codroid/files/home/workspace/magicroot-backup-8384115b`。

**Verification status:** subsequent uploaded 6.12.58 g3a7ac logs contain the
new `cover=`/`cover8k=` diagnostics, so a diagnostic build has run on-device,
but reclaim misses and hit-without-root outcomes remain.  This is not a
successful end-to-end verification.  g142 reclaim success remains unverified.

### 2026-11-07 native terminal-state and fail-closed reap rebuild

The three identical C copies (`98260-6.12`, `6658`, `6689`) now write `ARMED`
when a victim is registered and `NO_ROOT` only at a terminal no-root park.
`PC98260_STATE_FILE` lets the detached runner distinguish pre-arm exit, a
running native process and terminal failure.  State updates use a same-filesystem
temporary file plus atomic `rename`; if the initial `ARMED` state cannot be
persisted, the child is killed/reaped before `arm_ready` and the UAF is refused.
`waitid` errors no longer fall
through to `waitpid`, and `victim_reap()` marks `REPAIRED` only after a
successful `waitpid` of the target PID; failures remain `UNPROVEN`.

All 12 source-complete payloads above were rebuilt sequentially on-device with
Termux clang 21.1.8 (`-std=gnu11 -O2 -w -pthread`, dynamic bionic PIE, no
`-static`).  Each is 76,096 B.  61258b and aph112 remain byte-identical.
Source-locked 6.1.x, f171/g554 and H1C binaries were not replaced.

The shared runner resets `98260.log` only when a new native run is actually
allowed, records run ID, boot ID and payload SHA-256, and the Compose failure
export appends the complete current native log.  H1C similarly resets its
diagnostic logs only after the live-plant guard, preventing an early failure
from inheriting an older rootd success log.  These are logging/lifetime fixes,
not evidence of a successful on-device root run.  No post-change UAF or
zygote/hotfix run has been performed.

## syms 表补充（2026-11-08）

管理器随附的 6.18/6.12/6.6 LKM 比本仓库原先按内置模板裁剪的 syms 表多导入
若干非导出符号。本轮只对拥有**同构建内核镜像/全量 kallsyms 导出**的 profile
追加地址，且每个导出都先与表中现有条目逐项比对，全部命中同一构建后才写入。

### 6.18.21 g186

`syms_61821_brm.txt` 265 → 272 项。来源：HOneClick g186 全量表
`syms-115.txt`（SHA-256
`15b661f3abe71abc663f66f02d98ed3241e230777f5dfd78d4bfa608b90773af`），
与现有 265 项逐项地址一致。新增
`bpf_get_btf_vmlinux`、`btf_find_by_name_kind`、`btf_name_by_offset`、
`btf_type_by_id`、`btf_type_skip_modifiers`、`copy_from_kernel_nofault`、
`capable`。

### 6.12.x / 6.6.x

| 表 | 内核构建 | 导出源 | 符号数 |
|---|---|---|---:|
| `syms_61258_bakasu.txt` | 6.12.58-g3a7ac1674240 | B 槽 boot.img `ae921fa3…` | 241→247 |
| `syms_61258_fina.txt` | 同上 | 同上 | 235→243 |
| `syms_61258c_resukisu.txt` | 6.12.58-g42fcf008ff5c | 荣耀 X80ProMax BSN-AN00 10.0.0.102 boot.img | 233→239 |
| `syms_61258c_sukisu.txt` | 同上 | 同上 | 245→251 |
| `syms_61258c_fina.txt` | 同上 | 同上 | 232→240 |
| `syms_6138_bakasu.txt` | 6.12.38-gfde7767f6ef6 | 荣耀 RobotPhone APH-AN00 10.0.0.103 boot.img | 241→247 |
| `syms_6138_sukisu.txt` | 同上 | 同上 | 245→251 |
| `syms_6138_fina.txt` | 同上 | 同上 | 232→240 |
| `98260-g142/syms_g142_bakasu.txt` | 6.12.58-g142ddad31e60 | `build/kallsyms/g142.txt` | 233→239 |
| `98260-g142/syms_g142_fina.txt` | 同上 | 同上 | 232→240 |
| `98260-g554/syms_66118_bakasu.txt` | 6.6.118-g554929766a0d | 荣耀 400 DNN-AN00 11.0.0.110 boot.img | 240→246 |
| `98260-g554/syms_66118_sukisu.txt` | 同上 | 同上 | 246→252 |
| `98260-g554/syms_66118_fina.txt` | 同上 | 同上 | 234→242 |
| `98260-f171/syms_66118_bakasu.txt` | 6.6.118-gf17133276a57 | 荣耀 400 DNN-AN00 10.0.0.175 boot.img | 240→246 |
| `98260-f171/syms_66118_sukisu.txt` | 同上 | 同上 | 246→252 |
| `98260-f171/syms_66118_fina.txt` | 同上 | 同上 | 234→242 |
| `syms_6123_bakasu.txt` | 6.12.23-g45ea5e4bce8a | Toolkit `kernel-data/6.12.23-BKQ-AN10/kallsyms.txt` | 241→247 |
| `syms_6123_sukisu.txt` | 同上 | 同上 | 245→251 |
| `syms_6123_fina.txt` | 同上 | 同上 | 232→240 |
| `syms_6138y_bakasu.txt` | 6.12.38-g7ae8ec909e03 | Toolkit `kernel-data/6.12.38-YLP-W00/kallsyms.txt` | 241→247 |
| `syms_6138y_sukisu.txt` | 同上 | 同上 | 245→251 |
| `syms_6138y_fina.txt` | 同上 | 同上 | 232→240 |
| `98260-6658/syms_6658_bakasu.txt` | 6.6.58-g6484937db664 | `MagicRoot-6.6.x-kernels-20261101.zip` 6.6.58-PPG-AN00 kallsyms | 240→246 |
| `98260-6658/syms_6658_sukisu.txt` | 同上 | 同上 | 246→252 |
| `98260-6658/syms_6658_fina.txt` | 同上 | 同上 | 234→242 |
| `syms_61258b_bakasu.txt` | 6.12.58-g459a4285ccf8 | `boot_ota_1794077165279.img`（`97dfd166…`） | 241→247 |
| `syms_61258b_sukisu.txt` | 同上 | 同上 | 247→253 |
| `syms_61258b_fina.txt` | 同上 | 同上 | 235→243 |
| `syms_g856_bakasu.txt` | 6.12.23-gcd85666d7884 | `boot_ota_1793682544248.img` `e5eeda2c…` | 233→239 |
| `syms_g856_sukisu.txt` | 同上 | 同上 | 245→251 |
| `syms_g856_fina.txt` | 同上 | 同上 | 232→240 |
| `98260-6689/syms_6689_bakasu.txt` | 6.6.89-g082e5a98dac1 | `boot_ota_1793726728599.img` `91315bd8…` | 240→246 |
| `98260-6689/syms_6689_sukisu.txt` | 同上 | 同上 | 246→252 |
| `98260-6689/syms_6689_fina.txt` | 同上 | 同上 | 234→242 |
| `98260-ga812/syms_ga812_bakasu.txt` | 6.6.118-ga812a1946391 | `build/kallsyms/ga812.txt` | 233→239 |
| `98260-ga812/syms_ga812_sukisu.txt` | 同上 | 同上 | 245→251 |
| `98260-ga812/syms_ga812_fina.txt` | 同上 | 同上 | 232→240 |

导出工具是仓库内的维护者工具（不进入 APK）：

```bash
javac -cp build/boot-tools/classes -d build/boot-tools/classes tools/ExportKernelKallsyms.java
java -cp build/boot-tools/classes com.aoki.magicroot.ExportKernelKallsyms <boot.img> <out.txt>
```

6.18 参考镜像复核：用户提供的
`6.18.21-android17-5-g928d1bb4f1d7_boot(2).img`（`8848fb1f…`）与
`magic9promax-boot.img`（`7d027334…`，镜像头/ramdisk 不同）内核一致，
导出的 143,621 行 kallsyms 与 `syms_61821_kernelsu.txt` 的 138,181 个
名字、地址逐项相同；`boot(1).img`（`697a6356…`）是 6.12.58-g142，
导出与 `build/kallsyms/g142.txt` 逐字节相同。

本机 `/storage/emulated/0/ 我的文件/boot (1).img`（目录名带前导空格）的内核
是 g186 构建 `6.18.21-android17-5-ge186062ea75f-abogki564062290-4k`
（未压缩，43,207,168 B）。自适应导出 143,769 行后与
`syms_61821_brm.txt` 全表比对：272 项全部存在、地址一致，0 缺失 0 不匹配，
7 项补丁得到独立镜像确认。同目录 `boot (2).img` 是 61258c。

荣耀 boot 对照两批（`荣耀boot对照_20261103_旧版本` / `_第二批`）的机型
镜像全部只读读取内核版本并逐个核对；LDY-AN00、VKI-AN00 的 legacy LZ4
内核用维护者工具 `build/audit-tools/unlz4legacy.c` 解出后确认是 6138 与
f171。boot 镜像只读导出，未写入任何分区。

最后一轮提供的 `boot_ota_1794077165279.img`
（`97dfd166…`）内核为 `6.12.58-android16-6-g459a4285ccf8`，补齐后所有
16 个 profile × 5 Flavor 的内置模板与管理器 LKM 矩阵均为 80/80
`MISSING=0`；详见 `docs/KERNEL-FLAVOR-AUDIT.md`。

### 2026-11-08 构建与交付

```text
APK        main/app/MagicRoot.apk
size       61,897,684 B
sha256     fb59b364515f6dc5506dfa06d28fdcf250bba36d7a09a945fe45a24ae34cf8c0
package    com.aoki.magicroot
version    12 / 1.0.5
签名       V3 release (CN=MagicRoot, OU=Release, O=Android, C=NA)
交付       /sdcard/cccodroid/MagicRoot-1.0.5-zygisk-fix.apk
```

`tools/check.sh` 为 ALL CHECKS PASSED（325 个 APK 资产逐字节一致）。
未安装该 APK，未执行真机 root/LKM/zygote 链路。

### 2026-11-08 部分释放 victim 不再收尸（AP_S_PANIC 修复）

现场两次提权（02:53:02 / 02:56:20）都在拿到 `uid=0` 后立即重启，
`sys.resettype=abnormal:AP_S_PANIC`，`98260.log` 停在
`[cred] answer uid=0 ... r=2000`。根因：attempt 1/2 打空后留下了
`freed` 只覆盖部分 half 的 OPEN victim；`victim_sweep()` 末尾的
`(v->freed & v->need) != v->need` 分支把「部分释放」误当成「从未释放的
活 slab」，直接 `waitpid()` 收尸。已释放 half 的页此时可能已属外部
owner，`posix_cpu_timers_exit` 沿外部 rb_node 走即 `rb_next` panic。

修复：在 never-freed 收尸分支前增加

```c
if (v->freed & v->need) {
    victim_state(v, V_UNPROVEN, "freed_but_unproven");
    continue;
}
```

只有从未观察到任何 needed half 释放的 victim 才允许收尸；部分释放的
victim 交给 `victim_watch_forever()` 继续观察，等 repair 证明所有
needed half 都是我方零页后再收。三份同源 C（98260-6.12 / 6658 / 6689）
已同步。

12 个源码完整 payload 重新编译（76,144 B，Termux clang 21.1.8，
`-std=gnu11 -O2 -w -pthread`，动态 bionic PIE）：

```text
98260/exploit-android-key-ptr          5f573296b5234d2976aba87ee412631a45d2fc88c6ba95dbe1f0fe0805f554f5
98260-61258b/exploit-android-key-ptr   aad9b9ee737f32bd668fa18540a162df0a7d30a3e22249febd8d6e4696992dca
98260-aph112/exploit-android-key-ptr   aad9b9ee737f32bd668fa18540a162df0a7d30a3e22249febd8d6e4696992dca
98260-61258c/exploit-android-key-ptr   eab83312cb3eaee762860f4cad5b0e5bec573cb112af289a93baaa2f286c68c8
98260-6138/exploit-android-key-ptr     c9e196a4e9d093382c6dde036af5c81ac562e12d0a937ba05620a32e5240ec98
98260-6138y/exploit-android-key-ptr    532c3c49d5b23b0d173ee61d39e904d4aa263db380526c162a753b766dfbb528
98260-6123/exploit-android-key-ptr     c95cb6dceac0679151407abad27ab3f172c6d586e8752ff1b5ce199bd720292e
98260-g856/exploit-android-key-ptr     4cadf2fbee85261c07cc954479e4c410d2b625c4afd3b1206a20bdf974c406f0
98260-g142/exploit-android-key-ptr     e5d4a5095bb59964a7edfd0e37aa813f341fdbf62f59c9aa0ea96c821e28141a
98260-6658/exploit-android-key-ptr     fd5e6fe0b0542ac869e2c6b0b3d9b8c4c1420c4047dc66961e688b60211b6624
98260-ga812/exploit-android-key-ptr    7b096aecbaff5cd41ac3d779607c918da70955f2c211c47dac29f0b6c8a2700e
98260-6689/exploit-android-key-ptr     3980ea0cd1e15ff6b75373aa00ee26ef4fd45476667c925c83f7dee0450f0152
```

`tools/test_98260_uaf_lifecycle.py` 新增
`test_partially_freed_victims_are_never_reaped`，锁定「部分释放 guard 必须
在 never-freed 收尸之前」。未在真机验证。

## Zygisk provider 修复资产（2026-11-08）

### 已移除 `zygisknext-sepolicy-1.5.3.rule`

**当前状态：该资产及所有主动补全代码已于 2026-11-08 移除，不再打包或部署。**
以下仅为历史来源记录，不代表当前 APK 仍包含该文件。

```text
path   main/app/assets/zygisknext-sepolicy-1.5.3.rule
size   304 B
sha256 fffdf6706deee384911878b3c11a30747e58aa26192d53300dbd568346ae0699
source Zygisk Next v1.5.3 (880-22a1bf5-release) 官方模块包
       uploads/20261107193537-Zygisk-Next-1.5.3-880-22a1bf5-release.zip
license GPL-3.0 (LSPosed Developers)
```

现场实证：模块安装后 `sepolicy.rule` 缺失，`zygiskd` 启动时
`verify1 failed` → `Module files corrupted` → 模块自我禁用
（写 `disable` 并把 `module.prop` 改成错误文本）；之后每次启动都读
abort 状态拒绝运行。补回**与模块版本匹配**的 1.5.3 规则后，
`verify1` 通过，daemon 正常 attach init：`inject_state=1`，
重启 zygote 后 `zygote_states=1`，LSPosed `System server: connected`。
1.5.2 的 631 B 规则内容不同（含 magisk_file 等），不能用于 1.5.3。

### `lsposed-hotfix.sh` v11–v12

- 先用 `ksud zygisk status` 检测 provider：只有 `external_providers`
  报告 `zygisksu` 时才执行 Zygisk Next 专属修复；KSU 内置 FolkZygisk、
  YukiZygisk 等其他实现原样使用，不触碰其模块/daemon。
- **v12 已移除主动补全**：不再内置、释放、传递或恢复
  `zygisknext-sepolicy-1.5.3.rule`。只使用安装模块自己已有的
  `sepolicy.rule`；缺失时记录 `reason=module_rule_required` 并拒绝启动
  zygiskd 或重新启用不完整模块。
- 仅在模块自身规则存在时，从 `module.prop.orig` 恢复自我禁用状态、删除
  `disable`、备份并清理 `.abort_msg`/`.magic`/`.injecting`，记录
  `ZYGISK_MODULE_RECOVERED` / `ZYGISK_STATE_RESET`。
- daemon 已 attach init 并退出（1.5.x 设计）时，`.magic` + `modules_info`
  且无 `.abort_msg` 视为注入完成，不再重复启动。
- 在 `ksud services` 前补建 `/data/adb/service.d`（模块 service.sh 需要）。
- 最终判定：非 zygisksu provider 时只看 lspd + bridge，不再因
  `FINAL_ZYGISK_NEXT` 缺 daemon 误报 partial。
- v11 慢启动修复：`app_process --nice-name=lspd` 的改名可能晚于旧版
  固定 3 秒检查，现改为最长 20 秒轮询；启动输出保存到
  `lsposed-hotfix-tool.log.launch`，失败时回贴末尾 40 行。
  延迟 4 秒的 shell 回归及 Android root-shell helper 实测通过；插桩修复的
  真机 zygote/system_server 重启闭环已完成，LSPosed 7939 connected。
  这些真机结果属于此前版本，不代表 v12 又执行了 hotfix/zygote 重启。
- 当前 v12 脚本 SHA-256：
  `9393085faf7a3ddbccfe33d10b8e9964f94d1ac4d99b2af03a0cc097a893564b`。

## g142 双链路适配与 6.12.x 复核（2026-11-08）

来源：用户提供的 honor_ubl 3.1.1 `aph136g142` 适配包；原始研究材料许可证
MIT，完整通知为 `LICENSES/Honor-UBL-Adaptation-MIT.txt`。适配包 SHA-256：

```text
97b1377bad0059e23b1244aac40cb3b3cd524f7c9d80b5937afdb599092aada1  honor_ubl-3.1.1-g142-kernel-adapter.zip
b75a12047c240669ca2987198d116238779706d513744a058245da7a4f0b1486  honor_ubl-3.1.1-g142-source-and-binaries.zip
```

新增 64560 专用 KASLR helper 及其源码：

```text
925ecd35fda6ba70a6dafa137ae2bffcfe009f164376e2cc98888a0edf1bb5d6  main/app/assets/kaslr_slide_aph136g142
ab7a3ff6b0382017e4a3296fe402132b2dae9132f04381346ff3239ebea340ef  binary-sources/64560/kaslr_slide_aph136g142.c
```

helper 是参考包的 NDK r29 / Android 35 静态 aarch64 产物，六锚点地址来自
g142 boot/Image。`98260-g142/syms_g142_kernelsu.txt` 同步参考 226 项表（仅补入
`init_cred`），SHA-256 为
`57ad9712f7b608ea8c95fe877e8788526b64fac5738559b7e4968f2888c3e725`。

98260 保留当前带生命周期/trace 修复的动态 PIE，不回退到参考旧静态 UAF。
目标头仅校正当前 C 未引用的 `LINK_ALLOC_TASK` / `BNE_LINK`；重建后资产不变：

```text
e5d4a5095bb59964a7edfd0e37aa813f341fdbf62f59c9aa0ea96c821e28141a  98260-g142/exploit-android-key-ptr
8838ab17e38252492df3761b74126855bde8a77ed5ab02255b67ebef81376ab1  98260-g142/pc98260-su
```

新增 `98260-g142/SHA256SUMS.txt`，覆盖 payload、su、target 与五张 Flavor
符号表。6.12 的 9 profile × 5 Flavor 共 45 组内置模板均静态
`PATCHED=... MISSING=0`，9 个 payload 均可由当前源码逐字节重建。
`build-98260-6.12.ps1` 的记录 hash 已更新；只有显式 `-VerifyRecordedHash`
才把 on-device 记录 hash 作为硬门禁，Windows NDK 不再产生误拒。
`build-98260-direct.ps1` 的 profile 定义、hash 输出和安装目录也已修正。

完整接入和验证边界见 `docs/APH136G142-ADAPT.md`。未在 g142 设备执行
UAF/rootd/LKM；参考报告与本仓库均将该链路标为静态适配。

## 6.12 / g142 四项优化（2026-11-08）

详细实现和验证边界见 `docs/612-G142-OPTIMIZATION.md`。本轮只读预检现在按
verdict 返回 0/2/3（ok/blocked/inconclusive），不再固定成功。三份共享 C
源码 SHA-256 均为
`1657761c1f57cdc4940ca3b165770ebdefa3dfb9aaca8563668065f7cdc84c64`。
12 个 payload 用 Termux clang 21.1.8 动态 PIE 重建，均为 76,160 B：

```text
65c019609811277058d0cea18fb9ac2bbbb541fde5a59a1b9176ff61ccb89be3  98260/exploit-android-key-ptr
a2f9bd8dc378bf929e1605648f4d92344ff389371210801e744edc06244e9a18  98260-61258b/exploit-android-key-ptr
a2f9bd8dc378bf929e1605648f4d92344ff389371210801e744edc06244e9a18  98260-aph112/exploit-android-key-ptr
b3b95bd21926564cb42b6abe8ced59482a86f38dd26a9043a3272cd8e4e63f6b  98260-61258c/exploit-android-key-ptr
12c393692f4b61434284f50af80b54b0e1848379ebe92917e1508f6ad98705ef  98260-6138/exploit-android-key-ptr
e7ef13c31c5b8a097df284a6aba8f0463c6b920e21e40345589f82b25e641c16  98260-6138y/exploit-android-key-ptr
3ccda0670c72d8c26181a632c2600bf7476946d862c20de549ba4e648e651da2  98260-6123/exploit-android-key-ptr
d34b729a50e2aa7639d5cbd11493581ff32420def7f29c1cd5de0763971f8e93  98260-g856/exploit-android-key-ptr
acb9454565e2209d134680ad801dd6c2eab58310d5ac71a2395d558af260c510  98260-g142/exploit-android-key-ptr
48654c1810faf7dd1698242a42bcd66fd5d9981a3a2de9f194ac96f494d01230  98260-6658/exploit-android-key-ptr
2d77d671427899f3f7c45bc303108533d6bce04793f8a5c8a56f552f2c4ac257  98260-6689/exploit-android-key-ptr
56dd1c2ee685e2f5abd1e58d44f70591dc44c3e0d90753831062ccd65500bc26  98260-ga812/exploit-android-key-ptr
```

g142 KASLR helper 改为同源码动态 PIE，源码 hash 保持
`ab7a3ff6b0382017e4a3296fe402132b2dae9132f04381346ff3239ebea340ef`，
新资产为 10,704 B，SHA-256
`50af62de1e9aa6768efd3f3f0fcd520b888fdf08aac756d819e22cc5e4cb0adb`。
合成 capture 回归通过；原静态 ET_EXEC 在当前开发环境不能直接执行，未宣称
完成原二进制直接对照或 g142 真机采样。

g142/ga812 的 `pc98260-su` 新增到顶层 canonical 去重，aph112 的既有 payload
去重 hash 同步为 a2f9bd8d…；当前去重映射共 41 项。6.12 staging 排除并清理
113 个 6.1 专属文件（150,983,149 B），APK 内仍保留其他内核资产。

## 98260 real-cred 原位写与 direct-finit（2026-11-09）

本轮由用户明确要求把 real-cred 路线 port 到现有内核。相应 payload 从
`binary-sources/98260-6.12/`、`6658/`、`6689/`、`61821/`、`61821-brm/` 和
`98260-h1c/` 的当前源码重建。最终态不再把 `task->cred` 指向回收页内的伪造
cred，而是对 exec-mint 子进程的真实 cred 原地清零 uid/gid；KSU 使用 PLANT_PTR
写 `cap_effective`，由仍保留 CAP_SYS_MODULE 的 real-cred listener 直接执行
`finit_module`，避免 exec 后按 CapBnd 丢失该能力。listener 是临时命令交接，
不是 fake-cred 页面保活者；KSU 成功加载后自动退出，UAF 父进程仍保留至重启。

当前资产 SHA-256：

```text
c1c399a521d738b44f4b7526d606b78d74baf4cfbfa29f504b9be0dbaf41af95  98260/exploit-android-key-ptr
29204a7b4d3112bb00ef41996426d2836292c606af49e0d8ee4cb2c90ce89ab3  98260-61258b/exploit-android-key-ptr
13830c142fbe306a6c8602d76eb147be7753b0dafd0a24dcfed9f39ed369f169  98260-61258c/exploit-android-key-ptr
06fe53bdf2676823e4f91d29d82a4d0280c3f5adc238f23a43f0867a6ad5ec44  98260-6138/exploit-android-key-ptr
8c503566e924f6412e3901a7a3e4c2475ff35474d46628b8cf9fe8b7b1ce8565  98260-6138y/exploit-android-key-ptr
c24607fb4cf1670dfe58fc1de6343d570c3b737eb90cc50d787ae78e47f5d8e7  98260-6123/exploit-android-key-ptr
29204a7b4d3112bb00ef41996426d2836292c606af49e0d8ee4cb2c90ce89ab3  98260-aph112/exploit-android-key-ptr
2eb1f5b87703327d70e53e3d8637896fc4b02f1ccfa4c31b955a6ff9e157f43c  98260-g142/exploit-android-key-ptr
a7b3162833f32c8c7753fbd8c8184499957e0e5f4268be627d56380a55fe529c  98260-g856/exploit-android-key-ptr
c4db56ad0af4a1f0eef9ae747b2b75b66a514c95e23459cb280a3b5a7e6f6686  98260-6658/exploit-android-key-ptr
d3c95a1dbccc73b35ae8ac95b4a3998a7f04599baebf98a99b7995b003d23feb  98260-6689/exploit-android-key-ptr
e1423daeea919ed7b7e25e03f5f980eefd31199c754aeb4de7f18bb65b6a3962  98260-ga812/exploit-android-key-ptr
0db44f889c32673dcc5df0a60d9a54fa0d5a933412af3d23b60e16472dc9d4df  98260-61821/exploit-android-key-ptr
94d774ce96e2bc5574333b54c5400d0327025454ba5f40d7565c4ee050db1e18  98260-61821-brm/exploit-android-key-ptr
5ff8456a171d0618120e1ce4feb7dd411f9a717486c027f97a8c0bb07acb4dee  98260-h1c/cve98260_plant
```

6.12/6.6/GA812/61821/H1C 均为本机 clang 21.1.8 动态 PIE；61258c、BRM、H1C
按各自发布参数 strip。legacy BRM 因而从历史静态 NDK r28c 改为本机可复现的
动态 PIE。`build-98260-6.12.ps1` 的九组记录 hash、各 SHA256SUMS 和
`tools/asset_dedup_map.json` 的 aph112→61258b 映射已同步。没有新增资产路径，
现有 ASSETS/profile 注册不变；f171/g554 及 6.1 派生 payload 未替换，runner 对它们
保留旧协议。

direct-finit/shutdown 仅用独立 socket 和测试桩验证协议及退出，未加载模块。
6.12.58 此前已真机验证 real-cred uid0 与 CAP_SYS_MODULE 原语；本轮新 runner 的
真实 KSU 加载/管理器闭环、其余内核和 6.18 均未做对应真机验证。详见
`docs/98260-REAL-CRED-PORT-PLAN.md`。

## 2026-11-09 6.12 real-cred capture retry rebuild

19:06 的失败日志在 UAF 之前中止：`[cred] no real cred ... site recs=0`。同一
boot 上的只读 `--diag-cred` 实测显示 slide 正确（`prepare_creds+0x2c`，
隐含 slide 与 `0x1269600000` 一致，`pid_hits=1`），说明这是一次可重试的瞬时
漏采，而不是常量或内核不匹配。`kmem` trigger 也可能写入成功但事件未实际启用。

源码改动（`uaf_plant_61258.c`）：

- 捕获前读取 `events/kmem/kmem_cache_alloc/enable` 校验事件真实启用；失败时
  disable/再次 enable 后复查；（该读回在 shell 域被 SELinux 拒绝，已在同日
  下一版改为校验 `rss_stat/trigger`，见下节）
- `leak_real_cred()` 改为最多 3 次有界重试；每次 miss 会通过 EOF 释放 mintwait
  子进程，再重新 arm trace。整个捕获阶段在任何 UAF 之前，重试不写内核内存；
- 新增只读 `--diag-cred` 模式及失败直方图：raw bytes、cred/k_itimer 尺寸记录的
  call site、隐含 slide、pid 命中数；不触发 UAF、不写 cred。

本机 clang 21.1.8 动态 PIE 重建的九个 6.12 资产（61258c 按发布参数 strip）：

```text
5528571cd03df888aa94d081477513855500dc6b3a9f38115afdc7caa5987081  98260/exploit-android-key-ptr
17b987b369f640569880a7863dc0eb8d8a12dc9eaf392cead32c14a899da119f  98260-61258b/exploit-android-key-ptr
17b987b369f640569880a7863dc0eb8d8a12dc9eaf392cead32c14a899da119f  98260-aph112/exploit-android-key-ptr
10d6572b50c614fd7952d21766c1810582c859e04596cd1c2f2a280d688a89ce  98260-61258c/exploit-android-key-ptr
9f2020890880a2bac36ba002dfa71f7fafc73824c47a21243fcb201b1749510c  98260-6138/exploit-android-key-ptr
d91d3defbd7e5c17c51ef20a98628cd2130d14d3557c40f910cca4242fca46b5  98260-6138y/exploit-android-key-ptr
0e748f8807f43049f733a42798c66891f57e34e32d0e5b4cdc29fad334de5cc6  98260-6123/exploit-android-key-ptr
a58eedd88dfe73a5e983ef7a48708c91826212af53ae66c80ff7a4ece7eb7dc6  98260-g856/exploit-android-key-ptr
ecf5a0c8e0d13633d19ade9cfabbfe75f1d8279b99d548b4723c3ddc50a5e764  98260-g142/exploit-android-key-ptr
```

这些 hash 是本机（cccodroid）clang 21.1.8 构建产物，与更早 Termux 路径构建的
hash 不同（debug 路径影响字节）。只读诊断与捕获重试在本机真机验证；重建后的
完整 UAF→KSU 链路未在本次重建后重新运行。6.6/6.18/H1C/6.1 源文件未改动。

## 2026-11-09 6.12 cred arm check fix rebuild

rc14 新增的 arm 校验读取 `events/kmem/kmem_cache_alloc/enable`，在 Android 的
SELinux enforcing 下 shell 域对该文件是 `EACCES`（同目录的 `rss_stat/trigger`
可写也可读）。因此三次重试全部停在
`[cred] kmem event not enabled after trigger` → `capture skipped`，
`raw=0`，链路在 UAF 之前 2 秒内失败。

实测证据（uid 2000 / enforcing）：

```text
ls -l .../events/kmem/kmem_cache_alloc/enable      -> Permission denied
cat .../events/kmem/kmem_cache_alloc/enable        -> Permission denied
cat .../events/kmem/rss_stat/trigger               -> 可读
写 enable_event 后 trigger 文件显示 enable_event:kmem:kmem_cache_alloc:unlimited
```

源码改动（`uaf_plant_61258.c`）：

- 删除 enable 文件读回；`cred_trigger_armed()` 改为读取 `rss_stat/trigger`，
  确认 `enable_event:kmem:kmem_cache_alloc` 已安装；缺失时移除并重新 arm，
  再查一次，仍缺失则关闭 tracing 并给出 `[cred] kmem trigger unavailable`。
- `--diag-cred` 增加 `trigger_armed=` 输出，便于只读复验该判定。
- 修正 `[selinux] enforce=` 缺少换行导致与下一条日志粘连。

本机 clang 21.1.8 重建的九个 6.12 资产（61258c 按发布参数 strip）：

```text
8c90abcd53db229ada9f9b390f8c0a6862499e232ca620433318758e1c2ad9a6  98260/exploit-android-key-ptr
a395651339deb20feee1313f814dacf12505898789793d3196cdfd2d3464d73e  98260-61258b/exploit-android-key-ptr
a395651339deb20feee1313f814dacf12505898789793d3196cdfd2d3464d73e  98260-aph112/exploit-android-key-ptr
95cc537f57fca2e12999e54144a87f0c23d2967321810f220e42a653ba432ac0  98260-61258c/exploit-android-key-ptr
4b706797f9ea2fe05b4137b93ccd216c80409935dfa59496463ddfcef8031a32  98260-6138/exploit-android-key-ptr
f96e3eea26705182bc021a65c7ba3a823ec1c2b8f02d3fd7cb667801d18caf8b  98260-6138y/exploit-android-key-ptr
05a23471abf1c0db953a534d77b7f8fd8d85b300897effb7f14a4a1831253722  98260-6123/exploit-android-key-ptr
289ce5d6590f4bd8587e565ec3be7a59e4ebf3634916e53b2f321a1e5ef4fd41  98260-g856/exploit-android-key-ptr
c1d536b7d119627bf19ae87d4009cf5c232e597aa3c2b198a182032cd74e2929  98260-g142/exploit-android-key-ptr
```

只读 `--diag-cred` 在同一 boot 实测通过：`trigger_armed=1`、slide
`0x1390200000`、`raw_bytes=86016 cred_recs=2 expected_hits=2 pid_hits=1`。
完整 UAF→KSU 链路未在本次重建后重新运行；6.6/6.18/H1C/6.1 源文件未改动。

## 2026-11-09 6.12 per-CPU tail scan + post-churn wait rebuild

22:27 的 rc15 运行在 169 秒内耗尽 12 次尝试。高负载下旧检测器把 4 MiB
预算共享给 cpu0..cpuN 的正向扫描，后续 CPU 的最新 `mm_page_alloc` 会被漏掉；
另有 4 次在完整 timer churn 后仍各等待 25 秒，约 100 秒耗在空等。

本次把 6.6 同源代码已有的 `trace_tail` 修复重新移植到 real-cred 6.12 源：
每 CPU 独立预算、从最新事件向旧事件扫描、alloc 优先扫描 free CPU；命中仍必须
同时满足 `mm_page_alloc`、覆盖 stale-node 所在 4 KiB 半页、task 为当前进程。
`PLANT_ZERO/PLANT_PTR`、tile 与收尸判据未改。完整 churn 未找到 free 时，尾部
被动等待默认收缩为 `min(PC98260_WAIT_CAP_S, 1000 ms)`，可用
`PC98260_POST_CHURN_WAIT_MS` 调整。

本机 clang 21.1.8 动态 PIE 重建的 12 个共享源资产（61258c 按发布参数 strip）：

```text
f829548b221eaa3f531e9e57380795cd09a96b9b9f6cc42efdeb9c97788b237c  98260/exploit-android-key-ptr
2d5b580172c54d2a3035604e0c2f49bbce9e40ca57e78630a91034a325d6879f  98260-61258b/exploit-android-key-ptr
2d5b580172c54d2a3035604e0c2f49bbce9e40ca57e78630a91034a325d6879f  98260-aph112/exploit-android-key-ptr
07f198d6a9e4710ef8a93a23ce06a94deddb6053f3abb15e19071c869dc16372  98260-61258c/exploit-android-key-ptr
7f3bfb7d5125f938d65d555900e4725ba8bc4672fc3031a9992758d0e17dd82e  98260-6138/exploit-android-key-ptr
376684f917895f307287c41d48a0e85463f26740633d73ca6587284bb2c1d790  98260-6138y/exploit-android-key-ptr
4ac1a59cd4b96a275db2d2fb900ebdd52e0b6eb33fcd5bfb91a581c4ee76ce78  98260-6123/exploit-android-key-ptr
c25853ec75f5a038f3bbbb55b8f8529ae7858ccec34920a0b36c394025300bf2  98260-g856/exploit-android-key-ptr
c50494d69f27e7823179e27aa208f509fc5a8319b84ba3ca04bd0d7a73777de5  98260-g142/exploit-android-key-ptr
989c9a652c2f8f762729922e72ce3f0bba35166adbbf1b6ebce67616f2acdc7e  98260-6658/exploit-android-key-ptr
bab78e1fcc4d9aa741ccfe8eb3944b0af1dee652ff3bd155f707aa76a76ca9e8  98260-6689/exploit-android-key-ptr
ba583a897e326032d74bf5fa400a8c5ffe59d54514acc7b3044e32fd08fdf90e  98260-ga812/exploit-android-key-ptr
```

未 strip 变体均为 81,952 B，61258c 为 71,024 B；61258b 与 aph112 继续逐字节
相同。6.12 与 6.6 三份共享 C 源已恢复逐字节一致，并一并补齐 ARMED/NO_ROOT
原子状态、waitid/waitpid 失败保持 UNPROVEN、preflight 真实退出码。此次完成
编译、语法与 43 项生命周期静态回归；当前 6.12 boot 已 parked，没有触发修复后
的真机 UAF，6.6 也无对应真机复验。6.18/H1C/6.1 源文件未改动。

## 2026-11-09 rc16 真机否决与 rc17 6.12 收缩候选

rc16 在设备执行后发生 `abnormal:AP_S_PANIC`，该候选不得合入。崩溃 boot 的
native 日志未能导出，dumplog/faultdetect 在 Enforcing 下拒绝 shell，故不能
把具体栈或根因归给某个 tile。此处只记录可确认的收缩，不伪造 panic 归因。

- 撤销 rc16 的 6.6 整文件同步；6658/6689 源恢复修改前快照（源 SHA-256
  `4d702f9a…fdda34f`），6.6 三份资产从 rc15 原样恢复：6658=`485a3a0d…f47240`、
  6689=`fe8d9de5…f2444e9d`、ga812=`c086c951…f006`，未重编 6.6。
- 6.12 仍使用 real-cred 原位写，但 uid/SELinux pass 恢复 fake-cred 已验证的
  `CRED + SELINUX + NONE` 三槽布局；撤销 rc10 的 self-parent cap 合并优化。
  CAP_SYS_MODULE 回到独立 PLANT_PTR pass，并在 finit 前逐次读取 bit16。
- per-CPU 尾部扫描只改变 trace 读取；churn 后 1 秒尾等待只影响 miss 耗时。
  ARMED/NO_ROOT 与 waitid/waitpid 失败门禁保留，均有本地回归覆盖。
- rc17 仅重建九份 6.12 payload，属**未合入候选**；真机未复验。

```text
32b44727f09be6e5b438ca53764d01e2e54578e420125b83998dec7186cd8f12  98260/exploit-android-key-ptr
c6fc03cf0a5fb7a893c396b90b0ead8d496cae3fa0f29a05182e0fceb98af3ad  98260-61258b/exploit-android-key-ptr
c6fc03cf0a5fb7a893c396b90b0ead8d496cae3fa0f29a05182e0fceb98af3ad  98260-aph112/exploit-android-key-ptr
d6e20fabb5292f893d02fb905c1c092f744734bb55d20dbde113a6962a155399  98260-61258c/exploit-android-key-ptr
257ceb5c47db39b66c8b4b45bc02c3356b58aa608a5717b8ce4cb25ae878281e  98260-6138/exploit-android-key-ptr
8dd8acb0e26e4f7b612ce2fc8174d72de375075c63d0a92c7e3aa3ca9d816942  98260-6138y/exploit-android-key-ptr
9cba664ed60773bf40dff3a918ba28cc0d14c1f5557ca9b8599dfadd40a4dd86  98260-6123/exploit-android-key-ptr
28800713a8a31fd25ca026df24ecbc114816850b0b5fa11880eaccc0f6ad9e25  98260-g856/exploit-android-key-ptr
0fcd02983a14d678fe06dd52897cd79ccc5e479eb21c3f3e69a3e80111e7916a  98260-g142/exploit-android-key-ptr
```

未 strip 的 6.12 变体为 81,792 B，61258c 为 70,896 B。
候选 APK 为 `/sdcard/cccodroid/MagicRoot-rc17.apk`，61,189,104 B，SHA-256
`7e60b19d18cffc9821e30a390750d271209a061a5cac18f26712589108e7d500`。

## 2026-11-09 98260 fake/real 双分支与 manager-paired late-load

本机 clang 21.1.8 重建九份 6.12 双模式 payload；同一二进制包含明确分开的
fake-cred/rootd 与 real-cred/separate-cap/direct-finit 分支，由 runner 的
`MAGICROOT_98260_CRED_MODE` 选择。6.6 仍保持 rc15 恢复资产，本轮未重编。

```text
480106febd1c40a7944243a040fce55474821288fbbbb5f08a685af2442d682e  98260/exploit-android-key-ptr
7a2ee238b83c34c3a14bc5093d5fee9e70f94008a3f50870b10f40ce0d08b876  98260-61258b/exploit-android-key-ptr
7a2ee238b83c34c3a14bc5093d5fee9e70f94008a3f50870b10f40ce0d08b876  98260-aph112/exploit-android-key-ptr
ce81e03a8c3976f206822869e1bb4b07bf1c0eb5302dff5c7458857338bf87cf  98260-61258c/exploit-android-key-ptr
bfa68cde9f76965ed78eb5785596b933f3d1b5a30ad4661d4742d3ef2e4198bf  98260-6138/exploit-android-key-ptr
18b82cb9f8af407f3be43aa0dc7100fad145963ee08b09b464c39fee3e5f3c5e  98260-6138y/exploit-android-key-ptr
08a1c0e557008f94bc635556abad87e8a96b45fbd8b93cada303bc6bedab5be9  98260-6123/exploit-android-key-ptr
60a73645ea5cb4b9455b49d7633042d034d08403fbbd442746586b5c45ab696f  98260-g856/exploit-android-key-ptr
303768639bb0235f2b3c748bdc83f95e8e2d090be0f86ef37fe9c16d00f6cf82  98260-g142/exploit-android-key-ptr
```

未 strip 变体为 85,448 B，61258c 为 74,288 B。`98260/run98260.sh`
SHA-256 为 `8125b8621a7e0731357d45e9979340dbe7db4b07d6cf284554b51bb435b5944c`；
`root_stage.sh` 为 `d3d95b08b4e1ffd096acccfdab93416f54126e5d95eea6af9a23e9a1df3af6e8`；
`lsposed-hotfix.sh` 为 `66ea7d1ca9619d13833734b95e7d67dc0a99e6b4388116075853d4737bdaaca9`。

real/fake 均强制从当前选中管理器 APK 提取配套 ksud/LKM，不再使用内置或其他
版本回退；两分支均不修改 packages.list。real 先 direct-finit 保住
CAP_SYS_MODULE，再由同管理器 ksud late-load 完成用户态；fake 直接由 rootd 调
管理器 late-load。rc17 的 unproven=3 + soft-reboot panic 后，guard 改为 root 侧
读回、unproven marker 增加 fsync，无效 marker + live plant 时 hotfix fail-closed。
以上为本地实现与静态验证，未做双分支真机测试。

双包（同版本、同 V3 证书、同 286 项资产，DEX 默认分支不同）：

```text
cc3cdc6e6b562bb5b2ecc346677e6a869d64e195856496cd2547c048b3647109  MagicRoot-real-cred.apk  61205489 B
ef4ce60eeb7a1d13ca2884f4ce20a6e9c28ce4f28854519de17c086f94d485a5  MagicRoot-fake-cred.apk  61205489 B
```

## 2026-11-10 free-gated precise-hit 6.12 重建

按 onekeyjb/Shark 的真实成功规格，将 stream reclaim 改为“无 free 证据不写入；
有 free 后默认 4096 次有界写、每 80 次检查、命中即停”。保留 self-task、
node_pfn、victim ledger 和 real/fake 分支写原语，不启用 pipe/AIO fallback。
九份 6.12 资产由本机 clang 21.1.8 重建；6.6 未重编。

```text
bd56d7fd5649251f72c564a2e408ee8b8b90640dffc41561ff2bc035ae65e083  98260/exploit-android-key-ptr
5ec749037887bae880691326d44f78b1a8ac4802df93d74fbc1ed7390aa6e723  98260-61258b/exploit-android-key-ptr
5ec749037887bae880691326d44f78b1a8ac4802df93d74fbc1ed7390aa6e723  98260-aph112/exploit-android-key-ptr
88c43f9622461f80d68a5790eb66f746ec2516e8a7500764ead3beaf7903fcbe  98260-61258c/exploit-android-key-ptr
9886d65feb19ecc8acdd0b698799adbc24f1f5753a65470210049cdbbc8580b4  98260-6138/exploit-android-key-ptr
f76cfdedafe9896691b65d147c44f3c202b5c9ad7c8830a31211bf245b91e148  98260-6138y/exploit-android-key-ptr
c9f1c902015db25587f7a237992bcfaf7d1294c661c28a0224b031eb16ce5046  98260-6123/exploit-android-key-ptr
0e9f511aff72bfc9bae52fdcbd31fccaaa385d4d9f4c330205dfe34041760137  98260-g856/exploit-android-key-ptr
75c654290088c28991caa2669fe3dac4c72c1408d0120208ed7c17d70c6460c8  98260-g142/exploit-android-key-ptr
```

未 strip 变体 85,688 B，61258c 74,528 B。新增恢复日志迁移到应用外部私有目录，
以便异常重启后由授权 shell 取证。该候选只有本地静态/JVM 验证，未真机复验；
详细依据见 `docs/ONEKEYJB-PRECISE-HIT.md`。

最终候选包（同 61,209,585 B、同版本和 V3 证书，286 项资产一致）：

```text
97d983dfcb30729431d5ecee2ebfaba6769e863fc6267e129572dff6e266748b  MagicRoot-real-cred.apk
8c7a19d601e3c687d6a5114544f127a915be44a54a419b180794b0db340860d8  MagicRoot-fake-cred.apk
```

## 2026-11-11 6.1 CGA 三项功能恢复（g264 / gaaa）

使用用户提供的原始 CGA 对象包，恢复 `su_compat`、`kernel_umount` 和
`selinux_hide`。原始包 SHA-256：
`170c60e1aff18679497e7a0d7e50d0719aadb2c6b94cdcf13082fa8fd759c911`。
上游基线为 KernelSU v3.3.1 `0c0fdb960178fa12d80d6cbcfdcb6ad8be6a865d`；
对象编译器为 Zig 0.13.0 自带 Clang 18.1.6。完整输入 hash、原样对象对照和
构建命令见 `docs/6157-CGA-FEATURE-RESTORE.md`。

```text
b44cc79de9196c65a0f2ffe1a6e5b23dff7713c68f8752c3fe861c627d78399a  g264/ksm-g264-base.ko
64ebb525f3f98c73a0cc648f27552b0e5792ee18aaf87c6b1fdade15a90bc377  g264/ksm-gaaa-base.ko
8864b383c8be0ced39018b6c30eb983bb7e19b2187645c520a78a6c08005e510  binary-sources/61157-g264/cga-feature-restore.json
```

两份模块均为 422384 B、226 个绝对符号、221 个活跳板。
`61157/g264/ksm-g264-base.ko` 同步为相同字节，去重表和
`6157-integrity.tsv` 已更新。`binary-sources/6157-g264/build-feature-restore.sh`
在全新输出目录复现了相同两份 hash。

旧 225/220 base 曾保存在 `binary-sources/61157-g264/legacy-cga/`；该审计副本
已从公开树移除（SHA-256 `6381ad16a904af8d7d2a702e04994ed22c3fd01c6e00229ec584634034a56c09`），
不打包进 APK。`g8a496/g2e1f` 缺少新增 tracepoint 符号的地址，
其余旧 CGA profile 也未重链，均保持旧资产；`g19a` 的完整上游 MagicPad 模块
未被替换。当前结果只有主机侧构建和静态验证，未真机加载。

## 2026-11-11 late-load init_cred / throne 修复

新增 `binary-sources/64560/native/throne_patch.c/.h`，把上游
`track_throne`/`do_track_throne` 的 `ksu_cred` 引用改为 `init_cred`，并支持
FinaSU 的包装层和严格 already 校验。两份 `ko_patch.c` 均调用它，保留
`REPAIRED` 与 SHN_XINDEX 修复；`build-binaries.ps1` 已纳入构建。

fake/primary 均先 `ksud insmod` patched KO，再 late-load 用户态阶段；不再先加载
管理器内嵌原模块。real direct-finit、staged patched-KO late-load、H1C 与
insmod fallback 同样消费修补模块。无证明地址显式为 `unavailable`，不伪造成功。

```text
fe3f983200083767baa822d76d46d32f6aa42bb3e4419762306b894b1f6dc10c  main/app/assets/ko_patch
```

2026-11-11 官方 KernelSU 管理器更新到 32727 后，其内嵌 LKM 多出 11 个
符号引用，随包符号表缺失导致 `MISSING=11`、KSU 阶段 fail-closed。ko_patch
现在输出 `MISSING_SYM=`，并接受可选的 `/proc/kallsyms` 转储做完全同名补全；
转储中的运行时地址直接作为 ABS 值，零地址一律拒绝。详见
`docs/RUNTIME-SYM-COMPLETION.md`。

real-cred 真机实测表明运行时补全在该路径不可用：`kptr_restrict=2` 且
rootd 在 finit 之后才启动，缺符号时 runner 等不到 rootd。主修复改为静态
补全：`tools/sync_manager_symbols.py` 仅在所有重叠符号地址一致时，把 11 项
从同内核 bakasu/fina/sukisu 表补入 14 个 kernelsu 表。用从管理器 APK 提取的
6.12.76 / 6.6.127 / 6.18.32 三个变体验证，16 个 profile 全部 236/236
`MISSING=0`；10 个有精确镜像的 profile 逐项核对 237 项零差异。运行时的
rootd 等待上限降为 6 秒，仅作为已存在 rootd 时的兜底。

`tools/test_init_cred_patch.py` 覆盖五 Flavor、6.6/6.18、Fina do_track_throne、
幂等和 late-load RC。`tools/sync_init_cred_symbols.py` 只用精确 boot 或全重叠
映射补地址。2026-11-11 补充的精确 6658 boot（SHA-256
`bf22d44ba14dd87327ea7b5dc8bb28fd71b1ae4b71c39e1f10a204c62039e278`）导出
109221 项 kallsyms，证明 `init_cred=0xffffffc082170748`；五张 6658 表全部重叠
符号零差异后各追加这一项，五 Flavor 模板均 `TRACK_THRONE=patched`、`MISSING=0`。
此前列出的 unavailable 缺失项全部补齐，详见 `docs/INIT-CRED-LATELOAD.md`。
未重新执行真机 UAF。

## 2026-11-11 跨半页 triple 修复与 12 份 payload 重编

2026-11-11 22:09 的 fake-cred 运行仍触发 `page_request` AP_S_PANIC。根因不是
此前的 free→write 盲写，而是 `pick_triple()` 允许三个 armed timer 节点跨 8 KiB
slab 的两个 4 KiB 半页，而回收命中只证明 victim 节点所在半页；`TILE_NONE`
节点（fake/uid 的 base 2、real cap 的 base 0/1）落在未证明半页时，reap 的
`timerqueue_del → rb_erase/rb_next` 读到释放后残留内容。修复与证据见
`docs/ONEKEYJB-PRECISE-HIT.md` 第 6 节。

三份同源 C 已改：
`binary-sources/98260-6.12/uaf_plant_61258.c`、`binary-sources/6658/uaf_plant_61258.c`、
`binary-sources/6689/uaf_plant_61258.c`。

重编命令（设备端 Termux clang 21.1.8，动态 bionic PIE）：

```text
clang -std=gnu11 -O2 -w -pthread -I <source-dir> [target define] -o exploit-android-key-ptr \
    uaf_plant_61258.c stubs.c rootd.c
```

`61258c` 另加 `-s`；6.6 的 ga812 用 `-DPC98260_TARGET_GA812`，其余 target define
与 `build-98260-6.12.ps1` 一致。可复现性：用改前源码 + `-DPC98260_TARGET_G142`
在本机重编得到与旧资产完全一致的 `75c65429…6460c8`。2026-11-11 23:xx 又做了
第二次修复（见本节末尾与 `docs/ONEKEYJB-PRECISE-HIT.md` 第 7 节），g142 现为
`402591e0…f65f65`，其余 11 份用同一命令重编。

```text
0fd3ff76cce3288252a2cf6f8ad64463f21542ab29f007fcdfda1dd36a0c0b4d  98260/exploit-android-key-ptr (6.12.58, 86,800 B)
5c76d21c012c000241c4716563da13b323a015d5b0f93902f717eba42b7ac10b  98260-61258b/exploit-android-key-ptr (104,816 B)
f203ce9e58323e44155354e945e480bcec4267e3f9ec57f4f68611814a13513e  98260-61258c/exploit-android-key-ptr (92,072 B, -s)
6c7126208ab4e139df3614519160da17dff8f5265d4c1d3177fab8442c3eda7a  98260-6138/exploit-android-key-ptr (104,816 B)
fecaa9c7c58b5b0da03c90c3c3a3af5232504967d685fda4528179249ba2d29c  98260-6123/exploit-android-key-ptr (104,816 B)
0f7c58b031e6e2bce059febe445576ef4a06b99ec380a9e2f5805901f3a867f0  98260-6138y/exploit-android-key-ptr (104,816 B)
38444791c48c63a8e09343d893d20a934c9daa3caaa38c1415db583f2f906c79  98260-g856/exploit-android-key-ptr (104,816 B)
36dc9e61224ae3dce3961a607949af5f114368507c2bb5d2a361f50810b39523  98260-g142/exploit-android-key-ptr (104,816 B)
5c76d21c012c000241c4716563da13b323a015d5b0f93902f717eba42b7ac10b  98260-aph112/exploit-android-key-ptr (104,816 B, 与 61258b 相同)
ae7c08311b367cc066dae9dc3ef43c1904cc274930616fc8fcb35be05a5850d8  98260-6658/exploit-android-key-ptr (98,968 B)
0a62e2c06095d0a2a75622a0f9650ba07dfbd978133c6af19c6f1de1e96bab72  98260-6689/exploit-android-key-ptr (98,968 B)
095d9af075fdaaf3678ed8710cccc53b1c209210773cbb02b2d4fb8c198d2371  98260-ga812/exploit-android-key-ptr (98,968 B)
```

6.6 说明：旧 6658/6689/ga812 资产来自 rc15 恢复（含 `.relr.dyn`，由 Windows
NDK 链产出），本次同源重编不再逐字节等于旧资产；新二进制为动态 PIE，
静态验证通过但**无 6.6 真机**。`98260-g554` 与 `98260-f171` 没有对应源码
（provenance-locked），保持旧资产未重编，仍带旧 triple 逻辑；这两条路线在
真机使用前必须先重编。

`main/app/assets/98260-6123|6138|6138y|aph112|g142|g856|98260/SHA256SUMS.txt`
与 `tools/asset_dedup_map.json` 的 aph112 canonical hash 同步更新。


## 2026-11-11 深夜 二次修复：回收判定改为整块 order>=1 + 扫描器不再在窗口内分配

2026-11-11 22:50 的 real-cred 运行给出了直接反证：cap 第 7 次尝试 stream 命中并
`waitpid(status=9)`，但子进程 CapEff 始终为 0。该次 `[alloc-hit]` 是
`order=0 … GFP_USER|__GFP_COMP|__GFP_ZERO|__GFP_ACCOUNT`，不是承载 8 KiB tile 的
socket 写；当天三次成功运行的命中全部是 `order=1`。

根因：`find_page_alloc()` 只要求「本进程有一条 mm_page_alloc 覆盖该 pfn」，而喷洒
循环每 80 次写就调用一次扫描，`trace_tail_open()` 每次 `malloc(1 MiB)` 并 fread 整个
per-cpu trace —— 这些新堆页就在回收窗口里缺页，正好满足「命中」。零页被 fread 之前
是静默不写（CapEff=0），被写入 trace 文本之后就是野指针 panic。

三份同源 C 的修改：

- `find_page_alloc()`：只接受 order>=1、与 base 8 KiB 对齐、覆盖 base..base+1 的
  本进程分配（socket 的 kmalloc-8k slab 才满足），order=0 一律判 miss；
- `victim_scan_budgeted()`：`cover_self` 使用同一硬命中判据，看护循环不按假命中收尸；
- `trace_tail_open()`：启动时预分配并预触页 12 MiB 静态缓冲，只保留 trace 尾部；
  `--exec-ok` 与 mintwait 分支在预触页之前退出，避免 exec 竞态里 memset 12 MiB；
- 日志：`PC98260_SYNC_LOG=$LOG.sync` 由 payload 以 O_SYNC 镜像写入，App 启动时先
  导出 `98260.log` / `98260.log.sync`，panic 后不再只剩 NUL。

12 份 payload 重编（设备端 clang 21.1.8），hash 见上一节。真机 UAF 仍未执行。


## 2026-11-12 last_kmsg 实证、深度修复与 6.18.21-117 全 Flavor 适配

用当前临时 root 的 `/system/bin/su` 取回三份 root-only `last_kmsg`：
21:48 与 22:09 的 `rb_next` 出错地址分别是 `007075645f616582`、
`005f706667203645`（内存字节含 trace 文本 `E6 gfp_`），22:48 为
`rb_erase+0x154` 读 `0x8`。这直接证明扫描器写入的 trace 文本进入了被回收
slab；先前“整块 order>=1 + 扫描缓冲预触页”的修复方向由此得到实证。

三份 98260 同源 C 进一步修复：

- 加入 HOneClick Beta6 风格的 `exec_ready` 门闩：回收 socket/trace 布防完成前，
  victim 不 exec、killer 不发 SIGKILL；
- 新增 `exec_entered` 证明：仅当确实进入过 `execve` 时，`--exec-ok` 的
  `status=0` 正常退出才可验收，避免 3 次已经 plant 成功的 cap 尝试被丢弃；
- reclaim 在开门闩前失败时，子进程仍持活 slab，可安全 kill/reap；门闩开启后
  仍沿用 unproven parked 规则；
- `waitpid` 完成后立即 `close_stream()`，不再跨 attempt 累积几十 MB socket 数据。

12 份 payload 重编，g142=`689117a4…f05b`，完整表见上一节。

6.18.21-117 资产来源与验证：

- boot.img：用户附件，SHA-256 `ab93b5f8c3886da156825e659bcb47c0b2e4ba40d963fd5eab1a722cf3a204cf`；
  本地生成 143930 符号并转为 `name 0xADDR`，输出 `syms_117.txt`
  （`959d14a35197bbc8218335a6b12555b61170c62e02ecbc0f0eca960d52979d4c`）。
- KernelSU：用户上传 `lkm-aarch64-android17-6.18_kernelsu.ko`，原始
  `6f8cc8454f6b571c3aedcf65a4c3cd410bcf9c1d36dce51d51ab70eb9b07dd80`。
- SukiSU：`SukiSU_v4.3.0-r2_41150-release` 的
  `lib/arm64-v8a/libtqqfthevwb.so` 内 raw-deflate 偏移 `0x15bb73`，原始模块与上述
  用户上传模块逐字节相同。
- FinaSU：`FinaSU_v1.6.0_kernel-bundle.zip` 的
  `arm64/android17-6.18_kernelsu.ko`，原始
  `547f0c0aab87b7a9163650fccf1fa4a1ff4dfbe86b2428acdb10db4860a6ae30`。
- BakaSU：`Manager-release (2).zip` 内 BakaSU 4.2.0-rc3 管理器
  `lib/arm64-v8a/libksud.so` raw-deflate 偏移 `0x14d270`，原始
  `8d7495caab0fabdc5a3414cb7f6f72518da3406a3629727dbbb0af6d1b50f26d`。
- Next：仓库现有 `98260-61821/ksu-template-61821-next.ko`。

五份均用 `llvm-objcopy` 改写为精确 117 vermagic，再运行 `ko_patch`：
kernelsu/bakasu/fina/next/sukisu 的 `MISSING` 全部为 0。修改后 hash：

```text
8e0846472a0de6843c594b52c8bd9bef8172bc9cf380c83c71e42695722e96a0  ksu-template-117-kernelsu.ko
72b1369f8f7e41ec85e497e3a26c75b67c12c99070edc6a4e73d1c7562f6c8c6  ksu-template-117-bakasu.ko
4584c6b47e6001637371ff576fd56c22fa56a5b50af4946af969d9c522297db3  ksu-template-117-fina.ko
34806ea8872f3acffd23124a66a20ecd2b2d97c22d3123107c7fd53d7a26d5c5  ksu-template-117-next.ko
8e0846472a0de6843c594b52c8bd9bef8172bc9cf380c83c71e42695722e96a0  ksu-template-117-sukisu.ko
```

这些管理器内嵌模块是 provenance-locked 二进制，不声称可在仓库内完整复现。


## 2026-11-12 凌晨 三次新 panic 的后续修复

新 last_kmsg 显示：01:14 fake-cred 的 `[tile] CRED ... zero=0x8` 后
`rb_erase+0x154` 读 `0x8`；根因是 fake 分支只调用 `leak_task()`，没有执行
`leak_real_cred()`，导致 `g_cred_kva` 为 0。现已在 fake 分支释放 task-leak
helper child 后补做真实 cred 捕获，并在 `one_uaf()` 入口拒绝非高地址 cred。
同时 00:03/01:12 的 init 收尸 panic 证明 unproven victim 在父进程退出后仍危险；
App 在 `98260_SOFT_REBOOT_SAFE=0` 时不再自动清理工作目录和 plant 看护现场。

12 份 payload 再次重编，g142=`689117a4…f05b`。新增
`test_fake_cred_capture_and_target_guard_precede_uaf`，生命周期测试 50/50 通过。


## 2026-11-12 Shark / onekeyjb 机制研究与路径重构

研究记录见 `docs/SHARK-ONEKEYJB-LIFETIME-RESEARCH.md`。Shark 与 onekeyjb 均为
GPL-3.0（onekeyjb 另有 TERMS.md），本轮未复制其源码。

按 Shark `8c704a44` 与后续 `cee30d6` 的最终语义，Shizuku helper 改为
`cwd=/`、`HOME=/` 并移除 TMPDIR；当前 98260 6.12/6.6 payload/rootd 与 H1C
plant/rootd 的 HOME 同步为 `/`。特权工作区仍为 `/data/local/tmp/magic`，因为
Shizuku shell 无法进入应用 filesDir。

12 份 payload 与 H1C plant 重编；g142=`689117a4…f05b`，H1C plant=
`e1761a128a99398ac957df504ffd2482f5c8417e22de337a6326e842ee581077`。


## 2026-11-12 全流程优化合并

新增 `victim_finish_or_watch()`：real-cred 只有在全部 victim 都已 reaped/resolved
时才允许父进程退出；任何 open/unproven victim 都继续进入永久看护。fake-cred
保留原有持页看护，不套用该退出路径。新增回归测试，生命周期 51/51。

其余 root 复用、精确 profile、管理器提取与禁止软重启均为现有能力，未重复改写。


## 2026-11-12 raw-trace / 多线程快路径

新增可回退快路径：4 个持久 spray worker + 二进制 raw-trace 事件读取。
worker 在首次 exec 门闩前创建并复用；raw 读取复用预触页缓冲；硬命中与 parked
规则不变。`PC98260_FAST_SPRAY=0` / `PC98260_RAW_TRACE=0` 可分别回退。

真机只读 raw+文本 trace 对照通过（未运行 UAF），事件 id=330/328，字段布局一致。
12 份 payload 重编，g142=`689117a4…f05b`。新增回归测试后生命周期 52/52。


## 2026-11-12 02:13 快路径回归修正

该次 12/12 miss 的直接条件是 raw_trace=0 而 fast_spray=1；raw 事件 ID 无权限，
多线程事件洪水压过文本扫描。现要求 fast path 必须同时满足 g_raw_active，否则
回到原顺序喷洒。日志新增 fast_pool/fast_spray 区分。12 份 payload 重编，
g142=`689117a4…f05b`，生命周期 52/52。


## 2026-11-12 其他非路径提速优化

raw 启用前清空旧事件；已有 KSU root 时跳过 boot settle；durable log 对高频
cross-half/churn 诊断行不做逐行 fsync，其余关键事件继续 fdatasync。
12 份 payload 重编，g142=`689117a4…f05b`；新增回归后生命周期 53/53。


## 2026-11-12 02:32 fake-cred 验收修正

该次日志中 raw+parallel 多次 <1s 命中，但 fake-cred 一直停在
`uid=0 euid=2000`：代码错误地要求 uid==0 && euid==0，导致补写循环耗尽预算。
real uid=0 已是 plant 成功证明；euid 由 mintwait 子进程在接管时 setuid(0)。
fake 分支现与 real-cred 一样按 uid==0 验收，不再做无意义的 euid 补写。
12 份 payload 重编，g142=`689117a4…f05b`；新增回归后生命周期 54/54。


## 2026-11-12 02:42 rootd chown 失败兜底

fake-cred 当前只有 uid/gid 改写，可能不保留 CAP_CHOWN；rootd 原先将
bind/chown/chmod/listen 合并为 fatal，导致 socket 建立失败并卡住 720 秒。
现 chown 被拒时使用 chmod 0666 兜底，peer 仍仅接受 uid 0/2000；run98260.sh
另有 rootd startup failed 的 fail-fast。12 份 payload 与 H1C plant 重编，
g142=`689117a4…f05b`；生命周期 56/56。


## 2026-11-12 02:55 恢复 fake-cred 完整安装并收紧 real-cred raw 窗口

旧版 fake-cred 并非只写 uid/gid：它在回收页内构造 FULLCAP cred、SELinux blob
并安装到 task->cred。此前改成 real-cred 风格 uid 写入后，rootd 出现 EACCES。
现恢复该 fake 语义；real-cred 的 uid/cap 路径不变。

real-cred 侧继续保留硬命中、unproven 看护，并要求 raw 启用前 drain 旧事件，
避免把上一次 attempt 的分配当作本次命中。rootd 的 chown 兜底仍保留。
12 份 payload 重编，g142=`689117a4…f05b`；生命周期 56/56。


## 2026-11-12 03:25 fake 成功后 panic 的页寿命修复

新日志已到 uid=0/euid=0 后才被截断。原因是此前为释放 socket 缓冲加入的
`close_stream()` 在 fake 成功后也执行了，但 fake 的 FULLCAP cred 正位于该回收页；
关闭 socket 等于释放正在使用的 cred 页。现 real-cred 才在 reap 后关闭 stream，
fake 永久保留该页。另在 pick_triple 过滤 fake cred/blob 与其他 rb_node 重叠的
坏候选，提高有效命中率。12 份 payload 重编，g142=`689117a4…f05b`；生命周期 59/59。


## 2026-11-12 03:43 成功后不再额外 sweep

最新 payload 仍在 uid=0/euid=0 后被截断；代码顺序显示成功后还会执行
victim_sweep()，可能再次触碰失败 attempt 留下的 zombie。现只有 rooted=0 才 sweep；
成功路径只汇总并进入看护，real-cred 的 victim_finish_or_watch 也不再先 sweep。
12 份 payload 重编，g142=`689117a4…f05b`；生命周期 60/60。


## 2026-11-12 03:48 fake 成功后 sweep 的遗漏修复

与 1.0.5 旧源码做函数级 diff 后发现：fake 分支仍保留无条件 victim_sweep()，
此前只改到了 real-cred。fake 成功后若还有失败 attempt 的 armed zombie，这一步
会再次收尸并 panic。现 fake 也只有 rooted=0 才 sweep；页保留、FULLCAP 安装、
raw drain 与重叠过滤继续保留。12 份 payload 重编，g142=`689117a4…f05b`；
生命周期 61/61。


## 2026-11-12 04:00 O_SYNC 定位：接管阶段 setuid 触发 panic

panic 前的 O_SYNC 镜像最后一行是 `asked child to take over (KSU)`，没有 rootd 输出。
fake 的 uid/euid 已为 0，mintwait 仍调用 setgid/setuid，令 prepare_creds 在伪造
cred + 零 SELinux blob 上执行，这是成功后 panic 的直接位置。现仅当 uid/euid 非 0
才 raise（real-cred 需要），fake 直接进入 rootd；接管路径新增 O_SYNC 日志点。
12 份 payload 重编，g142=`689117a4…f05b`；生命周期 62/62。


## 2026-11-13 新增 6.6.118 g893 与 6.1.157 g8d6 静态 profile

两个新构建都只做了本地镜像推导，没有对应真机；均按“静态适配”记录。

### 6.6.118 g893e848657cc

来源：

```text
boot_ota_1794139884130.img  sha256 fea0621288c95b7d003b7897d066f4d2f94bd21c596d6426dd5dd3714302cb7d
gzip kernel                 sha256 81dcc9c0c74033795f1ab3fe5aebb140893f9f750c3cfd38e32d710c8fae5466
arm64 Image                 sha256 7f3d439d9f0ce0affb6c8e1d8aa72e768177edb7b3b4710e6aee8f0cdd609b24
```

新增资产：

```text
98260-g893/exploit-android-key-ptr  b1aece91bb860af0b47fa40b68a1f4d75cdd7bf1329df4752beed05f83fa3772  94,384 B
98260-g893/pc98260-su              8838ab17e38252492df3761b74126855bde8a77ed5ab02255b67ebef81376ab1
98260-g893/target.sh                来源本仓库，255 B
syms_g893_*.txt：从 g893.elf 完整补齐 init_cred、各 6.6 Flavor 表、各管理器内嵌 6.6 LKM 与 susfs_guard_lkm-6.6 全部 undefined（kernelsu 268 / bakasu 277 / fina 304 / next 272 / sukisu 284），MISSING=0，TRACK_THRONE=patched
binary-sources/6658/pc98260_target_g893.h  （新增，KernelProfileGenerator 草稿 + objdump 核对）
```

### 6.1.157 g8d63307071ad

来源：

```text
boot_ota_1794143607737.img  sha256 b234993bcc2e0284184f8296f6965231934709d23fa3da29ac21868d0ad459f4
vmlinux-to-elf 重建 ELF     116,742 symbols
```

新增资产：

```text
98260-g8d6/exploit-android-key-ptr  6b118559a691f45d51cccb0815b623b1d03c5801df40f2beb34b995659bcc7d6  （g264 成功载荷 rebase；与 g84 同 hash，因为 7 个地址和两个布局常量完全一致）
g264/ksm-g8d6-base.ko              e9c20b2904742f26f3242da3983fcdaaf13fdea4503c3f38aac50e2767250321
g264/syms-g8d6.txt                 65df4d0dbfd8d35b2dd3e9732e323ff3a7acfd9a4a46d730af50b18e7c214d97（358 项，含 250 CGA 符号 + g8d6.elf 补齐的 init_cred 与全部 5 种 6.1 管理器 LKM 依赖符号）
```

推导与验证边界见 `docs/6.6.118-G893-ADAPT.md` 和
`docs/6157-G8D6-ADAPT.md`。

### 2026-11-13 21:35 真机反馈修复（脚本层，不改二进制资产）

- `run98260.sh`：exploit 启动后从自身日志回填 `[slide] measured/cached`；
  KSU 已请求但最终未加载时以 `ROOT_OK_KSU_FAIL code=82` 失败，不再误报
  `98260_SUCCESS=1`。
- `run6157_full.sh`：管理器 KO 的 runtime kallsyms 第一遍 patch 后，若仍有
  missing，用 per-build CGA 表 + boot slide 对已 patch 模块做第二遍填充；
  第一遍的 SHN_ABS 地址不会被覆盖。用于补齐 g8d6 的 `commit_creds`。


## 2026-11-16 可选 CVE-2026-98937 KASLR oracle（kaslr-98937）

- 来源：https://github.com/woshigenm/CVE-2026-98937（MIT，`Copyright (c) 2026 woshigenm`；
  核对提交 `93ea96ba6edfe0eee05efb31b1c507474ec7ea94`）
- `main/app/assets/kaslr-98937/poc98937`：由该仓库 `src/poc.c` 用本机 NDK r30
  `aarch64-linux-android24` 编译；哈希见 `main/SHA256SUMS.txt`。
- `main/app/assets/kaslr-98937/slide98937`：MagicRoot 自写（`slide98937.c`，随包），
  从泄漏 callchain 求 2 MiB 对齐 slide，并输出 `PREPARE`/`SELINUX_ARG` 供 64560 交叉校验。
- g142 目标常量来自精确内核 ELF（SHA-256 f445f775…b17c56）：
  `_stext=0xffffffc080010000`、`_etext=0xffffffc0812b0000`、`_text=0xffffffc080000000`、
  `prepare_creds=0xffffffc0801935b8`、`selinux_state=0xffffffc0827e7a60`。
- 行为：`run98260.sh` / `run.sh` 默认 auto 优先尝试，失败回退原有 KASLR 源；
  `MAGICROOT_KASLR_SOURCE=off` 关闭。64560 g142 的 anchors 下限在 98937 源下
  记录式调整为 3（`KASLR_98937_ANCHOR_OVERRIDE`），PREPARE/SELINUX_ARG 交叉校验保留。

## 2026-11-20 新增 6.12.81 g52d15df5db87 静态 profile（98260 专用）

来源：用户提供 Magic9（MLY-AN00）整包 OTA 解包 boot.img（PayloadDumper
目录，未随仓库分发）：

```text
boot.img   sha256 565f1e43e9f817e3bb07a5c7629ba286c021d658ed8cdb2535ddc464c01c98b2
arm64 Image sha256 98c094cc62c3abc2bd8928c8b7865a10338d085523ebef4f39e88f76607d811e（42,781,184 B，未压缩）
Linux version 6.12.81-android16-6-g52d15df5db87-abogki576042287-4k
```

上游修复核对：98260 修复 `acb03d388181`（exec: Cleanup POSIX timers
right after de_thread()）**未合入**（begin_new_exec 仍是
exec_task_namespaces 后置调用，de_thread 无清理）；64560 修复
`920f893f735e`（timer_lock_sighand 重试环）**已回迁**（
posix_cpu_timer_del 二进制逐条吻合）。该 build 仅适用 98260 链路，
详见 `docs/6.12.81-G52D15-ADAPT.md`。

新增资产：

```text
98260-g52d15/exploit-android-key-ptr  f69df321ecde8504da9fc0710ddfe79ce8f00512548e77e774fb3c01ac48096f  104,816 B
98260-g52d15/target.sh               来源本仓库（常量元数据）
syms_g52d15{,_bakasu,_fina,_next,_sukisu,_nova}.txt  六张同内容表，
  由内置 6.12 五模板 ELF 未定义符号并集（264 项）对新 Image kallsyms
  解析，MISSING=0
binary-sources/98260-6.12/pc98260_target_g52d15.h  新增 per-build 常量头
```

编译：本机 Termux clang 21.1.8 动态 bionic PIE，
`cc -std=gnu11 -O2 -w -pthread -DPC98260_TARGET_G52D15 -o
exploit-android-key-ptr uaf_plant_61258.c stubs.c rootd.c`。
与 6.12.58 构建的关键差异：该 build 不再内联 `alloc_posix_timer`，
`LINK_ALLOC_TIMER=alloc_posix_timer+0x28`（非 do_timer_create+0xac）。

验证状态：**仅静态适配**（无对应真机运行记录）；`tools/check.sh`
全绿（含 APK 位等值 395 资产）。

## 2026-11-21 清理：66118 上游预编译件不再随仓库保存

`binary-sources/66118/ksu/` 原保存 6.6.118 上游管理器解包产物，仅供离线审计，
构建与设备端链路都不读取。仓库准备公开前按“开发/审计资产”清理，目录整体移除；
以下 SHA-256 为移除前实测值，继续核对上游文件时使用：

```text
8d610b3070d4aa6fb116008c2e2caf4e3972aa73744d9106dc257a50e9bda66d  next-6.6-kernelsu.ko
2771a2ae989b522b5d70f3288ad5a2f379488962d09c1fe11e13a745eba89362  next-ksud
e57ce23de951be6b0dee5030f6724322fed126aa4af71828994437bfb0bb61ad  official-6.6-kernelsu.ko
4b665513992e305f6714239e6fa07423358c8569506f07148fefc63d3b80d96f  official-ksud
365c66e5435a9ecdb3dbb23ceda2d9253568defeee3682af95220087094eff5d  official-ksuinit
df257cbb58a6070da196004db76c49e2c254743153202992770c40c1208d5c1d  sukisu-6.6-kernelsu.ko
abc3822f6b4b8521d57f9159aa5b7a56b51b4013eb13f9e38297339cbd79ddec  sukisu-ksud
c7034b996c739734ecefe4357397549443725830c3e395ee4e2dd7913a4c2b26  sukisu-ksuinit
```

运行资产 `main/app/assets/ksu-template-66118-*.ko` 与设备端管理器提取路径不受影响；
`binary-sources/66118/` 下的 `profile-66118.json`、`syms_66118.txt`、
`pc98260_target_66118.h`、`PATCH-NOTES.md` 保留，用于复现编译与符号表核对。

## 2026-11-22 6.6.89 6689 module_blacklist 清零点

`binary-sources/6689/pc98260_target_6689.h` 新增
`LINK_MODULE_BLACKLIST = 0xffffffc082378568`；`uaf_plant_61258.c` 在
fake-cred/real-cred 分支前用 `one_uaf` 清零，日志
`[ksu] zero module_blacklist attempt`。payload 重编（NDK r30，未 strip，
99,144 B）：

```text
45b883e695a4c96f9cba755404cca9079e487cd7b6ca32049cd44d461f59b566  98260-6689/exploit-android-key-ptr
```

六份 `98260-6689/syms_6689_*.txt` 同步为从该 Image 解析的 274 条表
（6.6 五家并集 + init_cred；66118 模板导入 0 missing）。
