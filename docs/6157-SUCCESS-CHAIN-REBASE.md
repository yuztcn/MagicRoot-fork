# 6.1.x 98260: rebase on the proven 1.0.36 chain

Date: 2026-11-04.  Analysis was static only; no APK was installed, no exploit
helper was executed, and no module was loaded.

## Inputs

User-supplied files:

```text
MagicRoot-98260-1.0.36-6157.apk.1
sha256 cce10cb3ca64c4152f9c73c9b60f6a27bd9053dd3a919a708c7eb13de831bb0d
package com.aoki.magicroot, versionName 1.0.36-6157, versionCode 43

MagicRoot-6157-全量归档-20261102.tar.gz
sha256 6f0fd7cf03bfbc52bc3cfa0c1c964f9445a75221d62b4792210ac15d45320d21
```

The archive independently confirms the g7d M6 run and the g264 CGA/su-overlay
closure.  It also contains unrelated 43499/Pad3 material and device logs; those
were **not** imported.

## Proven g264 chain

The shipped g264 payload is the 2,327,648-byte static NDK r29 build:

```text
sha256 cc0b9693dcdba564585c39dfe3eb386860f1cede4251d0d7aca63d1e51762843
```

Facts confirmed from symbols, disassembly and the archived run log:

- `measure_slide` compares `k_itimer` with `0x108`;
- `collect_nth` compares it with `0x108` and uses
  `TIMER_LINK=0xffffffc0083bed18` (`do_timer_create+0x94`);
- `leak_task` uses `CRED_LINK=0xffffffc0080e6c6c` (`prepare_creds+0x20`);
- `main` uses `SELINUX_LINK-7=0xffffffc00a6fc9f9` and
  `sig_enforce=0xffffffc00a45dc60`;
- the normal and blind paths write cred/real-cred for the `0x838/0x830`
  family;
- `blind_reclaim_stream` is present and is enabled by
  `PC98260_G264_BLIND_RECLAIM=1`;
- `measure_slide` also constructs the negative timer link
  `0x3f7fc412e8` to calculate `site - timer_link` without 32-bit shell
  arithmetic;
- the provenance static uses raw linking bias `0xffffffc008…`;
- the previous 34,192-byte dynamic rebuild used biased addresses
  `0xffffffc080…` and **did not contain `blind_reclaim_stream` at all**.

The g264 asset has been restored byte-for-byte to the proven hash above.

## Proven g7d chain

g7d's original 2,319,440-byte payload remains unchanged.  Its successful KSU
handoff is not CGA:

```text
98260 bootstrap rootd
-> ksu6157-m6/ksu_loader.sh
-> magiskpolicy + ksu_rules
-> ko_patch2 with next_sym_addr.txt
-> load_ko with kernelsu-os9-selx11.ko
-> manager package/UID parameters
-> restore sig_enforce=Y
```

The 19-file `ksu6157-m6/` suite was restored from the supplied APK and is
registered for g7d only.  The OS9 and KSU331 modules both carry vermagic
`6.1.157-android14-11-g7d3922fade43`.  Exact file hashes are in
`binary-sources/61157-g264/m6-provenance.json`.

## Extended builds

The other eight builds retain their own remapped CGA module and now use the
proven static blind-reclaim engine instead of the feature-reduced 34 KiB
rebuild:

```text
g3306, g84, g77f, gce849, g5859, g54d, g40b1, ge9da
```

`rebase_success_payload.py` extracts each kernel's audited constants, subtracts
the old `0x78000000` link bias, and patches only:

- 11 absolute-address materializations (TIMER, CRED, SELINUX-7, sig_enforce,
  user_ns, init_groups, negative TIMER; multiple SELINUX call sites);
- 3 task->cred and 3 task->real_cred immediates;
- 2 `k_itimer` size comparisons;
- 4 absolute pointers in `.rodata` (root_user, user_ns, init_groups, ucounts).

No other bytes differ from the proven base.  The generator validates the
original value at every site before writing and re-disassembles every result.
The manifest is `success-profiles.json`; regeneration is:

```sh
python3 -I binary-sources/61157-g264/rebase_success_payload.py verify \
  --base main/app/assets/98260-g264/exploit-android-key-ptr \
  --profiles binary-sources/61157-g264/success-profiles.json \
  --output-root main/app/assets
```

Current hashes:

```text
98260-g264/exploit-android-key-ptr   cc0b9693dcdba564585c39dfe3eb386860f1cede4251d0d7aca63d1e51762843
98260-g3306/exploit-android-key-ptr  bba7b7e57f823f361073e89d2b986c91869a74cdfa31e3ad5d9c28a69f634a57
98260-g84/exploit-android-key-ptr    6b118559a691f45d51cccb0815b623b1d03c5801df40f2beb34b995659bcc7d6
98260-g77f/exploit-android-key-ptr   f1fff50a313fb5f63bc68f657628f5c7d08a0038837d7ef5e0a55e0e8dff85ba
98260-gce849/exploit-android-key-ptr 318c2ba312a7c461cd09146fd3fc3dab24d42890591e64a5a6fd2e276e0996e6
98260-g5859/exploit-android-key-ptr  25678da88f3769c63c6866f4d61700bb0126279f2033b3b3823eb945da323ba5
98260-g54d/exploit-android-key-ptr   0c5a86ab31057685a5583c6fbdb41051cfc7031ee327b8ec84fb53f105ebe48a
98260-g40b1/exploit-android-key-ptr  801f332954de365f8bc06b0c23794ff1f6e1a293b7be5bfb10a88aaba5895cd0
98260-ge9da/exploit-android-key-ptr  e6a44461c6d5fff39a62f1c993caf6579c94bce4e846ff84e8c3a3a0e6d12090
```

`g77f`, `gce849` and `g40b1` were audited as BTF family `0x840/0x118`, but
their previous 34 KiB payloads still encoded `0x838/0x108`.  The g77f CGA
module also carries the same 57 field remaps as g84.  The new manifest records
`layout_corrected=true` for all three and emits the correct family.

## Runner and deployment fixes

- g7d M6 branch restored ahead of CGA; g7d no longer receives g264 CGA files.
- Only g264 may use the `ksu6157-g264` `ksu_prepare`/`ksu-loader` absolute
  symbol table.
- Every other 6.1 build must use its own CGA base; missing assets now report
  `6157_handoff_unavailable` instead of falling through to another kernel's
  symbols or to 6.12/6.6 `ko_patch` templates.
- 6.1 preflight now emits `CHAIN_98260_PREFLIGHT_OK=1` on success.
- 6.1 success now follows the same SUSFS/soft-reboot/rootd cleanup path as the
  generic 98260 success branch; `SUSFS_ENABLE` is exported to the child.
- Deployment now whitelists shared 6.1 tools, exact per-build payload/CGA
  assets, g7d M6 assets, and no longer deploys 61157/64560/6.12 material to
  these kernels.
- Required-asset checks cover the exact payload, CGA base, patch helper,
  ksud/sigparam, su overlay, or the full essential M6 set for g7d.

The M6 suite is treated as byte-locked third-party material and added to
`.gitattributes` as `-text`.

## Verification

```sh
python3 -I tools/audit_6157_chain.py
```

The audit checks:

- all nine static payload hashes and blind-reclaim marker;
- g264 exact restoration;
- static AArch64 ET_EXEC without PT_INTERP;
- deterministic rebase reproduction;
- every CGA vermagic;
- all 19 M6 files, hashes and g7d vermagic;
- asset registration and g7d-only staging;
- branch order and fail-closed cross-kernel behavior;
- 6.1 preflight/SUSFS dispatch;
- Bash and Android mksh syntax.

Current result: `failures=0`.

## Remaining limits

- No current-change on-device run was performed.  g264 and g7d have historical
  successful closures, but this exact rebuilt APK must still be tested after a
  reboot on the authorized devices.
- g3306/g84/g77f/gce849/g5859/g54d/g40b1/ge9da have no physical device run.
  They now carry the proven UAF/reclaim engine and audited constants, but CGA
  late-load + manager + su overlay remain static-only for them.
- The other managers' `ksud` compatibility with the remapped CGA module is not
  proven by identical kernel assets.
- g19a/Pad3 remains on its separate 61157 route and is not part of this rebase.

## 2026-11-04 additional 6.1.128 profiles

Two unique old boots supplied in `荣耀boot对照_20261103_旧版本.zip` were added:

```text
6.1.128-android14-11-g8a4968670f1c
6.1.128-android14-11-g2e1f0741dafb
98260-g8a496/exploit-android-key-ptr  1db586a3f787a35d7f8872537470783397f2fbd9680a9877dd26beb2ca410f35
98260-g2e1f/exploit-android-key-ptr   e681569bcf6b51fa36e59622e6361b19653eeca2079c8b081f0b9a9ae2d47d27
```

Both are `0x838/0x108`; their distinct timer/cred function anchors are
recorded directly in `success-profiles.json`.  The manifest now verifies 11
payload profiles (g264 plus ten deterministic derivatives).

CGA bases are rewritten by `rebase_cga_module.py` from the unchanged g264
base, using `cga-profiles.json` extracted from the two target kallsyms:

```text
g264/ksm-g8a496-base.ko  450b242ba93e085de4545184882230980addefb336bd6922885b285863c19dfa
g264/ksm-g2e1f-base.ko   5b8f95453fa73e3c23aa0ffd071a2f354eb089358f4e13c2461fc87524075549
```

The generator maps all 225 absolute symbols and 220 live stubs by name and
rejects missing names, unknown stub addresses, and any byte outside the
three permitted patch classes.  Both builds remain static-only; no matching
device was tested.  Full report: `docs/61128-OLD-KERNELS-ADAPT.md`.

## 2026-11-07 additional 6.1.157 gaaa profile

The user-supplied gaaa boot was independently analysed and added to the same
static success-payload/CGA derivation flow:

```text
98260-gaaa/exploit-android-key-ptr  67cedbc21f3bd6c761291183dac054c5711407485fbff8c24a7d577409ee1fae
g264/ksm-gaaa-base.ko               64ebb525f3f98c73a0cc648f27552b0e5792ee18aaf87c6b1fdade15a90bc377
```

The manifest now verifies 12 payload profiles.  gaaa uses the audited
`0x838/0x830/0x108` family.  Since 2026-11-11 it uses the restored
226-symbol/221-stub CGA map recorded in `cga-feature-restore.json`; see
`docs/6157-CGA-FEATURE-RESTORE.md` and `docs/61157-GAAA-ADAPT.md`.  It remains
static-only and does not import the separate 43499/Pad3 route.
