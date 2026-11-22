# M6 Shell 1.9 APK — static analysis and chain audit

Date: 2026-11-04. This is a static reverse-engineering report only. The APK was
not installed or executed; no payload or kernel module was run.

## 1. Sample identity

```text
file      20261103213400-M6_Shell_1.9.apk.1
sha256    20c057f7fee9ba51bdf9649cdfa90f278269e5414ed7c597f4f729106d75b327
size      13,785,032 bytes
package   com.bvlansu.shell
version   1.9 (versionCode 10)
SDK       min 26, target/compile 36
signer    CN=BVLANSU, OU=Shell, O=BVLANSU, L=Suqian, ST=Jiangsu, C=CN
          cert SHA-256 3e5ea93c6091cd22cf55fbcc11d9081a00b9c60a4f2c0295ee12e43ceccf3b65
permissions: Shizuku API_V23 + its own non-exported receiver permission
network:  no INTERNET permission and no network endpoint strings found
```

It is **not** the M6 2.78 suite currently restored in
`main/app/assets/ksu6157-m6/`.  It is a separate single-activity Shizuku app.

## 2. Target kernel

Every executable and every manager variant is built for one exact kernel:

```text
build_target / vermagic:
6.1.157-android14-11-g84ffa64b710b
```

Confirmed in all six `exploit-1021*/1022*` binaries, the base `kernelsu.ko` and
all four manager variants.  The app also reads its bundled KSU module's
`vermagic=` and compares it with `uname -r` before doing anything.  It therefore
refuses other 6.1 builds, and has no relevance to g7d/g264/g3306/g77f/6.1.99/
6.1.128.

## 3. Assets

```text
assets/exploit-1021f   2,366,776 B  8232362c7eddc58c...
assets/exploit-1021h   2,367,920 B  2f997ccd772b468b...
assets/exploit-1021l   2,436,536 B  aa37bc517180c4d5...
assets/exploit-1021m   2,438,584 B  9f89711de7a89991...
assets/exploit-1022c   2,445,976 B  c568a1a0c108ae5e...
assets/exploit-1022g   2,450,248 B  12bb6eedea2f8903...
assets/kernelsu.ko       681,128 B  6673d9cb8d63a51b...  SukiSU base
assets/variants/com.resukisu.resukisu/kernelsu.ko
                        552,376 B  d53d9046a4280aef...
assets/variants/kqvdie.zeykvw.hpbcyd/kernelsu.ko
                        566,736 B  9c3abc5cd3efb67f...
assets/variants/me.weishu.kernelsu/kernelsu.ko
                        441,792 B  28f51719e1b06470...
assets/variants/me.yuki.fina/kernelsu.ko
                        663,728 B  132c16bb334be0d0...
assets/ksud           6,093,280 B  3f04ece47a648147...  SukiSU userspace
assets/load_ko        2,142,392 B  0038797145b54944...  same as restored M6 load_ko
assets/patcher           11,336 B  9841d18af969c38e...
assets/kgo.sh             4,501 B  ca7ef2cc4db5d003...
assets/postw.sh           1,786 B  f26ea2a20261a89e...
```

`exploit-1021h` is used only for `--check`.  `exploit-1022g` is the only
payload launched for both UI routes.  The other four exploit files are copied
but never referenced by executable commands in the decompiled DEX.  The
`kaslr_leak` and `su98260` names exist in code/asset lists but have no packaged
file.

## 4. Reconstructed runtime chain

1. User grants Shizuku and selects one of five manager packages.
2. App verifies the bundled manager-specific `kernelsu.ko` vermagic against
   `uname -r`; mismatch is refused.
3. `/data/local/tmp/.w9` is created and the listed assets are written through
   the Shizuku shell.
4. If the selected manager APK is present, its `lib/arm64-v8a/libksud.so` is
   extracted to `.w9/ksud`; otherwise the bundled SukiSU ksud remains.  The
   bundled ksud contains `versionCode=40000`, while the base module reports
   `KernelSU version 41100`; the no-manager fallback therefore has an
   unproven userspace/module version pairing.
5. `exploit-1021h --check` obtains the KASLR slide from JSON.
6. Default `b2` route starts:

```text
PC98260_SLIDE=<slide>
PC98260_KSU_SIG=1
PC98260_B2=1
PC98260_LOCKERS=7
PC98260_MAX_ATTEMPTS=1
PC98260_CHURN_PER_CPU=512
PC98260_CHURN_ROUNDS=64
PC98260_WAIT_CAP_S=60
PC98260_BUDGET_S=600
KSU_EXTRA='su_path=/system/bin/sh'
./exploit-1022g --no-real-cred
```

The traditional UI route launches the same binary with `PC98260_B_NODE=1`,
fallback enabled, a 120-second wait cap, and no `PC98260_B2`.

7. B2 waits up to 240 seconds for:

```sh
./su98260 -c 'id'
./su98260 -c 'sh kgo.sh'
```

8. `kgo.sh` is intended to enable root kallsyms access, run `patcher`, and load
   the patched module through `load_ko` with `allow_shell=1` and
   `su_path=/system/bin/sh`. `postw.sh` later restores kernel knobs and
   `setenforce 1`.

## 5. Critical packaging defect

The APK contains no `su98260` executable, no symlink creation, and no DEX asset
entry for it.  DEX calls it twice, but the only workflow that would install KSU
is hidden behind those calls.

`exploit-1022g` does contain `pc98260_try_ksu_install`, which would run:

```text
/data/local/tmp/.w9/kgo.sh > /data/local/tmp/.w9/child.log 2>&1
```

Static proof that this cannot rescue a fresh install:

- the function has no `bl`/`b` caller in the executable;
- neither its address nor the kgo string address appears in any runtime
  PT_LOAD segment as a pointer;
- its only raw pointer occurrences are debug metadata outside runtime segments;
- `axt` over the analyzed binary reports no caller;
- no other DEX command invokes `kgo.sh`.

Consequences:

- On a **fresh** `.w9`, both B2 and traditional routes can reach the temporary
  rootd but cannot invoke `kgo.sh`; the module is never loaded.
- The B2 route spends its full 240-second `su98260` wait before reporting a
  timeout.
- An old `.w9` left by a previous M6 Shell version that already contains
  `su98260` could mask the packaging defect.  That is not a self-contained
  install and was not tested here.

The existing MagicRoot `pc98260-su` client speaks the same
`/data/local/tmp/pc98260-root.sock` protocol and could serve as `su98260` in a
controlled port, but simply copying it into the APK assets would not be enough:
the DEX asset list and installation flow must also be changed.

## 6. Differences from the restored M6 2.78 / current MagicRoot g84 route

| Item | 1.9 | current repository |
|---|---|---|
| Target | g84 only | 10 supported 6.1 builds |
| UAF engine | new B2 single-timer payload, pressure-aware | proven 1.0.36 static blind engine; g7d uses original payload |
| KSU source | five manager-specific g84 modules | per-build CGA bases; g7d M6 modules |
| Relocation | on-device `patcher` against `/proc/kallsyms` | fixed per-build CGA mapping / M6 symbol lists |
| Bootstrap client | `su98260` (missing from APK) | `pc98260-su` / rootd + ksu workflow |
| Reboot guard | refuses if kernelsu already loaded; no UAF parked marker | explicit same-boot parked marker and no auto retry |
| Kernel knobs | temporarily writes `kptr_restrict=0`, `panic_on_oops=0`, `panic_on_warn=0`; postw restores | does not globally disable panic_on_oops/panic_on_warn |
| Verification | no successful device log supplied | g84 still static-only in this repository |

Only `load_ko` is byte-identical to the restored M6 suite.  The modules,
exploits, patcher, scripts and userspace flow are different.

The B2 singleton-timer / pressure strategy and on-device symbol patcher are
interesting, but they are new unverified mechanisms and cannot be represented
as an upgrade to the proven g264/g7d paths.

## 7. Safety observations

- Failure does not write a parked marker.  A second click after a failed UAF
  can start a second plant in the same boot.
- It temporarily lowers `panic_on_oops`/`panic_on_warn`; if `postw.sh` fails,
  those settings remain changed until reboot.
- It modifies `/data/adb` userspace and loads unsigned LKMs, with the same
  temporary-root and SELinux risks as the existing chain.
- No network permission or endpoint was found.
- No 43499/Pad3 assets were found.

## 8. Recommendation

Do not replace the current g7d M6 handoff with this package: it is g84-only and
its default flow is incomplete.  Do not replace the current rebased g84
payload at this time either; the current payload is deterministic and audited,
whereas 1.9 has no supplied device result and lacks its bootstrap client.

If this route is to be studied further, the minimal safe port is:

1. keep the current g84 chain as fallback;
2. stage `exploit-1022g`, the selected g84 manager module, `patcher`,
   `load_ko`, `kgo.sh`, `postw.sh` and `ksud` in a separate experimental directory;
3. supply the repository's existing `pc98260-su` as `su98260` (same socket
   protocol), with timeout and parked-marker handling;
4. preserve the UAF parent and block same-boot retries;
5. require an owned g84 device test before changing the default route.

No such port has been made in this repository.
