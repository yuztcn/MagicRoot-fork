# Kernel / KernelSU flavor audit

Date: 2026-11-04

Reproduction:

```bash
tools/audit_kernel_flavors.sh
```

The script runs the production `ksu_select_ko()` from
`main/app/assets/kernel_profiles.sh` for every profile and every flavor, then
checks that the selected LKM template and symbol table exist.

## Asset matrix

All 70 profile × flavor combinations currently resolve to an existing
template and symbol table (Nova tables are audited separately by the
`nova` section of `tools/audit_kernel_flavors.sh`):

| Profile | Kernel build | Chain | Flavors |
| --- | --- | --- | --- |
| 61258 | 6.12.58 g3a7ac1674240 | 64560 + 98260 | all 5 |
| 61258b | 6.12.58 g459a4285ccf8 | 64560 + 98260 | all 5 |
| 61258c | 6.12.58 g42fcf008ff5c | 98260 | all 5 |
| 6138 | 6.12.38 gfde7767f6ef6 | 64560 + 98260 | all 5 |
| 6138y | 6.12.38 g7ae8ec909e03 | 64560 + 98260 | all 5 |
| g4b36 | 6.12.38 g4b3671e1f5b7 | 98260 | all 5 + nova |
| 6123 | 6.12.23 g45ea5e4bce8a | 64560 + 98260 | all 5 |
| g554 | 6.6.118 g554929766a0d | 98260 | all 5 |
| f171 | 6.6.118 gf17133276a57 | 98260 | all 5 |
| 6658 | 6.6.58 g6484937db664 | 98260 | all 5 |
| 6689 | 6.6.89 g082e5a98dac1 | 98260 | all 5 |
| 61821 | 6.18.21 g928d1bb4f1d7 | 98260 | all 5 |
| 61821brm | 6.18.21 ge186062ea75f | 98260 | all 5 |
| aph112 | 6.12.58b g459a (APH-AN00) | 64560 + 98260 | all 5 |

The five bundled flavors are:

```text
kernelsu  resukisu (BakaSU)  next (KernelSU-Next)  sukisu  fina
```

SukiSU Nova (`nova`, `com.sukisu.nova`) is a separate sixth backend.  It has
no bundled LKM template: the runner always loads the LKM extracted from the
installed manager APK, and only the symbol table is shipped.  Nova tables are
present for these profiles (exact kernel image / kallsyms source):

```text
61258 61258c g856 6138 g142  g554 f171 6658 6689 ga812 g893
```

Missing tables (fail closed at `ko_patch`): 61258b/aph112 (`g459a4285ccf8`),
6138y, 6123, 61821brm.  6.1.x uses runtime kallsyms and is not
statically completed for Nova.  See `docs/SUKISU-NOVA-SUPPORT.md`.

MapleSU (`maplesu`, `dev.maplesu.manager`) is a separate seventh backend.
It has no bundled LKM template either: the KMI module is carved from the
installed manager APK (container `libksud_ksu.so`; `ksud` 32650 / uapi 7),
and `kernel_profiles.sh` maps it to `$D/ko-maplesu.ko` for every 6.1 /
6.6 / 6.12 / 6.18 branch.  It is recognised by package name only, never by
versionCode (Nova 35000 < SukiSU gate 41013).  See
`docs/SUKISU-NOVA-SUPPORT.md` and the manager flavor audit.

## Fixes applied by this check

- `61258c + resukisu` now falls back to `syms_61258c_resukisu.txt`.
- `6658 + resukisu` now uses `syms_6658_bakasu.txt`.
- `g554 / f171 + resukisu` now uses `syms_66118_bakasu.txt`.
- `aph112` non-official flavors use the matching 61258b per-flavor symbol
  tables because APH-AN00 shares the g459a 6.12.58b kernel build.

## Runtime scope

This audit proves **asset selection completeness**, not that every kernel can
actually load every LKM on hardware.

Actually exercised on the connected test device:

```text
MLY-AN00
6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k
Android 17
selected manager: FinaSU
```

Result: complete deployment passed, including manager ksud/LKM extraction and
`ko-fina.ko` selection.  The full 98260/64560 exploit was not started yet, so
the final `finit_module` / insmod load is not verified for all flavors.

Still needs real-device runs:

- 6.12.58b / 6.12.58c / 6.12.38 / 6.12.23
- 6.6.118 / 6.6.58 / 6.6.89
- 6.18.21 g928 and g186
- 6.1.157 g7d/gaaa/g3306/g84/g77f/g8d6, 6.1.99 gce849/g5859/g54d/ge9da, 6.1.128 g40b1
- all five flavors on each of the above

## Known non-flavor paths

These paths intentionally do not use the five-flavor asset selector:

- `64560-61821` (6.18.21 g928) uses a single official
  `ksu-template.ko` + `syms.txt`; it remains an official-KernelSU route.
- `6.1.157 g7d` uses the restored M6 suite.  `g264` may use the manager LKM
  only when its vermagic exactly matches and the g264 `ksu6157-g264` symbol
  table is available; its fallback is the g264 CGA base.  Every other 6.1.x
  build must use its own `g264/ksm-*-base.ko` and fails closed if absent - it
  must not borrow another kernel's absolute symbols.  The manager's `ksud` is
  extracted for the CGA userspace path; non-official manager compatibility
  remains a runtime test.
- 2026-11-13 test build: all 6.1.x CGA profiles (plus g7d before M6) try the
  selected manager's carved LKM first.  It prefers a runtime `/proc/kallsyms`
  table (`name 0xADDR`, slide=0) and falls back to the build's
  `g264/syms-<build>.txt` + boot slide via `ko_patch`, loads with `insmod`,
  and falls back to the CGA/M6 module on any failure.  The per-build tables
  are derived from each `ksm-<build>-base.ko` by
  `tools/gen_6157_syms_from_cga.py`; they are build-specific and must never
  be borrowed across builds.  gaaa `20261113T081541` proved the CGA base can
  itself be stale (`_printk` 0xE00 off), which is why runtime kallsyms is the
  primary source for the manager LKO path.
- 2026-11-13 19:51 gaaa + SukiSU 4.3.0-r2 verified the generic path: manager KO
  `6.1.166-dirty`, runtime kallsyms 217,184 lines, `PATCHED=254 MISSING=0`,
  `insmod rc=0`, `KSUD_INSTALL_RC=0`, `SU_PROVIDER=ready`, method
  `manager-ko-patched`.  Runtime kallsyms is now required by default; the
  per-build CGA table is opt-in only (`...ALLOW_CGA_SYMS=1`).
- `6.1.157 g19a495a97bff` is still static/experimental.

Any claim of “all kernels × all flavors fully load” must wait for a device run
for those profiles.

---

## 2026-11-08 符号覆盖复核（管理器随附 LKM）

本轮按用户随附的五套管理器归档（FinaSU v1.5.0 / BakaSU v4.2.0-rc3 /
SukiSU v4.3.0-r2 / KernelSU-Next v3.4.2 / KernelSU v3.3.1）逐一核对每个
内核家族 × Flavor 的随附 LKM 与本仓库 syms 表，使用 `ko_patch` 同一套
`name 0xADDR` 解析逻辑做静态验收。没有在真机加载任何模块。

### 6.18.21 g186（BRM）运行时缺口

现场日志 `20261107172618-fail_log_1794072143401.txt`：

```text
98260_KSU_AUTOPATCH=1 path=/data/local/tmp/magic/ko-sukisu-lateload.ko
98260_H1C_SYMS=.../98260-61821-brm/syms_61821_brm.txt
PATCHED=245 MISSING=6 REPAIRED=0
98260_H1C_FAIL=ko_patch_missing
```

根因：SukiSU 41150 `android17-6.18` LKM 有 251 个未定义符号，
`syms_61821_brm.txt`（265 项）缺 6 个 BTF/nofault 符号。修复方式是从
HOneClick g186 全量表 `syms-115.txt`
（SHA-256 `15b661f3abe71abc663f66f02d98ed3241e230777f5dfd78d4bfa608b90773af`）
补入：

```text
bpf_get_btf_vmlinux        0xffffffc080625ae8
btf_find_by_name_kind      0xffffffc08067343c
btf_name_by_offset         0xffffffc080673568
btf_type_by_id             0xffffffc08042ac08
btf_type_skip_modifiers    0xffffffc080673b00
copy_from_kernel_nofault   0xffffffc0800b9ad0
capable                    0xffffffc08012f264   (FinaSU 额外导入)
```

原 265 项与 `syms-115.txt` 逐项地址一致，证明是同一 g186 构建。
`syms_61821_brm.txt` 265 → 272 项。

验证（全部 `MISSING=0`）：

| 模块 | 未定义 | 结果 |
|---|---:|---|
| SukiSU 6.18 LKM（BuildID 539f2f3c，614,424 B） | 251 | `PATCHED=251 MISSING=0` |
| BakaSU 6.18 LKM（477,296 B） | 240 | `PATCHED=240 MISSING=0` |
| FinaSU 6.18 LKM（550,096 B） | 240 | `PATCHED=240 MISSING=0` |
| KernelSU 6.18 LKM（375,328 B） | 225 | `PATCHED=225 MISSING=0` |
| KernelSU-Next 6.18 LKM（473,552 B） | 227 | `PATCHED=227 MISSING=0` |
| `98260-h1c/ksu-template-115.ko` | — | `PATCHED=227 MISSING=0 REPAIRED=14` |

用现场 slide `0x20b5600000` 复现同一条链路，结果同上。

g928（`61821`）沿用 HOneClick 全量表 `syms_61821_kernelsu.txt`
（138,181 项），五个管理器 6.18 LKM 本来就全部 `MISSING=0`，未改动。

### 6.18 参考镜像复核

用户提供的三个镜像与荣耀 boot 对照包逐一核对后，实际内容如下：

| 镜像 | SHA-256 | 内核 |
|---|---|---|
| `6.18.21-android17-5-g928d1bb4f1d7_boot(2).img` | `8848fb1f…` | 6.18.21-g928d1bb4f1d7 |
| `magic9promax-boot.img` | `7d027334…` | 6.18.21-g928d1bb4f1d7（镜像头/ramdisk 不同，符号表与上图逐字节一致） |
| `boot(1).img` | `697a6356…` | 6.12.58-g142ddad31e60（即 profile g142） |

用自适应生成器从 g928 镜像导出的 143,621 行 kallsyms 与
`syms_61821_kernelsu.txt` 对比：138,181 个名字全部存在、地址全部一致，
证明该表就是参考内核本身。`boot(1).img` 导出的 129,139 行与
`build/kallsyms/g142.txt` 逐字节相同（SHA-256 `f6167060…`），
也验证了 g142 补符号所用的数据源。

这三份附件里没有 g186（BRM 内核），荣耀 boot 对照包（两批）里也没有
BRM-AN00。但本机 `/storage/emulated/0/ 我的文件/boot (1).img`（目录名带前导
空格，67,108,864 B，内核未压缩、43,207,168 B）就是 g186 构建
`6.18.21-android17-5-ge186062ea75f-abogki564062290-4k`。用自适应生成器导出
143,769 行 kallsyms 后与 `syms_61821_brm.txt` 全表比对：**272 项（原 265 +
新增 7）全部存在、地址全部一致，0 缺失 0 不匹配**。7 项补丁由此得到独立镜像
确认。同目录 `boot (2).img` 的内核是 6.12.58-g42fcf008ff5c（profile 61258c）。

### 管理器 LKM 比内置模板多导入的符号

`syms_*` 表原先按内置模板裁剪。管理器随附 LKM 更新后多出的固定集合：

| Flavor | 额外导入 |
|---|---|
| resukisu（BakaSU） | 6 项 BTF/nofault |
| sukisu（SukiSU 41150） | 6 项 BTF/nofault |
| fina（FinaSU 1.5.0） | 6 项 BTF/nofault + `capable` + `param_ops_string` |
| next（KernelSU-Next 3.4.2） | 无 |
| kernelsu（KernelSU 3.3.1） | 无 |

6.18 g186 的 FinaSU 只需要 `capable`，6.12/6.6 的 FinaSU 还需要
`param_ops_string`。

### 本轮补齐的表

只对拥有**同构建内核镜像或全量 kallsyms 导出**的 profile 追加符号；每个
导出都先用表中已有条目逐项比对地址，确认是同一构建后才写入。

| profile | 内核 | 数据源 | 变更 |
|---|---|---|---|
| 61258 | 6.12.58-g3a7ac1674240 | B 槽 boot.img（`ae921fa3…`）导出 129,131 项 | bakasu 241→247，fina 235→243 |
| 61258c | 6.12.58-g42fcf008ff5c | 荣耀 X80ProMax（BSN-AN00）10.0.0.102 boot.img，导出 128,754 项 | resukisu 233→239，sukisu 245→251，fina 232→240 |
| 6138 | 6.12.38-gfde7767f6ef6 | 荣耀 RobotPhone（APH-AN00）10.0.0.103 boot.img，导出 126,590 项 | bakasu 241→247，sukisu 245→251，fina 232→240 |
| g142 | 6.12.58-g142ddad31e60 | `build/kallsyms/g142.txt`（129,139 项） | bakasu 233→239，fina 232→240 |
| g856 | 6.12.23-gcd85666d7884 | `boot_ota_1793682544248.img` 导出 126,268 项 | bakasu 233→239，sukisu 245→251，fina 232→240 |
| 6689 | 6.6.89-g082e5a98dac1 | `boot_ota_1793726728599.img` 导出 110,155 项 | bakasu 240→246，sukisu 246→252，fina 234→242 |
| g554 | 6.6.118-g554929766a0d | 荣耀 400（DNN-AN00）11.0.0.110 boot.img，导出 111,075 项 | bakasu 240→246，sukisu 246→252，fina 234→242 |
| f171 | 6.6.118-gf17133276a57 | 荣耀 400（DNN-AN00）10.0.0.175 boot.img，导出 110,992 项 | bakasu 240→246，sukisu 246→252，fina 234→242 |
| ga812 | 6.6.118-ga812a1946391 | `build/kallsyms/ga812.txt`（111,132 项） | bakasu 233→239，sukisu 245→251，fina 232→240 |
| g893 | 6.6.118-g893e848657cc | `boot_ota_1794139884130.img` 导出 113,141 项 | bakasu 239，sukisu 251，fina 238（含 manager 32727 补充符号） |
| 61821brm | 6.18.21-ge186062ea75f | HOneClick `syms-115.txt` | 265→272 |
| 6123 | 6.12.23-g45ea5e4bce8a | Toolkit `kernel-data/6.12.23-BKQ-AN10/kallsyms.txt`（122,197 项） | bakasu 241→247，sukisu 245→251，fina 232→240 |
| 6138y | 6.12.38-g7ae8ec909e03 | Toolkit `kernel-data/6.12.38-YLP-W00/kallsyms.txt`（122,640 项） | bakasu 241→247，sukisu 245→251，fina 232→240 |
| 6658 | 6.6.58-g6484937db664 | `MagicRoot-6.6.x-kernels-20261101.zip` 的 `6.6.58-PPG-AN00-9.0.0.112/kallsyms.txt`（105,853 项） | bakasu 240→246，sukisu 246→252，fina 234→242 |
| 61258b（aph112 共用） | 6.12.58-g459a4285ccf8 | `boot_ota_1794077165279.img`（`97dfd166…`）导出 129,075 项 | bakasu 241→247，sukisu 247→253，fina 235→243 |

2026-11-11 补充的完整 `boot (3).img`（SHA-256 `bf22d44b…e278`）精确匹配 6658，
重新导出 109,221 项 kallsyms，补证 `init_cred=0xffffffc082170748`。五张 6658
Flavor 表在追加前的全部重叠符号均与该导出零差异。

荣耀 boot 对照两批（`荣耀boot对照_20261103_旧版本` / `_第二批`）的 27+27
个机型镜像已全部用 `PeekRelease` 读取内核版本并核对；命中的 profile 只用
对应构建的镜像导出，未命中的不借用其他型号地址。LDY-AN00 与 VKI-AN00
的内核是 legacy LZ4 帧，用 `build/audit-tools/unlz4legacy.c` 解出后确认
分别是 6138 与 f171。

生成导出的维护者命令（不进入 APK）：

```bash
javac -cp build/boot-tools/classes -d build/boot-tools/classes tools/ExportKernelKallsyms.java
java -cp build/boot-tools/classes com.aoki.magicroot.ExportKernelKallsyms <boot.img> <out.txt>
```

### 仍缺数据的 profile（fail-closed）

以下 profile 没有对应构建的 boot.img 或全量 kallsyms 导出，无法在本工作区
离线补出地址；不猜地址、不从其他内核借用：

2026-11-08 最后一轮补充的 `boot_ota_1794077165279.img`
（SHA-256 `97dfd166cbf09017954812dcbf7e1fab0f235e280a1f89f5f560de9a4118cef9`）
内核正是 `6.12.58-android16-6-g459a4285ccf8-abogki532718632-4k`，
补齐 61258b（aph112 共用）后**所有 profile 均无缺符号**。此前该 profile
在 resukisu / sukisu / fina 上会 `MISSING=6`（fina 为 8）并 fail-closed；
现在 16 profile × 5 Flavor 的内置模板与管理器 LKM 两套矩阵都是 80/80
`MISSING=0`。

### 官方管理器 32727 LKM 矩阵（2026-11-11）

从官方管理器 APK 的 libksud.so 提取三个 KMI 变体（6.12.76、6.6.127、
6.18.32），对 16 个 profile 的 kernelsu 表执行 patch：

```text
6.12 变体 9 个 profile：236/236，MISSING=0
6.6  变体 5 个 profile：236/236，MISSING=0
6.18 变体 2 个 profile：236/236，MISSING=0
```

其中 10 个 profile 另有精确 kallsyms 导出，整表逐项核对零差异；
61258b、aph112、6123、6138y 无本地镜像，只以同内核供体表的 219/226 项
重叠一致作为证据。补全工具：`tools/sync_manager_symbols.py`。

### 构建期验收基线

- 内置模板矩阵（16 profile × 5 Flavor = 80 行）：**80 行 `MISSING=0`**。
- 管理器随附 LKM 矩阵（同 80 行）：**80 行 `MISSING=0`**。
- 6.18 两个 profile 的 10 行在两种矩阵里都是 `MISSING=0`。
