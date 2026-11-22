# HOneClick upstream integration audit (2026-11-01)

参考仓库：<https://github.com/superboyyy/HOneClick>

审计时上游 HEAD：

```text
0ede55620b5fd782c4fbce296c0864897e347756
2026-11-01 15:13:27 +1100
Merge pull request #2 from yu1101610062/fix/late-load-su-access
```

## 上游已验证内核

```text
A: 6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k  (98260-109 / 64560)
B: 6.18.21-android17-5-ge186062ea75f-abogki564062290-4k  (98260-115)
```

上游 profile 地址来自 `assets/exploit-profiles.json`：

| profile | timer_link | cred_link | slide_site_low |
|---|---|---|---|
| 109 / g928 | `0xffffffc0803e005c` | `0xffffffc080147378` | `0x1e005c` |
| 115 / g186 | `0xffffffc0803e1fd0` | `0xffffffc08014cd90` | `0x1e1fd0` |

两个 profile 的 `k_itimer` 均为 `0x180`，slab 为 `21 x 384 / order-1`。
当前 MagicRoot 的 `98260-61821` / `98260-61821-brm` 使用同一组
6.18.21 内核 release，并按精确 `uname -r` 选择。

## 已吸收的修改

### 1. Late-load SU access fix（g928 109）

上游 PR #2 修复 KernelSU 在 late-load 时缓存 `prepare_creds()` 身份、
导致普通 shell `su` 的 `faccessat` 返回 `EACCES` 的问题。

本仓库把上游修正后的 g928 模板放入：

```text
main/app/assets/64560-61821/ksu-template.ko
main/app/assets/98260-61821/ksu-template.ko
```

```text
size   492,728
sha256 86ed32a0946490736850d0c5d7a703c6e5bfde541e82864ed892b31e2b590563
```

这是上游 `SU_ACCESS_FIX.md` 记录的 output hash，输入为原
`e33b7c5d...` g928 模板。

当前符号表覆盖：

```text
64560 syms: 0 missing
98260 syms: 0 missing
```

### 2. 6.18.21 ge186 的 WKL 型号适配

`98260-61821-brm/target.sh` 保持 exact kernel 锁定，同时允许：

```text
BRM-AN00
WKL-AN20
WKL-AN80
```

BRM/WKL 共用同一个 `ge186062ea75f` 内核构建；型号不改变链接偏移，
因此仍由完整 `uname -r` 作为硬门槛。

## 已接入的 109/115 可用路线

上游 CVE-2026-98260 运行时已经接入为独立 HOneClick 引擎：

```text
main/app/assets/98260-h1c/
  cve98260_plant
  cve98260_slide
  cve98260_su
  cve98260_module
  addrcalc
  root_stage.sh
  run_h1c.sh
```

触发条件：

```text
PROFILE_LOCAL=61821      (g928 / 109)
PROFILE_LOCAL=61821brm   (g186 / 115)
```

6.18.21 无条件走 H1C；`MAGICROOT_98260_ENGINE` 已不再读取。2026-11-04
起 `cve98260_plant` 为修复复合页 PFN 匹配而重建，115 模板也打了 bootstrap
凭据补丁，详见 `docs/61821-115-CHAIN-ANALYSIS.md`。

新引擎复用现有 `ksu_select_ko` 选出的管理器模板和符号表，因此仍然保留
KernelSU / BakaSU / Next / SukiSU / FinaSU 多 Flavor 支持。执行顺序：

```text
preflight -> slide site -> ko_patch -> cve98260 rootd
-> cve98260_module finit_module -> direct su / ksud debug su
-> root_stage.sh
```

109 模板使用上游 SU access fix；115 模板保留现有 g186 专用模板。
如果预检、rootd、模块加载或 root_stage 任一步失败，新引擎返回独立的
`98260_H1C_FAIL=...` 标记，不自动重试。

legacy BRM 路线仍可通过：

```sh
export MAGICROOT_98260_ENGINE=brm
```

选择。两条路线共用 exact `uname -r` 锁定和相同的多 Flavor 管理器选择，
不会把另一内核的符号表混入。

