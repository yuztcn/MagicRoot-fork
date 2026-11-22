# 参考项目与源码归属

本项目的源码复用、随包分发与纯技术参考边界明确划分如下（完整文本见根目录 `LICENSE`、`THIRD_PARTY_NOTICES.md` 与 `LICENSES/`）：

## 一、实际使用 / 二次修改源码

### 64560 链路
- **初始漏洞原语**：`Feng1586/CVE-2026-64560-public`
  - https://github.com/Feng1586/CVE-2026-64560-public
  - **MIT**（根 `LICENSE` 为 MIT 带范围尾注，GitHub API 标 `NOASSERTION`；`LICENSES/CVE-2026-64560-public-MIT.txt`）
  - 对应 `t64560_v36.c` / `t64560_v42.c` 零写原语。
- **适配与源码参考**：`superboyyy/HOneClick`（根 `LICENSE` 为 **MIT** 带范围尾注，API 标 `NOASSERTION`）
  - https://github.com/superboyyy/HOneClick
  - 对应 `binary-sources/64560/upstream-honeclick/`、`KernelProfileGenerator.java` 与 6.18 H1C 适配。
- **g142 适配源码**：`honor_ubl 3.1.1` `aph136g142`（MIT，`LICENSES/Honor-UBL-Adaptation-MIT.txt`）
  - 对应 `binary-sources/64560/kaslr_slide_aph136g142.c` 与 `pc98260_target_g142.h`。

### 98260 链路（分层来源）
- **初始 plant 与共享 `rootd`/`su` 基础**：`EAEdward/xiaomi9pmroot`（原名 `yt-root-98260`）
  - https://github.com/EAEdward/xiaomi9pmroot
  - **MIT**，`Copyright (c) 2026 yt-root-98260 contributors`（核对提交 `d37dd2b` / `b2dbd18`，`LICENSES/Xiaomi9pmroot-MIT.txt`）
  - `uaf_plant_61258.c` 的初始 UAF/页回收逻辑与 `rootd.c` / `su98260.c` 基础来源，本项目在其上做 per-build 常量、ledger 与部署适配。
- **real-cred 三原语增量**：`woshigenm/CVE-2026-98260`
  - https://github.com/woshigenm/CVE-2026-98260
  - **MIT**，`Copyright (c) 2026 woshigenm`（`LICENSES/Woshigenm-MIT.txt`）
  - 2026-11-09 之后合入的 `PLANT_ZERO`/`PLANT_PTR`/`PLANT_SELINUX`、`leak_real_cred`、`mintwait`、`collect_site_pid`。
- **`rootd`/`su` 最早公开共享来源**：`quyicheng03-boop/CVE-2026-98260-popsicle-android`
  - https://github.com/quyicheng03-boop/CVE-2026-98260-popsicle-android
  - **MIT**（2026-10-29 `70829ac` 启用；`Copyright (c) 2026 quyicheng03-boop`，`LICENSES/Popsicle-MIT.txt`）
  - 与 `xiaomi9pmroot` 共享的 `pc98260_su.c` / `pc98260_rootd.c` 客户端与守护进程基础（且 `HOneClick` `98260-h1c/pc98260_rootd.c` 亦经 `sganggs` 溯源至此）；**未复用 `popsicle` 的 plant 源码**。

### UI / 框架源码
- `Miuix`、`Jetpack Compose / AndroidX`、`Shizuku API`（`XiaoTong6666` fork）、`Kyant0/AndroidLiquidGlass`：均 **Apache-2.0**。

## 二、未使用源码，仅随包分发预编译二进制

- **KernelSU / KernelSU-Next / BakaSU（GPL-2.0）、SukiSU Ultra（GPL-3.0）、FinaSU（遵循上游）**：随 APK 分发预编译 `.ko` 模板与 6.1 / 6.18.21 历史回退 `ksud`（通用路径运行时从已安装管理器提取 `ksud`，未使用管理器源码构建）。
- **SuSFS（`inforcqb/susfs4ksu-lkm`，遵循上游）**：随包分发预编译 `susfs_insmod` 与 `susfs_guard_lkm-*.ko`。
- **6.1.x CGA 模块与 64560 发布资产**：`ksm-*-base.ko` 与历史 `t64560_v36`/`t64560_cred` 等以预编译产物随包分发，对应源码保存在 `binary-sources/` 作审计参考。

## 三、仅技术参考（未复用源码、未随包分发）

- `YuKongA/CVE-2026-98260`（MIT）、`Yunnijian/OnePlus16-Jailbreak`（GPL-3.0；早期快照 MIT）、`AzirX1337/CVE-2026-98260-OnePlus16-PYB110-Jailbreak`（MIT）、`xingranya/onekeyjb`（GPL-3.0）、`No-World/rootkit`（MIT）、`TKgbUssr/PMX110-6.18.21-exploit`、`LSPosed` / `Zygisk Next`（仅设备端热修复）。
