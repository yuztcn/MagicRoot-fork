# Third-party notices / 第三方组件与许可

MagicRoot 1.0.6 及以后版本（应用 Java/Kotlin 代码、脚本与各内核 profile 适配修改）采用
`LICENSE` 中的 GNU AGPL-3.0（协议原文）；该协议不改变、不覆盖下述任何第三方源码或随包预编译产物的原始许可证。
1.0.5 及更早版本仍按 MIT 授权。项目版权声明与适用范围见 `NOTICE.md`，完整许可证文本见 `LICENSES/`。

AGPL-3.0 与 MIT / Apache-2.0 / GPL-3.0 兼容，但与 GPL-2.0-only 不兼容。随包的
KernelSU / KernelSU-Next / BakaSU GPL-2.0 预编译 LKM 按独立作品分发，不在本项目的
AGPL 重授权范围内；不要把它们并入 AGPL 作品而不先解决 GPL-2.0 兼容性问题。

为确保权属与合规边界清晰，以下严格区分三类行为：
1. **实际使用或二次修改了上游源码**（编译或并入本仓库源码树）；
2. **未使用上游源码编译，仅随 APK 打包分发预编译二进制 / 模块模板**；
3. **仅作技术参考（既未复用源码，也未随包分发二进制）**。

---

## 一、实际使用 / 二次修改源码的部分

### 1. CVE-2026-98260 链路源码

- **`EAEdward/xiaomi9pmroot`（原名 `yt-root-98260`，98260 初始 plant 与共享 `rootd`/`su` 基础）**
  - 来源：https://github.com/EAEdward/xiaomi9pmroot
  - 核对提交：`d37dd2b330d5` / `b2dbd18d4327849b6d90b98d0eb95bef46406da1`（2026-10-25）
  - 许可证：**MIT**，`Copyright (c) 2026 yt-root-98260 contributors`（全文见 `LICENSES/Xiaomi9pmroot-MIT.txt`）
  - 使用部分：`binary-sources/98260-6.12/uaf_plant_61258.c`（以及 `6658/`、`6689/`、`61821/`）的初始 UAF 触发、slab 页回收与 fake-cred 基础逻辑，以及 `rootd.c` / `su98260.c` 基础实现。MagicRoot 在其上做了 per-build 常量、victim ledger、复合页回收修复与部署适配，属二次修改。

- **`woshigenm/CVE-2026-98260`（98260 real-cred 最终写入原语增量）**
  - 来源：https://github.com/woshigenm/CVE-2026-98260
  - 许可证：**MIT**，`Copyright (c) 2026 woshigenm`（全文见 `LICENSES/Woshigenm-MIT.txt`）
  - 使用部分：2026-11-09 之后移植并合入 `binary-sources/98260-6.12/uaf_plant_61258.c` 等源码的 `PLANT_ZERO` / `PLANT_PTR` / `PLANT_SELINUX`、`leak_real_cred`、`mintwait`、`collect_site_pid` 等 real-cred 原语。

- **`woshigenm/CVE-2026-98937`（可选 KASLR slide oracle 的 PoC 来源）**
  - 来源：https://github.com/woshigenm/CVE-2026-98937
  - 核对提交：`93ea96ba6edfe0eee05efb31b1c507474ec7ea94`（2026-11-01）
  - 许可证：**MIT**，`Copyright (c) 2026 woshigenm`（全文见 `LICENSES/Woshigenm-MIT.txt`）
  - 使用部分：`main/app/assets/kaslr-98937/poc98937` 由该仓库 `src/poc.c` 编译；
    `slide98937` 及 `run98937.sh` 为本项目自写，未复制上游实现。

- **`quyicheng03-boop/CVE-2026-98260-popsicle-android`（共享 `pc98260_rootd` / `pc98260_su` 最早公开来源）**
  - 来源：https://github.com/quyicheng03-boop/CVE-2026-98260-popsicle-android
  - 核对提交：`8525ad4`（2026-10-23，全 GitHub 当前可见最早公开提交）；`70829ac`（2026-10-29 启用 MIT）
  - 许可证：**MIT**，`Copyright (c) 2026 quyicheng03-boop`（全文见 `LICENSES/Popsicle-MIT.txt`）
  - 使用部分：与 `xiaomi9pmroot` 共享的 `pc98260_su.c`（86 行逐字节同内容）与 `pc98260_rootd.c` 基础服务端（对应本仓库 `su98260.c`、`pc98260_su.c`、`rootd.c`、`pc98260_rootd.c` 及其编译产物 `pc98260-su` / `exploit-android-key-ptr`）。**本仓库未使用 popsicle 的 `exploit-android-key-ptr.c`（plant 源码）**，该 plant 仅作早期对照参考并已确认无源码复制。

- **`superboyyy/HOneClick`（6.18.21 H1C 引擎、boot.img 生成器与 64560 审计/KSU 补丁）**
  - 来源：https://github.com/superboyyy/HOneClick（核对提交 `0ede556` / `45743d6`）
  - 许可证：根 `LICENSE` 原文为 **MIT**（`Copyright (c) 2026 superboyyy`，末尾附带“仅覆盖原创研究材料”说明；GitHub API 因此识别为 `NOASSERTION`；全文与边界见 `LICENSES/HOneClick-MIT.txt` 与 `LICENSES/HOneClick-NOASSERTION.md`）。注：HOneClick 在自身 `THIRD_PARTY_NOTICES.md` 中标明其 `native/cve98260/` 改自 `sganggs` 且不作公开发布授权。
  - 使用部分：
    - `main/compose-app/app/src/main/java/com/aoki/magicroot/KernelProfileGenerator.java`（移植自 HOneClick `boot.img` / `kallsyms` / `BTF` profile 生成器）；
    - `binary-sources/98260-h1c/{uaf_plant.c, pc98260_rootd.c}`、`61821-brm/uaf_plant.c`、`61157-g264/uaf_plant.c`（基于 HOneClick `native/cve98260/` 修改为 6.18 / 6.1 适配；其中 `pc98260_rootd.c` 向上游可追溯至 `sganggs` / `popsicle`）；
    - `binary-sources/64560/upstream-honeclick/` 与 `6.18.21` 115/928 KernelSU 凭证引导补丁思路及 `syms_61821_brm.txt`。

### 2. CVE-2026-64560 与目标适配源码

- **`Feng1586/CVE-2026-64560-public` / GhostLock（64560 零写原语基础）**
  - 来源：https://github.com/Feng1586/CVE-2026-64560-public（基线 `63b4f2b`）
  - 许可证：根 `LICENSE` 原文为 **MIT**（`Copyright (c) 2026 GhostLock/CVE-2026-64560 research contributors`，附带仅覆盖原创研究材料之尾注；GitHub API 因此标 `NOASSERTION`；见 `LICENSES/CVE-2026-64560-public-MIT.txt` 与 `LICENSES/GhostLock-MIT.txt`；此前文档误写为 Apache-2.0，现予更正）
  - 使用部分：`t64560_v36.c`、`t64560_v42.c` 零写原语（经 HOneClick 适配进入 `binary-sources/64560/upstream-honeclick/`，并由 MagicRoot 在 `binary-sources/64560/merge/` 与发布资产中使用）。

- **`honor_ubl` 3.1.1 `aph136g142` 适配源码**
  - 来源：用户提供的 g142 kernel adapter / source-and-binaries 包
  - 许可证：**MIT**（`LICENSES/Honor-UBL-Adaptation-MIT.txt`）
  - 使用部分：`binary-sources/64560/kaslr_slide_aph136g142.c`、`binary-sources/98260-6.12/pc98260_target_g142.h` 及 g142 符号与常量核对。

### 3. UI 与 Android 框架组件

- **Miuix**（https://github.com/compose-miuix-ui/miuix）— **Apache-2.0**
- **Jetpack Compose / Compose Multiplatform / AndroidX** — **Apache-2.0**
- **Kyant0/AndroidLiquidGlass**（https://github.com/Kyant0/AndroidLiquidGlass）— **Apache-2.0**（`CombinedBackdrop.kt`、`LiquidLens.kt` 适配）
- **Shizuku API**（`RikkaApps/Shizuku-API` / `XiaoTong6666/Shizuku-API` fork，patch 6）— **Apache-2.0**

---

## 二、未使用源码，仅随 APK 打包分发预编译产物的部分

以下组件**未在本项目中修改或复用其完整上游源码参与应用编译**，仅作为预编译二进制 / 内核模块模板 / 历史交接套件随 `main/app/assets/` 打包分发，并**继续完全受各自上游许可证（而非 MagicRoot AGPL-3.0）约束**：

- **KernelSU / KernelSU-Next / BakaSU / SukiSU Ultra / FinaSU 预编译 LKM 模板与历史回退 `ksud`**
  - 上游与许可证：
    - KernelSU（https://github.com/tiann/KernelSU）— **GPL-2.0**
    - KernelSU-Next（https://github.com/rifsxd/KernelSU-Next）— **GPL-2.0**
    - BakaSU（https://github.com/Baka-SU/BakaSU）— **GPL-2.0**
    - SukiSU Ultra（https://github.com/SukiSU-Ultra/SukiSU-Ultra）— **GPL-3.0**
    - FinaSU — 遵循上游仓库许可证
  - 分发行为：仅随包分发预编译 `.ko` 模板（`ksu-template*.ko`、`98260-h1c/ksu-template-115.ko`、`61157/kernelsu-*.ko`、`ksu6157*/kernelsu-honor.ko` 等）及 6.1 / 6.18.21 历史回退 `ksud`（`61157/ksud`、`64560-61821/ksud`、`ksu6157*/ksud`）。通用路径已移除内置 `ksud_*`，改为运行时从设备已安装管理器提取 `ksud`。

- **6.1.x CGA 模块与基线二进制（`g264/ksm-*-base.ko`、`61157/g264/ksm-g264-base.ko`）**
  - 分发行为：随包分发预编译 `ksm-g264-base.ko` 及确定性重基址派生 `.ko`；对应 GPL 内核模块审计/复刻源码（`binary-sources/6157-g264/cga/`）保留在源码归档中。

- **SuSFS（`inforcqb/susfs4ksu-lkm`）**
  - 许可证：以 `inforcqb/susfs4ksu-lkm` 仓库声明为准（GPL）
  - 分发行为：未使用上游源码编译，随包分发预编译 `susfs_insmod` 与 `susfs_guard_lkm-{6.6, 6.12, 6.18}.ko`。

- **64560 历史发布二进制（`t64560_v36`、`t64560_cred`、`addrcalc`、`forker`、`ko_patch`、`cred_target`、`wait_helper` 等）**
  - 分发行为：发布 APK 保留历史已验证的预编译二进制随包分发；对应审计/复现源码保留在 `binary-sources/64560/`（`kaslr_slide_aph136g142`、`ksu_grant` 等为本地源码构建）。

---

## 三、仅作技术/思路参考（未复用源码、未随包分发二进制）

- **`YuKongA/CVE-2026-98260`**（MIT）— `woshigenm` 下游 6.12.69 移植，仅作对照参考。
- **`Yunnijian/OnePlus16-Jailbreak`**（仓库当前 `LICENSE` 为 GPL-3.0；早期快照留存 MIT）— 仅作 98260 流程与清理参考，未复用其源码或二进制。
- **`AzirX1337/CVE-2026-98260-OnePlus16-PYB110-Jailbreak`**（MIT）— 仅作背景与流程参考。
- **`xingranya/onekeyjb`**（GPL-3.0）— 仅作 `knowledge/` 故障口径与 `LiveLogStore` 逐行日志回读思路参考；未复制其 UI、机型限制、热切换或自研 plant 代码。
- **`No-World/rootkit`**（MIT）— 仅作 64560 链路阶段机与进程清理优化参考，不是 98260 初始项目。
- **`TKgbUssr/PMX110-6.18.21-exploit`** — 仅作 `su_entry.sh` 思路参考。
- **LSPosed / Zygisk Next** — **不随包分发** APK 或模块（安全边界：禁止内置安装 LSPosed 管理器），仅通过 `lsposed-hotfix.sh` 对设备端已有环境热修复。

---

## 特别致谢与免责声明

- 98260 适配思路：GitHub / 酷安 @Higanoneko
- 感谢所有上游漏洞研究、KernelSU 家族与 UI 开源项目作者
- 本仓库中的 CVE-2026-98260 / CVE-2026-64560 适配代码仅用于自有、已授权调试设备的安全研究，不提供任何担保。
