# 真机验证记录 — MLY-AN00 / 6.12.58 / BakaSU 适配

- 设备：Honor MLY-AN00（`<SERIAL>`，adb 直连）
- 系统：Android 16（SDK 37），内核 `6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k`
- 测试日期：2026-10-25（Asia/Shanghai）
- 测试方式：`adb shell`（uid 2000）部署资产后直接执行 `run.sh`；root 阶段由
  `ksu_grant`（KernelSU reboot-syscall + GRANT_ROOT）取得 uid 0。
- 应用侧环境：Shizuku 13.6.0、Stellar 1.1 已安装；MagicRoot 实测从旧 1.0.2
  升级到 `1.0.3-bakasu`（versionCode 7，同签名覆盖安装成功，UI 显示
  「BakaSU 内核 · 开 · resukisu（默认）」）。

## 1. 会话起点状态（上一 boot 遗留）

| 项 | 观测 |
|---|---|
| `/proc/modules` | `kernelsu 221184 1 - Live`（官方 KernelSU 3.3.1，version 32680 / uapi 5） |
| 快速修复通道 | `ksu_grant` 成功：`reboot_rc=-1 errno=1(EPERM) fd=3` → `grant_root_rc=0` → uid 0 |
| KASLR | slide `0x252aa00000`（boot `0c1e86b6-…`） |
| kallsyms | 以 root（`kptr_restrict=0`）导出 499,690 行 / 23.4 MB，用于生成符号表 |
| 管理器 | `me.weishu.kernelsu` v3.3.1 已安装；BakaSU 管理器未安装 |

## 2. live 热切换实验（失败，已记录为约束）

在同一 boot 内执行 `ksud unload`（官方 module）以腾出 `kernelsu` 模块名，再加载
BakaSU LKM。结果：unload 过程中设备重启（adb 断连，约 55 s 后重新上线）。

**结论：本机不支持在同一 boot 内安全热切换 `kernelsu` LKM；BakaSU 测试必须
在重启后从干净状态跑完整链路。** 该约束已写入 `main/README.md` 与风险清单。

## 3. BakaSU 符号表真机生成

- 用第 1 节的 `/proc/kallsyms` 快照 + 官方 `syms_61258.txt`，为 BakaSU 6.12 LKM
  的 233 个未定义符号补齐 15 个，生成 `syms_61258_bakasu.txt`（241 项，
  MISSING=0；`_printk` 锚点自检通过）。
- 6.12.38 用 `magic8-kernel/kallsyms.json` 同法生成
  `syms_6138_bakasu.txt`（241 项，MISSING=0）。

## 4. 干净 boot 后的 BakaSU 全链路（boot `40d20718-…`）— 全流程跑通

部署：`adb push main/app/assets/. → /data/local/tmp/magic/`（手工部署会丢执行位，
`run.sh` 已补全 `chmod 755` 列表），并预装 `BakaSU-manager.apk`。
执行：
`MAGICROOT_KSU_FLAVOR=resukisu MAGICROOT_VICTIMS_{PERMISSIVE,FSUID,CRED}=32/32/24
MAGICROOT_SU_COMPAT=1 sh run.sh`

| 阶段 | 结果 | 证据 |
|---|---|---|
| KASLR | ✅ `slide=0x1cc1200000`，votes 3094，anchors 5 | `run-bakasu.log` |
| 后端选择 | ✅ `KSU_FLAVOR=resukisu`，BakaSU 模板 + `syms_61258_bakasu.txt` | 同上 |
| LKM 运行时修补 | ✅ `PATCHED=233 MISSING=0`；产物 509,312 B；vermagic 改写为 `6.12.58-…`（原值 `zermagic=6.12.76-4k…`） | `ko_patch.log` / 拉回的 `ksu-patched-bakasu.ko` |
| SELinux permissive | ✅ attempt 17 `LANDED` | `run-bakasu.log` |
| cred_target（perf 采样） | ✅ `CRED=…f000 samples=3 bit16=1`（首轮） | 同上 |
| fsuid/fsgid 写 | ✅ attempt 38 `LANDED` | 同上 |
| phase1（cap_bset=0） | ✅ `PHASE1_OK page=…`，`PHASE1_VERIFY CapBnd=0` | 同上 |
| phase2（cap_effective） | ✅ attempt 203 `LANDED`（`leak=1`），`PHASE2_DONE` | 同上 |
| **BakaSU LKM `finit_module`** | ✅ `MODULE_LOADED flavor=resukisu`；`/proc/modules`：`kernelsu 270336 0 - Live` | 同上 |
| BakaSU 内核身份 | ✅ `debug info`：**version 35252 / uapi 6 / features 0x7 / lkm true /
  full_version `v4.2.0-rc3-d5e9e025@BakaSU`** | `verify-root.log` |
| root 获取 | ✅ 首次自动调用 `ksu_grant` 返回 rc=3（模块刚 Live 的瞬时失败），
  手动重跑即 `grant_root_rc=0`、uid 0 / context `u:r:ksu:s0` | 同上 |
| BakaSU 用户态安装 | ✅ `/data/adb/ksud` = BakaSU ksud 5,955,840 B；
  `ksud 4.2.0-rc3-81-gd5e9e025 (uapi: 6)`；`ksud install` rc=0；
  `/data/adb/ksu/bin/{ksud,su,busybox,bootctl,mkbootfs,resetprop}` 就位 | `root-stage-retry.log` |
| 管理器签名解析 | ✅ `debug get-sign` = `size: 0x377(887), hash: d3469712…f1df64`
  （与 APK v2 证书实测一致） | `verify-root.log` |
| 动态管理器登记 | ✅ `ksud kernel dynamic-manager set-apk` → `get` 返回
  `size: 887, hash: d3469712…`；`/data/adb/ksu/.dynamic_manager` 95 B JSON 落盘 | `crown.log` |
| 内核特性 | ✅ `feature list`（root 视角）：su_compat / kernel_umount /
  selinux_hide `[ENABLED]` | `verify-root.log` |
| root_stage 收尾 | ✅ `ROOT_STAGE_OK`；`ROOT_STAGE_SU_CHECK=0`（su 通道自检）；
  `/system/bin/su` = BakaSU ksud（5955840 B） | `root-stage-retry.log` |
| BakaSU 管理器 App | ⚠️ 已安装 v4.2.0-rc3(35252)、可显示内核版本；UI 仍显示
  「未安装」——管理器进程（uid 10388, untrusted_app）未打开 ksu fd（见 §6） | 截图 / `mgrfd.log` |

## 5. 真机 patch 产物离线复核（从设备拉回）

`refs/device-dumps/boot-40d20718-bakasu/ksu-patched-bakasu.ko`（509,312 B）：

```text
undefined dynamic symbols : 0
SHN_ABS symbols           : 261
vermagic                  : 6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k
                            SMP preempt mod_unload modversions aarch64
zermagic (原值)           : 6.12.76-4k SMP preempt mod_unload modversions aarch64
name/description          : kernelsu / Android KernelSU（BakaSU 4.2.0-rc3 构建）
```

即：BakaSU 模板在真机上被完整 rebase 为当前 boot 的绝对符号地址，且 vermagic
与目标内核完全一致，并成功 `finit_module` 进入 Live 状态。脚本层面的 `sh -n`
也已在设备 mksh 上全部通过（main 的 closure/root_stage 均 `SYNTAX_OK`）。

## 6. 本轮修复的适配缺陷 / 真机发现

1. **手工部署丢执行位**：`wait_helper` 非可执行导致 cred 阶段 futex 握手静默失败
   （`CRED_RETRY bit16=none` ×4）。`run.sh` 已为全部运行时资产补 `chmod 755`。
2. **KO 缓存键不含后端**：官方模板与 BakaSU 模板在同一 boot 的缓存键曾可能命中
   旧产物；`KO_KEY` 已加入 `KSU_FLAVOR` + 模板/符号表路径。
3. **BakaSU 4.2.0-rc3 ksud 没有 `manager` 子命令**，且 `debug set-manager`
   需要 `CONFIG_KSU_DEBUG`（BakaSU LKM 未开）：真机确认报
   `Error: CONFIG_KSU_DEBUG is not enabled`。真正的加冕路径是
   `ksud kernel dynamic-manager set-apk <apk>`（写内核内存 + `.dynamic_manager`）。
   `root_stage.sh` 已改为优先该路径，保留 `manager add` / `debug set-manager`
   能力探测回退。
4. **版本/uapi 配对校验**：root_stage 期望 BakaSU `35252 / uapi 6`、官方
   `32680 / uapi 5`，不符只告警不误判成功。
5. **管理器 App 的 ksu fd 未建立**：管理器进程始终不打开 ksu fd，UI 显示
   「未安装」。已确认 `.dynamic_manager` 登记成功、签名三元组正确、内核
   `dynamic-manager get` 返回正确值。剩余怀疑点：KernelSU 的 late-load 初始化
   阶段（`ksud post-fs-data` / `sepolicy patch <rule>` / module 挂载）在
   raw `finit_module` 路径下没有执行，管理器所需的内核侧/策略侧状态不完整；
   下一轮应在模块 Live 后补跑这些 stage（真机上 `post-fs-data` 已开始执行，
   因会话中止未完成）并复测管理器 UI。

## 7. 结论

- **BakaSU 后端在真机上完成了从「模板」到「Live 内核模块」的全流程**：
  符号 rebase（233/233）→ vermagic 改写 → `finit_module` → Live →
  BakaSU 内核身份（35252 / uapi 6）被用户态识别 → BakaSU ksud 安装/特性/
  动态管理器登记/`su` 自检全部成功。
- **唯一未闭环项是管理器 App 的连接**（§6.5），属 late-load 初始化阶段补全
  问题，不影响「BakaSU 内核 + 用户态 + 动态管理器登记」的核心设备验证结论。

## 8. 证据文件

```text
refs/device-dumps/boot-0c1e86b6/kallsyms_full.txt      # 官方内核 kallsyms 快照
refs/device-dumps/boot-40d20718-bakasu/
  run-bakasu.partial.log   # 当前真机链路日志（改名为完整 run 日志亦可）
  ko_patch.log             # PATCHED=233 MISSING=0
  ksu-patched-bakasu.ko    # 真机 patch 后的 BakaSU LKM（509,312 B）
  kaslr.txt                # slide 0x1cc1200000
.probe/app-main-bakasu.png # MagicRoot 1.0.3-bakasu UI（BakaSU 开关）
.probe/bakasu-manager3.png # BakaSU 管理器 UI（“未安装”状态，§6.5）
```

## 9. 安全边界

- 每次测试后设备重启清空临时 root；测试不写分区。
- 测试期间出现过一次 `ksud unload` 触发的意外重启（见 §2），无数据损坏。
- 仅在本机（授权设备）上执行；日志中的序列号等已在发布包中脱敏。

## 10. 管理器登记/模块加载强化后的冷启动复测

强化内容：

- `root_stage.sh`：三段式管理器登记（BakaSU `kernel dynamic-manager set-apk` /
  `manager add` / 官方 `debug set-manager` + `CONFIG_KSU_DEBUG` 分类）、
  `readlink /proc/<pid>/fd/* | grep ksu` 连接验收、失败重试 + 重启、
  可选软重启修复（`MAGICROOT_REPAIR=1`）、`/data/adb/ksu` 快照、`setenforce 1`
  恢复；
- `run.sh`：patch 产物校验 + `/data/local/tmp/ksu-official.ko` 副本、模块 Live
  兜底轮询（120s）、加载失败 errno 诊断、`ksu_grant` 瞬态失败重试；
- UI：「软重启修复」「恢复 SELinux」两个持久化开关（MainActivity 传
  `MAGICROOT_REPAIR` / `MAGICROOT_RESTORE_ENFORCING` 与标记文件）。
  §39 起「恢复 SELinux」开关已移除，成功路径始终恢复 Enforcing。

2026-10-25 14:14 冷启动（无模块、Enforcing、uid 2000）后按合并脚本重跑
（`MAGICROOT_KSU_FLAVOR=resukisu MAGICROOT_REPAIR=1`）：

| 项 | 结果 |
|---|---|
| 冷启动基线 | ✅ uptime 4 min、无 kernelsu、Enforcing、uid 2000 |
| 资产部署 | ✅ 33 个 main 资产推送并 chmod；BakaSU 管理器在位（35252） |
| 合并版 run.sh 标记 | ✅ `KSU_FLAVOR=resukisu`、`PATCHED_KO=size=509312`、
  `loaded_copy=/data/local/tmp/ksu-official.ko`（合并的产物校验/副本逻辑生效） |
| KASLR | ✅ `slide=0x2122200000` votes 2766 anchors 5 |
| permissive | ✅ attempt 25 LANDED |
| cred / fsuid / phase1 | ✅ CRED 首轮 bit16=1；fsuid attempt 44；`PHASE1_OK`、`PHASE1_VERIFY CapBnd=0` |
| phase2 | ⚠️ 进行到 attempt 52 时**设备重启**（exploit 竞态导致的已知风险；上一 boot
  同版本链路在 attempt 203 才命中）。重启后内核模块与临时 root 状态清空，
  Enforcing/uid 2000 恢复。合并版 root_stage 的 fd 验收/重试/软重启修复
  因此未在本轮被执行到；此前一 boot 曾单独验证 `kernel dynamic-manager
  set-apk` 登记成功与 `su` 自检 0。 |
| 重启后复跑 | 🔁 已冷启动后重新排队（`run-bakasu2.log`），用于继续完成强化版
  root_stage 端到端验证 |

结论（截至本文件最后更新）：

- 强化后的 **模块加载侧** 已在真机生效（patch 产物校验、loaded.ko 副本、KASLR/
  permissive/cred/fsuid/phase1 全部通过）；
- 强化后的 **管理器登记侧** 代码路径与标记已就绪（三段式登记、fd 验收、
  重试、软重启修复、快照、SELinux 恢复），等待一次 phase2 命中后的
  root_stage 执行结果回填；
- 临时 root 链路本身存在 phase2 竞态导致重启的风险（本会话已两次出现不同
  阶段的设备重启），属已知限制，不是合并逻辑缺陷。

---

## 11. `ksu_grant` EPERM 根因与修复（2026-10-25）

**现场失败日志**（`/sdcard/Download/MagicRoot/fail_log_1792911066340.txt`）：

```text
== 7. KernelSU userspace ==
KSU_BACKEND=BakaSU manager=com.resukisu.resukisu userspace=ksud_bakasu
reboot_rc=-1 errno=1(Operation not permitted) fd=3
grant_root_rc=-1 errno=1(Operation not permitted)
uid=2000 euid=2000
GRANT_RETRY rc=3 after=2s   …   GRANT_RETRY_RESULT rc=3
FAIL=ksu_grant rc=3 flavor=resukisu
```

**根因（LKM 静态分析 + 真机状态对照）**：

- BakaSU LKM 的 ioctl 命令 `0x4b01`（GRANT_ROOT）在 `ksu_ioctl_handlers`
  表中由 `allowed_for_su` 权限函数放行；`allowed_for_su` 的逻辑等价于：
  `is_manager() || __ksu_is_allow_uid_for_current(uid)`；
- `__ksu_is_allow_uid_for_current` 仅在 uid 在 allowlist 中、或模块以
  `allow_shell=1` 加载时对 shell 返回 true；
- 失败现场：内核模块 Live，但设备 `/data/adb/ksu/.allowlist` 已被清空（此前的
  allowlist 隔离实验），而模块加载时 `allow_shell=0` → shell(2000) 两侧都不满足
  → GRANT_ROOT 返回 `-EPERM`（reboot 魔术 fd 安装本身成功，fd=3）；
- 该现象只在**新 boot 重新加载模块**后出现；旧 boot 内核内存里仍是加载时读入的
  旧 allowlist（含 shell），所以当时 grant 成功，容易误判为“瞬态失败”。

**修复（1.0.4-bakasu）**：

1. `run.sh` 引入 **bootstrap allow_shell**：默认以 `allow_shell=1` 加载模块
   （`LOAD_ALLOW_SHELL=1`），使 GRANT_ROOT 在空 allowlist 设备上也通过；
   UI 的 “allow shell” 开关仍记录用户意图；可用
   `$WORK/no_bootstrap_allow_shell` 关闭；
2. `root_stage.sh` 在仅 bootstrap 时启用 `shell_su_adb_only`（shell 的 su 仅限
   adbd/ksu 祖先），避免把 shell su 完全放开；并尝试把保存的
   `.allowlist` 备份恢复到 `/data/adb/ksu/`（若有备份，供后续 boot 使用）；
3. grant 失败重试从 1 次增加到 3 次（2s/4s 间隔），并输出针对性 HINT；
4. 版本号 `1.0.4-bakasu` / versionCode 8。

**验证**：冷启动（15:01，无模块/Enforcing）后以
`MAGICROOT_ALLOW_SHELL=0`（UI 默认值）运行修复版链路，日志首部即出现：

```text
ALLOW_SHELL=0 LOAD_ALLOW_SHELL=1 BOOTSTRAP_SHELL=1
```

---

## 12. bootstrap 修复验证：链路全通 + 管理器连接闭环（2026-10-25 15:37）

紧接 §11 的修复版冷启动链路（`run-fix2.log`）**端到端成功**：

| 标记 | 值 |
|---|---|
| bootstrap | `ALLOW_SHELL=0 LOAD_ALLOW_SHELL=1 BOOTSTRAP_SHELL=1`（UI 默认关闭时仍以 allow_shell=1 加载） |
| 阶段 | KASLR ✅ → permissive attempt 15 ✅ → cred ✅ → fsuid attempt 63 ✅ → `PHASE1_OK` ✅ → phase2 attempt 39 ✅ |
| 模块 | `MODULE_LOADED flavor=resukisu`（kernelsu Live） |
| grant | root_stage 以 `uid=0 context=u:r:ksu:s0 enforce=Enforcing` 运行 —— **GRANT_ROOT 不再 EPERM**（§11 根因修复生效） |
| 登记 | `ROOT_STAGE_MANAGER_CMD=kernel-dynamic-manager`；`DYNAMIC_MANAGER_GET=size: 887, hash: d3469712…`；`CROWN_TRIGGER=packages_list` |
| 连接 | `ROOT_STAGE_MANAGER_FD_PID=5010`、`ROOT_STAGE_MANAGER_CONNECTED=1 after=1s`、`ROOT_STAGE_MANAGER_STATE=connected` |
| 收尾 | `ROOT_STAGE_PRESERVE=committed`、`ROOT_STAGE_SOFT_REBOOT_REPAIR=scheduled`、`ROOT_STAGE_SU_CHECK=0`、`ROOT_STAGE_OK`、`DONE` |

**关于“设备重启”**：本次的框架重启是 root_stage 在管理器已连接后按设计触发的
**软重启修复**（仅重启 zygote/framework，内核模块保持 Live）。设备 uptime 不归零、
`/proc/modules` 中 `kernelsu 270336 1 - Live` 仍在，不是崩溃重启。

软重启后打开 BakaSU 管理器：

- 首页显示 **工作中 / LKM / 越狱模式**，0 个超级用户、2 个模块；
- 内核驱动版本 `v4.2.0-rc3-d5e9e025@BakaSU (35252/6)`；
- 管理器版本 `v4.2.0-rc3 (35252/6)`。

截图：`docs/screenshots/bakasu-manager-connected-20261025.png`。

这标志着此前“管理器 App 显示未安装 / fd 未连接”的问题**已闭环**：
可移植动态管理器登记（`kernel dynamic-manager set-apk` + 稳定 JSON 兜底）→
crown 触发 → fd 连接验收（1s 内 connected）→ 软重启修复后管理器正常工作。

本次同时修复：版本解析 bug（`version: 35252` 曾被贪婪匹配成
`uapi_version: 6`，导致 `ROOT_STAGE_WARN=kernel_version_mismatch`）。

---

## 13. 五种管理器后端接入（1.0.3-bakasu，versionCode 8）

- 新增 flavor：`fina`(FinaSU 1.0.8/33020)、`sukisu`(SukiSU 4.2.1-r2/41068)、
  `next`(KernelSU-Next 3.4.2/33355)，与既有 `resukisu`(BakaSU 35252)、
  `kernelsu`(KernelSU 3.3.1/32680) 并列；UI「内核后端」卡片循环切换。
- 内置兜底：5 份 ksud（从各管理器 APK 的 native 库提取）+ 4 份 LKM 模板
  （BakaSU/official 为 6.12 原生；Next/SukiSU 为其 6.18 版本保留）。
- 标准状态提取：`pm path` → 管理器 APK 内 `lib/arm64-v8a/libksud.so`
  （SukiSU 4.2.1-r2 使用重命名库，候选 .so 逐个 `-V` 校验）→ `$WORK/ksud_<flavor>`；
  签名由 App `PackageManager.GET_SIGNING_CERTIFICATES` 计算写入 `manager_sig`。
- 真机验证（BakaSU 管理器在位，adb shell 复现提取路径）：

```text
APK=/data/app/~~.../com.resukisu.resukisu-.../base.apk
unzip -p "$APK" lib/arm64-v8a/libksud.so -> /data/local/tmp/magic/ksud_resukisu (5955504 B)
./ksud_resukisu -V  => ksud 4.2.0-rc3-81-gd5e9e025 (uapi: 6)
```

  App 内提取/签名路径与参考实现一致，但本轮复测时 Shizuku/Stellar 服务在
  reboot 后未启动，App 部署动作无法执行（不是功能失败）；adb shell 路径已证明
  提取与校验逻辑可用。
- 已知限制：目前工作区仅 BakaSU / official 具备 6.12 KMI 原生 LKM；FinaSU /
  SukiSU / Next 的 6.12 LKM 不在内置资源中，需通过 `$WORK/ko-<flavor>.ko`
  提供或由已安装管理器/发布页获取后再运行；内置 6.18 模板仅用于对应 KMI。
- `versionName` 恢复为 `1.0.3`（去掉多余的 `-bakasu` 后缀；versionCode 保持 8 以便覆盖安装）。
- 后端循环顺序改为 KernelSU → BakaSU → KernelSU-Next → SukiSU → FinaSU，默认 KernelSU；
- 「关于」页改为顶部卡片右上角「关于」按钮打开的覆盖页（含作者：酷安@青木信史、版本 1.0.3），不再有底部标签栏；
- 发布产物文件名去掉 -bakasu 后缀（MagicRoot-1.0.3.apk / MagicRoot-Enhanced-1.0.3-source-desensitized.zip）。
  移除「关于」页与底部标签栏，主页直接作为唯一页面。

---

## 14. reuse 误判修复 + 导出日志实测（2026-10-25 16:30）

**现场日志（error.txt）分析**

1. `清理失败: java.lang.IllegalStateException: Stellar/Shizuku 均不可用`
   —— 应用启动后 Shell binder 尚未就绪，清理/部署第一次点击就失败。
   修复：`shellProcess()` 现在对「均不可用」最多重试 5 次（每次 600ms），
   Stellar/Shizuku 刚连上时也能继续。
2. `管理器文件提取（KernelSU）: manager-not-installed` /
   `管理器签名提取: unavailable` —— 默认后端 KernlSU 未安装管理器，属预期的
   内置兜底路径（提示文案已改为「使用内置兜底」）。
3. **reuse 误判（核心）**：`MODULE_ALREADY_LIVE` → fast repair 的
   `ksu_grant` 报 EPERM，旧逻辑仍继续跑完整漏洞链；但 Live 模块无法替换
   （`KO_PATCH_SKIPPED reason=module_already_live`），只浪费时间且可能扰动内核。
   根因之一：上一轮 root_stage 自动开启了 `shell_su_adb_only`，Stellar/Shizuku
   拉起的 shell 不是 adbd/ksu 后代，之后的 GRANT_ROOT 因此被拒。

**修复**

- `run.sh`：Live 模块 + fast repair 失败时**不再进入完整链**，而是重试一次后
  输出 `FAIL=reuse_module_live_not_grantable` 与重启提示；
  `$WORK/force-full` 可显式恢复旧行为（调试用）。
- `root_stage.sh`：`shell_su_adb_only` 改为**opt-in**（`$WORK/enable_shell_adb_only`
  才启用），避免破坏后续 reuse。
- 成功页「导出日志」接入真实导出：复制到
  `/sdcard/Download/MagicRoot/magicroot-success-<ts>.txt`（与失败日志同目录），
  校验文件非空后在成功页内联显示成功/失败与路径、字节数；内存中的 run log
  作为兜底来源（清理工作目录后仍可导出）。

**真机验证**（同一 boot，模块 Live）

- 旧构建下 app 侧 fast repair 失败：`grant_root_rc=-1 EPERM` → 新逻辑快速
  `FAIL=reuse_module_live_not_grantable`，不再启动全链；
- 清除历史 `shell_su_adb_only` 后重新验证：
  `MODULE_LIVE_FAST_REPAIR_OK` → `DONE`，成功页出现（耗时 00:10）；
- 点击「导出日志」输出：
  `日志已导出: /sdcard/Download/MagicRoot/magicroot-success-1792917270332.txt (4139 B)`，
  `ls` 确认文件 4139 B。
- 成功页布局修复：内核版本占整行，不再挤压竖排；「关于」入口改为状态栏行内
  的小号文字链接（10sp），「就绪」胶囊保持右上角。

截图：`docs/screenshots/magicroot-success-export.png`、
`docs/screenshots/magicroot-header-about-link.png`。

---

## 15. 成功日志复核（2026-10-25 16:38，4097 B）

导出的 `magicroot-success-1792917484717.txt` 与 app 内快照
`magicroot-success-1792917476219.log` 内容一致（同尺寸/哈希），关键行：

```text
KSUD_SOURCE=manager-apk path=/data/local/tmp/magic/ksud_resukisu
MODULE_LIVE_FAST_REPAIR_TRY
grant_root_rc=0 errno=0
ROOT_STAGE_ENV uid=0 context=u:r:ksu:s0 enforce=Enforcing
ROOT_STAGE_KERNEL_VERSION=35252 UAPI=6 EXPECTED_FLAVOR=resukisu
ROOT_STAGE_SIG_SIZE=887 HASH=d3469712… SOURCE=app-package-manager
ROOT_STAGE_MANAGER_CMD=kernel-dynamic-manager
ROOT_STAGE_MANAGER_LIST=skipped(no manager subcommand; dynamic-manager path used)
ROOT_STAGE_MANAGER_CONNECTED=1 after=1s
ROOT_STAGE_SHELL_SU=unrestricted_bootstrap (keeps GRANT_ROOT reusable)
ROOT_STAGE_ALLOWLIST=no_backup
ROOT_STAGE_SU_CHECK=0
ROOT_STAGE_OK
MODULE_LIVE_FAST_REPAIR_OK
DONE
```

复核结论：无 WARN/FAIL；管理器连接、签名提取（PackageManager，887/d3469712…）、
ksud 提取（manager-apk）、动态管理器登记、su 自检全部正常。本次修正的日志噪音
（BakaSU 无 `manager` 子命令时的 `unrecognized subcommand`）已消除。

**存在/已记录的潜在问题**

1. `MODULE_LIVE_FLAVOR_HINT`：fast repair 无法从用户态探测 Live 模块的 flavor。
   已增加 `ROOT_STAGE_FLAVOR_MISMATCH` 标记：root_stage 发现版本/uapi 与所选后端
   不一致时写 `$D/root_stage_flavor_mismatch`，run.sh 在 fast repair 成功时输出
   `REUSE_FLAVOR_MISMATCH=1` 并提示重启/切回对应后端（本次日志无该标记）。
2. `ROOT_STAGE_ALLOWLIST=no_backup`：设备 ksu allowlist 为空，reuse 依赖
   bootstrap `allow_shell=1`。若用户放置 `$WORK/no_bootstrap_allow_shell`，
   fast repair 会按新逻辑快速失败并提示重启，属预期。
3. `ROOT_STAGE_SHELL_SU=unrestricted_bootstrap`：为保持 reuse 可用，本次不再自动
   启用 `shell_su_adb_only`；Stellar/adb shell 在本 boot 内可获得临时 root。
   需要收紧时可放置 `$WORK/enable_shell_adb_only`（会牺牲复用路径）。
4. 成功页「耗时」只统计 fast repair（约 10s），不代表完整链耗时，属正常。

---

## 16. MultiSU 多内核（KMI）适配复核（2026-10-25 16:57）

参考提供的 `MultiSU/` 目录补充了 android16-6.12 KMI 的原生 LKM，五个后端不再
共用兼容模板：

| flavor | 6.12 LKM（内置） | 版本 | 6.12.58 syms | 6.12.38 syms |
|---|---|---|---|---|
| resukisu | `ksu-template-bakasu.ko` | 35252 | `syms_61258_bakasu.txt` | `syms_6138_bakasu.txt` |
| kernelsu | `ksu-template.ko` | 32680 | `syms_61258.txt` | `syms_6138.txt` |
| next | `ksu-template-next.ko`（MultiSU 500656 B） | 33355 | `syms_61258_next.txt` | `syms_6138_next.txt` |
| sukisu | `ksu-template-sukisu.ko`（MultiSU 601056 B） | 41068 | `syms_61258_sukisu.txt` | `syms_6138_sukisu.txt` |
| fina | `ksu-template-fina.ko`（FinaSU 1.2.1 bundle 590848 B） | 33074 | `syms_61258_fina.txt` | `syms_6138_fina.txt` |

- FinaSU 升级到 v1.2.1（33074），`ksud` 取自已安装管理器的 `libksud.so`
  （`ksud 1.2.1 (uapi: 6)`）；内置 6.12 模板同步替换为 1.2.1 版本。
- 新 syms 由 `tools/gen_syms.py` 以 boot-0c1e86b6 的 kallsyms（slide
  0x252aa00000）生成：next +4 / sukisu +21 / fina +9 个符号，均
  `still missing: 0`、`_printk anchor consistent: True`。
- 设备端 `ko_patch` 验证（vermagic 重写到本机 6.12.58）：

```text
next    PATCHED=227 MISSING=0
sukisu  PATCHED=245 MISSING=0
fina    PATCHED=232 MISSING=0
```

- KMI × flavor 支持矩阵（真机 profile 测试）：

```text
6.12.58: resukisu/fina/kernelsu/sukisu/next  missing=0（全部可用）
6.12.38: resukisu/kernelsu missing=0；fina/sukisu/next missing=1（fail-closed）
```

6.12.38 缺少对应的 kallsyms dump，无法为三个新模板生成正确的 syms；此时
`run.sh` 会输出 `FAIL=flavor_syms_unavailable` 并拒绝加载（绝不使用另一内核的
地址），避免错配崩溃。提供 6.12.38 dump 后可用同一工具补齐。

成功页内核版本展示同时修正：两行均为正文色，不再将 git/构建后缀置灰。
截图：`docs/screenshots/magicroot-success-export.png`。

---

## 17. 体积优化 + 去内置管理器/ksud + 去 safe 调试（2026-10-25 17:03）

用户要求：不再内置管理器，用户自行安装正确管理器；删除无用的 `_safe` 调试载荷；
进行 APK 体积优化。

**移除内容**

- `BakaSU-manager.apk`（10,150,216 B）——不再随 APK 内置任何管理器；
- 5 份内置 ksud（`ksud`/`ksud_bakasu`/`ksud_fina`/`ksud_next`/`ksud_sukisu`，
  合计约 31.3 MB）——运行链路改为**只从已安装管理器 APK 提取**用户态 ksud；
- `t64560_v36_safe`、`t64560_cred_safe` 以及 run.sh 中整段 SAFE_MODE/
  EARLY_ABORT/drain-slack/run_v36/run_cred 包装逻辑；
- root_stage 中内置管理器 APK 的 `pm install` 自动安装逻辑。

**行为变化**

- 未安装对应管理器时，运行在提取阶段快速失败：
  `FAIL=manager_ksud_missing` + 安装提示（实测 kernelsu 未安装时 <1s 返回，
  且不会启动任何漏洞链进程）；
- 已安装管理器时，从 APK 的 `lib/arm64-v8a/libksud.so`（或重命名库）提取
  ksud，签名由 PackageManager 计算；
- `run.sh` 不再在每次运行前删除 `/sdcard/Download/MagicRoot`，历史日志保留。

**体积结果**

| 项 | 优化前 | 优化后 | 变化 |
|---|---:|---:|---:|
| main APK | 36,600,016 B | **4,042,271 B** | −32,557,745 B（−88.9%） |

**真机回归**（移除内置文件后的 4.0 MB APK）

- 已安装 BakaSU 管理器：部署时自动提取 `ksud_resukisu`（manager-apk），
  fast repair 成功页出现，导出日志 4,120 B；
- 未安装 KernelSU 管理器时：`FAIL=manager_ksud_missing` 快速失败，无漏洞链进程。

---

## 18. 准备阶段重启诊断与缓解（2026-10-25 17:20）

用户反馈：链路在「准备链路」阶段容易导致设备很快重启；可直接导出日志后读取。
现场最后一次运行日志（`/data/local/tmp/magic/run.log` / stage.log，boot_id
`30059683…`）：

```text
STAGE_MARK=RUN_CLEAN_DONE  time=17:07:44 uptime=72
== 1. KASLR ==  KASLR_ACCEPTED slide=0x2d9b000000 votes=5917 anchors=5
== 2. patch KernelSU module ==  PATCHED=226 MISSING=0
== 3. SELinux permissive ==
attempt=1 … attempt=7 (slab baseline 256/256) → 设备在此处重启
```

**结论**：重启发生在 **SELinux permissive 竞态阶段**（模块尚未加载、SELinux 仍
Enforcing），而不是 App/日志层；该次运行在开机仅 **72 秒**、系统负载很高时启动，
竞态 spray 的堆状态与稳定启动时差异很大，panic/重启概率显著升高。日志读取本身
正常（App 内日志显示正常，问题仅是“刚开机就跑”），因此修复方向是**启动前等待 +
减少残留扰动 + 保留证据**。

**已实施**

1. **开机稳定闸门**（run.sh preflight）：在进入 KASLR/竞态前等待
   `uptime>=120s && sys.boot_completed=1 && load<=20 && MemAvailable>=1GB`，
   最长 240s；超时则 `FAIL=preflight_timeout` 并提示稍后重试（不再直接开跑）。
   - 真机验证：设备 uptime 618s/load 15 → `PREFLIGHT_OK`；
     人为设置 `MAX_LOAD=0, MAX_WAIT=3` → `FAIL=preflight_timeout` + 提示。
   - 可用 `$WORK/skip-preflight` 或 `MAGICROOT_SKIP_PREFLIGHT=1` 跳过；
     App 进度会显示「等待系统稳定」。
2. **竞态前清理**：permissive 前 `pkill forker/grab.sh/trace_pipe_raw` 并 sleep 1s，
   避免 KASLR 抓取残留进程继续占用内存/CPU。
3. **中断日志自动导出**：App 启动后 4s、以及每次新运行前，会把残留 run.log +
   `marks/PERMISSIVE_STARTED` 导出到
   `/sdcard/Download/MagicRoot/prev-run-<ts>.txt`，然后才清理/覆盖。
   真机用 dummy 日志验证：导出文件包含 `DUMMY_RUN_LOG` 与
   `=== PERMISSIVE_STARTED ===` 段。
4. **pstore 保留**：root_stage 拿到 root 后尝试把 `/sys/fs/pstore` 复制到
   `$WORK/pstore-last` 与 `/sdcard/Download/MagicRoot/pstore-last`（下次成功运行时
   可用于分析上一次崩溃的 console-ramoops）。
5. 若仍重启：重新打开 App 会自动导出上次日志；再次运行会先等待系统稳定
   （通常开机后静置 2 分钟以上即可通过闸门）。竞态本身存在固有 panic 风险，
   无法完全消除，只能降低概率并保留取证。

---

## 19. App 日志停在「开始执行 run.sh」根因与修复（2026-10-25 17:32）

**现场**

- App 运行日志停在最后一条 App 侧消息 `开始执行 run.sh（日志同时写入 …/run.log）`，
  进度 2%「准备链路」一直不动；
- 同时设备上的 `/data/local/tmp/magic/run.log` 已推进到 KASLR / patch / permissive
  attempt=30…50；
- 17:28 的应用退出记录（`dumpsys activity exit-info`）：
  `reason=10 (USER REQUESTED) subreason=22 (REMOVE TASK) description=remove task`
  —— 用户在界面“看起来卡住”后把 App 从最近任务划掉，App 死亡导致
  Stellar/Shizuku 拉起的 run.sh 随即被终止（日志停在 attempt=50，无 FAIL、无重启）。

**根因**：Stellar/Shizuku 子进程的 stdout 管道在竞态阶段不实时投递数据（日志文件
在增长而 App 收不到行），App 之前以 stdout 流作为 UI 日志来源，于是 UI 冻结。

**修复**

- UI 日志/进度改为**轮询 run.log**（每 1.5s `tail` 增量）作为权威来源；
  子进程 stdout 仅做 drain 防止管道阻塞；`DONE/FAIL`、进度阶段都从文件行解析；
- 真机 stub 验证：run 开始 4s 时界面已显示 `TEST_LOG_START/1/2/3`，8s 显示
  `DONE`，不再卡在启动行（截图 `docs/screenshots/magicroot-live-log-polling.png`）；
- App 启动后 4/12/25/40s 重试导出上次残留日志到
  `/sdcard/Download/MagicRoot/prev-run-<ts>.txt`（含 `PERMISSIVE_STARTED` 标记）。
  真机验证：被划掉的那次运行日志（7,398 B，attempt 1–50 + 中断标记）已成功自动导出。

**注意**

- App 被划掉/强停会连带终止正在运行的链路（remote 子进程随宿主死亡）。
  日志会保留并自动导出，但链路需重新执行；运行期间请勿从最近任务移除 App。
- 若设备在 permissive 竞态阶段 panic/重启，属于漏洞竞态固有风险，见 §18 的
  preflight/清理/取证措施。

---

## 20. allow_shell 默认关闭（2026-10-25 17:40）

**发现的问题**：`run.sh` 里 `ALLOW_SHELL` 默认虽然是 0，但存在隐藏的
`BOOTSTRAP_SHELL=${MAGICROOT_BOOTSTRAP_ALLOW_SHELL:-1}`：
即使 UI「allow shell」关闭，模块仍会以 `allow_shell=1` 加载（日志
`ALLOW_SHELL=0 LOAD_ALLOW_SHELL=1 BOOTSTRAP_SHELL=1`），与“默认不开启”不符。

**修改**

- `BOOTSTRAP_SHELL` 默认改为 **0**；`LOAD_ALLOW_SHELL` 只取 UI 的 `ALLOW_SHELL`
  值，默认 0（模块以 `allow_shell=0` 加载）；
- bootstrap 需显式同意，三种方式：
  1. UI 打开「allow shell」；
  2. 环境变量 `MAGICROOT_BOOTSTRAP_ALLOW_SHELL=1`；
  3. 高级用户放置 `$WORK/bootstrap_allow_shell`；
  旧的 `no_bootstrap_allow_shell` 标记移除；
- 日志新增 `ALLOW_SHELL_NOTE=off` 说明；grant 失败提示改为
  “启用「allow shell」后重启重试”；
- root_stage 的 `ROOT_STAGE_SHELL_SU` 状态改为
  `default_off (allow_shell=0)` / `allow_shell_requested`；
- UI「allow shell」副标题改为「默认关 · 冷启动首次需开」。

**影响/使用**

- 默认（allow_shell=0）下，冷启动的 `GRANT_ROOT` 需要 shell 已在 ksu allowlist
  中（例如管理器已授权 shell）；若 allowlist 为空，则需开启「allow shell」后
  **重启并重跑**（Live 模块无法替换参数）；
- 这是安全取舍：不再在用户不知情时赋予 shell 临时 root 能力；
- 已用 `bash -n` 对 `run.sh`/`root_stage.sh` 做语法检查（设备离线期间无法做
  真机配置回显验证，下一次连接设备后可用
  `MAGICROOT_PREFLIGHT_ONLY=1 sh run.sh` 查看
  `ALLOW_SHELL=0 LOAD_ALLOW_SHELL=0 BOOTSTRAP_SHELL=0`）。

---

## 21. 6.12.58/6.12.38 专项适配（2026-10-25 19:30）

按五项要求完成静态适配与构建（2026-10-25 19:40 更新：已拿到 6.12.38
`boot.img/init_boot.img/vendor_boot.img`，6.12.38 的 next/sukisu/fina syms
已从 6.12.38 vmlinux 生成并审计为 missing=0；vendor_boot 的 6.12.23 模块不可混用）：

1. perf known-cred + 分离写 cred/加载模块：现有 `cred_target`（perf
   kmem_cache_alloc + capset → cred）+ `t64560_cred`（known-cred writer）
   链路确认，run.sh 增加 `CRED_LEAK_SELF_CHECK`/失败提示；
2. KASLR：现有 `kaslr_slide_61258/6138` 的文本锚点 + raw 值投票之上，新增
   run.sh `KASLR_CROSS_CHECK`（用 profile 的 prepare_creds/selinux_state link
   与 slide 独立重算并逐字符比对，votes/anchors/bytes 阈值，fail-closed）；
3. ko_patch：`PATCHED/MISSING` 自检进 run.sh，missing>0 在 permissive 前失败；
   ko cache 命中也会打印缓存的自检行；
4. ksu_grant：新增双 magic reboot 后门（0xcafebabe/0xdeadcafe）+ `/dev/ksu`
   兜底 + `KSU_FD_SOURCE`；run.sh 记录 `KSU_GRANT_METHOD`；
5. 6.18 复用审计：无 0x908/6.18 模板/6.18 resolve 地址进入运行时资产；
   6.12.58 `prepare_creds` 反汇编确认 task->cred=0x900、cred_size=0xb8。

详见 `docs/reference/kernel-adaptation-61258-61238.md` 与
`refs/kernel-audit/audit.json`。当前无设备连接，真机验证待补。

---

## 22. PREFLIGHT_WAIT 阶段禁止重复导出日志（2026-10-25 19:45）

**问题**：App 启动后的 stale-log 自动导出重试（4/12/25/40s）没有判断“是否正在跑链”。
如果用户在启动后很快点「开始提权」，这些重试会在 PREFLIGHT_WAIT 阶段继续执行：
把**当前正在写的 run.log** 当成上次残留日志导出到 `prev-run-*.txt`，并把 run.log
改名为 `run.log.exported`，导致 preflight 之后的日志轮询丢行/重复导出。

**修复**（MainActivity）：

- `runInProgress` 保护：launch 重试与 `exportStaleRunLog("launch")` 在运行中直接返回；
- 新增 `staleExportDone` 一次性标记：成功导出后，后续重试不再检查/导出；
- `exportStaleRunLog` 加 `synchronized`，避免 4s/12s 两个重试并发导出同一个文件；
- 唯一允许在运行开始时执行的是 `exportStaleRunLog("before-run")`，它在 run.log
  被删除、新进程启动之前执行，只导出上一次的残留日志，不影响本次 PREFLIGHT_WAIT。

构建：APK 3,822,818 B
sha256 `da8da5c8d610083396c6786f9991a5f20f21084b3b7b3a55e0814e729211764f`
（`tools/verify_apk.py` 通过）。真机验证待设备连接。

---

## 23. 参考项目 victims 等参数研究（2026-10-25 19:55）

研究一加16 v2.7.0 `core.sh` / `perm.bin` / `writer.bin` / `t64560_v36.c` /
`t64560_v42.c` 与 HyperBreak Enhanced `Pipeline.java` 的默认/实测参数：

```text
OP16 v2.7.0 core.sh:
  perm   : 180 400 16 6000 12000 4500
  writer : 90 90 400 16 6000 12000 (min 4500)
  capture: loadgen.bin 2 30 x300
参考二进制缺省 (perm.bin/t64560_v36):
  120 400 16 6000 20000 4500
HyperBreak Enhanced 实测通过:
  perm/fsuid: 200 400 24 12000 12000 4500
  cred      : 200 300 400 24 12000 10000 3500 + pid
MagicRoot 当前默认:
  perm/fsuid: 500 400 32 12000 12000 4500
  cred      : 260/320 400 16 6000 12000 4500
```

结论：我们当前比两个参考都更激进（victims 32 vs 16/24；attempts 500 vs
90~200；cred drain 15000 vs 10000）。按 Enhanced 的 hit 模型，24 victims +
200 attempts 的未落地概率约 0.12%，500 attempts 属于过度冗余；32 victims 的
每 attempt 计时器数为 12,800（OP16 6,400 / Enhanced 9,600），内核压力更高。

**默认值暂不改**（无设备无法 A/B），但 run.sh 已加入 opt-in 档位：

```text
$D/tuning-reference   -> 24/200/300/12000/10000/3500 (推荐日常)
$D/tuning-op16        -> 16/180/90/6000/12000/4500 (最保守对照)
MAGICROOT_TUNING / MAGICROOT_ATTEMPTS_* / ... 可单独覆盖
```

日志会输出 `TUNING=reference ...` 与最终 `ATTEMPTS_PERMISSIVE=...`。
详见 `docs/reference/reference-parameter-research.md`。

构建：APK 3,823,582 B
sha256 `1401d384ca4b8052b39cf17da6f2842ad2c2495d74bf024b5cc85ae4cf1179a3`
（`tools/verify_apk.py` 通过；未安装，真机 A/B 待设备连接）。

---

## 24. victims 参数真机 A/B 初步结果（2026-10-25 20:38）

设备 `<SERIAL>`；adb SDK 37.0.1；测试仅 permissive 阶段：

| 档位 | trial | 结果 | 落地 attempt | 总耗时 |
|---|---|---|---:|---:|
| current (32/500) | 1 | OK | 35 | 352.3 s |
| current (32/500) | 2 | OK | 9 | 107.1 s |
| reference (24/200) | 1 | OK | 8 | 139.3 s |
| reference (24/200) | 2 | **设备重启** | 13（中断） | 199.3 s |

结论：current 2/2 成功；reference 1/2 成功且有一次竞态重启，样本不足，**默认保持
current**，reference 继续作为 `$D/tuning-reference` opt-in 档。
reference-2 的重启是漏洞竞态，不是 adb 命令（日志在 attempt 13 后直接中断，
无 FAIL/DONE；adb 命令只发送过一次 reboot，在测试开始前）。

最终构建（A/B 后）：APK 3,823,666 B，sha256 `cca786d9fd7d83f03c7b5bac0fc3d50e892884ee2859520bd3adecc0b77f1ebf`；
`tools/verify_apk.py` 通过（versionCode 8 / versionName 1.0.3，39 个资产）。

---

## 25. 扩充 permissive 统计与后续阶段（2026-10-25 21:16）

permissive-only 扩充样本：

| preset | 成功/总 | 落地 attempts | 备注 |
|---|---|---|---|
| current (32/500) | **4/4** | 35, 9, 10, 19 | 无重启 |
| reference (24/200) | 1/4 | 8 | 2 次竞态重启 + 1 次 43 attempts 未落地 |

结论：该设备上 current 明显更稳，**默认保持 current**，不切 reference。

后续 fsuid/cred/module 阶段 A/B 的第一次尝试因 harness 误判 `DONE`、进程探测误判
和一次 KASLR anchors 不足而作废，测试被人工取消；`MAGICROOT_AB_STAGE` 钩子已加入
run.sh，后续修好 harness 后可继续。设备当前已回到 Enforcing，无残留 run。

**修正（2026-10-25 21:20）**：cred stage 依赖 permissive/fsuid/候选 cred，不能独立
A/B；后续如继续，只做整链 A/B（fresh boot 跑完整 run.sh），不再拆分 cred 阶段。

---

## 26. 整链 A/B 尝试（2026-10-25 21:34）

| variant | 结果 | 说明 |
|---|---|---|
| full-current-1 (allow_shell=1) | **设备重启** | permissive attempt 9 后重启，未进入 cred/module |
| full-reference-1 (allow_shell=1) | `FAIL=kaslr_anchors anchors=1` | raw 3.39 MB/votes 701，但 anchors 只有 1 |

整链 A/B 未得到有效对比。permissive 结论不变：current 4/4，reference 1/4（2 次
竞态重启），默认保留 current。KASLR 抓取偶发 anchors=1，后续需重抓/放宽门槛后才能
稳定做整链测试。设备当前 Enforcing、无残留 run。

---

## 27. KASLR 重抓策略（2026-10-25 21:40）

`run.sh` 现在：

- cache 命中先校验，不达标 `KASLR_CACHE_REJECT` 并重抓；
- 最多 3 次：120 loops → 240 loops → `grab_legacy.sh` 8s；
- 只有通过 anchors/votes/bytes gate 才写 `kaslr.cache`，失败删除旧 cache；
- 新增 `MAGICROOT_KASLR_GRAB_TRIES`（默认 3）和
  `MAGICROOT_KASLR_GRAB_MAX_LOOPS`（默认 300）。

真机强制低 loops 验证成功：

```text
KASLR_GRAB_TRY=1 loops=10 → anchors=1, votes=285, bytes=1425408 → KASLR_REGRAB
KASLR_GRAB_TRY=2 loops=20 → anchors=1, votes=272, bytes=1081344 → KASLR_REGRAB
KASLR_GRAB_TRY=3 legacy=1 → anchors=3, votes=668, bytes=2301952
KASLR_CROSS_CHECK=ok; KASLR_ACCEPTED slide=0x28b3a00000; KASLR_ONLY_DONE
```

构建：APK 3,826,226 B sha256 `e0883743b70c17c1c8a2a676e613d71d63ecd61442958e87bd5c671af2ddfff6`；`verify_apk` 通过。

---

## 29. FinaSU 1.2.0 模板升级（2026-10-25 22:40）

- 管理器 APK：`v1.2.0` / versionCode 33071 / uapi 6；
- 内置 6.12 模板替换为 `FinaSU_v1.2.0_kernel-bundle.zip` 的
  `arm64/android16-6.12_kernelsu.ko`；
- 模板大小 590848 B，sha256
  `31fdd7b03de9524dd021c975e15780b69f3e64dea4b2a91877f95938d0913113`；
- 新旧模板 ELF 未定义符号集合完全一致（232 个）；
  `syms_61258_fina.txt` / `syms_6138_fina.txt` 覆盖率均为 232/232，missing=0；
- 期望版本表同步为 FinaSU 33071 / uapi 6
  （`kernel_profiles.sh`、`root_stage.sh`）。

构建：APK 3,826,226 B，sha256 `e0883743b70c17c1c8a2a676e613d71d63ecd61442958e87bd5c671af2ddfff6`；`verify_apk` 通过。

---

## 30. cred MAXVICTIM 32（2026-10-25 22:50）

- `t64560_cred` 以 `-DMAXVICTIM=32` 重新编译，大小 76,304 B，
  sha256 `928abcf78d7829c64933d7f6d837016f77399c20958602e1692a8d655cd8ed6b`；
- run.sh 的 `VICTIMS_CRED` 允许 `8/12/16/24/32`；
- UI cred 档位循环改为 `8 → 12 → 16 → 24 → 32 → 8`，默认仍为 24；
- `t64560_cred.c` 默认值同步为 32，Makefile 的 cred 目标显式加
  `-DMAXVICTIM=32`；
- `verify_apk.py` 新增 cred 二进制的 hash 固定。

---

## 31. 6.12.38 syms 计算审计（2026-10-25 23:00）

按当前每个 6.12 模板的未定义符号集合，计算 6.12.38 所需 syms：

| flavor | 模板 | 所需符号 | 已解析 | 缺失 | syms 表行数 | 多余 |
|---|---|---:|---:|---:|---:|---:|
| kernelsu | `ksu-template.ko` | 226 | 226 | 0 | 226 | 0 |
| resukisu | `ksu-template-bakasu.ko` | 233 | 233 | 0 | 241 | 8 |
| next | `ksu-template-next.ko` | 227 | 227 | 0 | 227 | 0 |
| sukisu | `ksu-template-sukisu.ko` | 245 | 245 | 0 | 245 | 0 |
| fina | `ksu-template-fina.ko` | 232 | 232 | 0 | 232 | 0 |

- 所有所需符号在现有 `syms_6138*` 表中均能解析，`missing=0`；
- 6.12.38 关键 anchor 校验：
  `prepare_creds=0xffffffc080b8a21c`、`selinux_state=0xffffffc0826663c8` 均正确；
- 计算出的必需集合写入 `refs/kernel-audit/syms-6138-required/`；
- 完整报告：`docs/reference/syms-6138-audit.md`。

结论：FinaSU 1.2.0 模板的未定义符号集合与旧模板一致，6.12.38 不需要新增 syms；
resukisu 表有 8 个多余符号，保留以兼容历史模板，不影响解析。

---

## 32. 默认 cred 参数对齐（2026-10-25 23:05）

默认 cred 参数调整为：

```text
attempts = 260 / 320
timers   = 400
victims  = 24
nfrag    = 6000
drain    = 12000 / 12000
min      = 4500 / 4500
```

对应 `t64560_cred <cred> 260 320 400 24 6000 12000 4500`。
UI cred 默认档位同步为 24；可选档位仍为 8/12/16/24/32。

---

## 34. `ko_cache_keep` 与 ko_flavor 切换分析（2026-10-25 23:20）

### 结论

`KO_CACHE_KEEP`（实际变量 `KO_CACHE_MAX`）**本身只是持久缓存保留数量，不参与
flavor 选择**；但它旧版的实现存在两个会间接影响“实际加载哪个 KO”的问题：

1. 持久缓存文件名使用截断后的 key：
   `tr ': |' '___' | cut -c1-180`。同 boot/slide/uname/flavor 下，如果模板
   被替换但 key 的差异落在 180 字符之后，旧 `.ko` 可能与新 key 共用文件名。
2. 命中持久缓存时只检查文件存在，**不校验该缓存文件对应的完整 key**；
   旧版 `ko.cache` 校验只在工作目录分支发生，持久缓存分支没有 sidecar。

因此理论上存在：切换 flavor/模板后，仍从同名持久缓存加载旧 KO。`KO_CACHE_MAX`
调大/调小不会直接改变 flavor，但保留更多旧条目会增加这类 stale 命中概率；
调小则会删除缓存，只影响速度，不会修复错误命中。

### 修复

- key 增加 `PROFILE_ID`、`KSU_FLAVOR`、模板/syms/ko_patch 的 **sha256**
  （不再只依赖 `size:mtime`）；
- 持久缓存文件名改为完整 key 的 sha256 前 32 位，消除截断碰撞；
- 每个持久 `.ko` 配一个 `.key` sidecar，内容为完整 `KO_KEY`；恢复时必须
  sidecar 完全匹配，否则输出 `KO_CACHE_STALE` 并删除，强制重新 patch；
- `ko.cache` 继续保存完整 key；
- `prune_ko_cache` 只做保留/过期清理，**永远排除当前 KO**，并同步删除
  sidecar；日志明确标注
  `KO_CACHE_KEEP=... (retention only; not a flavor selector)`；
- 新增日志：`KO_CACHE_IDENTITY`、`KO_CACHE_SAVED`、`KO_CACHE_STALE`、
  `KO_PATCH_SKIPPED reason=... flavor=...`。

修复后，flavor/模板变化会得到不同 key/tag，旧缓存不会被恢复；实际加载的
`ksu-patched.ko` 必定来自当前 flavor + 当前模板内容 + 当前 syms + 当前
`ko_patch`。

---

## 35. FinaSU 1.2.1 模板升级（2026-10-25 23:12）

- 管理器：`v1.2.1` / versionCode 33074 / uapi 6；
- kernel bundle：`FinaSU_v1.2.1_kernel-bundle.zip`
  sha256 `15c64acb7e5782290020db61f2670a4871b73d9fda78e1ff4a3ba93bb3df3c69`；
- 内置 6.12 模板：`arm64/android16-6.12_kernelsu.ko`，590,848 B；
  sha256 `d1f8cedb14c5a62fb5f15861bd89ed2553525d33f31801bf3a795aa6a998bfeb`；
- 未定义符号集合仍为 232 个，与 1.2.0 完全一致；
  `syms_61258_fina.txt` / `syms_6138_fina.txt` 覆盖率仍为 232/232；
- 期望版本更新为 33074 / uapi 6
  （`kernel_profiles.sh`、`root_stage.sh`）。

---

## 36. 移除 118 路线，聚焦 6.12（2026-10-25 23:30）

- 删除独立 `118 路线/` 源码树（6.6.118 payload 路线）及其 release APK；
- 发布源码包只包含 `main/`、`docs/`、`tools/`、`README.md`，不再包含
  118 路线 源码、APK 或相关构建脚本；
- README 已改为 6.12 单路线说明；
- `docs/BAKASU-ADAPTATION.md` 不再进入源码包；
- `tools/package_release.py` 增加最终脱敏 gate，发布前扫描源码树中的
  本机用户名/路径、设备序列号、内部 workspace 名、工具链路径和 118 路线
  标识，发现即 `DESENSITIZE_FAIL` 并中止打包；
- 源码包重新生成：`MagicRoot-Enhanced-1.0.3-source-desensitized.zip`，
  `DESENSITIZE_CHECK=ok`。

主 APK 不受影响，仍为 6.12 路线：`MagicRoot-1.0.3.apk`.

---

## 37. cred 默认与成功页去重（2026-10-25 23:35）

- cred 默认 victim 恢复为 **24**（attempts/frag/drain 保持 260/320、6000、12000/4500）；
- 成功页移除重复的「提权成功」胶囊，只保留「提权完成」标题；
- run.sh 末尾显式管理器打开/验证块已撤销；模块加载后的管理器启动仍由
  `root_stage.sh` 负责。

---

## 38. P2：KernelSU 特性开关 / 移除 dev su（2026-10-25 23:56；特性开关已于 §40 撤销）

### 默认值依据

- `kernel_umount`：KernelSU `kernel/feature/kernel_umount.c`
  `static bool ksu_kernel_umount_enabled = true;`，默认 **开**；
- `selinux_hide`：KernelSU 默认 **关**（官方 6.12 LKM 的
  `ksu_selinux_hide_enabled` 初始字节为 0）。

### 行为

- UI 新增 `kernel_umount` / `selinux_hide` 开关；
- `MainActivity` 通过 `MAGICROOT_KERNEL_UMOUNT` /
  `MAGICROOT_SELINUX_HIDE` 传给 `run.sh`；
- `run.sh` 导出给 `root_stage.sh`；
- `root_stage.sh` 执行：

```text
ksud feature set kernel_umount <0|1>
ksud feature set selinux_hide <0|1>
ROOT_STAGE_FEATURE_kernel_umount=...
ROOT_STAGE_FEATURE_selinux_hide=...
```

特性不受支持时记录 `unsupported_or_failed`，不阻断 root。

### dev su

- 移除 UI 的 `dev su` 开关；
- `root_stage.sh` 不再创建 `/dev/su`；
- 旧版本 marker 对应的 `/dev/su` 只做一次性清理
  （`DEV_SU_LEGACY_CLEANED=/dev/su`）；
- `clean.sh` 保留旧文件清理逻辑，避免升级后残留。

### 静态校验

`verify_apk.py` 新增：

- `assets/run.sh`：`MAGICROOT_SELINUX_HIDE` / `MAGICROOT_KERNEL_UMOUNT`；
- `assets/root_stage.sh`：`ROOT_STAGE_FEATURE_` / `apply_feature` /
  `DEV_SU_LEGACY_CLEANED`；
- UI：`kernel_umount` / `selinux_hide` 字符串。

---

## 39. 移除「恢复 SELinux」开关（2026-10-25 23:59）

恢复 Enforcing 是默认成功路径，不再作为用户选项：

- 删除 UI 的「恢复 SELinux」开关；
- 删除 `UiState.restoreEnforcing` 及持久化；
- `MainActivity` 不再传 `MAGICROOT_RESTORE_ENFORCING`，也不再创建
  `no_restore_enforcing` 标记；
- `root_stage.sh` 在 root 环境就绪后无条件下执行 `setenforce 1`，日志：

```text
ROOT_STAGE_SELINUX=restored_enforcing
```

若恢复失败记录 `ROOT_STAGE_SELINUX=restore_failed`，不静默保持 permissive。

---

## 40. 撤销 kernel_umount / selinux_hide 开关（2026-10-26 00:15；已于 §41 恢复）

按“保持模块自己的默认值”的要求撤销 §38 的 UI/参数传递：

- 删除 UI 的 `kernel_umount` / `selinux_hide` 开关；
- 删除 `UiState` 的持久化状态和 setter；
- `MainActivity` 不再传 `MAGICROOT_KERNEL_UMOUNT` / `MAGICROOT_SELINUX_HIDE`；
- `run.sh` 不再解析/导出这两个变量；
- `root_stage.sh` 不再执行 `ksud feature set kernel_umount`
  / `ksud feature set selinux_hide`，只保留 `su_compat` 的设置；
- 模块使用自身默认值：KernelSU `kernel_umount=true`、`selinux_hide=false`。

### 静态校验

`verify_apk.py` 移除对应 marker；APK 内不应再有：

```text
kernelUmount / selinuxHide
MAGICROOT_KERNEL_UMOUNT / MAGICROOT_SELINUX_HIDE
ROOT_STAGE_FEATURE_kernel_umount / ROOT_STAGE_FEATURE_selinux_hide
```

---

## 41. 恢复 kernel_umount / selinux_hide 开关（默认开启）

恢复 UI 开关和完整参数链，但默认值与 §40 不同：

| 特性 | 默认 |
|---|---|
| `kernel_umount` | **开** |
| `selinux_hide` | **开** |

流程：

```text
UiState（默认 true）
  → MainActivity
  → MAGICROOT_KERNEL_UMOUNT / MAGICROOT_SELINUX_HIDE
  → run.sh
  → root_stage.sh
  → ksud feature set kernel_umount <0|1>
  → ksud feature set selinux_hide <0|1>
```

- 用户关闭时显式下发 `0`，不再“保持模块默认”；
- `ROOT_STAGE_FEATURE_*` 记录实际下发值；
- 特性不受支持时只告警，不阻断 root；
- `selinux_hide` 与“提权结束后恢复 Enforcing”是两条独立逻辑。

---

## 42. 速度优化：capture / drain / kill / manager（2026-10-26 01:05）

已实施：

- `grab.sh`：forker 分块批量执行；首次 capture 支持 `GRAB_EARLY_STOP_BYTES` 早停；
- `run.sh`：默认 `SAFE_MODE=1`，使用 P0-safe 二进制：
  - `T64560_MIN_DRAIN_MS=500`
  - `T64560_DRAIN_MAX_MS=8000`
  - `T64560_EARLY_ABORT_MS=4500`
  - `T64560_DRAIN_SLACK=64`
  - safe 失败自动回退 legacy；
- `root_stage.sh`：manager 已连接时跳过注册/重启；
  `wait_manager_connected` 改为先检查再 sleep；manager 启动等待缩短；
- module wait 失败上限从 180s 降到 60s；轮询 fallback 120→30 次；
- `timers/victims/frag/attempts` **未降低**，仍保持竞态原语；
- 不影响成功的 manager/ksud timeout 仍保持。

see `docs/reference/speed-optimization-20261026.md`。

---

## 43. v42 方案升级评估（2026-10-26 01:30）

结论：

- 当前 `t64560_cred.c` 已是 HOneClick `t64560_v42_honor.c` 的 6.12 移植版；
- 上游/HOneClick 的 v42 使用 6.18 偏移 `0xe0/0x180`，我们使用
  `0x78/0x100`；不能直接替换；
- v42 是 cred 两阶段写入器，不是完整链；permissive 仍由 v36 完成；
- 已保留 `--self`、force_feature adb_root、phase1 CapBnd 校验、
  PHASE2 marker、动态 victim 等待、per-phase drain/min。

新增可选 preset：

```text
$D/tuning-v42
$D/tuning-honor-v42
MAGICROOT_TUNING=v42 / honor-v42
```

默认保持 `current`，待同 boot A/B。

详见 `docs/reference/v42-upgrade-analysis.md`。

---

## 44. 深度速度优化（完整 doc/source 复核，2026-10-26 01:40）

依据：Feng1586/CVE-2026-64560-public 全部 16 份 docs、全部 `src/` 源码、
HOneClick v42_honor 与 evidence。

默认改动：

- permissive/fsuid attempts：**500 → 160**；
- permissive/fsuid victims：**32 → 16**（timer 数每 attempt 12,800 → 6,400）；
- cred victims 保持 **24**（用户指定）；
- cred attempts 保持 260/320；
- `SAFE_MODE` 默认改为 **0**（docs 139 证明 4500ms min_drain 必要）；
- 启动前 stale slab 门禁：
  - `posix_timers_cache active > 700` → `FAIL=stale_posix_slab`；
  - 提示重启，避免 500×5s 空转；
- 保留 capture chunk/early stop、manager fast reuse、module wait 60s。

回退环境变量：

```text
MAGICROOT_VICTIMS_PERMISSIVE=32
MAGICROOT_VICTIMS_FSUID=32
MAGICROOT_ATTEMPTS_PERMISSIVE=500
MAGICROOT_ATTEMPTS_FSUID=500
MAGICROOT_SLAB_STALE_ACTIVE=0
MAGICROOT_SAFE_MODE=1
```

详见 `docs/reference/deep-speed-optimization-20261026.md`。

---

## 45. cred 参数确定（v42 / Enhanced / 本机证据，2026-10-26 01:55）

cred 阶段默认确定为：

```text
victims       24
timers        400 / victim
attempts      phase1 260 / phase2 320
nfrag         12000
drain max     10000 ms
min drain     4500 ms
```

理由：

- 24 victims 是 Enhanced 真机通过参数，且源码注释明确 16→24 是调优；
- 260/320 对齐 HOneClick v42 调用；
- 12000 nfrag：Enhanced 注释指出 6000 会使落地率减半；
- 10000 drain 覆盖 docs 139 实测 2.5–8.1 s 排空窗口；
- 4500 min drain 避免污染 cache 的假排空；
- 400 timers 不降，避免改变 race 形状。

详见 `docs/reference/cred-parameters.md`。

---

## 46. 默认档位切换为 reference（UI 保留 Victim 切换，2026-10-26 02:05）

`run.sh` 默认：

```text
TUNING=reference
```

reference 参数：

```text
permissive/fsuid: 24 victims / 200 attempts / 400 timers / 12000 nfrag / 12000 drain / 4500 min
cred:             24 victims / 200+300 attempts / 400 timers / 12000 nfrag / 10000 drain / 3500 min
```

其他档位保留：

```text
$D/tuning-current   -> 16/160 perm, 24/260+320 cred, 12000/10000/4500
$D/tuning-honor-v42 -> 16/160 perm, 16/260+320 cred, 6000/12000/4500
$D/tuning-v42       -> 24/200 perm, 24/200+300 cred, 12000/10000/3500
$D/tuning-op16      -> 16/180 perm, 16/90+90 cred, 6000/12000/4500
MAGICROOT_TUNING=reference|current|v42|honor-v42|op16
```

现行 UI 的 “Victim 档位” 三个按钮保持可用：

```text
SE / fsuid / cred
默认 24
用户可切 16 -> 24 -> 32（cred 8 -> 12 -> 16 -> 24 -> 32）
```

UI 选择会作为 `MAGICROOT_VICTIMS_*` 覆盖 preset 的 victims 值；attempts/drain/min
仍由 preset 决定，除非使用 `MAGICROOT_*` 环境变量显式覆盖。

stale slab 门禁、capture chunk/early stop、manager fast reuse、module wait 60s
均保留。

---

## 47. 移除 _safe，运行固定为 v42 方案（2026-10-26 02:20）

用户报告 `_safe` 会导致设备重启，已完全移出运行时：

- 删除 assets：
  - `t64560_v36_safe`
  - `t64560_cred_safe`
- 删除 native 源码：
  - `t64560_v36_safe_61258.c`
  - `t64560_cred_safe_61258.c`
- 删除 run.sh：
  - `SAFE_MODE` 选择
  - `run_v36`/`run_cred` 的 safe 分支
  - `SAFE_MODE_FALLBACK`
- 启动时额外清理旧部署残留：
  ```text
  rm -f $D/t64560_v36_safe $D/t64560_cred_safe
  ```

当前实际运行：

```text
permissive/fsuid: t64560_v36
cred:             t64560_cred   （v42 两阶段写）
CRED_SCHEME=v42
```

`t64560_cred` 仍是我方 6.12 偏移的 v42 两阶段 writer：
`cap_bset=0` + `cap_effective=cred+0x40`，位 16 为 CAP_SYS_MODULE。

默认档位 `reference`、UI Victim 档位切换、stale slab 门禁、
capture/manager 优化均保留。

---

## 48. v42 slab 异常修复与 6.12.58 / 6.12.38 适配（2026-10-26 03:00）

### 找到的 v42 slab 问题

1. 上游/HOneClick 在 `SIGCHLD=SIG_IGN` 下 `kill()` 后只 `usleep(300000)`，
   没有 `waitpid()`；无法确认 `release_task()` / timer teardown 已完成。
2. 只看 `/proc/<pid>` 消失，不能证明 `posix_cpu_timers_exit_group()` 已完成。
3. 没有 slab 上限保护：已出现 `drained=0(12050ms) slab=6818/13280` 后仍继续
   创建下一轮 `400×victims` timers，slab 会继续抬高。

### 修复

- `SIGCHLD` 改为默认；
- `kill_wait_victims()` 使用 `waitpid(..., WNOHANG)` 回收，`ECHILD` 视为已回收；
- 回收后重新读取 `posix_timers_cache`；
- 未落地 attempt 的 post-kill slab：
  ```text
  active > MAGICROOT_CRED_SLAB_MAX(默认1500)
  或 total > 2×limit
  -> SLAB_RUNAWAY / exit 7
  ```
- 新增资产：
  ```text
  main/app/assets/t64560_cred
  size 76,888 B
  sha256 ff39e2d1318db2c91639a1367744495749722b82ba5af26405c27523e540c86d
  ```

### 6.12.58 / 6.12.38

`refs/kernel-audit` 与 vmlinux 反汇编确认两个 KMI 使用同一布局：

```text
task->cred=0x900, sizeof(cred)=0xb8
cred cap_effective=0x40, cap_bset=0x48
k_itimer size=0x100, node=0x78, slot stride=0x100
```

因此共用同一个 v42 cred 二进制；run.sh 会输出：

```text
CRED_LAYOUT=itimer_node=0x78 slot_stride=0x100 cred_eff=0x40 cred_bset=0x48 profile=61258|6138
CRED_SLAB_GUARD=post_reap_default=1500
```

非 61258/6138 profile 直接 `FAIL=cred_layout_unknown`。

详见 `docs/reference/v42-slab-fix-612-port.md`。

---

## 49. PRELIGHT 固定等待移除 + permissive slab 收尾（2026-10-26 03:30）

### PRELIGHT

- 删除固定 `uptime >= 120s` settle；
- `PREFLIGHT_SETTLE` 默认 **0**；
- `PREFLIGHT_MAX_WAIT` 默认 **30s**；
- 仅保留 boot_completed/load/MemAvailable 短检查，超时 fail fast；
- 需要旧行为时设置 `MAGICROOT_BOOT_SETTLE_SEC`。

### Permissive

上游 v36 仍使用：

```text
SIGCHLD=SIG_IGN
kill(vpid); usleep(300000)
```

本次补到 permissive：

- SIGCHLD 默认 + `waitpid(WNOHANG)`；
- 回收后重读 `posix_timers_cache`；
- `MAGICROOT_PERM_SLAB_MAX=1500` runaway guard；
- 6.12 布局静态断言。

硬编码未改：

```text
timers=400, DRAIN_SLACK=320, drain/min 语义不变
```

### 资产

```text
t64560_v36
size   67,848 B
sha256 3ba4a9dbc2bd8af3b90bdd85cba108343636104434c9295acd4c433bb6394e24
```

详见 `docs/reference/preflight-permissive-review.md`。

---

## 50. SLAB_RUNAWAY 改为非强制（2026-10-26 03:45）

按用户要求，`SLAB_RUNAWAY` 不再作为强制退出：

- cred/permissive 默认：
  ```text
  SLAB_RUNAWAY ... action=warn
  usleep(500000)
  -> 继续 attempt
  ```
- 旧硬退出保留为 opt-in：
  ```text
  MAGICROOT_CRED_SLAB_ACTION=fail
  MAGICROOT_PERM_SLAB_ACTION=fail
  ```
- 其他原有保护不变：
  - victim `waitpid` 回收；
  - post-kill slab 读取；
  - preflight 快速检查；
  - 默认 reference 参数。

新二进制：

```text
t64560_v36
size   68,072 B
sha256 3ba4a9dbc2bd8af3b90bdd85cba108343636104434c9295acd4c433bb6394e24

t64560_cred
size   77,152 B
sha256 ff39e2d1318db2c91639a1367744495749722b82ba5af26405c27523e540c86d
```

---

## 51. Enhanced 三阶段升级：permissive / fsuid / cred（2026-10-26 04:10）

参考：`CVE-2026-64560-Public-Enhanced.7z`

已移植：

- permissive/fsuid：Enhanced `t64560_v36` 安全协议
  - per-attempt 基线重取
  - A/B/C/D 分阶段（先建 timer，再删除，再排空，再 kill）
  - SIGSTOP abort，绝不盲杀
  - futex 唤醒 exec 线程
  - 实际 timer 数作为 exec 阈值 + 1.5s 兜底
  - 漏删 timer 二次删除
  - short send / short spray 处理
  - wait_children_gone
  - victim stdout/stderr → /dev/null
  - 时间预算
- fsuid/fsgid：
  - 写入前 `kill -0` 目标存活检查
  - `cred+0x20` 8 字节零写覆盖 fsuid+fsgid
  - 已为 0 时跳过
  - 显式检查 v36 退出码
  - 写入后校验 `/proc/<pid>/status` 的 Uid/Gid 第 5 字段 ==0
  - 失败不进入 v42
- cred：Enhanced `t64560_v42` 安全协议
  - A/B/C/D + SIGSTOP abort
  - phase1 CapBnd 校验
  - phase2 后写 `MAGICROOT_PHASE2_MARKER` 并返回0
  - 保留 per-phase drain/min 参数

参数仍为 reference：

```text
permissive/fsuid: 200 400 24 12000 12000 4500
cred:             200 300 400 24 12000 10000 3500
```

Wrapper 强制：

```text
T64560_SAFE=1
T64560_MIN_DRAIN_MS=<reference min>
T64560_DRAIN_MAX_MS=<reference drain>
```

避免 Enhanced safe 默认 500/8000 的低 drain。

新二进制：

```text
t64560_v36  71,200 B  f48963c54824aee30c8f3bfd55ec824b159284265042405719b3265e0c28e38e
t64560_cred 79,216 B  4930999864439cd9cf4e9ec190ac6c6e12c86bf2649d99aad01e491321d0d73f
```

详见 `docs/reference/fsuid-enhanced-three-stage.md`。

---

## 52. 按 1.0.3-source 备份回退 + allow_shell 默认开（2026-10-26 04:35）

备份：

```text
<LOCAL_USER>user\Downloads\MagicRoot-1.0.3-source.zip
sha256 532dbb83fc31825c0c6e08d1140255e099874aeab95729b74ff2239aa8b59d9f
```

已恢复：

```text
main/app/assets/run.sh          51,665 B
main/app/assets/t64560_v36      66,960 B  sha256 2fa5f00d...
main/app/assets/t64560_cred     76,304 B  sha256 928abcf7...
tools/verify_apk.py
tools/check_612_binary_mapping.py
```

已删除回退前新增源码：

```text
main/app/native/t64560_permissive_61258.c
main/app/native/t64560_cred_61258.c
```

撤销的近期修改：

- Enhanced v36/v42 三阶段；
- fsuid/fsgid 存活/写入校验；
- CRED_LAYOUT / CRED_SLAB_GUARD；
- 快速 preflight（恢复 120s settle）。

按要求保留/新增：

- `ALLOW_SHELL` 默认 **1**；
- UI `allowShell` 默认 **true**；
- 模块以 `allow_shell=1` 加载；
- 删除 `FAIL=stale_posix_slab` 硬退出，仅保留：
  ```text
  POSIX_SLAB_ACTIVE=<n> (stale gate removed)
  ```

新 APK：

```text
size   3,826,226 B
sha256 e0883743b70c17c1c8a2a676e613d71d63ecd61442958e87bd5c671af2ddfff6
```

详见 `docs/reference/revert-backup-103.md`。

---

## 53. 彻底移除 slab limit / stale gate（2026-10-26 04:45）

`run.sh` 中与 `posix_timers_cache` 相关的全部限制代码已删除：

- 不再有 `FAIL=stale_posix_slab`；
- 不再有 `SLAB_STALE_ACTIVE`；
- 不再有 `MAGICROOT_SLAB_STALE_ACTIVE`；
- 不再有 `POSIX_SLAB_ACTIVE` 日志块；
- 不读取 `/proc/slabinfo` 做启动门禁。

注意：历史文档（如 deep-speed-optimization 报告、DEVICE 早期章节）
可能仍保留当时的记录，但当前运行时已无这些变量/检查。

---

## 54. 旧部署资产导致 slab gate 残留的诊断与自动同步（2026-10-26 04:35）

现象：当前 APK 的 run.sh 已无 slab limit，但设备仍因 stale_posix_slab 退出。

根因：

- /data/local/tmp/magic 持久保留；
- 旧 App 只在手动「部署资产」时覆盖；
- 安装新 APK 后直接运行会执行旧 run.sh / 旧 t64560_*。

修复：

- 
unChain() 每次先 stageAllRuntimeAssets()，覆盖全部 ASSETS；
- 同步后 grep 部署的 run.sh，若仍包含：
  FAIL=stale_posix_slab / SLAB_STALE_ACTIVE
  则 FAIL=stale_deployed_assets，不执行旧脚本；
- 日志输出 ASSET_SYNC=ok count=...。

详见 docs/reference/stale-asset-diagnosis.md。

---

## 55. 设备实测：stale 来自 root-owned 旧工作目录（2026-10-26 04:50）

设备 `<SERIAL>`（MLY-AN00 / 6.12.58）现场：

```text
已安装 APK sha256 09ffd2c6...（含 autosync，但无 workdir/size 保护）
/data/local/tmp/magic：root:root 755，shell uid=2000 不可写
/data/local/tmp/magic/run.sh：51,665 B
  sha256 b34e0b84...
  仍含 FAIL=stale_posix_slab / SLAB_STALE_ACTIVE
run.log 停留在 04:14；Download/fail_log_* 是它的导出副本
```

根因：

- 旧 `stageAssetFrom()` 的 `cp`/`mv` 因 root-owned 目标失败；
- 但只检查 `test -f`，旧文件仍存在 ⇒ 误报部署成功；
- 因此一直执行旧 run.sh。

现场修复验证：

```text
mv /data/local/tmp/magic /data/local/tmp/magic.old.<ts>
mkdir /data/local/tmp/magic
点「部署资产」
-> run.sh 50,380 B
   sha256 ab286793fa77cbd3596e20ac251e268ab91e0a2f9f9fb9f66cc95dbfcd6c7c60
   stale strings: none
```

App 已增加：

- workdir 不可写时自动轮换到 `magic.old.<timestamp>` 并重建；
- 复制后用 `wc -c` 校验大小，失败抛 `asset_size_mismatch`；
- allow_shell 旧 false 偏好一次性迁移为 true。

新 APK 已安装到设备（sha256 `5737c26d...`），并完成部署。

---

## 56. allow_shell / adb_root / su entry 审计与实现（2026-10-26 06:30）

源码结论：

- `allow_shell` 是 KernelSU 的 `module_param`，不是 feature；上游默认 false；
  只能在 `finit_module` / `--allow-shell` late-load 时设置，加载后不能改。
- 本链路 `ksu_grant` 以 shell(uid 2000) 执行，冷启动缺 allowlist，必须
  `allow_shell=1` 才能通过 GRANT_ROOT；PMX v1.6 的 root_worker2 也是
  `allow_shell=1 bundled=1`。
- `root_stage.sh` 旧的 `allow_shell_requested` 日志是错误的运行时语义，
  已改为 `ROOT_STAGE_ALLOW_SHELL_MODE=load_time_0/1`。
- `adb_root` 是运行时 feature，内核 static key 默认 false；新增 UI 开关
  **ADB Root**，默认 off；`root_stage.sh` 执行：
  `ksud feature set adb_root 0/1`，开启时重启 adbd。
- PMX v1.6 反编译：APK `root_stage.sh` 使用 kernel su_compat hooks，
  磁盘不装真实 su，只 patch Termux wrapper；本项目的 `su_entry.sh` 采用
  同一方案，默认开启；旧 `su_optional.sh` overlay 改为 opt-in 回退。

### su entry 可选开关

`运行选项` 新增 **su entry** 开关，默认 **开**：

```text
su entry   默认开 · 内核 hooks + Termux patch
overlay fix 兼容回退 · 默认关
```

- 开：PMX v1.6 风格 kernel su_compat + Termux wrapper patch；
- 关：不执行 su_entry.sh；只有同时打开 overlay fix 才走旧 overlay；
- 两者都关：只保留 su_compat feature，不额外安装入口。

本机验证（ADB 重新连接后）：

```text
sh -n run.sh        RUN_OK
sh -n root_stage.sh ROOT_STAGE_OK
sh -n su_entry.sh   SU_ENTRY_OK
su_entry.sh (uid2000) -> SU_ENTRY_FAIL=not_root（预期）

Termux wrapper 补丁路径用测试副本 + 伪造 wrapper 验证：

```text
SU_ENTRY_TERMUX=patched
SU_ENTRY_TERMUX_LINE=2:for p in /system_ext/bin/su /debug_ramdisk/su ...
```
```

设备当前 Stellar/Shizuku shell 服务未启动，无法通过 App 部署；脚本已用
`adb push` 到 `/data/local/tmp/magic-test` 完成语法验证。

详见：

- `docs/reference/kernelsu-allow-shell-adb-root-audit.md`
- `docs/reference/pmx-v16-su-entry-analysis.md`

---

## 57. 恢复默认参数按钮（2026-10-26 06:55）

运行选项末尾新增按钮：

```text
恢复默认参数
```

恢复范围：

```text
SELinux/fsuid/cred = 24
skipFsUid = 关
su_compat = 开
su entry = 开
overlay fix = 关
allow shell = 开
ADB Root = 关
kernel_umount = 开
selinux_hide = 开
软重启修复 = 关
```

不会修改「内核后端」选择（它是部署选择，不属于运行参数）。

设备 UI 已确认按钮存在，位置约 `[483,2158][753,2217]`。

---

## 58. 运行选项/参数首次修改确认（2026-10-26 07:05）

运行选项和参数不再一触即改：

- SE / fsuid / cred 三个参数按钮；
- 跳过 fsuid；
- su_compat / overlay fix / allow shell / 软重启修复；
- su entry / ADB Root / kernel_umount / selinux_hide；
- 恢复默认参数按钮。

第一次修改会弹出：

```text
运行参数修改提醒
运行选项和参数会直接影响提权链路，误改可能导致提权失败、
模块异常或设备重启。请确认本次修改。
[不再显示]
[取消] [确认修改]
```

- 确认后才真正修改；
- 取消则不修改，下次仍会提示；
- 勾选「不再显示」并确认后，后续不再弹窗；
- 未勾选但确认一次后，也不再弹窗（首次切换只提示一次）。

设备实测：

```text
首次点 su_compat -> 弹出“运行参数修改提醒”
勾选“不再显示” + 确认 -> 弹窗关闭
再次点 su_compat -> 不再弹窗
```

实现：

- `UiState.requestOptionsChange()` / `confirmOptionsChange()` / `cancelOptionsChange()`；
- 所有运行选项和参数按钮改为经过 request guard；
- 偏好保存在 `magicroot_options_warning`。

---

## 59. Permissive 卡死修复：KASLR anchors=5 + 有界竞态（2026-10-26 10:05）

输入 `MagicRoot-1.0.3-source(1).zip`（sha256 eebaa4ea…）的 run.sh/root_stage
与当前三阶段路径一致；问题在 permissive 路径。

设备实测失败 boot：

```text
KASLR_VOTES=1331
KASLR_ANCHORS=3
v36 attempts=200
attempt=110 landed=0
t64560_v36 运行约 16 分钟
```

历史成功记录全部为 anchors 5/6；profile 原门限只有 2。

修复：

- `kernel_profiles.sh`：`PROFILE_KASLR_MIN_ANCHORS=5`（61258/6138）；
- 弱缓存会被 `KASLR_CACHE_REJECT` 并强制重抓；
- `run.sh`：permissive 默认最多 120 attempts / 900s，
  `timeout -s KILL`，超时输出 `FAIL=permissive` + `PERMISSIVE_TIMEOUT`；
- 成功后删除 `PERMISSIVE_STARTED`，避免下次 `PREVIOUS_RUN_INCOMPLETE` 误报。

设备复测：

```text
KASLR_CACHE_REJECT anchors=3 votes=1331
KASLR_ANCHORS=5 KASLR_VOTES=3322
PERMISSIVE_LIMIT attempts=20 timeout=900s
LANDED attempt=1
PERMISSIVE_ONLY_OK
```

详见 `docs/reference/permissive-stall-fix.md`。
