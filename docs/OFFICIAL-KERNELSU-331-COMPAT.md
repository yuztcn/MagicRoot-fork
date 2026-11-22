# 正式版 KernelSU v3.3.1 与 6.12.58 g142 加载链兼容性

审计对象：

```text
KernelSU_v3.3.1.apk
SHA-256 b4a059ace71de2fa65cc7f12b1c58d55fc23ab25e057ee4230ce779742abe450
package me.weishu.kernelsu / versionCode 32680 / versionName v3.3.1
```

目标内核（BRT-AN00 与 MLY-AN00 同构建）：

```text
6.12.58-android16-6-g142ddad31e60-abogki576095858-4k
```

## 管理器自带什么

APK 不包含 `.ko` zip 条目；LKM 以 raw-deflate 流嵌在
`lib/arm64-v8a/libksud.so` 中（0xED 起始，解压后为 ELF）。离线 carve 出 10 个
对象，其中与本机相关的两个：

| KMI | vermagic | 大小 | 模块版本 |
|---|---|---|---|
| android16-6.12 | `6.12.76-4k SMP preempt mod_unload modversions aarch64` | 404,928 | `KernelSU version 32680, package name me.weishu.kernelsu` |
| android17-6.18 | `6.18.32-4k-g47cc22554442-dirty ...` | 375,328 | 同上 |

`.modinfo` 声明 `parmtype=allow_shell:bool`、`parmtype=norc:bool`、
`parmtype=bundled:bool`。因此 `allow_shell=1` / `norc=1` 是合法模块参数。

## 离线 ko_patch 验证（6.12.76 → 6.12.58 g142）

```text
ko_patch ko-5.ko patched.ko syms_g142_kernelsu.txt 0 \
  6.12.58-android16-6-g142ddad31e60-abogki576095858-4k

TRACK_THRONE=patched track=0x6018 adrp=0x6058 ldr=0x605c rd=x0
PATCHED=226 MISSING=0 REPAIRED=0
VERMAGIC=6.12.58-android16-6-g142ddad31e60-abogki576095858-4k SMP preempt mod_unload modversions aarch64
```

反汇编确认 throne 补丁只做预期的等价改写：

```text
原始: 6058 adrp x8, <ksu_cred>; 605c ldr x0, [x8]
补丁: 6058 adrp x8, <init_cred>; 605c add x0, x8, #0
```

符号表覆盖了模块全部未定义符号（MISSING=0），vermagic 重写正确。
**ko_patch 本身没有结构性不兼容。**

## 官方 ksud 的 CLI 契约

```text
late-load: --kmi / --package-name / --allow-shell / --magica / --post-magica
insmod:    ksud insmod <MODULE> [PARAMS]...
```

与 run98260.sh 的调用一致：先 `ksud insmod <patched.ko> allow_shell=1`，再
`ksud late-load --kmi android16-6.12 --package-name me.weishu.kernelsu --allow-shell`。
ksud 自带 “KernelSU already loaded, skip loading ko”，所以先 insmod 再 late-load
是受支持的顺序。

## 真正的风险：模块 live ≠ 用户态已注册

`98260_KSU=loaded` 只证明 LKM 驻留。`/data/adb/ksu/bin/`、su 入口与管理器注册
由 `ksud install` / late-load 用户态阶段完成。审计发现两个会让“模块 live 但
管理器不可用、su 不存在”的路径：

1. **post-load `ksud install` 被 `.ksu_loaded` 跳过**。原条件是
   `KSU_SU_READY != 1 && ! -f .ksu_loaded`。自从“模块 live 即成功”的判据落地后，
   `finish_ksu_loaded` 会写 `.ksu_loaded`，late-load 用户态失败时 install
   永远不会执行 → 没有 `/data/adb/ksu/bin/`、没有 su、管理器未注册。
2. **应用在 su 未就绪时仍自动清理工作目录**，删掉 rootd 客户端
   （`pc98260-su`），于是 Tools > “su entry” 修复的四个候选全部不存在；
   日志表现为 `/system/bin/su: inaccessible or not found`。

修复：

- run98260.sh：install 不再看 `.ksu_loaded`，只要 `KSU_SU_READY != 1` 就执行；
  依次探测 `$SU`、`/system/bin/su`、`su`、`/data/adb/ksu/bin/su` 取第一个
  uid=0 的提供者；install 成功后补跑一次 late-load（注册管理器包名），并
  重新探测 su 写 `98260_SU_PROVIDER_POST`。
- MainActivity：模块 loaded 但 `98260_KSU_SU_WAIT=1` /
  `98260_SU_PROVIDER_EARLY=` / `98260_SU_PROVIDER_POST=` 都不存在时，
  跳过自动清理并保留 rootd，提示可在本 boot 内重试 su entry。

## 工作版证据与 throne 开关

用户确认正常的构建是 `MagicRoot.apk` SHA-256
`8384115b388de860510dd89c3e0f00b2889a68664511f4ca2107a6f359befd46`
（63,303,248 B）。该 APK 内的 `assets/ko_patch` 为
`fe3f9832…6dc10c`，对官方 3.3.1 的 6.12.76 模块实测输出
`TRACK_THRONE=patched`、`PATCHED=226`、`MISSING=0`，即在启用 init_cred
改写的情况下管理器注册和 su 均正常。因此 **throne 补丁不是这次不兼容的原因**。

为便于对比排查，ko_patch 增加显式开关（默认保持工作版行为）：

```text
MAGICROOT_THRONE_PATCH=0|off|false|no   关闭 init_cred 改写
其他/未设置                              保持 patched（工作版行为）
```

关闭时输出 `TRACK_THRONE=disabled`，runner 把它当作合法结果并记录
`98260_THRONE_PATCH=disabled reason=compat_default`，继续用同一 KO
（只做符号/vermagic 改写）。

工作版的完整源码、APK 内全部资产与逐字节复现配方保存在
`/data/user/0/cc.codroid/files/home/workspace/magicroot-backup-8384115b`
（`BACKUP-README.md`、`build-repro.sh`、`SOURCE-SNAPSHOT.sha256`）。

## 仍需真机确认的边界

- 6.12.76 模块在 6.12.58 内核上是否被接受（modversions CRC、结构差异）。
  判据：`98260_INIT_CRED_INSMOD_RC=0`、`98260_INIT_CRED_MODULE_LIVE=1`；
  失败时看 `98260_INIT_CRED_INSMOD_RC` 与 `98260-ksu.log` 的
  `load module failed` / dmesg。
- `98260_KSUD_INSTALL_RC=0` 且 `98260_SU_PROVIDER_POST=` 出现，才算管理器用户态
  与 su 可用。
- init_cred throne 补丁只影响 root 授予时的 cred 选择；离线改写等价，未在本
  内核上做真机功能验证。

## BRT-AN00 与 soft-reboot 策略（2026-11-13）

- BRT-AN00 与 MLY-AN00 共用
  `6.12.58-android16-6-g142ddad31e60-abogki576095858-4k`。g142 的 profile
  选择只看 `uname -r` 精确串：
  `KernelLogHelper.shouldStage98260Asset` 用 release 前缀，
  `kernel_profiles.sh` 的 `select_kernel_profile` /
  `select_chain_98260_profile` 用完整的 `$-release` case；`CHAIN_98260_MODELS`
  只是元数据，当前没有被任何脚本读取，g142 的 `target.sh` 也是空列表。
  因此 BRT-AN00 不会因为型号字符串（含尾随空格/后缀差异）被门控，拿到的是同一套
  `98260-g142` payload、符号表、KASLR helper 和 KO 模板。
- 唯一与型号相关的既有逻辑是 APH-AN00 的 61258b→aph112 分流和 Honor 平行空间
  uid 探测；两者都不命中 g142，BRT-AN00 不需要额外分支。
- soft-reboot 策略已对齐：`/data/adb/ksu/soft_reboot.lock` 现在是**显式 opt-in**
  （`MAGICROOT_SOFT_REBOOT_GUARD=1`），默认不布防。原因是 FinaSU 等 Flavor 必须
  用 `ksud soft-reboot` 跑模块 `post-fs-data` / `services`。风险不变：late-load
  KSU 的 stop/start 可能被 Honor watchdog 转成硬重启，未证明的 timer-UAF victim
  也可能触发 `page_request` panic；完整重启仍是更安全的恢复方式。
