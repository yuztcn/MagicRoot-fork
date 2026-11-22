# CLAUDE.md — MagicRoot 98260 项目工作指令

本文件面向 Claude Code / 其他编码代理。开始修改前先读本文件，并优先遵守用户最新明确指令。

## 1. 项目定位

MagicRoot 是一个 Android 一次性临时 root 工具，包名 `com.aoki.magicroot`。

当前发布线：

```text
versionCode 13
versionName 1.0.6
targetSdk 37 / minSdk 34 / arm64-v8a
```

活跃工程目录：

```text
main/compose-app/          当前实际编译的 Compose/Miuix 应用
main/app/assets/           当前实际打包的设备端脚本和二进制资产
main/app/                  build.ps1、旧版资源和 libs
```

旧版 `main/app/src/` 与 legacy 构建目录已移除（见 §10）。实际控制器是：

```text
main/compose-app/app/src/main/java/com/aoki/magicroot/MainActivity.java
```

主要能力：

- 临时 root：64560（历史链路）和 98260（Honor 适配链路）
- 98260 支持 6.12 / 6.6 / 6.18；6.18.21 强制 H1C 引擎
- 6.1.x：6.1.157 / 6.1.99 / 6.1.128 的受支持构建统一走
  `run6157_full.sh`；g7d 用 M6 交接，g264 用 g264 CGA/su，
  其余构建用按内核重映射的 CGA 模块；g19a 走旧 61157
- 多管理器 Flavor：`kernelsu`、`resukisu`、`fina`、`sukisu`、`next`、`nova`
  （SukiSU Nova，`com.sukisu.nova`；LKM 从管理器 APK 提取，无内置模板）
- 6.18.x 支持导入 boot.img 本地生成自适应 profile
- UI 是单页 + 首页/工具/关于三个底部页签，使用 Compose + Miuix

## 2. 安全边界（必须遵守）

- 仅用于本人设备或明确授权设备；一次性临时 root，重启失效。
- 不修改分区、不做持久化、不制作永久 root。
- 不要 kill rootd/exploit 的 PPID=1 父进程：它是 UAF 页面持有者，必须保留到重启。
- 不要由自动化脚本/代理执行 `ksud soft-reboot`；该操作会拆除 UAF/rootd，已实测触发 `page_request` 内核 panic。
  管理器自己的 soft-reboot 自 2026-11-13 起默认放行（guard 改为 opt-in：
  `MAGICROOT_SOFT_REBOOT_GUARD=1` 才布防），以便 FinaSU 等 Flavor 跑模块
  post-fs-data/services；风险由用户承担，脚本仍不得自行调用。
- 不安装 LSPosed 管理器 APK；LSPosed 修复只做设备端热修复。
- 不做小米/其他未授权机型适配。
- 不添加新的设备型号、BTF 哈希、ROM 构建哈希等硬性限制项。用户明确要求不要新增限制项。
- 43499/Pad3 路线只保持“不引入”，不要临时补入。
- 不把 APK、签名密钥、设备日志、用户数据提交到源码历史。
- 真机测试会临时切换 SELinux permissive、加载未签名 LKM，存在 panic/重启风险；执行前确认用户意图。

## 3. 构建

构建脚本：

```text
main/app/build.ps1
```

它调用 `main/compose-app/gradlew.bat assembleRelease`，然后：

1. 用 `tools/strip_baseline.py` 删除 baseline profile assets
2. `zipalign`
3. 用发布 keystore 重新 `apksigner`
4. 输出 `main/app/MagicRoot.apk`

需要：

- JDK 25
- Android SDK Platform 37、Build-Tools 37.0.0
- 发布 keystore（由用户本地提供，不随仓库分发）

从仓库根目录执行：

```powershell
$env:ANDROID_HOME = 'C:\path\to\sdk'
$env:JAVA_HOME    = 'C:\path\to\jdk25'
$env:GRADLE_USER_HOME = "$PWD\main\.gradle-home"

powershell -NoProfile -ExecutionPolicy Bypass -File .\main\app\build.ps1 `
  -Sdk $env:ANDROID_HOME `
  -Jdk $env:JAVA_HOME `
  -Keystore 'C:\path\to\release.keystore' `
  -StorePass 'MagicRoot' `
  -KeyAlias 'magicroot' `
  -KeyPass 'MagicRoot'
```

本机当前常用路径：

```text
SDK:      C:\Users\HourG\Downloads\mly-fw\sdk
JDK:      C:\Users\HourG\Downloads\mly-fw\jdk25\jdk-25.0.4.1+1
Keystore: C:\Users\HourG\Documents\deepseek-harness\MagicRoot98260\work\release-keys\magicroot-release.keystore
输出:     C:\...\MagicRoot-Enhanced-1.0.4-98260\main\app\MagicRoot.apk
```

构建完成后至少确认：

```powershell
Get-Item .\main\app\MagicRoot.apk
Get-FileHash .\main\app\MagicRoot.apk -Algorithm SHA256
```

源码包：

```powershell
.\tools\package-source.ps1 `
  -Project . `
  -Output 'C:\Users\HourG\Downloads\MagicRoot\MagicRoot-1.0.6-source.zip'
```

新增资产后如果源码包脚本的 `$required` 路径失效，要同步更新 `tools/package-source.ps1`。

## 4. 代码结构

### 4.1 UI 与控制器

```text
main/compose-app/app/src/main/kotlin/com/aoki/magicroot/
  MiuixHost.kt        Compose/Miuix 全部页面、对话框、单页步骤条
  UiState.kt          持久化 UI 状态、反馈、日志
  CombinedBackdrop.kt / LiquidLens.kt   背景效果

main/compose-app/app/src/main/java/com/aoki/magicroot/
  MainActivity.java               控制器：Shizuku、授权、部署、运行、清理、修复
  KernelLogHelper.java            纯 Java 内核版本/vermagic 解析、路由表、APK 资产去重映射、日志切片
  RunProgress.java                运行进度状态分类器
  KernelProfileGenerator.java     6.18 boot.img 自适应 profile 生成器
  AdaptiveManager.java            自适应 manager 辅助
```

规则：

- 所有布局都在 Compose；不要在 Java 控制器里新建 View/Activity。
- 保持单页主流程，不要拆成多 Activity。
- Miuix 组件优先；项目固定 Compose 1.12.2 / Miuix 0.9.4 / AGP 9.1.0 / Gradle 9.3.1。
- 不随意升级 UI 栈版本。
- 保持首页 5 步主流程、工具页、关于页的现有结构。

### 4.2 设备端脚本

```text
main/app/assets/run.sh                  顶层分派：64560 / 98260 / 6.1 / 预检
main/app/assets/kernel_profiles.sh      profile、KO、syms、Flavor 选择
main/app/assets/98260/run98260.sh       98260 共享链路
main/app/assets/98260/run6157_full.sh   6.1.x 98260（g7d M6 / g264 CGA / 其余按构建 CGA）
main/app/assets/98260-h1c/run_h1c.sh    6.18 H1C 引擎
main/app/assets/61157/run61157.sh       6.1 g19a 旧路线
main/app/assets/root_stage.sh           KSU 加载后管理闭环
main/app/assets/clean.sh                临时文件清理
main/app/assets/lsposed-hotfix.sh       Zygisk/LSPosed 热修复
```

设备工作目录：

```text
/data/local/tmp/magic
```

部署完成后 App 会自动清理工作目录（默认成功自动清理）。清理会重置
`assetsDeployed=false`，用户下次必须重新部署。任何在工作目录写日志/标记的修复脚本，
必须先 `mkdir -p /data/local/tmp/magic`，否则会出现“脚本从未执行但 App 显示成功”。

### 4.3 资产与 profile

资产目录就是 APK 的 assets 源：

```text
main/app/assets/
```

`main/compose-app/app/build.gradle.kts` 通过：

```kotlin
sourceSets.main {
    assets.directories.add("../../app/assets")
    res.directories.add("../../app/res")
}
```

将 `main/app/assets` 打包。

活跃资产注册点在 compose `MainActivity.java`：

- `ASSETS`：所有基础资产
- `ASSETS_98260`：各 98260 profile 目录
- `shouldStageLegacyAsset(...)`：按内核/Flavor/链路筛选
- `shouldStage98260Asset(...)`：按精确 profile 目录筛选
- `stageAllRuntimeAssets(...)`：生成部署计划
- `stagePlanBatch(...)`：ZIP 批量部署
- `normalizeBatchPermissions()`：尾部统一 chmod

**新增资产时必须同步修改这些位置，而不是只把文件丢进 assets。** 漏注册会导致：
构建成功、文件在 APK 里，但设备端从未部署。

## 5. 资产修改工作流

新增/替换设备端资产时按顺序做：

1. 文件放到 `main/app/assets/<相对路径>`。
2. 在 compose `MainActivity.java` 的 `ASSETS` 或 `ASSETS_98260` 增加路径。
3. 在 `shouldStageLegacyAsset` / `shouldStage98260Asset` 增加正确的
   kernel/profile/Flavor/chain 条件。
4. 若是新目录，检查 `stageAllRuntimeAssets` 的 profile 循环是否需要纳入。
6. 若是 6.1.x run6157 的运行资产，同步执行
   `python3 -I tools/gen_6157_integrity.py` 更新部署后完整性清单。
7. 若是源码包必需资产，更新 `tools/package-source.ps1` 的 `$required`。
8. 在 `BINARY-SOURCES.md` 记录来源、版本、SHA-256、许可证。
9. Shell 脚本用 LF；执行 `bash -n`。
10. 构建并检查部署日志：

```text
ASSET_PLAN count=...
ASSET_BATCH=ok entries=...
ASSET_SYNC=ok ... mode=batch
```

### 资产规则

- 不要修改已发布二进制的字节，除非用户明确要求替换；替换必须更新来源和 hash。
- `.sh` 必须 LF；`.ko`/二进制不要被 Git 行尾转换。
- `main/app/assets/**/syms*.txt` 和 `ksu-syms.txt` 在 `.gitattributes` 中是
  `-text`，不要改成普通文本处理。
- 不要重新引入内置 `ksud_*` 回退；当前策略是从已安装管理器提取 `ksud`。
- 不要为了体积随意删除 6.1 / 6.18 适配目录；它们对应不同内核。
- 部署必须按内核精确筛选，不能重新变成全量部署。
- 内置二进制来源不完整时，在 `BINARY-SOURCES.md` 标明 provenance-locked，
  不要伪装成可复现构建。

## 6. 内核/链路规则

### 6.18.21

- 强制 H1C：即使 UI/旧状态保存了 BRM，6.18.21 也必须落到 H1C。
- H1C 使用 `98260-h1c/` 资产，预检 load 上限为 60。
- 自适应：只接受 `6.18.*` 的 boot.img；生成器只解析本地镜像，不联网。
- 生成符号表必须是本项目 `name 0xADDR` 格式，不是 HOneClick 的
  `ADDR type name`。
- 生成 profile 只对完全相同的 `uname -r` 生效。
- 不要给 6.18 添加固定 build hash 门禁。
- H1C 的 LKM/ksud 优先从当前管理器提取；g928 使用管理器 LKM + Flavor
  符号表，g186 + kernelsu 保留上游 115 官方模块。
- `ko_patch` 必须保留 `SHN_XINDEX (0xffff)` -> `.modinfo` 修复；115 模板
  有 14 个此类符号。

### 6.1.x

- `98260/run6157_full.sh` 覆盖：
  - 6.1.157：g7d3922fade43、g2646292297b1、gaaa383620ebf、g3306a328b7be、g84ffa64b710b、g77f76e323a02、g8d63307071ad
  - 6.1.99：gce84935796c9、g5859fbdbad8c、g54d40b4fb287、ge9da27488f45
  - 6.1.128：g40b1fd119d9b、g8a4968670f1c、g2e1f0741dafb
- g19a495a97bff：`61157/run61157.sh`
- 每颗内核使用自己的 payload 目录；g7d 默认走已恢复的
  `ksu6157-m6/` M6 交接，其余构建使用自己的 `g264/ksm-<build>-base.ko`。
- 只有 g264 可进入 `ksu6157-g264` 的 `ksu_prepare`/`ksu-loader`
  绝对符号路线；其他 6.1 构建缺失自己的 CGA base 时必须失败，不能借用
  g264 符号或 6.12/6.6 模板。
- 上游 1.0.36 成功 g264 静态载荷为
  `cc0b9693dcdba564585c39dfe3eb386860f1cede4251d0d7aca63d1e51762843`；
  其他构建由 `binary-sources/61157-g264/rebase_success_payload.py`
  确定性派生，不要退回无 `blind_reclaim_stream` 的 34 KiB 重编译版。
- 6.1.x 的 ksud 优先从当前选中管理器提取，内置 `ksu6157-g264/ksud` 只是回退。
- 6.1.x 运行档位固定为 attempts=6 / churn_per_cpu=32 / wait_cap=8；
  App 只对精确 6.1 profile 覆盖，不沿用 98260 的 12/256/25 档位。
- 6.1.157 g08de1e2b38ba 只有 98937 KASLR 常量，没有 payload/CGA，
  未进入 `run6157_full.sh` 分派，不要当作可 root 的适配。
- 不要给 6.1.x 添加型号、BTF hash、config hash 门禁。
- 43499 不引入。
- `ksu6157/ksu-syms.txt` 必须 LF。
- 只有 g264 完成真机 root/KSU 闭环；其余 6.1.x 为静态适配，不能声称已端到端验证。

### 6.12 / 6.6

- 不要整体替换 `run98260.sh` 为上游版本；本仓库包含 H1C、BRM、
  61258b/c、aph112、6658 等上游没有的内容。
- 采用“外科手术式”合入，不要覆盖整个文件。
- profile 精确匹配 `uname -r`。
- `6.12.38 g4b3671e1f5b7`（profile `g4b36`）是新的 6.12.38 构建：
  `pc98260_target_g4b36.h` + 独立 payload + `syms_g4b36*`，路由只在
  精确 release 生效，见 `docs/6.12.38-G4B36-ADAPT.md
docs/6.12.81-G52D15-ADAPT.md`。该 build 仅有
  静态适配，尚无真机验证。
- `6.12.81 g52d15df5db87`（profile `g52d15`）是 6.12.81 构建：该内核
  不再内联 `alloc_posix_timer`，`LINK_ALLOC_TIMER=alloc_posix_timer+0x28`；
  98260 修复未合入（漏洞可达），64560 修复已回迁（仅 98260 适用）。
  见 `docs/6.12.81-G52D15-ADAPT.md`。该 build 仅有静态适配，尚无真机验证。
- 6.12 当前的 98260 链路已验证；6.6 仅有资产和静态验证。管理器 LKM
  提取在 raw-deflate/plain `.ko` 之后、内置模板之前，还会调用管理器
  自己的 `ksud debug extract-binary android<kmi>_kernelsu.ko`（FinaSU
  1.6.3）并校验 ELF/vermagic/大小。

### Flavor

六种 Flavor 必须保持可切换：

```text
kernelsu / resukisu / fina / sukisu / next / nova
```

- `nova` = SukiSU Nova（`com.sukisu.nova`）。它没有内置 LKM 模板，运行时
  始终从已安装管理器 APK 提取；只随包提供 `syms_<profile>_nova.txt`。
- 6.12/6.6 中已有精确内核镜像的 profile 已补齐 nova 表；没有精确镜像的
  6.12 构建（61258b/aph112、6138y、6123）与 61821brm 仍缺表，
  选择 nova 会在 `ko_patch` 阶段 fail-closed。
- 6.1.x 走运行时 kallsyms，本轮没有为 nova 静态补 6.1 表。
- 不要因为管理器显示的包名未知就沿用上一个 flavor；Nova 必须走 `nova`。
  详见 `docs/SUKISU-NOVA-SUPPORT.md`。

某个内核只有单一后端能力时，应在文档中说明，不要把其他后端模板硬套。

## 7. 部署、清理与软重启修复

### 部署

- 当前部署为 ZIP 批量模式：App 本地生成 ZIP → 一次复制 → 一次 unzip → 一次 chmod。
- 不要退回逐文件 `cp/chmod/wc/test` 的旧路径（每文件 5–7 次 Shizuku 往返）。
- 部署结束统一 `chmod -R 777 /data/local/tmp/magic`，因为部署 shell 可能是 root，
  而 `run.sh` 以 uid=2000 运行。
- 部署必须按 `uname -r`、profile、chain、Flavor 精确筛选。

### 清理

- 成功自动清理后必须 `ui.markAssetsDeployed(false)`，否则用户无法重新部署。
- `doClean()` 和自动清理分支都要 reset 部署状态。
- 清理只删除 `/data/local/tmp/magic` 和 App 外部 stage 缓存，不碰 `/data/adb` 管理器数据。

### LSPosed/zygote 修复

- 修复走 `lsposed-hotfix.sh`，只重启 zygote/lspd，不调用 `ksud soft-reboot`。
- Root 启动命令前必须 `mkdir -p /data/local/tmp/magic`，否则日志重定向失败，
  脚本根本不会执行。
- 修复启动后应等待日志出现 `=== BEGIN` 再向用户报告成功。
- 修复成功判据：

```text
LSPD_STARTED=...
NEW_SYSTEM_SERVER=...
BRIDGE_OK=... binder received
System server: connected
Modules: ... installed, ... enabled user states
SOFT_REBOOT_REPAIR=ok
```

### rootd

- 只清理 rootd listener 子进程；PPID=1 的 exploit 父进程必须保留到重启。
- rootd listener 需要 root helper 扫描 `/proc/<pid>/fd`；uid=2000 shell 可能没有权限。
- socket 已 unlink 时，通过 PPID=1 的 exploit 父进程定位 listener 子进程，不要 kill 父进程。
- 不要自动重试失败的 98260 运行；plant/socket 状态会保持 parked 到重启。

## 8. 常用验证

### 脚本语法

```bash
bash -n main/app/assets/run.sh
bash -n main/app/assets/98260/run98260.sh
bash -n main/app/assets/98260/run6157_full.sh
bash -n main/app/assets/98260-h1c/run_h1c.sh
bash -n main/app/assets/61157/run61157.sh
bash -n main/app/assets/lsposed-hotfix.sh
```

### 静态校验

优先使用仓库一键门禁（聚合语法、LF、资产双向对账、profile 路由表、去重映射、Java 单测与链路审计）：

```bash
bash tools/check.sh
```

也可以单独运行各检查工具：

```bash
python tools/verify_apk.py
python tools/verify_98260_assets.py
bash tools/audit_kernel_flavors.sh
python tools/audit_6157_chain.py
python tools/test_61128_adaptation.py all
python tools/test_98260_finalize.py
python tools/test_h1c_flow.py
python tools/test_termux_su_entry.py
```

注意：

- `verify_apk.py` 里有历史本地工具链路径和部分固定 hash，视为辅助检查，
  不要盲信其硬编码值。
- `verify_98260_dual.py` 依赖工作区外的 `port/` 参考目录，缺失时不要把它当 CI 门禁。
- 静态校验通过不等于真机链路通过。

### 真机

```powershell
adb devices
adb install -r .\main\app\MagicRoot.apk
adb shell am start -n com.aoki.magicroot/.MainActivity
```

典型检查：

```text
root:              su -c id -> uid=0(root)
KSU:               grep kernelsu /proc/modules
LSPosed:           lspctl status -> System server: connected
部署:              ASSET_BATCH=ok / ASSET_SYNC=ok mode=batch
提权成功:          DONE
提权失败:          FAIL=...
```

不要在没有确认设备的情况下自动跑 root 链路；一次开机不建议连续多次触发 98260。

## 9. 版本与 Git

- 当前 `versionCode 13` / `versionName 1.0.6`；除非用户明确要求，不要升级版本。
- 主分支：`master`；历史特性分支：`feature/adaptive-manager-libexec`。
- 提交信息使用：

```text
feat: ...
fix: ...
perf: ...
docs: ...
chore: ...
```

- 不提交 APK、`.idsig`、keystore、`local.properties`、构建日志。
- `.gitattributes` 强制 `*.sh` LF、`*.ps1` CRLF、`*.java`/`*.kt` LF；
  符号表是 `-text`。不要用编辑器把脚本转成 CRLF。
- 大资产变更要和 `BINARY-SOURCES.md`、源码包 `$required` 一起提交。
- 文档变更同步更新 `docs/` 与工作区 `进度.md`（如果存在）。

## 10. 已知状态与坑

当前验证状态：

- 6.12.58 MLY-AN00：完整提权、KernelSU、LSPosed 修复已验证。
- 6.18.21：自适应生成器已用 g928 boot.img 验证；完整提权无对应设备。
- 6.1.x：g264 CGA/su 与 g7d M6 均有历史真机闭环，但当前重建 APK
  仍需复验；g3306/g84/g77f/gce849/g5859/g54d/g40b1/ge9da/g8a496/g2e1f
  均无对应真机，成功型静态载荷与 CGA 仍属静态适配。
- 批量部署实测约 2.4 秒。
- APK 已移除内置 `ksud_*` 回退，体积约 69 MB。
- `/data/adb/ksu/soft_reboot.lock` guard 现在是显式 opt-in
  （`MAGICROOT_SOFT_REBOOT_GUARD=1`），默认不布防，管理器 soft-reboot 可执行。
  布防时也只对遵守它的管理器有效；SukiSU 外部 CLI 仍可能绕过，App 无法拦截。
- 上次 21:00 异常重启为 faultdetect `page_request` PANIC，时间线无
  `SYSTEM_RESTART`，与 timer-UAF 收尸同类。
- 当前 rootd PPID=1 父进程保留时，不要 kill；重启自然清理。
- 旧版 `main/app/src/`、legacy 构建脚本与审计预编译件已移除；不要重新引入。
- `main/app/assets/98260-6157/run6157.sh` 已删除；6.1 使用
  `98260/run6157_full.sh`。
- 自适应生成的 `syms.txt` 必须转换为 `name 0xADDR`，否则 `ko_patch` 不能解析。
- 自动清理后，软重启修复脚本必须先建工作目录。
- 部署状态 reset 是重新部署的前提。

## 11. 完成定义

一次修改至少满足：

1. 说明改动范围和风险。
2. 不破坏现有版本号、包名、签名和单页 UI。
3. 新增/替换资产已注册进 `ASSETS`/`ASSETS_98260` 和部署筛选。
4. Shell 已 `bash -n`。
5. APK 构建成功并给出路径/hash。
6. 若涉及 device 行为，明确说明哪些在真机验证、哪些未验证。
7. 更新相关 docs / BINARY-SOURCES / 进度记录。
8. 不把未验证的 6.18/6.1 路径描述成“已完整验证”。

## 12. 关键参考文档

```text
README.md
README-98260.md
BINARY-SOURCES.md
docs/6.18.21-BOOT-PROFILES.md
docs/98260-H1C-ENGINE.md
docs/ADAPTIVE-61821-PROFILE.md
docs/6157-SUPPORT-AUDIT.md
docs/61128-OLD-KERNELS-ADAPT.md
docs/KERNEL-FLAVOR-AUDIT.md
docs/98260-REBOOT-PANIC-2026-11-02.md
docs/LSPOSED-7938-ANALYSIS.md
docs/DEVICE-VERIFY.md
进度.md（工作区根目录）
```

如文档和代码/资产不一致，先以当前构建脚本、`ASSETS` 注册和已验证真机日志为准，并在同一提交中修正文档。
