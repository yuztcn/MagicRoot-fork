# MagicRoot（手机端 APK）

> **旧版说明（1.0.3 时代，已过时）**：以下描述的是早期 BakaSU/双内核手工
> 打包流程。当前构建由 `build.ps1` → `main/compose-app` Gradle 驱动；
> 资产注册/链路分派以 `main/compose-app/.../MainActivity.java` 和
> `assets/kernel_profiles.sh` 为准。保留仅作历史参考，详见 `LEGACY.md`。

把 CVE-2026-64560 的分阶段链路打包成 Android APK：
手机上优先通过 **Stellar API** 以 shell/root 身份执行，Stellar 不可用时回退 **Shizuku**，不需要电脑参与提权流程。

> 双内核自动识别（主项目仅 6.12）：支持 `6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k` 与 `6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k`。`run.sh` 会按精确 `uname -r` 选择对应的 `kaslr_slide_*` 与 `syms_*`；其余内核直接 `FAIL=kernel_unsupported`。
>
> 另预留 5.15 / 6.1 / 6.18 的 LKM 模板和 profile。由于尚未提供对应内核的 KASLR 锚点与符号表，这些 profile 会以 `FAIL=profile_not_ready` 安全退出，不会误用 6.12 资产。

## 根后端：BakaSU（默认）/ 官方 KernelSU（回退）

从 1.0.3-bakasu 开始，内置两套完整的 KernelSU 系根后端，UI「BakaSU 内核」
开关切换（默认开 = BakaSU）：

```text
BakaSU (resukisu)
  ksu-template-bakasu.ko   BakaSU KMI android16-6.12 nightly 模板，运行时 ko_patch
  ksud_bakasu              BakaSU 4.2.0 ksud（35252 / uapi 6）
  BakaSU-manager.apk       com.resukisu.resukisu v4.2.0-rc3
  syms_61258_bakasu.txt    BakaSU 符号表（241 项，233/233 覆盖，MISSING=0）
  root_stage               debug set-manager（4.2.0 无 manager 子命令）→
                           pins 签名元组 887/d3469712… → /data/adb/ksu/.dynamic_manager

official KernelSU 3.3.1
  ksu-template.ko / ksud  官方 LKM 模板与 ksud（32680 / uapi 5）
  root_stage               debug set-manager（官方 ksud 无 manager 子命令）
```

切换后端后需要重新点「部署资产」。`kernel_profiles.sh` 负责选择模板/符号表，
`run.sh` 的 KO 缓存键包含 flavor 与模板路径，避免两种后端互相复用 patched ko。
BakaSU 的 LKM 是「符号模板」：加载前必须由 `ko_patch` 按当前 boot 的 KASLR
slide 重写符号与 vermagic；请勿直接 `insmod` 原始模板。

真机验证记录见仓库根目录 `docs/DEVICE-VERIFY.md`。

## su 说明

`su_compat` 默认启用，本提权链本身不依赖裸 `su`。

`kernel_umount` / `selinux_hide` 由 UI 开关控制，**本项目默认均开启**：

```text
kernel_umount  默认开
selinux_hide   默认开
```

`root_stage.sh` 通过：

```text
ksud feature set kernel_umount <0|1>
ksud feature set selinux_hide <0|1>
```

应用开关值；不支持的特性只记录 `unsupported_or_failed`，不阻断 root。
关闭开关后会显式下发 0，而不是依赖模块默认值。


### allow_shell 说明

`allow_shell` 是可选调试项，**默认关闭**：

```text
allow shell
```

对应 KernelSU 内核模块加载参数：

```text
allow_shell=1
```

开启后，KernelSU 会把 UID 2000（`shell`）无条件放行，`adb shell` 可直接调用 `su` 获得 root，不经过 Manager 的 allowlist 授权。

实现链路：

```text
UI allow shell
  -> MainActivity 传 MAGICROOT_ALLOW_SHELL=1
  -> run.sh ALLOW_SHELL=1
  -> cred_target 读取 MAGICROOT_ALLOW_SHELL
  -> finit_module(..., "allow_shell=1")
```

关闭时：

```text
finit_module(..., "")
```

即不传 `allow_shell`。

安全提示：

- 该选项会放宽所有 shell UID 进程的 root 权限；
- 不建议在生产设备长期开启；
- 仅在 adb 调试、首次 root 验证时临时使用；
- 模块已经加载时改 UI 不会改变当前模块参数，下次加载才生效。

### dev su 说明（已移除）

旧版的 `dev su` 开关已移除，`root_stage.sh` 不再创建 `/dev/su`。升级后
`root_stage.sh` 只清理旧版本 marker 标记的文件，并输出
`DEV_SU_LEGACY_CLEANED=/dev/su`；`clean.sh` 仍按 marker/内容匹配删除旧版本
残留，不会碰其他工具创建的文件。




## v42 预设（分析/A-B 用）

默认已切换为 `reference`（24/24/24，200+200 permissive，200+300 cred，
12000 nfrag，10000 cred drain，3500 cred min）。现行 UI 的 Victim 档位按钮
仍可让用户单独覆盖 16/24/32。

可在工作目录放置 marker 选择其他档位：

```text
$D/tuning-current
  16 perm victims / 160 permissive / 24 cred victims /
  260+320 cred attempts / 12000 nfrag / 10000 drain / 4500 min

$D/tuning-v42
  24 victim / 200+300 cred attempts / 12000 nfrag / 10000 drain / 3500 min

$D/tuning-honor-v42
  16 victim / 160 permissive / 260+320 cred / 6000 nfrag / 12000 drain / 4500 min
```

或使用环境变量：

```text
MAGICROOT_TUNING=reference|current|v42|legacy-v42|alt
```

当前默认 reference 与 Enhanced 真机通过参数一致；current 是快路径备选。
当前实现已经是 legacy v42 调参的 6.12 移植版，保留 0x78/0x100 偏移；
不要直接替换上游 0xe0/0x180 的源码/二进制。

## 已合并的夜间优化

- futex forker + 新版 grab.sh：40 轮约 4 秒，替代原来固定 8 秒抓取；
- KASLR 每次启动现抓，不做跨重启缓存；新 grab 失败时回退 `grab_legacy.sh`；
- KASLR 结果增加 `PREPARE/SELINUX_ARG` 地址预检，异常直接 FAIL，不进入 ko_patch；
- 模块已 Live 时直接复用：输出 `MODULE_ALREADY_LIVE`，走 `ksu_grant`，
  跳过 KASLR/permissive/cred/patch；失败则 `FAIL=reuse_root_stage`。

以下核心竞态参数保持验收版不变：
`t64560_v36 0 <target> 300 400 32 12000 12000 4500`、
fsuid 同参数、phase2 `16 6000`，未改成夜间实验版的 16/6000 permissive。

## 安装与使用

1. 安装 [MagicRoot.apk](MagicRoot.apk)（新签名，包名 `com.aoki.magicroot`）。
2. 确保 **Stellar 已安装并在运行**（推荐）：
   - 安装 `roro.stellar.manager`，启动 Stellar 服务（ADB 或 Root）；
   - 重启后 Stellar 服务会停止，需要重新启动；
   - 没有 Stellar 时回退 Shizuku：打开 Shizuku → 通过「无线调试」启动。
3. 打开 `MagicRoot`：
   - `1. 授权 Stellar / Shizuku`：优先请求 Stellar `stellar` 权限；Stellar 不可用时走 Shizuku；
   - `2. 部署资产`：把 `assets/` 里的二进制、脚本、`syms.txt`、`ksu-template.ko` 推到
     `/data/local/tmp/magic`；
   - `3. 开始提权`：执行 `run.sh`，日志实时显示在页面上；启动后四个按钮（授权 / 部署 / 开始 / 清理）全部置灰，直到日志出现 `DONE` 或 `FAIL=` 才恢复。
4. 成功判据：
   - `getenforce` = `Permissive`；
   - `/proc/modules` 出现 `kernelsu ... Live`；
   - `ksu_grant` 输出 `grant_root_rc=0` 与 `ROOT_STAGE_OK`；
   - `/data/local/tmp/magic/root_id` 含 `uid=0(root)` 和 `context=u:r:ksu:s0`。

> `root_stage.sh` 只安装 ksud、创建 `/data/adb/ksu/bin` 软链并刷新 mark；不启用 `su_compat`，也不修复终端默认 `su`。

## UI 与烧屏

- 按钮改为 2×2 网格，减少顶部占用，日志区更大；
- 深色背景、等宽日志字体，减少 OLED 静态高亮；
- 不再设置 `FLAG_KEEP_SCREEN_ON`，长时间执行允许系统自动熄屏；
- 执行期间仍持有 `PARTIAL_WAKE_LOCK`，熄屏不影响提权线程；
- 目标 SDK 提升到 37，使用 `WindowInsets` 处理 edge-to-edge 状态栏/导航栏。

## 工作目录与自动清理

- 工作目录：`/data/local/tmp/magic`；
- 提权成功（日志出现 `DONE`）后，APK 会自动执行清理：删除本项目工作目录，
  以及 App 外部 stage 缓存；
- 不卸载 `/data/adb` 下的 KernelSU 本体；
- `/sdcard/Download/MagicRoot` 的失败日志会保留，便于排查；
- 成功后如需再次运行，必须重新点「2. 部署资产」；
- `FAIL=` 时保留工作目录与日志用于排查；可点「4. 清理临时文件」立即清理本项目残留。

## 签名与包名

- 包名：`com.aoki.magicroot`
- 桌面名称：`MagicRoot`
- 版本：`1.0.2`（versionCode `6`）
- targetSdkVersion：`37`
- 签名材料和口令由发布者本地维护，不随项目分发。

## run.sh 做了什么

1. `grab.sh` 抓 `sched_blocked_reason` 的 raw trace；
2. `kaslr_slide` 用内置锚点（本机 vmlinux 的链接期地址）推导当前 boot 的 slide，
   并输出 `SELINUX_ARG`、`PREPARE`；
3. `ko_patch` 用 `syms.txt + slide` 把 226 个未定义符号改成 `SHN_ABS`，并重写 vermagic；
4. `t64560_v36` 把 SELinux 切成 permissive；
5. `cred_target` 通过 perf 采样 `kmem_cache_alloc` 拿到自己的 cred（CAPBND_OK 门闩）；
6. `t64560_v36` 清零 fsuid/fsgid（cred+0x20）；
7. `t64560_cred` 两阶段写：cap_bset=0 → cap_effective=page，落地后 helper 加载 KernelSU；
8. `ksu_grant` 通过 KernelSU 的 reboot-hook 拿 root fd，执行 `root_stage.sh` 安装 ksud。

## KernelSU 模块

`ksu-template.ko` 是用户提供的 6.12.76 模块。当前 `ko_patch` 在加载前按
`patch_ksu_cred_v331.py` 思路完成符号驱动等价修改（不再把模板描述为已预先修改）：

- 定位 `track_throne` 内的 `adrp/ldr`（本模块在 `0x6058/0x605c`，目标寄存器 x0）；
- 把 `ldr x0,[x8]` 改成 `add x0,x8,#0`；
- 新增 `init_cred` 未定义符号并把两条重定位指过去；
- 运行时由 `ko_patch` 按 `syms.txt + slide` 解析为绝对地址。

模块加载前不会参与任何内核状态修改；reboot 后 slide 变化，必须重新由 `ko_patch` 生成。

## 风险

这是 CVE-2026-64560 的 UAF 利用链，**不是稳定的一键 root**：

- 竞态命中率约 1/1000–1/5000 次 exec；
- 命中后若 8KB frag 没有接管被释放的 order-1 slab 页，内核会 panic/自动重启；
- 参考项目自身报告约 50% 成功率，并明确“不适合无人值守反复跑”。

设备重启后：SELinux 恢复 Enforcing、slide 失效、模块消失；重新启动 Stellar（或 Shizuku），
必要时重新执行 `2. 部署资产`，再从 `3. 开始提权` 重跑（脚本会重新抓 KASLR、重打模块）。

## 构建

- `src/`：legacy Java 控制器参考；实际 UI 在 `../compose-app/`；
- `native/`：`kaslr_slide.c`、`ko_patch.c`、`addrcalc.c`（Zig 静态 aarch64）；
- `assets/`：上述二进制 + `t64560_v36` / `cred_target` / `t64560_cred` / `ksu_grant` +
  `ksud` + `ksu-template.ko` + `syms.txt` + 脚本；
- `build.ps1`：调用 `compose-app/gradlew.bat assembleRelease`，复制到 `app/MagicRoot.apk`；
- `build-legacy.ps1`：旧的 aapt2/javac/d8 手工构建。

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1 `
  -Sdk <sdk> -Jdk <jdk25> `
  -Keystore .\aoki-magicroot.keystore `
  -StorePass <pass> -KeyAlias magicroot -KeyPass <pass>
```

### 为什么不能直接执行 /data/adb/ksu/bin/su

`/data/adb` 默认是 root-only 目录（通常 0700），普通 App 没有目录搜索权限，
所以：

```text
/data/adb/ksu/bin/su -c id
```

会报 `Permission Denied`。这不是 KernelSU allowlist 拒绝，而是路径本身对 App
不可达。

可用入口：


不要通过放宽 `/data/adb` 权限来解决。
