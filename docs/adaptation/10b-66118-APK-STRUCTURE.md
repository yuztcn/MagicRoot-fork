# APP-STRUCTURE.md —— KMRoot(98260) APK 结构与关键实现

> 分析对象：`work/adapt-66118/apk/KMRoot(98260).apk.1`
> 结论摘要：**这是一个把完整 CVE-2026-98260 利用链、KernelSU LKM/管理器/ksud、
> 完整 kallsyms 符号表和 5 阶段 shell 编排全部伪装成 `lib/arm64-v8a/*.so` 打包的
> “单 APK 一键 root”工具**。没有 `assets/`，没有 `res/raw`，Java/Kotlin 层只做
> Shizuku 授权、落盘、拉起 `run.sh` 和日志/阶段解析。
>
> 全部证据均在 `EXTRACT/` 下可复现；本文引用的行号均指
> `EXTRACT/03-payload/run.sh`、`take_slide.sh` 等文件的实际行号。

---

## 1. APK 身份

| 项 | 值 |
|---|---|
| 文件 | `KMRoot(98260).apk.1`（20,496,369 B，sha256 `d86f5ec38f4e1c6dc70f0be457c9752c6eb02d2c8d710582144fc9b51574fb6a`） |
| 包名 | `com.km.kmroot` |
| versionName / versionCode | `0.4.3-98260` / `43` |
| minSdk / targetSdk / compileSdk | 30 / 34 / 34（Android 14 构建） |
| 应用名 | `KMRoot 98260`（`resources.arsc` 仅 1 个 string） |
| debuggable | **true** |
| 权限 | 仅 `moe.shizuku.manager.permission.API_V23` |
| queries | `moe.shizuku.privileged.api`、`me.weishu.kernelsu` |
| 组件 | `com.km.kmroot.MainActivity`(LAUNCHER/exported)、`rikka.shizuku.ShizukuProvider`(exported, authorities=`com.km.kmroot.shizuku`) |
| 其它 | `allowBackup=false`、`extractNativeLibs=true`、`usesCleartextTraffic=false` |
| 签名 | 仅 v2；证书 `C=US,O=Android,CN=Android Debug`，SHA-256 `37046e22b983496ad31d02cc238b68e73df447f3ef2f7bba239e06c326ff6682` |
| 构建元数据 | AGP `8.5.2`（`META-INF/com/android/build/gradle/app-metadata.properties`） |

**解读**：debug 签名 + `debuggable=true` + 仅一个 Shizuku 权限 ⇒ 它自己不需要任何
危险权限，真正的 root 操作全部由 Shizuku 提供的 **shell 域**（uid 2000）落地执行；
`extractNativeLibs=true` 保证 `lib*.so` 会被安装器解压到 `nativeLibraryDir`，
运行期再由 App 用 `cp` 复制到 `/data/local/tmp/kmroot98260` 并改名。

## 2. 物理结构（zip entry）

| entry | 大小 | 真实类型/用途 |
|---|---|---|
| `classes.dex` | 77,232 | shade: androidx.annotation + rikka.shizuku + moe.shizuku AIDL |
| `classes2.dex` | 2,100 | `com.km.kmroot.R` 系列 |
| `classes3.dex` | 16,164 | `core/Cfg`、`core/Shell`、`core/ShizukuBridge` |
| `classes4.dex` | 11,608 | `engine/Engine` 编排/日志解析 |
| `classes5.dex` | 21,184 | `MainActivity` + Compose UI |
| `lib/arm64-v8a/librunsh.so` | 7,628 | **shell 脚本**（BOM + `#!/system/bin/sh`） |
| `lib/arm64-v8a/libtakslide.so` | 605 | **shell 脚本** |
| `lib/arm64-v8a/libsyms.so` | 4,917,172 | **文本 kallsyms 表**（`ffffffc080000000 T _text` 格式） |
| `lib/arm64-v8a/libt98260plant.so` | 1,451,336 | **aarch64 静态 ELF**（exploit 主链） |
| `lib/arm64-v8a/libt98260su.so` | 1,039,944 | **aarch64 静态 ELF**（rootd 客户端） |
| `lib/arm64-v8a/libpreppatch.so` | 1,171,152 | **aarch64 静态 ELF**（ko 重定位重写） |
| `lib/arm64-v8a/libprepsolve.so` | 1,205,480 | **aarch64 静态 ELF**（KASLR slide 求解） |
| `lib/arm64-v8a/libforker.so` | 911,960 | **aarch64 静态 ELF**（trace 采样触发器） |
| `lib/arm64-v8a/libksud.so` | 6,402,736 | **aarch64 静态 ELF**（定制 KernelSU ksud 3.3.1） |
| `lib/arm64-v8a/libkernelsu.so` | 330,664 | **ET_REL kernel module**（KernelSU LKM；不是 JNI 库） |
| `lib/arm64-v8a/libmanagerapk.so` | 13,637,206 | **ZIP/APK**（官方 KernelSU v3.3.1 管理器） |
| `lib/arm64-v8a/libadbroot.so` | 9,800 | ELF shared object（官方管理器同款 adb root 辅助库） |
| `res/*` | 188,652 | 5 个 launcher 图标 + 1 张赞赏二维码 `zanshang.png` |
| `resources.arsc` | 1,548 | 只有 `app_name`/icon/drawable 三个资源 |

`aapt2 dump badging` 输出的 `native-code: 'arm64-v8a'` 与上表一致 —— APK **没有**
`assets/`，所有“资产”都藏在 nativeLibraryDir。

## 3. Java/Kotlin 层（DEX）结构与职责

| 类 | dex | 职责（证据：`EXTRACT/02-dex/disasm/`） |
|---|---|---|
| `com.km.kmroot.core.Cfg` | classes3 | 静态载荷映射表、native 目录探测、生成 `mkdir/cp/chmod` 脚本、落盘校验脚本 |
| `com.km.kmroot.core.Shell` + `Shell$Live` + `Shell$Line` | classes3 | 通过 Shizuku `newProcess` 启动 `sh -c`，双线程泵 stdout/stderr 逐行回调 |
| `com.km.kmroot.core.ShizukuBridge` + `State` | classes3 | Shizuku 安装/运行/授权/就绪状态机（NOT_INSTALLED/NOT_RUNNING/NO_PERMISSION/READY/UNKNOWN） |
| `com.km.kmroot.engine.Engine` + `Listener` | classes4 | 主流程编排：环境检查→落盘→校验→启动 run.sh→解析阶段/错误→收尾校验→安全停止 |
| `com.km.kmroot.MainActivity` + 16 个 lambda | classes5 | Compose UI、日志窗口、Shizuku 授权弹窗、一键/停止/复制/清空/赞赏 |
| `rikka.shizuku.*` / `moe.shizuku.*` | classes.dex | Shizuku 客户端 + AIDL（版本内嵌） |

### 3.1 `Cfg.NATIVE_MAP` —— 12 条落盘映射（`disasm/Cfg.txt` 行 92–179）

`Cfg.<clinit>` 构造 `[[Ljava/lang/String;`（12 行 × 2 列），`disasm/Cfg.txt` 可见
逐条 `const-string "libt98260plant.so"` / `"/data/local/tmp/kmroot98260/t98260_plant"`
成对出现。完整映射（按类内顺序）：

| # | nativeLibraryDir 中的文件名 | 落盘路径 |
|---|---|---|
| 0 | `libt98260plant.so` | `/data/local/tmp/kmroot98260/t98260_plant` |
| 1 | `libt98260su.so` | `.../t98260_su` |
| 2 | `libprepsolve.so` | `.../prep_solve` |
| 3 | `libpreppatch.so` | `.../prep_patch` |
| 4 | `libforker.so` | `.../forker` |
| 5 | `libsyms.so` | `.../syms.txt` |
| 6 | `librunsh.so` | `.../run.sh` |
| 7 | `libtakslide.so` | `.../take_slide.sh` |
| 8 | `libksud.so` | `.../ksud` |
| 9 | `libkernelsu.so` | `.../kernelsu.ko` |
| 10 | `libadbroot.so` | `.../libadbroot.so` |
| 11 | `libmanagerapk.so` | `.../manager.apk` |

`Cfg.nativeDir()`（`Cfg.txt` 行 303–369）先查 `ApplicationInfo.nativeLibraryDir`
下是否存在 `libt98260plant.so`，否则回退 `<nativeLibraryDir>/arm64`。
`Cfg.copyScript()`（行 203–302）生成的命令形如：

```sh
mkdir -p '/data/local/tmp/kmroot98260' 2>/dev/null;
cp -f '<nativeLibraryDir>/libt98260plant.so' '/data/local/tmp/kmroot98260/t98260_plant';
chmod 755 '/data/local/tmp/kmroot98260/t98260_plant';
...
chmod 644  .../syms.txt .../run.sh .../take_slide.sh .../kernelsu.ko
```

`Cfg.verifyScript()`（行 370–419）对每个目标 `echo "size:$(stat -c %s '<path>') name:<path>"`，
Engine 用返回值判断“载荷落地失败（nativeLibraryDir 里缺文件）”。

### 3.2 `Engine` 的运行状态机（`disasm/Engine.txt` + `02-dex/classes4-strings.txt`）

Engine 静态/实例字段：`INST`、`running`、`done`、`failed`、`worker`、`live`、`listener`、
`lastLabel`、`lastLineAt`、`lastPct`、`summary`、`sawProbeFail`、`sawLoadFail`、
`sawMissSafe`、`sawRebootRequired`；方法：`start/stop/isRunning/runInternal/onLine/stage/safe/finish/log/get`。

它识别的阶段/结果 token（全部在 `classes4-strings.txt`）：

| token | 语义 |
|---|---|
| `SLAB` | `[0]` slab 几何自检输出（`posix_timers_cache` order/object_size/objs_per_slab） |
| `[1/5]` `probe` `PROBE_FAIL` `FAIL=probe` | 设备/漏洞 probe |
| `[2/5]` `采样 KASLR` / `SLIDE=` / `SOLVE_FAIL` | trace 采样与 slide 求解 |
| `[3/5]` `98260 主链` / `ROOTD_READY` / `PLANT_OK` / `SELinux Permissive` / `PLANT_FAIL` / `FAIL=reclaim` | UAF/cred/rootd |
| `[4/5]` `KernelSU 接管` / `MODULE_LOADED` / `LOAD_FAIL` | ksud insmod |
| `[5/5]` `管理器/收尾` / `DONE` | install manager + 清理 |
| `DEPLOY_FAIL` `REBOOT_REQUIRED` `WARN=kernel-mismatch` `miss-safe` `FAIL=reap` `safe-exit` | 失败分类；Engine 在 UI 上给中文解释 |
| `SLAB_GEOMETRY_UNEXPECTED` / `SLAB_PREFLIGHT_UNAVAILABLE` | 几何不符只告警，不拦截 |

Engine 在拉起 run.sh 之前会通过 Shizuku shell 执行的环境检查（strings 原文）：

```sh
getprop ro.product.model; getprop ro.build.display.id; uname -r; getenforce; \
  grep -i kernelsu /proc/modules | head -n1
test -w /sys/kernel/tracing/events/kmem/rss_stat/trigger && echo TRACE_OK || echo TRACE_DENIED
```

`TRACE_DENIED` 直接给出“tracefs 不可写，98260 无法采样/抢页”的提示 —— 与 run.sh
的 `[2/5]` 强依赖 tracefs 完全对应（这是本方案对目标设备的关键前提之一）。

拉起命令：`sh /data/local/tmp/kmroot98260/run.sh`，工作目录
`/data/local/tmp/kmroot98260`，随后 `tail -n 30 plant.log` 之类的实时日志。
收尾 checks（strings）：`pm path me.weishu.kernelsu 2>&1`、`su -c id 2>&1`、
`grep -i kernelsu /proc/modules | head -n1`；成功文案“越狱成功：KernelSU Live，su 可用，管理器已打开”。

### 3.3 UI 文案（`classes5-strings.txt`）

`KMRoot` / `CVE-2026-98260 · 临时 root` / `一键越狱` / `停止` / `运行中…` /
`成功` `失败` / `[OK]` `[FAIL]` / `日志` `复制` `清空` /
“临时 root，重启失效；98260 为竞态 UAF，可能内核 panic / 重启。仅用于自有设备。”
/ “KMRoot 没有自己的 shell 域。请安装并启动 Shizuku，授权后再回来。”
/ 赞赏页（酷安 @KaMuaMua2020，`res/drawable/zanshang.png`）。
作者定位信息仅此，无网络权限、无后台上传逻辑。

## 4. Native 载荷逐项说明

> 所有 payload 的 sha256 见 `EXTRACT/03-payload/payload-inventory.txt`。
> 二进制均由 **Zig 0.14.1 / clang 19.1.7 + musl 静态链接** 交叉编译；溯源见 §6。

### 4.1 `librunsh.so` → `run.sh`（7,628 B，226 行）

作用：**5 阶段一键编排**。要点（行号即文件行号）：

| 行 | 内容 |
|---|---|
| L1–L27 | 定位自身目录 `D`（支持 `PKJ110_DIR` 覆盖）；检查 `t98260_plant/t98260_su/prep_solve/forker/syms.txt/take_slide.sh` 全部存在，否则 `DEPLOY_FAIL`；`chmod 755 ... prep_patch forker ksud`；环境变量：`PKJ110_DISABLE_ANTIROOT=1`、`KMROOT_FAST=0`、`KMROOT_FORCE_EXPLOIT=0`、`KMROOT_SKIP_SELINUX=0`；常量 `KO=kernelsu.ko`、`KSUD=ksud`、`LIB=libadbroot.so`、`MPKG=me.weishu.kernelsu`、`APK=manager.apk`；打印 `EXPLOIT=98260 DEVICE=PKJ110 ENGINE=t98260 MANAGER=kernelsu` |
| L28–L42 | **几何自检**：读 `/sys/kernel/slab/posix_timers_cache/{order,object_size,objs_per_slab}`，期望 `order=1 object=264`（`264B×31 ≤ 8KiB`），不符仅 `SLAB_GEOMETRY_UNEXPECTED` 告警继续 |
| L44–L55 | `unload_guard()`：**OPLUS antiroot** —— 经 rootd 执行 `pm disable-user --user 0 com.oplus.exsystemservice`、`pkill -9 -f com.oplus.exsystemservice`、`sleep 5`、`pm enable com.oplus.exsystemservice`，并提示恢复后可能需软重启 zygote/SystemUI |
| L57–L96 | `finish_manager()`：`chmod`；`ksud insmod kernelsu.ko`；失败则 `ksud unload` 后重试；仍无 `/proc/modules` 则 `LOAD_FAIL` + `uname -r`/`dmesg` 里 grep `kernelsu|vermagic|unknown symbol|disagrees|invalid module` 后 `exit 15`；成功后 `ksud install --libadbroot ./libadbroot.so --data-path /data/adb`、`pm install -r manager.apk`、`unload_guard`、`id; getenforce; grep kernelsu /proc/modules`；su 可用则清理 plant/root.sock（遇到 `miss-safe`/`held` 则保留 zombie 并提示重启） |
| L98–L110 | `held_for_boot()`/`miss.$BOOTID`：**每个 boot_id 只允许一次失败尝试**，命中即 `REBOOT_REQUIRED`（防止在已留下未回收 zombie 的 boot 上二次触发野写） |
| L111–L131 | `finish_loaded()`：KSU 已在 `/proc/modules` 时只校验/安装管理器/清理，不重复 exploit |
| L132–L143 | 若已加载且未 `FORCE_EXPLOIT` → 直接 `finish_loaded`；`FORCE=1` 时强制再跑并 `SKIP_SELINUX=1` |
| L144–L153 | `[1/5] probe`：`./t98260_plant --probe > probe.log`，失败 `PROBE_FAIL exit 11` |
| L154–L181 | `[2/5]`：解析 `slide.cache`（boot_id→slide）；否则循环 3 次 `sh take_slide.sh` + `./prep_solve . syms.txt`，从 `slide.txt` 取 `SLIDE`；失败 `SOLVE_FAIL exit 12` |
| L182–L212 | `[3/5]`：`setsid sh -c "./t98260_plant --slide $SLIDE --budget 240 [--fast] [--skip-selinux] | tee plant.log" &`；轮询 ≤110×3s 等 `ROOTD_READY`/`FAIL=(task|selinux|cred|init|probe)`/`PARKED=1`；要求 `getenforce == Permissive` 才算 `PLANT_OK`，否则 `PLANT_FAIL exit 13` 并 touch `miss.$BOOTID` |
| L213–L222 | `FORCE` 模式：保留/清理逻辑（同样遵守 zombie 安全） |
| L223–L226 | `[4/5] handoff to KernelSU`→`finish_manager`→`echo DONE` |

**失败安全设计**：`held`/`miss.$BOOTID` 标记 + “不要 kill plant（zombie 回收会 panic）”
+ `miss-safe`/`safe-exit` 保留现场，是本方案对竞态 UAF 的核心工程保护。

### 4.2 `libtakslide.so` → `take_slide.sh`（605 B，19 行）

```
L3  rm -f bl_*.bin bl_text.txt
L4  echo 1 > /sys/kernel/tracing/events/sched/sched_blocked_reason/enable
L5  echo 1 > /sys/kernel/tracing/tracing_on
L6-8 for c in 0..3: cat /sys/kernel/tracing/per_cpu/cpu$c/trace_pipe_raw > bl_$c.bin &
L9  sleep 1
L11-14 while i<60: $D/forker 2 30     # 制造大量调度阻塞事件
L15 grep "sched_blocked_reason" /sys/kernel/tracing/trace > bl_text.txt
L16 pkill -f trace_pipe_raw
L18-19 打印每个 bl_*.bin 大小与 bl_text.txt 行数
```

思路：`sched_blocked_reason` 事件把“内核调用者地址（含 KASLR slide）与函数内偏移”
写进 trace；`bl_text.txt` 给出 caller 符号+偏移，`bl_*.bin` 的 raw 数据里出现完整
地址，`prep_solve` 用 syms 反推 slide。

### 4.3 `libsyms.so` → `syms.txt`（4,917,172 B）

`nm -n` 风格纯文本：`ffffffc080000000 T _text` … `ffffffc0823f0000 B _end`，
共 **110,445 行**（110,119 个唯一地址；type 计数 t=33250, T=30151, d=27689,
r=10129, D=5563, b=2874, B=455, W=275, R=58, V=1）。
即 **OPPO 目标 build（`6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k`）
的完整 kallsyms 快照**，是 `prep_solve` 的必需输入。

### 4.4 `libt98260plant.so` → `t98260_plant`（1,451,336 B）

- 内嵌**精确目标版本串**：`6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k`
  （`--probe` 时打印 `PROBE_KERNEL=%s`，与 `uname -r` 不符则
  `WARN=kernel-mismatch expect=... got=...`但默认继续）。
- 命令行：`t98260_plant --probe` 或 `--slide <hex> [--budget <sec>] [--fast] [--skip-selinux] [--timers N]`。
- probe 输出：`PROBE_KERNEL/PROBE_UID/PROBE_SELINUX/PROBE_TRACE/PROBE_RSS/PROBE_TRIGGER/PROBE_OK`；
  `PROBE_TRACE` 表示 tracefs 可写（写 `kmem/rss_stat/trigger`）。
- 主链输出：`SLIDE=%#lx BUDGET=... SKIP_SELINUX=...`、`SELINUX_TRY=%d`、
  `RECLAIM_MODE=cred node=%lx off=%#x` 或 `RECLAIM_MODE=tile off=%#x target=%lx`、
  `CRED_INSTALLED=%#lx attempt=%d`、`LEAK_TASK/LEAK_TIMERS`、`PARKED=1`（安全停驻）、
  `ROOTD_LISTEN path=%s pid=%d`、`ROOTD_READY path=%s child=%d`、
  `FAIL=(task|selinux|cred|init|probe) REASON=... T=%lldms`、`RETRY=...`。
- 依赖路径：`/sys/kernel/tracing/*`、`/proc/self/status`、`/sys/fs/selinux/enforce`、
  `/proc/sys/kernel/random/boot_id`、rootd socket `root.sock`。
- 观测到的保护：`PARKED=1` 与 `miss-safe` 语义配合 run.sh 的 reboot 状态机。

### 4.5 `libt98260su.so` → `t98260_su`（1,039,944 B）

rootd socket 客户端：`usage: %s -c <command>`，连接 `root.sock`，把命令交给
rootd（已替换 cred 的进程）执行并回传 stdout/stderr；有 `connect rootd` 日志与
`Connection refused/reset` 等错误串。run.sh 中所有“以 root 执行”的动作
（chmod/insmod/pm install/pkill/disable service）都通过它完成。

### 4.6 `libprepsolve.so` → `prep_solve`（1,205,480 B）

`usage: prep_solve <bl_dir> <syms.txt>`；
读取 `<bl_dir>/bl_text.txt`、`<bl_dir>/bl_%d.bin`、可选 `<bl_dir>/target.txt`，
输出 `<bl_dir>/slide.txt`；stdout 关键行：`syms=%zu`、
`slide=0x%llx votes=%d anchors=%d observed=%zu`、
`no slide candidate (anchors=%d observed=%zu)`、`no raw values`。
**这是把 6.12 方案里硬编码 anchor 的 `kaslr_slide_*.c` 泛化成“符号表驱动”的关键工具**：
只要换 `syms.txt` 即可适配其它 6.6.118/6.12 build（详见 REPORT §4）。

### 4.7 `libpreppatch.so` → `prep_patch`（1,171,152 B）

`usage: prep_patch <base.ko> <syms.txt> <slide_hex> <out.ko>`；
输出 `patched=%d slide=0x%llx`；错误串 `bad section headers`、`no symtab/strtab`、`bad slide`。
它按 `syms.txt`（链接期地址）+ slide 把 `base.ko` 的导入符号重定位改写成目标内核绝对地址，
生成可直接 insmod 的 ko。**当前 `run.sh` 并没有调用它**（只 chmod 755），
KSU 加载走 ksud 自身的 vermagic 替换 + kallsyms 解析路径；`prep_patch` 属于
“离线/备用”工具，但对目标适配很有价值（可与 Honor `ko_patch` 互为替代）。

### 4.8 `libforker.so` → `forker`（911,960 B）

`take_slide.sh` 里以 `forker 2 30` 调用，用于制造/维持阻塞任务，使
`sched_blocked_reason` 事件高频出现并连续采样 60 轮。

### 4.9 `libksud.so` → `ksud`（6,402,736 B）

- 自报 `KernelSU version 3.3.1 (uapi: 5)` / `KSU_VER_CODE 32680` 的 Rust 静态 ELF。
- 关键能力（字符串证据见 `03-payload/ksud-key-strings.txt`）：
  `insmod`（“Load a kernel module with kallsyms access”）、
  “Kernel requires vermagic”/“Replaced module vermagic with kernel-required value”/
  “init_module failed after replacing vermagic”（**加载时自动把 ko 的 vermagic 改成运行内核要求值**）、
  `install --libadbroot`、`unload`、`late-load`、`boot-patch`/`boot-patch-v2`、
  `feature set（allow_shell/su_compat/kernel_umount/sulog/selinux_hide/…）`、
  `block-module`（示例直接点名 `oplus_secure_guard`）、
  `android12-5.10 … android17-6.18` KMI 表与 `/data/adb/ksu/lib/<KMI>_kernelsu.ko` 约定、
  内嵌 1 个 AArch64 `ET_REL` bootstrap（文件偏移 `0x291e54`）用于 boot Image 注入时解析 kallsyms。
- 与官方管理器中内置的 `libksud.so`（4,990,848 B）**不是同一二进制**，说明作者用了
  带 late-load/bootstrap 扩展的定制 ksud 分支。

### 4.10 `libkernelsu.so` → `kernelsu.ko`（330,664 B，ET_REL）

```
parmtype=allow_shell:bool / norc:bool / bundled:bool
license=GPL  author=weishu  description=Android KernelSU  name=kernelsu  depends=
vermagic=6.6.127-4k-g46a034eca005-dirty SMP preempt mod_unload modversions aarch64
```

- 1753 个符号，其中 **225 个 undefined（导入）**，5046 条重定位全部指向这些导入符号
  → 说明包里的是**未预置地址的 base ko**，运行期由 ksud（或 prep_patch）解析。
- 内含 `.BTF`（20,485 B）、`.gnu.linkonce.this_module`、`__versions`（**size=0**）。
- **关键差异**：它按 `6.6.127`（`-dirty` 本地树）编译，而 exploit 目标串是 `6.6.118`；
  加载依赖 ksud 的 vermagic 替换 + kallsyms 解析，属于“跨小版本 LKM 复用”的风险点。

### 4.11 `libmanagerapk.so` → `manager.apk`（13,637,206 B）

官方 KernelSU `me.weishu.kernelsu` **v3.3.1**（versionCode 32680，uapi 5），
compileSdk 37 / targetSdk 37；签名 `CN=KernelSU`（证书 SHA-256
`c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6`）。
内部含官方 `libksud.so`、JNI `libkernelsu.so`、`libadbroot.so`（与外层载荷逐字节一致）。

### 4.12 `libadbroot.so`（9,800 B）

与 manager.apk 内 `lib/arm64-v8a/libadbroot.so` sha256 完全一致
（`95509b04...`），供 `ksud install --libadbroot` 使用。

## 5. 端到端运行流程（还原）

```
用户点“一键越狱”
  └─ Engine: 检查 Shizuku 状态（ShizukuBridge.State.READY）
     └─ Shizuku newProcess("sh") ──► uid 2000 shell 域
        1) 环境检查：getprop/uname -r/getenforce/proc/modules/tracefs 可写
        2) Cfg.copyScript() 落盘 12 个载荷 → /data/local/tmp/kmroot98260
        3) Cfg.verifyScript() 校验 size/name
        4) sh /data/local/tmp/kmroot98260/run.sh
           [0]   读 /sys/kernel/slab/posix_timers_cache 几何（期望 264B/order1/31objs）
           [1/5] ./t98260_plant --probe
           [2/5] sh take_slide.sh  → bl_text.txt + bl_0..3.bin
                 ./prep_solve . syms.txt → slide.txt
           [3/5] ./t98260_plant --slide <slide> --budget 240
                  → SELinux=Permissive + cred 替换 + rootd(root.sock) → ROOTD_READY
           [4/5] ./t98260_su -c './ksud insmod kernelsu.ko'
                  （ksud 自动替换 vermagic + 解析 225 个符号）
                  → /proc/modules 出现 kernelsu
           [5/5] ./t98260_su -c './ksud install --libadbroot ./libadbroot.so --data-path /data/adb'
                 ./t98260_su -c 'pm install -r ./manager.apk'
                 ./t98260_su -c 'pm disable-user com.oplus.exsystemservice' … 'pm enable …'（OPLUS antiroot）
                 ./t98260_su -c 'pkill -9 -x t98260_plant; rm -f root.sock'（su 可用且无 miss-safe 时）
                 monkey -p me.weishu.kernelsu …
        5) Engine 收尾校验：pm path me.weishu.kernelsu / su -c id / /proc/modules
```

## 6. 构建溯源（二进制内嵌路径）

| 载荷 | 关键内嵌路径 |
|---|---|
| 全部 exploit 载荷 | `E:/root/Tools/KMRoot-98260-X8U`（作者工作区） |
| `t98260_plant`/`t98260_su`/`prep_patch`/`prep_solve`/`forker` | `E:\root\Tools\PKJ110-98260-port`（`prep_patch.c` 源码目录 `exploit/src`） |
| 工具链 | `E:\root\Tools\_tmp\zig\zig-x86_64-windows-0.14.1\...`，`clang version 19.1.7`（zig-bootstrap），musl 静态 |
| 目标设备代号 | `PKJ110`（来自工作区/路径与环境变量名 `PKJ110_DIR`）；run.sh 另见 `PYB110_DIR` 兼容变量 |

## 7. 可复用性分级（给适配用的结论）

| 级别 | 资产 |
|---|---|
| **可直接复用**（与内核 build 无关） | `librunsh.so`（改内核门槛/antiroot 后）、`libtakslide.so`、`prep_solve`（换 syms 即可）、`forker`、`ksud`（3.3.1 定制版）、`manager.apk`（官方 3.3.1）、`libadbroot.so`、App 层的 Cfg/Shell/ShizukuBridge/Engine 实现思路、12 项落盘表、run.sh 的 reboot/miss 安全状态机 |
| **可复用但必须换参数/输入** | `prep_patch`（换目标 syms + slide）、`kernelsu.ko`（换/重编目标 KMI 的 LKM）、`syms.txt`（必须换成目标 build 的 kallsyms） |
| **不能直接复用**（与 build 绑定） | `t98260_plant`、`t98260_su`（内嵌 `6.6.118-...g9bc34d5b0c79-abogki537459655` 的链接期地址与 struct 偏移） |
| **仅 OPLUS 适用** | `unload_guard()` 里 `com.oplus.exsystemservice` 的 disable/enable 逻辑；Honor 目标需替换/删除 |

## 8. 未纳入/忽略项

- `res/drawable/zanshang.png`（赞赏二维码，159,841 B）仅记录 sha256，不展开。
- `classes.dex` 的 Shizuku/AIDL 属于第三方库，只确认来源与版本行为，不做逐方法分析。
- `EXTRACT/02-dex/disasm/*.txt` 为 dexdump 原始反汇编（UTF-16 转换后的文本），
  字号/寄存器注释按 dexdump 格式保留，未做 jadx 级还原（本机无 jadx，且证据已足够）。
