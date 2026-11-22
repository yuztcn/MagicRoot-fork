# REPORT.md —— KMRoot(98260) APK 逆向与 6.6.118 适配可行性报告

> 任务：离线逆向 `work/adapt-66118/apk/KMRoot(98260).apk.1`，梳理其 6.6.x 内核适配逻辑，
> 与现有 Honor MagicOS 6.12.58 方案（`MagicRoot-Enhanced-1.0.4-98260`）逐项对比，
> 给出 **Honor 目标 6.6.118 设备**的适配可行性、风险与验证步骤。
>
> 范围声明：**全离线**。未连接任何真机、未写系统分区、未执行 APK 内任何二进制。
> APK 内工具/脚本只做静态读取与反汇编；目标机信息仅只读引用
> `work/adapt-66118/boot/`（Lead 预置的 boot.img 取证结果）。
>
> 结论等级：**整包不可直接用；方法论 + 大部分资产可移植，属“有条件可行（中等工作量，
> 先决条件是设备端 probe 能通过）”**。关键阻塞点见 §7/§9。

---

## 1. 结论摘要（TL;DR）

1. **APK 是什么**：`com.km.kmroot` v0.4.3-98260，一个把 **完整 CVE-2026-98260 一键
   root 链**（exploit + rootd + KernelSU LKM + 定制 ksud + 官方管理器 + 完整 kallsyms
   + 5 阶段 shell 编排）全部伪装成 `lib/arm64-v8a/*.so` 塞进 APK 的工具。Java 层只做
   Shizuku 授权、落盘 12 个载荷到 `/data/local/tmp/kmroot98260`、`sh run.sh`、解析日志阶段
   （详见 `APP-STRUCTURE.md`）。
2. **它自带的 exploit 目标 build 是 OPPO/ColorOS 的**
   `6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k`（`t98260_plant` 内嵌字符串），
   与 Honor 目标 6.6.118 设备的
   `6.6.118-android15-8-gf17133276a57-abogki518694926-4k` **同为 6.6.118/4K/VA39/同链接基址，
   但不是同一个 build**。
3. **符号级差异已量化**：APK 内 syms 与目标内核 104,356 个同名符号中，
   **仅 35 个地址相同（0.03%）**；KSU LKM 需要的 225 个导入符号里
   **214 个在目标 build 上的地址不同**。⇒ `t98260_plant`/`t98260_su` 内嵌的链接期地址
   **不能直接用于目标**，必须按目标 build 重编/重定位。
4. **可移植的“方法论”最关键**：`take_slide.sh + prep_solve + syms.txt` 的
   **tracefs `sched_blocked_reason` 泄漏 + 全量 kallsyms 投票求 KASLR slide** 方法
   与内核 build 无关，只要换目标 syms 即可；**我已经用 APK 的方法论从目标 boot 镜像
   离线恢复出 107,605 个符号的完整符号表**（`EXTRACT/05-target-66118/`），并补齐了
   目标 build 的关键几何/调用点常量（k_itimer=264、cred=184、prepare_creds/do_timer_create/
   begin_new_exec 调用点等），见 §6。
5. **KSU 链路**：APK 的策略是“**base LKM + ksud 运行期解析**”——`kernelsu.ko` 是未打地址的
   base（225 个导入/5046 条重定位），`ksud` 加载时用 kallsyms 解析 225 个符号并把
   vermagic 替换成运行内核要求值。目标内核 `KALLSYMS_ALL=y`、vermagic 的
   `SMP preempt mod_unload modversions aarch64` 与 LKM 完全一致 ⇒ **名称层面 225/225
   全部可在目标 kallsyms 中解析**；但该 LKM 是按 `6.6.127` 树编的，跨小版本 struct 风险
   需设备验证（推荐用 KernelSU 源码按 android15-6.6/4k KMI 重编，或用 `prep_patch` 重定位）。
6. **目标设备仅有的两个硬性先决条件**（离线无法确认）：
   - **tracefs 可写**：shell 域必须能写 `/sys/kernel/tracing/events/kmem/rss_stat/trigger`
     与 `.../sched/sched_blocked_reason/enable`（APK 的 probe/Engine 都把它当硬门禁）；
   - **MTE/KASAN 行为**：目标 config 里 `CONFIG_ARM64_MTE=y` + `CONFIG_KASAN=y` +
     `CONFIG_KASAN_HW_TAGS=y`（dev/eng 风格内核），UAF 链可能被硬件标签检测/panic；
     必须先用 `t98260_plant --probe` 实测。
7. **不建议**把 KMRoot APK 直接当产品：OPLUS 专用 antiroot（`com.oplus.exsystemservice`）、
   debug 签名、无安全/清理框架、无多机 profiling。建议按 MagicRoot 现有架构新增
   `66118` profile：**复用 KMRoot 的 6.6.118 资产+方法，exploit 则基于 Honor 已有源码
   （`binary-sources/98260-6.12/` + `cve-98260-repo/`）按目标常量重编**。

---

## 2. 分析对象、输入与方法

### 2.1 对象

| 项 | 值 |
|---|---|
| APK | `work/adapt-66118/apk/KMRoot(98260).apk.1` |
| size / sha256 | 20,496,369 B / `d86f5ec38f4e1c6dc70f0be457c9752c6eb02d2c8d710582144fc9b51574fb6a` |
| 包名/版本 | `com.km.kmroot` / `0.4.3-98260`（versionCode 43） |
| 签名 | v2 only，`CN=Android Debug`（`37046e22…ff6682`） |
| 对照方案 | `MagicRoot-Enhanced-1.0.4-98260`（Honor MLY-AN00/BKQ-AN90，6.12.58/6.12.38/6.12.23） |
| 目标机取证 | `work/adapt-66118/boot/`（boot(1).img → kernel.bin/config/BTF，只读） |

### 2.2 工具与命令（均可复现）

| 目的 | 命令/工具 |
|---|---|
| 清单/权限/资源 | `aapt2.exe dump badging/permissions/resources`（SDK build-tools 37.0.0） |
| 签名 | `apksigner.bat verify --verbose --print-certs`（JDK21 临时 `JAVA_HOME`） |
| 解包/逐 entry 哈希 | PowerShell `ZipFile::ExtractToDirectory` + `Get-FileHash` |
| DEX | `dexdump.exe -f/-d`（5 个 dex），自写 `analyze_dex.py` 按类拆文件（见 `EXTRACT/06-tools`） |
| 二进制字符串 | 自写 Python 正则抽取 `[\x20-\x7e]{5,}` runs（`_tmp/strings/*.txt`） |
| ELF/ko 结构 | 自写 Python `struct` 解析 ELF header/section/symtab/rela/.modinfo |
| 目标 kallsyms 恢复 | `vmlinux-to-elf 1.3.6`（工作区 `work/toolchain/vmlinux-to-elf`），对 `boot/EXTRACT/kernel.bin` |
| 目标 BTF/调用点 | 自写 BTF parser + capstone ARM64 反汇编（`EXTRACT/05-target-66118/scripts/`） |

### 2.3 可复现证据目录

- `EXTRACT/01-identity/`：manifest/badging/签名/逐 entry sha256/管理器签名
- `EXTRACT/02-dex/`：类清单、Cfg/Engine/MainActivity/Shell/ShizukuBridge 反汇编、命令与 UI 字符串
- `EXTRACT/03-payload/`：11 个运行时载荷 + 清单 + kernelsu.ko 结构/导入符号 + ksud 关键串 + 构建溯源
- `EXTRACT/04-manager/`：官方 KernelSU v3.3.1 manager.apk + native 库对比
- `EXTRACT/05-target-66118/`：目标 build 的符号表、BTF 几何、调用点常量、比对 JSON、复现脚本
- `EXTRACT/06-tools/`：本次分析脚本
- `APP-STRUCTURE.md`：包结构/DEX/assets/so/关键脚本的逐项说明

---

## 3. APK 的 6.6.x 适配逻辑（逆向结论）

### 3.1 目标指纹（写死在二进制里）

`t98260_plant` 的字符串常量：

```
6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k
```

`run.sh` 头注释：

```
# CVE-2026-98260 one-key flow (offsets: 6.6.118-android15-8-g9bc34d5b0c79).
```

`run.sh` 几何自检（L28–L42）：读 `/sys/kernel/slab/posix_timers_cache/{order,object_size,objs_per_slab}`，
**期望 `order=1 / object_size=264 / objs_per_slab=31`**（264×31 ≤ 8 KiB），不符仅告警继续。
`librunsh.so` 的 `PKJ110_*`/`PYB110_*` 环境变量、`com.oplus.exsystemservice` 处理、作者工作区
`KMRoot-98260-X8U`、`PKJ110-98260-port` 均指向 **OPPO/ColorOS 设备（代号 PKJ110）**。

### 3.2 KASLR slide：trace 泄漏 + 全量符号表投票

这是 APK 与 Honor 现有方案**最值得复用的部分**：

1. `take_slide.sh` 打开 tracefs，使能 `sched_blocked_reason` 事件；对 cpu0..3
   `cat per_cpu/cpu$c/trace_pipe_raw > bl_$c.bin`；循环 60 次 `forker 2 30` 制造阻塞，
   再 `grep sched_blocked_reason /sys/kernel/tracing/trace > bl_text.txt`。
2. `prep_solve <bl_dir> <syms.txt>`：从 `bl_text.txt` 拿 `caller=<func>+0xNN`（符号名+函数内偏移），
   到 `syms.txt` 查链接期地址 → 得到若干 target 链接地址；在 `bl_*.bin` 的 raw 数据里找
   形如 `target + slide` 的 8 字节值，要求 slide 2 MiB 对齐、≥多个 anchor、票数最高且唯一，
   最后输出 `slide.txt`（`slide=0x%llx votes=… anchors=… observed=…`）。
3. **它不需要把 exploit 的地址常量写死**：唯一输入是目标 build 的 `syms.txt`。
   Honor 现有 6.12 方案里 `kaslr_slide_61258.c` 是同一算法的**硬编码 anchor 版本**
   （6 个 anchor + `SELINUX_STATE/PREPARE_CREDS` 常量，见 `binary-sources/64560/native/kaslr_slide_61258.c`
   L23–L33），APK 的 `prep_solve` 是它的**符号表驱动泛化版**。

> 复现要点：`sched_blocked_reason` 依赖 `CONFIG_SCHED_INFO`；tracefs 写权限是硬前提。

### 3.3 漏洞链（plant）

`t98260_plant` 命令行：`--probe` 或 `--slide <hex> [--budget <sec>] [--fast] [--skip-selinux] [--timers N]`。
从字符串可还原其阶段：

| 阶段 | 证据字符串 |
|---|---|
| probe | `PROBE_KERNEL/PROBE_UID/PROBE_SELINUX/PROBE_TRACE/PROBE_RSS/PROBE_TRIGGER/PROBE_OK`；`WARN=kernel-mismatch expect=%s got=%s` |
| slab/触发 | 写 `/sys/kernel/tracing/events/kmem/rss_stat/trigger`、`.../rss_stat/enable`、`buffer_size_kb` |
| timer UAF | `collect_timers`、`timer_create/timer_settime/setitimer`、`RETRY=timers`、`LEAK_TIMERS n=%d`、`LEAK_TASK` |
| 页回收/抢占 | `RECLAIM_MODE=cred node=%lx off=%#x`、`RECLAIM_MODE=tile off=%#x target=%lx`、`past_budget` |
| SELinux | `SELINUX=already`、`SELINUX_TRY=%d`、`SELINUX_MISS=%d`、`--skip-selinux`、`/sys/fs/selinux/enforce` |
| cred 替换 | `CRED_INSTALLED=%#lx attempt=%d`、`FAIL=cred-pattern` |
| rootd | `ROOTD_LISTEN path=%s pid=%d`、`ROOTD_READY path=%s child=%d`、`PARKED=1` |
| 失败分类 | `FAIL=(task|selinux|cred|init|probe) REASON=… T=…ms`、`miss-safe`、`safe-exit` |

目标 build 的几何要求来自 `run.sh`：`posix_timers_cache = 264 B / order-1(8 KiB) / 31 objs`。
**在目标 Honor 6.6.118 内核 BTF 中 `struct k_itimer` 恰好也是 264 B**（见 §6.2），
说明该 UAF 的 slab 前提在目标上成立。

### 3.4 SELinux / rootd / 提权收尾

- plant 通过 UAF 写 `selinux_state->enforcing = 0`（`/sys/fs/selinux/enforce` 只是读取校验），
  然后替换 cred 并 fork rootd；rootd 在 `root.sock` 上监听，`t98260_su -c '<cmd>'` 以 uid0 执行。
- `run.sh` 要求 `getenforce == Permissive` 才判 `PLANT_OK`（L205–L212），否则 `PLANT_FAIL` 并
  `touch miss.$BOOTID`（该 boot 内禁止二次尝试）。
- **zombie 安全**：`posix_cpu_timers_exit` 的 UAF 会让进程携带未回收 timer，若在错误时机
  kill 会 panic；run.sh 用 `held`/`miss.$BOOTID`/`SAFE_KEEP`/`PARKED=1` 保护，宁可要求重启。

### 3.5 KernelSU 接管

`finish_manager()`（run.sh L57–L96）：

```sh
./t98260_su -c "chmod 755 ksud kernelsu.ko libadbroot.so"
./t98260_su -c "./ksud insmod ./kernelsu.ko"     # 失败→./ksud unload 后重试
grep -qi kernelsu /proc/modules || { ...dmesg 诊断...; exit 15; }
./t98260_su -c "./ksud install --libadbroot ./libadbroot.so --data-path /data/adb"
./t98260_su -c "pm install -r ./manager.apk"
```

`ksud` 侧关键字符串证明它承担了两件“跨 build”工作：
“**Kernel requires vermagic** / **Replaced module vermagic with kernel-required value** /
init_module failed after replacing vermagic”，以及
“**Load a kernel module with kallsyms access**”。
即：**base ko（无地址、vermagic 是 6.6.127）+ 运行期 kallsyms 解析 + vermagic 替换**。
这就是为什么包里的 LKM 可以在 6.6.118 上尝试加载（仍属跨小版本风险，见 §7.4）。

### 3.6 antiroot（OPLUS 专用）

`unload_guard()`（run.sh L44–L55）：

```sh
pm disable-user --user 0 com.oplus.exsystemservice
pkill -9 -f com.oplus.exsystemservice
sleep 5
pm enable com.oplus.exsystemservice
```

这是 ColorOS 的“反 root 检测服务”处理方式；**Honor 目标机没有该包**，应删除或替换为
Honor 对应安全组件（`work/targets/` 下的 `com.hihonor.securitypluginbase`、
`com.hihonor.trustspace`、`com.hihonor.gtxdrivers`、`com.hihonor.trustagent` 等可作为排查起点）。

### 3.7 5 阶段编排与 App 层

`run.sh`（226 行）阶段：`[0] 几何自检 → [1/5] probe → [2/5] slide → [3/5] plant →
[4/5] KSU 接管 → [5/5] manager/收尾`；`DONE` 结束。
App 的 `Engine` 只做：Shizuku 就绪检查 → 环境检查（model/build/uname/getenforce/proc/modules/
tracefs 可写）→ `Cfg.copyScript` 落盘 12 文件 → `Cfg.verifyScript` 校验 → `sh run.sh` →
逐行解析上述 token → 收尾 `pm path me.weishu.kernelsu`/`su -c id`/`/proc/modules` →
失败分类文案。细节见 `APP-STRUCTURE.md` §3。

---

## 4. 与 Honor 6.12.58 现有实现逐项对比

对照对象：`MagicRoot-Enhanced-1.0.4-98260`（`main/app/assets/` + `run.sh/root_stage.sh/
kernel_profiles.sh` + `binary-sources/` + `cve-98260-repo/`）。

| 项 | Honor 现有 6.12.58 方案 | KMRoot APK（6.6.118 OPPO） | 结论 |
|---|---|---|---|
| 目标内核 | `6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k`（另有 6.12.38/6.12.38 Y/6.12.23 profile） | `6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k` | 内核系列不同；机制可借鉴 |
| 目标设备 | Honor MLY-AN00 / BKQ-AN90 | OPPO PKJ110（ColorOS 17） | — |
| 漏洞链 | CVE-2026-98260 同一 CVE；`assets/98260{,-6123,-6138,-6138y}/exploit-android-key-ptr` + `pc98260-su`，按 build 分目录、`target.sh` 元数据 | `t98260_plant` + `t98260_su` + `run.sh`，单 build 写死在二进制 | **同 CVE、不同实现/版本**；Honor 用“一 build 一二进制+元数据”，APK 用“apt 单一二进制+运行期符号表” |
| exploit 形态 | 每 build 预编译，常量由 `pc98260_target_*.h` 编译期注入（来自 BTF + vmlinux.elf 推导）；体积 2.21 MB / 2.14 MB | 单二进制内嵌 `6.6.118-g9bc…` 地址；1.45 MB / 1.04 MB | **APK 二进制不可直接用于 Honor 目标**（符号 214/225 不同） |
| KASLR | `kaslr_slide_61258/6138/6138y/6123`（40 KB，硬编码 anchor + `SELINUX_STATE/PREPARE_CREDS` 常量，C 源码见 `binary-sources/64560/native/kaslr_slide_61258.c`） | `take_slide.sh` + `prep_solve` + **全量 syms**（4.9 MB，110,445 行），符号表驱动、阈值投票 | **APK 版更通用**；换目标 syms 即可，建议吸收进 MagicRoot |
| 符号表 | `syms_61258.txt` 等：226 行 `name 0xaddr`（仅 KSU LKM 需要的非导出符号，供 `ko_patch`） | `syms.txt`：110,445 行 `addr type name`（完整 kallsyms，供 slide 求解） | 两种用途/两种格式，不能互换；目标需各生成一份（已产出，见 §6） |
| KSU LKM | 每 flavor 一个 6.12 KMI 模板（`ksu-template.ko` 485 KB，另有 bakasu/fina/next/sukisu 共 5 种）+ 对应 `syms_61258{,_flavor}.txt`；多后端可选 | 单一 `kernelsu.ko`（330 KB，**按 6.6.127 编**，225 导入/5046 重定位），官方 KernelSU 3.3.1 语义 | 方案取舍不同；目标建议重编 android15-6.6/4k LKM |
| ko 地址/vermagic 处理 | `ko_patch <in.ko> <out.ko> <syms.txt> <slide_hex> <vermagic>`（1,163,240 B）：按 `name 0xaddr` 表 + slide + **vermagic 参数**离线/运行期重定位并改 vermagic；`run.sh` 在 `ksud late-load` 前调用 | `prep_patch <base.ko> <syms.txt> <slide> <out.ko>`（1,171,152 B，功能同源但 **不接收 vermagic**）；**当前 run.sh 不调用**，改由 ksud 在 insmod 时替换 vermagic + kallsyms 解析 | 两个工具可互为替代；目标适配建议优先用 Honor `ko_patch`（已支持目标 vermagic 形参）或 APK `prep_patch`+ksud |
| ksud | 从已安装 manager APK 提取（`ksu_flavor_ksud`），无内置 ksud | 内置定制 ksud 3.3.1（6.4 MB，多 late-load/bootstrap/boot-patch-v2） | APK 的 ksud 更完整（可在无 root 前 through adb root late-load），可作为工具候选 |
| manager APK | 不内置；需设备已有或用户提供；多 flavor 包名 | 内置官方 KernelSU v3.3.1（32680/uapi5，官方签名） | 目标若继续官方 KSU 3.3.1 路线，可直接用 |
| `libadbroot.so` | 无统一说明（来自 manager 提取） | 与官方 manager 内同文件逐字节一致（9,800 B） | 直接可用 |
| KSU 安装路径 | `ksud late-load --kmi android16-6.12` + `/data/adb/ksu/lib/android16-6.12_kernelsu.ko`，失败回退 `insmod` | `ksud insmod kernelsu.ko`（`ksud install --libadbroot` 装 userspace） | 目标 6.6.118 可走 `insmod`（ksud 内建 kallsyms 解析） |
| antiroot | Honor 方案无 OPLUS 逻辑（另有 STP/TrustSpace 处理在 `root_stage.sh`/`clean.sh`/`su_entry.sh`） | `pm disable/pkill/pm enable com.oplus.exsystemservice` | **必须替换**；Honor 目标要实测自身安全组件 |
| 编排/安全 | `run.sh`(64 KB)+`root_stage.sh`(27 KB)+`clean.sh`/`grab.sh`/`su_entry.sh`，多链（64560/98260）、完整 cleanup/verify/UI 状态 | 单 226 行 `run.sh`，5 阶段 + `held`/`miss.$BOOTID`/`PARKED` 状态机 | Honor 框架更成熟；**吸收 APK 的 `held/miss/PARKED` 语义**（其 6.12 方案已部分具备） |
| App 层 | Kotlin/Compose MagicRoot，多 profile/多链/Saf/日志/清理 | Java+Compose，Cfg/Shell/ShizukuBridge/Engine，12 载荷映射 | 目标集成进 MagicRoot；APK 的 Cfg/Engine 逻辑可参考 |
| 6.6.118 历史 | **DEVICE-VERIFY §36 记录：2026-10-25 已删除独立“118 路线”源码树及其 release APK，聚焦 6.12** | 本 APK 是当时 118 路线的外部参考实现之一 | 本次适配相当于**复活/重做 118 profile**，须按新流程重建，不能沿用已删源码 |

---

## 5. 目标 6.6.118 设备事实（只读引用）

来源：`work/adapt-66118/boot/`（`boot(1).img` sha256 `3dacd60d…cbff4e`，kernel.bin
sha256 `e8ce5dbf…6f9c79`，37,128,704 B；config 212,910 B）。

| 项 | 值 | 对适配的意义 |
|---|---|---|
| release | `6.6.118-android15-8-gf17133276a57-abogki518694926-4k` | 与 APK 目标 **build 不同**（g-hash/abogki 号都不同） |
| vermagic | `6.6.118-…-4k SMP preempt mod_unload modversions aarch64` | 与 APK LKM 的 vermagic **flag 段完全一致** ⇒ ksud 替换 vermagic 后格式兼容 |
| 链接基址 | `_text=0xffffffc080000000`、`_stext=0xffffffc080010000`、`_etext=0xffffffc0810b0000` | 与 APK 目标**完全相同**（同 android15-6.6/4K/VA39 布局基线） |
| 页/VA | 4 KiB、VA_BITS=39、PAGE_OFFSET=0xffffff8000000000 | 同上 |
| KASLR | `RANDOMIZE_BASE=y` | 需要 slide 求解 |
| kallsyms | `KALLSYMS_ALL=y` + `KALLSYMS_BASE_RELATIVE=y` | ksud “kallsyms access” 与离线恢复都可用（ksud 明确要求 KALLSYMS_ALL） |
| 模块 | `MODULES=y, MODVERSIONS=y, MODULE_UNLOAD=y, MODULE_SIG=y`（**SIG_FORCE 未开**）、`MODULE_SIG_PROTECT=y` | 未强制签名，理论上允许 unsigned LKM；`MODULE_SIG_PROTECT` 是 Honor 厂商项，需实测 |
| trace | `TRACING=y, KPROBES=y, FTRACE=y, SCHED_INFO=y, DEBUG_FS=y` | `sched_blocked_reason` 事件与 tracefs **在编译期具备**；运行期权限待测 |
| 加固 | `ARM64_MTE=y`、`KASAN=y`+`KASAN_HW_TAGS=y`、`INIT_ON_ALLOC_DEFAULT_ON=y`、`SLAB_FREELIST_RANDOM/HARDENED=y`、`SHUFFLE_PAGE_ALLOCATOR=y`、`FORTIFY_SOURCE=y`、`HARDENED_USERCOPY=y` | **最大不确定性**：MTE/KASAN 可能直接检测/终止 UAF 链；init_on_alloc 影响堆喷射语义（需设备 probe 验证） |
| SELinux | `SECURITY_SELINUX=y, SELINUX_DEVELOP=y` | 允许 setenforce/写 enforcing 语义 |
| 其它 | `DEBUG_INFO=y`、`DEBUG_INFO_BTF=y`、`MAGIC_SYSRQ=y`、`PANIC_ON_OOPS=y`、AVB fingerprint `qti/sun/sun:15/…`、oem base `AAK-LGRP1-CHN 10.0.0.175(SP1)`、security_patch 2026-08-01 | 看起来是带 KASAN 的 eng/dev 内核镜像（`eng.root` 指纹）；panic-on-oops 让失败代价更高 |

> 设备型号未在 boot.img 内直接给出（`ro.product.model` 在 system/vendor build.prop），
> 报告中以“Honor 6.6.118 目标机（`qti/sun` 平台）”称呼，未做任何联网设备数据库推断。

---

## 6. 目标 6.6.118 适配关键差异（量化）

### 6.1 符号地址：几乎全不同

用 vmlinux-to-elf 从目标 Image 恢复 kallsyms，得到 **107,605 个非零符号**
（nm 风格全表见 `EXTRACT/05-target-66118/syms-66118-target.nm.gz`，另附 225 符号的
Honor 格式表 `syms-66118-target.honor-225.txt`）。与 APK 内 syms 比对
（`EXTRACT/05-target-66118/sym-compare.json`）：

| 指标 | 值 |
|---|---|
| APK syms / 目标 syms | 106,365 / 107,605 |
| 同名符号 | 104,356 |
| **地址完全相同** | **35（0.03%）** |
| `_text/_stext/_etext` | 完全相同（同布局基线） |
| `_end` | 目标 +0x20000（数据/BSS 变大） |
| `selinux_state` | APK `0xffffffc08239c620` → 目标 `0xffffffc0823ba418`（+122,360） |
| `init_cred` | `0xffffffc082170c48` → `0xffffffc082190790` |
| `prepare_creds` | `0xffffffc0800e4050` → `0xffffffc080253680` |
| `commit_creds` | `0xffffffc0800e45f8` → `0xffffffc080253b28` |
| `posix_timers_cache` | `0xffffffc08237eaa0` → `0xffffffc08239c7a0` |
| `begin_new_exec` | `0xffffffc0803e3eb0` → `0xffffffc0801e7ccc` |
| KSU LKM 225 个导入符号 | 214 个在目标上地址不同（全表见上） |

⇒ **`t98260_plant` 内嵌的链接期地址全部失效**；APK 的 `WARN=kernel-mismatch` 只告警不拦截，
在目标上继续跑 = 高概率写错地址 → panic。**必须按目标 build 重编/重定位 exploit**。

### 6.2 结构几何：关键项与 APK 期望一致

目标 BTF 解析（`EXTRACT/05-target-66118/btf-geometry.json`，BTF 位于 kernel.bin
偏移 `0x172f4c0`，144,042 个 type）：

| 项 | 目标 6.6.118 | APK/6.6.118 OPPO 期望 | Honor 6.12.58 参考值 | 判定 |
|---|---|---|---|---|
| `struct k_itimer` sizeof | **264 (0x108)** | **264**（run.sh 自检） | 256 (0x100) | ✅ 目标与 APK 一致 |
| `k_itimer.it` 偏移 | **120 (0x78)** | —（APK 未公开） | 0x78 | ✅ 与 6.12 也一致 |
| `struct cred` sizeof | 184 (0xb8) | — | 184 | ✅ |
| `cred` uid..fsgid / cap_eff / security / user_ns | 8/12/16/20/24/28/32/36, 64, 128, 144 | — | 一致（0x40/0x80/0x90） | ✅ |
| `task_struct.cred` / `real_cred` / `comm` | **2080 (0x820) / 2072 (0x818) / 2096 (0x830)** | — | 6.12 为 0x900/0x8f8/0x910 | ⚠️ 6.6 与 6.12 不同（符合预期）；需按目标值编 exploit |
| `selinux_state` sizeof / `enforcing` | 128 (0x80) / 偏移 0 | — | 0x80 / 0 | ✅ |
| `posix_timers_cache` 符号 | `0xffffffc08239c7a0` | 需运行期 slide | — | ✅ 可解析 |

**这意味着 APK 的几何假设（264B/order1/31objs、cred 184B、k_itimer.it=0x78）
在目标 6.6.118 上成立**；差异集中在 task_struct 偏移（6.6 系列 0x818/0x820）
与所有绝对地址。

### 6.3 调用点/链接期常量（目标 build，已离线推导）

用 capstone 对恢复出的 ELF 反汇编，得到（完整 JSON：
`EXTRACT/05-target-66118/derived-sites-66118.json`；**可直接填进
`pc98260_target_66118.h`**）：

| 常量 | 目标值 | 推导证据 |
|---|---|---|
| `LINK_SELINUX_STATE` | `0xffffffc0823ba418` | symtab |
| `LINK_INIT_USER_NS` | `0xffffffc08218ef98` | symtab |
| `LINK_ROOT_USER` | `0xffffffc08218f228` | symtab |
| `LINK_INIT_GROUPS` | `0xffffffc082190788` | symtab |
| `LINK_INIT_UCOUNTS` | `0xffffffc082190cf8` | symtab |
| `LINK_INIT_CRED` | `0xffffffc082190790` | symtab |
| `LINK_POSIX_TIMERS_CACHE` | `0xffffffc08239c7a0` | symtab |
| `LINK_CRED_JAR` | `0xffffffc082376830` | symtab |
| `LINK_TASK_STRUCT_CACHEP` | `0xffffffc082375990` | symtab |
| `LINK_MEMSTART_ADDR` | `0xffffffc081698a48` | symtab |
| `LINK_PREPARE_CREDS` | `0xffffffc080253680` | symtab |
| `LINK_COMMIT_CREDS` | `0xffffffc080253b28` | symtab |
| **`LINK_ALLOC_CRED`** | `prepare_creds+0x20 = 0xffffffc0802536a0` | 反汇编：`adrp 0x82376000; ldr [x8,#0x830]`(=cred_jar) `mov w1,#0xcc0; bl kmem_cache_alloc`，下一条指令偏移 0x20 |
| **`LINK_ALLOC_TIMER`** | `do_timer_create+0x94 = 0xffffffc0803aec40` | 反汇编：`adrp 0x8239c000; ldr [x20,#0x7a0]`(=posix_timers_cache) `bl kmem_cache_alloc`，下一条指令偏移 0x94 |
| `LINK_ALLOC_TASK` | `copy_process+0x144 = 0xffffffc0801e0e48` | `adrp 0x82375000; ldr [x28,#0x990]`(=task_struct_cachep) `bl kmem_cache_alloc_node`，下一条指令偏移 0x144 |
| `LINK_BNE` (begin_new_exec) | `0xffffffc0801e7ccc` | symtab |
| `BNE_RELEASE_TASK_OFF` | `0x3f0` | `bl release_task` 下一条 |
| `BNE_DOWN_READ_OFF` | `0x50c` | `bl down_read_killable`（与 6.12.58 头文件 **0x50c 相同**） |
| `BNE_TIMERS_EXIT_OFF` | `0x6b0` | `bl posix_cpu_timers_exit` |
| `BNE_EXIT_ITIMERS_OFF` | `0x6c0` | `bl exit_itimers` |
| `GEOM_PAGE_OFFSET/VA_BITS` | `0xffffff8000000000` / 39 | config（与 6.12/APK 均一致） |

> ⚠️ `GEOM_MEMSTART_PFN`（Honor 6.12 表为 `0x80000`）需要目标机运行时 memblock 信息或
> `/proc/iomem` 校验，离线无法确定，留作设备端 probe。

**漏洞可利用性静态旁证**：目标 `begin_new_exec` 在 `+0x3f0/+0x50c/+0x6b0/+0x6c0` 分别调用
`release_task / down_read_killable / posix_cpu_timers_exit / exit_itimers`，与 Honor 6.12.58
`pc98260_target_61258.h` 里标注的“vulnerability check”调用点结构同型
（6.12 为 `0x410/0x50c/0x87c/0x88c`）⇒ 目标内核保留了同一竞态窗口（仍需设备端 probe 证实）。

### 6.4 LKM 跨版本可行性

- APK `kernelsu.ko` 有 **225 个导入符号**，我们在目标 kallsyms 中逐一查找：
  **225/225 全部存在**（含 `_printk`、`prepare_creds`、`commit_creds`、`selinux_state`、
  `posix_timers_cache`、`kmalloc_caches`、`__tracepoint_sys_enter` 等）。
- 目标 vermagic 的 flag 段（`SMP preempt mod_unload modversions aarch64`）与 LKM 的完全一致，
  因此 ksud 的“替换 vermagic 为内核要求值”能生成格式合法的字符串。
- 但 LKM 是按 `6.6.127` 编译的；`6.6.118 ↔ 6.6.127` 同属 6.6 LTS，KMI 结构通常稳定，
  仍属**中风险**。两条降低风险路径：
  1. 用 KernelSU 源码（工作区已有 `KernelSU-main.zip`/`ksunext-src`/`ksu-extract`）
     按 android15-6.6/4k KMI 重编，再用 `prep_patch`/Honor `ko_patch` 按目标 syms+slide 重定位；
  2. 沿用 APK 的 base ko + `ksud insmod`（运行期 kallsyms），先用 `--probe`/空转验证。
- 目标 `CONFIG_MODULE_SIG_PROTECT=y`（Honor 厂商项）是唯一可能直接拒绝 unsigned LKM 的开关；
  `MODULE_SIG_FORCE` 未开，AOSP 语义下允许 unsigned（仅 taint），需设备端 dmesg 实测。

---

## 7. 可行性判定

### 7.1 分级结论

| 方案 | 可行性 | 说明 |
|---|---|---|
| A. **把 KMRoot APK 直接当 Honor 6.6.118 工具使用** | ❌ 不可行 | exploit 目标 build 不匹配（符号 0.03% 重合）；OPLUS antiroot；debug 签名；无 MagicRoot 的验证/清理/多链框架 |
| B. **复用 KMRoot 的 6.6.118 资产 + 方法论，接入 MagicRoot 新 `66118` profile** | ✅ **可行（中等工作量，2 个硬前提待设备验证）** | 见 7.2 拆分；核心资产已提取并离线校验 |
| C. 把 APK 二进制逐字节 patch 成目标 build | ❌ 不推荐 | 214/225 符号地址不同 + struct 偏移/调用点不同 + 无源码级可审计性；panic 代价高 |
| D. 仅把 APK 作为参考/工具箱（符号表、ksud、manager、run.sh 语义） | ✅ 立即可做 | 已完成提取（EXTRACT），可并入 `release/toolkit` 的 6.6 适配工具 |

### 7.2 资产拆分（可直接用 / 需换参数 / 必须重做）

| 类别 | 资产 | 处置 |
|---|---|---|
| ✅ 与 build 无关，直接复用 | `take_slide.sh`（仅改 `D` 变量）、`prep_solve`、`forker`、`syms.txt` **格式**、`ksud`（定制 3.3.1，含 kallsyms/vermagic/bootstrap 能力）、`manager.apk`（官方 3.3.1）、`libadbroot.so`、`run.sh` 的 `held/miss.$BOOTID/PARKED/SAFE_KEEP` 安全状态机、Cfg 12 项落盘表、Engine 阶段/错误 token 解析 | 直接并入 MagicRoot 6.6.118 profile |
| 🔁 可复用但必须换输入 | `prep_patch` / Honor `ko_patch`（输入换成目标 `syms.txt` + 目标 slide + vermagic）、`kernelsu.ko`（重编或重定位）、目标 `syms.txt`（已离线产出）、Honor `kernel_profiles.sh`（新增 66118 profile 表） | 按 §6.3 常量生成 |
| 🔴 必须重做 | `t98260_plant` / `t98260_su`（目标 build 的链接期地址/结构偏移不同）；`run.sh` 的 OPLUS antiroot 段；kernel 版本白名单/门槛；`Engine` 的目标机型提示 | 基于 Honor 已有源码重编（见 7.3） |
| ⚪ 仅参考 | APK 的 UI/签名/包名/赞赏页 | 不采用 |

### 7.3 推荐的落地路线（与现有 Honor 方案衔接）

1. **新增 profile**：`kernel_profiles.sh` 增加
   `6.6.118-android15-8-gf17133276a57-abogki518694926-4k` → `PROFILE_ID=66118`，
   记录 §6.3 的链接期常量、`GEOM_*`（k_itimer 264/ cred 184 / task 偏移 0x818/0x820）、
   `syms`/`ko` 模板路径、KASLR 方式=“trace+syms”（复用 APK 方法）。
2. **重编 exploit**：以 Honor 现有 `binary-sources/98260-6.12/`（`uaf_plant_61258.c` +
   `pc98260_target_*.h` + `build-98260-direct.ps1`）为基线，替换为目标
   `pc98260_target_66118.h`（§6.3 常量），用工作区 NDK/zig 重建 `exploit/t98260_plant` 与
   `su` 客户端；`cve-98260-repo/src/*` 仅作方法参考。
3. **KASLR**：优先吸收 APK 方案 —— `take_slide.sh` + `prep_solve` + 目标全量 syms
   （**本次已产出** `syms-66118-target.nm.gz`）；保留 Honor 现有 `kaslr_slide_*` 作为回退。
4. **KSU**：用官方 KernelSU 3.3.1（manager.apk 已提取/签名官方）+ 目标 KMI LKM
   （重编或 APK base+`ksud insmod`），加载后按 Honor 现有 `ko_patch`/`prep_patch` 流程
   注入目标 syms+slide；`ksud install --libadbroot` 装 userspace；manager 用 `pm install -r`。
5. **antiroot**：删除 OPLUS 段；依据 Honor 目标（`work/targets/` 中 security/trust 相关 APK）
   实测是否需要处理（先不加，观察 `su`/SELinux/管理器是否正常）。
6. **App 层**：MagicRoot 已有 Kotlin/Compose + `run.sh/root_stage.sh` 框架，无需引入 KMRoot
   的 Java 层；只移植 Cfg 的 12 项落盘表、Engine 的 token 解析与“tracefs 硬门禁”提示。
7. **安全门禁**：沿用 `held`/`miss.$BOOTID`/`PARKED`/`SAFE_KEEP` 语义；每个 boot_id 只允许
   一次失败尝试；失败后必须重启，禁止 kill 未回收 zombie。

### 7.4 工作量与前置条件

| 工作项 | 估计 | 前置 |
|---|---|---|
| 目标 syms/常量/头文件（本次已完成 90%） | 已完成离线部分 | boot 镜像（已有） |
| exploit 重编 + 静态核对 | 1–2 人日 | Honor 源码/NDK（已有） |
| LKM 重编/重定位 + ksud 链路 | 0.5–1 人日 | KernelSU 源码（已有） |
| MagicRoot 66118 profile + 脚本集成 | 0.5–1 人日 | 现有工程 |
| 设备端分级验证 | 0.5–1 人日（含多次重启） | **tracefs 可写 + MTE/KASAN 可接受 + 设备可用** |
| **合计** | **约 3–5 人日（不含设备不可控风险）** | |

---

## 8. 验证步骤（离线已完成 / 设备端待执行）

> 本任务只做离线部分。设备端步骤写在这里供 Lead/后续执行者使用；
> **任何设备操作前须确认“自有设备、允许变砖风险、可恢复”**。

### 8.1 离线（本报告已执行，可复现）

| # | 检查 | 结果 |
|---|---|---|
| O1 | APK 解包 + 逐 entry sha256 | ✅ `EXTRACT/01-identity/` |
| O2 | manifest/签名/管理器签名 | ✅ v2 debug；manager 官方 KSU 3.3.1 签名 |
| O3 | DEX 类/字符串/12 项落盘表 | ✅ `EXTRACT/02-dex/` |
| O4 | 11 个载荷提取 + 类型识别 + sha256 | ✅ `EXTRACT/03-payload/` |
| O5 | `kernelsu.ko` 结构/vermagic/225 导入符号 | ✅ 按 6.6.127 编译；目标 225/225 名称可解析 |
| O6 | 目标 kallsyms 恢复 | ✅ 107,605 符号，base 与 APK 相同 |
| O7 | 目标 BTF 几何 | ✅ k_itimer 264 == APK 期望；cred 184；task 0x818/0x820 |
| O8 | 目标调用点/常量推导 | ✅ `derived-sites-66118.json` |
| O9 | 漏洞窗口静态同型（begin_new_exec 调用点） | ✅ 同 6.12.58 结构 |
| O10 | 生成目标 syms（nm 全量 + Honor 225） | ✅ `EXTRACT/05-target-66118/` |

### 8.2 设备端（建议顺序；每步失败即停，必要时重启）

| # | 步骤 | 判定 |
|---|---|---|
| D0 | 只读环境：`uname -r`、`getenforce`、`getprop ro.product.model`、`cat /proc/version`、`cat /proc/modules` | 确认 release 与目标串完全一致 |
| D1 | tracefs 权限：`test -w /sys/kernel/tracing/events/kmem/rss_stat/trigger`、`test -w /sys/kernel/tracing/events/sched/sched_blocked_reason/enable` | 必须成功（否则方案 A/整链不可行，需考虑其它 KASLR/触发途径） |
| D2 | slab 几何：`cat /sys/kernel/slab/posix_timers_cache/{object_size,order,objs_per_slab}` | 期望 264 / 1 / 31（警告不拦截） |
| D3 | 内核配置旁证：`zcat /proc/config.gz` 或 boot 镜像已知项 | 确认 MTE/KASAN 是否运行时开启（`dmesg | grep -i -E 'kasan|mte'`） |
| D4 | 只读 probe：`t98260_plant --probe`（目标 build 重编后） | `PROBE_OK` 且 `PROBE_KERNEL` 与 `uname -r` 一致 |
| D5 | KASLR：`sh take_slide.sh` + `prep_solve . syms.txt` | 输出 slide 且 votes/anchors 达阈值；建议连续 3 次成功 |
| D6 | 单链 dry-run：先 `--budget` 小、`--fast`，观察是否有 KASAN/MTE 报错/panic | 无 panic；有 `RECLAIM_MODE/CRED_INSTALLED` 进度 |
| D7 | 全链：`run.sh`（`KMROOT_FORCE_EXPLOIT` 视情况） | `PLANT_OK` + `MODULE_LOADED` + `su -c id`=0 |
| D8 | 管理器：`pm path me.weishu.kernelsu`、`su -c id`、重启后 KSU 仍在（LKM 不持久，重启失效） | 官方 3.3.1 管理器可打开 |
| D9 | 清理/回滚：`ksud unload`、`pm uninstall`、删除 `/data/local/tmp/kmroot98260`、重启 | 回到初始状态（LKM 临时、不写 boot 分区） |

**安全约束（必须遵守）**：不 patch/flash boot/vbmeta；不改系统分区；LKM 模式默认重启失效；
任何 `miss-safe`/`PARKED=1`/野写风险出现时立刻停止并重启，不 kill plant。

---

## 9. 风险清单

| 级别 | 风险 | 影响 | 缓解 |
|---|---|---|---|
| 🔴 高 | 目标内核 `CONFIG_ARM64_MTE=y` + `CONFIG_KASAN_HW_TAGS=y`（eng 内核） | UAF/野读可能被 MTE 标签/ KASAN 捕获 → oops/panic（目标 `PANIC_ON_OOPS=y`） | D4/D6 先 probe；必要时在 `--skip-selinux`/`--fast` 下小 budget 试；若普遍触发需重新设计利用（或换无 KASAN 的正式内核版） |
| 🔴 高 | exploit build 不匹配（g9bc vs f171；同名符号地址仅 0.03% 相同） | 直接复用 plant = 写错地址 → panic/变砖 | **必须重编**（§7.3）；不得直接跑 APK 内 plant |
| 🟠 中 | LKM 按 6.6.127 编，目标 6.6.118 | struct/KMI 漂移 → 加载失败或运行期崩溃 | 重编 android15-6.6/4k LKM；或 `prep_patch` + probe 验证 |
| 🟠 中 | `CONFIG_MODULE_SIG=y` + `MODULE_SIG_PROTECT=y`（Honor 厂商） | unsigned LKM 可能被拒 | 先 `insmod` 试；看 dmesg `module verification failed/Protected`；必要时走 ksud 的其它加载路径或放弃 LKM 只用 rootd 临时 root |
| 🟠 中 | tracefs 在 shell 域不可写 | probe/slide 直接失败 | D1 硬门禁；若不可写需换 KASLR 泄漏/触发途径 |
| 🟠 中 | 竞态 UAF 本身可能 panic（`PANIC_ON_OOPS=y`、`PANIC_TIMEOUT=-1`） | 变砖/重启 | `held`/`miss.$BOOTID`/`PARKED` 状态机；一次失败即重启；不 kill zombie |
| 🟡 低 | Honor antiroot/安全组件未知（OPLUS 段无效） | su 被检测/拦截、管理器闪退 | 先删除 OPLUS 段；按 `work/targets/` 安全组件清单观测；必要时在 rootd 存活窗口内 disable |
| 🟡 低 | SLUB freelist 随机化/`init_on_alloc`/shuffle page allocator 与 OPPO 不同 | 抢页命中率下降、重试次数增加 | run.sh 已有 `--budget/--fast/--timers/RETRY` 调参；目标 header 可加 per-build 参数 |
| 🟡 低 | APK 官方管理器签名与设备已装其它 KSU fork 冲突 | `pm install -r` 失败 | 先 `pm path` 判断已装包；必要时保留现有 KSU 版本或卸载重装（会丢模块配置） |
| ⚪ 信息 | 设备型号/系统版本未在 boot 镜像中确认（`ro.product.model` 待读） | 影响 antiroot 组件选择 | D0 读取后更新 |

---

## 10. 证据索引（关键文件与哈希）

| 证据 | 位置 | sha256/要点 |
|---|---|---|
| APK 整包 | `KMRoot(98260).apk.1` | `d86f5ec3…b51574fb6a`，20,496,369 B |
| OPPO 目标版本串 | `EXTRACT/03-payload/t98260_plant`（strings） | `6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k` |
| 5 阶段编排 | `EXTRACT/03-payload/run.sh`（226 行） | `391da76d…5c96a`；L28 几何、L57–L96 KSU、L144–L226 主流程 |
| slide 采样 | `EXTRACT/03-payload/take_slide.sh`（19 行） | `7b9a1a26…819c41` |
| slide 求解 | `prep_solve` | `6e040719…67d380`；usage/输出串见 §3.2 |
| ko 重定位工具 | `prep_patch` | `ec4071a7…b861`；usage 见 §4.7 |
| KSU LKM | `EXTRACT/03-payload/kernelsu.ko` | `e57ce23d…61ad`；225 导入/5046 重定位；vermagic 6.6.127 |
| 定制 ksud | `EXTRACT/03-payload/ksud` | `049491e2…bfb1b`；3.3.1/uapi5；vermagic 替换 + kallsyms |
| 官方管理器 | `EXTRACT/04-manager/manager.apk` | `b4a059ac…e450`；官方签名 v3.3.1 |
| OPPO 完整 syms | `EXTRACT/03-payload/syms.bin` | `3762646a…c41`；110,445 行 |
| **目标完整 syms** | `EXTRACT/05-target-66118/syms-66118-target.nm.gz` | 107,605 符号（本次从目标 Image 恢复） |
| 目标 225 符号（Honor 格式） | `EXTRACT/05-target-66118/syms-66118-target.honor-225.txt` | 全部命中 |
| 符号差异 | `EXTRACT/05-target-66118/sym-compare.json` | 104,356 同名 / 35 地址相同 |
| 目标几何 | `EXTRACT/05-target-66118/btf-geometry.json` | k_itimer 264 / cred 184 / task 0x818,0x820 |
| 目标常量/调用点 | `EXTRACT/05-target-66118/derived-sites-66118.json` | §6.3 全表 |
| 目标内核信息 | `EXTRACT/05-target-66118/kernel-info.md` | release/vermagic/config 摘要 |
| Honor 对照 | `MagicRoot-Enhanced-1.0.4-98260/main/app/assets/{run.sh,kernel_profiles.sh,98260/run98260.sh,syms_61258.txt,ko_patch,ksu-template*.ko}` | 见 §4 表 |
| Honor 目标头（方法参考） | `MagicRoot-Enhanced-1.0.4-98260/binary-sources/98260-6.12/pc98260_target_61258.h` | GEO_/LINK_/BNE_ 常量格式 |
| Honor KASLR 源码 | `.../binary-sources/64560/native/kaslr_slide_61258.c` L23–L33 | 硬编码 anchor 版 |
| 6.6.118 路线历史 | `.../docs/DEVICE-VERIFY.md` §36 | “已删除 118 路线源码树/release APK” |

---

## 11. 未决问题（交给设备端/后续）

1. 目标机 `ro.product.model`/`ro.build.display.id` 与实际系统版本（boot 镜像只带 AVB 属性；
   OEM base `AAK-LGRP1-CHN 10.0.0.175(SP1)`、`qti/sun/sun:15/…/eng.root`）。
2. tracefs 在 shell/SELinux 域的可写性（决定整链是否成立）。
3. MTE/KASAN_HW_TAGS 在运行时是否开启、UAF 链是否会被捕获（决定是否需要 MTE 绕过/换链）。
4. `GEOM_MEMSTART_PFN` 目标值（建议设备端从 `/proc/iomem`、`/proc/kpageflags` 或 dmesg
   的 memblock 输出核对；Honor 6.12 参考值为 `0x80000`）。
5. Honor 目标 antiroot/安全组件是否会拦截 su/KSU 管理器（`com.hihonor.*` 系列）。
6. 目标设备是否已有官方 KernelSU 3.3.1 管理器（决定 `pm install -r` 是否成功/是否需卸载）。
7. `t98260_plant` 的完整源码（APK 只给二进制；重编需以 Honor 现有源码为基线，不能保证
   与 APK 实现逐指令等价 —— 但 CVE/常量/接口已足够重建）。

---

## 12. 一句话给 Lead

> KMRoot(98260) APK 是 **ColorOS 6.6.118（OPPO PKJ110）的一键 root 参考实现**：
> 漏洞/思路与 Honor 现有 CVE-2026-98260 方案同源，**它的 tracefs+syms 求 KASLR slide、
> base LKM+ksud 运行期解析、官方 KSU 3.3.1 组合、以及 12 载荷落盘/5 阶段/reboot 安全
> 状态机可直接吸收**；但它的 exploit 二进制写死了 OPPO build 的地址（与 Honor 目标
> 6.6.118 符号重合率 0.03%），**必须用 Honor 已有源码按本报告 §6.3 的目标常量重编**。
> 离线侧我已把目标 build 的完整符号表、几何和调用点常量全部产出（`EXTRACT/05-target-66118/`），
> 适配剩余工作约 3–5 人日；能否真正跑通取决于设备端两个硬前提：
> **tracefs 可写** 与 **MTE/KASAN_HW_TAGS 下 UAF 链是否可用**。
