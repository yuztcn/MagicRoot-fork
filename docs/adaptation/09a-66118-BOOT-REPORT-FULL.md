# REPORT.md — boot(1).img 静态适配报告（CVE-2026-98260 / 6.6.118 android15-8）

> 任务：`work/adapt-66118/boot`（team task-2）。只做离线静态分析；**未连接、未写入任何真机，未执行 flash**。
> 输入：`work/adapt-66118/boot/boot(1).img`（100,663,296 B，sha256 `3dacd60d…ff4e`）
> 参照：`MagicRoot-Enhanced-1.0.4-98260`（Honor MagicOS / 6.12.x）与
> `release/toolkit/MagicRoot-Kernel-Adaptation-Toolkit-1.0.5`（boot.img→profile 适配流水线）
> 关键产物：`PATCHED/pc98260_target_66118.h`、`PATCHED/profile-66118.json`、`PATCHED/syms_66118.txt`、
> `PATCHED/build/exploit-android-key-ptr-66118`、`BOOT-HEADER.md`、`EXTRACT/*`

---

## 1. 结论（先看这一节）

1. **该 boot.img 的内核确实是 `6.6.118`**：
   `Linux version 6.6.118-android15-8-gf17133276a57-abogki518694926-4k (kleaf@build-host) … #1 SMP PREEMPT Sun May 31 12:01:53 UTC 2026`，
   vermagic = `6.6.118-android15-8-gf17133276a57-abogki518694926-4k SMP preempt mod_unload modversions aarch64`。
   KMI 代际 **android15-8**，4K page。
2. **它是 Honor（MagicOS）OEM 内核的 boot，不是 ColorOS/OPPO 的 boot**：
   内核内嵌 config 含 26 个 `CONFIG_HONOR_*`（Honor 私有特性），vbmeta `com.oem.base_version=AAK-LGRP1-CHN 10.0.0.175(SP1)`，
   AVB 布局与 Honor Magic8 Pro 6.12.58 参照 boot **同构**；全镜像/内核中无 `CONFIG_OPLUS_*`、无 OPLUS/OPPO 内核私有串。
   vbmeta fingerprint `qti/sun/sun:15/…` 只说明平台是 **高通 sun（SM8750 家族）/ Android 15 基线**。
3. **与 ColorOS 17 6.6.x KMRoot APK 的关系：同一 KMI 代际、不同构建，不可直接复用常量。**
   APK 载荷 `t98260_plant` 内置目标为 `6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k`；
   本 boot 是 `…-gf17133276a57-abogki518694926-4k`。两者都是 6.6.118/android15-8/4K，说明 **CVE-2026-98260 链迁移到本内核是可行的**
   （同类 UAF 前提已在本内核静态验证成立，见 §5.2），但 APK 里的 symbol/KASLR/target 常量 **对本构建全部无效**，必须用本报告 §5 的派生结果。
4. **静态适配已完成**：本报告给出了本内核的完整 per-build 常量（LINK_*、2 个 call site、BTF 几何、漏洞调用顺序），
   生成了可直接进流水线的 `pc98260_target_66118.h` / `profile-66118.json` / `syms_66118.txt`，
   并用项目自带 NDK r28c **成功编译出本构建的 `exploit-android-key-ptr-66118`**（静态产物，未上机）。
5. **不需要也不应该改 boot 分区**：MagicRoot 的 6.12 方案是「UAF 提权（98260）+ KSU LKM 临时加载」，
   boot.img 只用于离线提取 profile。本镜像 AVB 为 SHA256_RSA4096、OEM 私钥不在手上，
   **任何改动过的 boot.img 都无法通过 AVB 校验**（详见 §6），因此 `PATCHED/` 里给的是
   “无损重打包证明 + 适配常量/二进制”，明确标注**不可刷入**。
6. 主要风险：本构建 `PANIC_ON_OOPS=y + PANIC_TIMEOUT=-1`（错一个常量就 panic）、
   `KASAN/KFENCE/UBSAN/CFI_CLANG` 全开（与 Honor 6.12 参照一致，6.12 链已实测可跑通，但失败代价高）、
   `GEO_TASK_OBJSIZE` 与 `GEOM_MEMSTART_PFN` 只能设备端读取/校验。**未上机验证，禁止直接刷写/直接跑。**

---

## 2. 证据一：内核身份与构建

### 2.1 banner / vermagic（`EXTRACT/kernel-recon.json`、`kernel.bin` 内直接搜索）

```
Linux version 6.6.118-android15-8-gf17133276a57-abogki518694926-4k (kleaf@build-host)
(Android (11368308, +pgo, +bolt, +lto, +mlgo, based on r…), clang…, LLD 18.0.0)
#1 SMP PREEMPT Sun May 31 12:01:53 UTC 2026
vermagic: 6.6.118-android15-8-gf17133276a57-abogki518694926-4k SMP preempt mod_unload modversions aarch64
```

- kernel 为**未压缩 arm64 Image**：文件头 `MZ`（EFI stub），0x38 处 `ARM\x64`，`_text=0xffffffc080000000`。
- `CONFIG_KALLSYMS_ALL=y`、`CONFIG_KALLSYMS_BASE_RELATIVE=y`（offsets 为绝对地址）、内嵌 `IKCONFIG`、
  内嵌 **完整 BTF**（6,212,735 B，193,328 个 type）→ 可完整离线做符号/结构体派生（§5）。
- 构建身份：Honor 从 ACK android15-6.6 生成，`-abogki518694926` 为 ACK build id，`-g<commit>` 为内核 commit 前 12 位。

### 2.2 OEM 证据（config 内嵌，`EXTRACT/kernel.config`）

```
CONFIG_HONOR_IO_MEASURE=y / CONFIG_HONOR_PSI=y / CONFIG_HONOR_PGO_CLANG=y / CONFIG_HONOR_PRINTK_PREFIX=y
CONFIG_HONOR_CPU_FREQ_POWER_STAT=y / CONFIG_HONOR_ALLOC_STACK_PAGE_ON_DEMAND=y / CONFIG_HONOR_VMAP_ALLOC_PAGE_ON_DEMAND=y
CONFIG_HONOR_BLK_CGROUP_IOSMART=y / CONFIG_HONOR_BLK_CGROUP_IOLIMIT=y / CONFIG_HONOR_BLOCK_MQ_DEADLINE=y
CONFIG_HONOR_MEM_STATS=y / CONFIG_HONOR_UFS_DSM=y / CONFIG_HONOR_DMABUF_MEMINFO=y
CONFIG_HONOR_BINDER_TRANSACTION_BRIEF=y / CONFIG_HONOR_BINDER_TRANSACTION_DESCRIPTOR=y
CONFIG_HONOR_BOOT_TIME=y / CONFIG_HONOR_CACHE_DISK=y / CONFIG_HONOR_F2FS_DSM=y
CONFIG_HONOR_F2FS_FS_COMPRESSION_OPTM(+_DEBUG/_RA_ALIGNMENT)=y / CONFIG_HONOR_F2FS_HOTNESS_CLUSTERING=y
CONFIG_HONOR_F2FS_BLKFRAG=y / CONFIG_HONOR_F2FS_SMART_DISCARD=y / CONFIG_HONOR_F2FS_FS_SIS_DISK=y
CONFIG_HONOR_THREAD_STACK_STAT=y / CONFIG_HONOR_DIE_CATCH=y
```

- `CONFIG_LOCALVERSION="-4k"`、`CONFIG_CMDLINE="console=ttynull stack_depot_disable=on cgroup_disable=pressure
  kasan.stacktrace=off kvm-arm.mode=protected bootconfig ioremap_guard"` —— 与 Honor 6.12 参照 config 逐字同源
  （仅多 `ioremap_guard`，6.6 特性），进一步证明同一条 Honor GKI 配置基线。
- 另有 `CONFIG_MTK_GZVM=m`、`CONFIG_GUNYAH=y`（GKI defconfig 通用项）与大量平台项，**不代表设备平台**；
  平台判断应以 vbmeta fingerprint 的 `qti/sun/sun` 为准。

### 2.3 vbmeta 构建元数据（`EXTRACT/avb-layout.json`）

| property | 值 | 含义 |
|---|---|---|
| `com.oem.base_version` | `AAK-LGRP1-CHN 10.0.0.175(SP1)` | Honor OEM base version（设备代号 AAK，版本 10.0.0.175 SP1） |
| `com.android.build.boot.os_version` | `15` | Android 15 基线 |
| `com.android.build.boot.fingerprint` | `qti/sun/sun:15/AQ3A.250214.001/eng.root.00000000.000000:user/release-keys` | 高通 sun / Android 15 基线 / OEM 流水线固定写法 |
| `com.android.build.boot.security_patch` | `2026-08-01` | 安全补丁级别 |
| boot signature 属性 | `ARCH=arm64`、`BRANCH=`、`KERNEL_RELEASE=6.6.118-android15-8-gf17133276a57-abogki518694926-4k` | GKI boot signature 双签名 |

设备代号 `AAK` 与本项目已有 Honor 代号体系（`BKQ` = Magic8 Pro、`MLY`、`YLP`）同级；
公开研究仓库把 `AAK-AN00` 标为 Honor WIN RT（外部旁证，不作本报告唯一依据：
<https://github.com/hui191/cve-2026-43499-aak-an00>）。**结论：Honor AAK（Android 15 / MagicOS 10.0.0.175），不是 ColorOS。**

### 2.4 与 ColorOS 17 6.6.x KMRoot APK 的构建对照

| 项 | 本 boot.img | KMRoot(98260).apk.1 期望目标 |
|---|---|---|
| kernel release | `6.6.118-android15-8-gf17133276a57-abogki518694926-4k` | `6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k`（`t98260_plant` 内嵌串） |
| KMI | android15-8 / 4K | android15-8 / 4K |
| `k_itimer` 大小 | 0x108 = **264 B**（BTF） | run.sh 几何自检按 264 B / order-1 / 31 obj 推导 |
| 结论 | — | **同一内核代际，不同 build；常量/符号不可跨构建照抄** |

> `k_itimer` 264 B 与 APK 端口假设一致，是个好信号：6.6.118 的 `posix_timers_cache` 几何与 APK 端口相同，
> 但 KASLR/符号/call-site 必须按本构建重推（本报告已完成，见 §5）。

---

## 3. boot.img 结构（详见 `BOOT-HEADER.md`）

- boot header **v4**、`header_size=1584`、kernel_size **0x2368A00**、ramdisk_size **0**、v4 signature_size **0**、cmdline 空、os_version=0；
- kernel @ **0x1000**；内容页对齐结束 @ 0x236A000；
- 0x236A000–0x236E000：Honor/GKI 的 **16 KiB boot signature**（2 × AVB0 meta，SHA256_RSA4096，含 `KERNEL_RELEASE` 属性）；
- 0x236E000：**分区 vbmeta**（2496 B，SHA256_RSA4096，hash 描述符 `partition_name=boot`、`image_size=37,150,720`）；
- 0x5FFFFC0：**AVB footer**（96 MiB 分区末尾）；
- 无损重打包（`repack_boot.py` → `PATCHED/boot-repack-identical.img`）与原镜像 **sha256 完全一致**。

---

## 4. 与 Honor 6.12.58 方案的差异表（能否复用）

| 维度 | 6.12.58 方案（本项目已实现） | 本 6.6.118 构建 | 可否复用 |
|---|---|---|---|
| 攻击链 | CVE-2026-98260（posix timer UAF）+ KSU LKM 临时加载 | 同（UAF 前提已静态验证，§5.2） | ✅ 方法可复用 |
| 提权常数 | `pc98260_target_*.h`（per-build） | 已重新派生 `pc98260_target_66118.h` | ✅ 已生成 |
| KASLR | 98260 链自测 slide（tracefs/perf），64560 用 `kaslr_slide_*` | 98260 链方式仍适用；64560 anchors 缺 `ufshcd_issue_dev_cmd`，需换锚点 | ⚠️ 64560 侧需改锚点 |
| KSU LKM | 预编译 android16-6.12 KMI 模板（6.12.76-4k-…），设备端 `ko_patch` 改 vermagic + 符号 SHN_ABS | **6.12 模板不可用**（6.6 内核缺 `*_noprof` 等 12~14 个符号）；改用 6.6 家族 LKM（如 APK 内 `kernelsu.ko`，225 个未定义符号在本 kallsyms **全部可解析**） | ⚠️ 换 KO，流程同 |
| boot.img 使用方式 | 仅离线提取 Image/kallsyms/BTF → profile；不刷 boot | 同 | ✅ |
| AVB/签名 | 不改 boot | 不改 boot（OEM 私钥不可得，改必拒） | ✅ |
| SELinux 处理 | UAF 后置 permissive + KSU | 同；本镜像 config `CONFIG_SECURITY_SELINUX_DEVELOP=y`，运行期可切 permissive | ✅ |

---

## 5. 静态适配（本报告核心）

### 5.1 符号与 call site（`derive_profile.py` + `EXTRACT/kallsyms.txt` + capstone 复核）

生成方式：
```powershell
python release/toolkit/MagicRoot-Kernel-Adaptation-Toolkit-1.0.5/tools/vmlinux-to-elf/…/kallsyms_finder
       EXTRACT/kernel.bin --output EXTRACT/kallsyms.txt      # 107,605 个唯一符号
python …/tools/cve-98260-porting-tools/derive_profile.py EXTRACT/kernel.bin EXTRACT/kallsyms.txt x
python work/adapt-66118/boot/gen_profile.py                  # 生成 header/profile/syms
```

| 常量 | Honor 6.12.58（参照） | **本 6.6.118（派生值）** | 说明 |
|---|---|---|---|
| LINK_SELINUX_STATE | 0xffffffc0827e7a60 | **0xffffffc0823ba418** | `selinux_state` |
| LINK_INIT_USER_NS | 0xffffffc082572138 | **0xffffffc08218ef98** | `init_user_ns` |
| LINK_ROOT_USER | 0xffffffc0825723b0 | **0xffffffc08218f228** | `root_user` |
| LINK_INIT_GROUPS | 0xffffffc082573878 | **0xffffffc082190788** | `init_groups` |
| LINK_INIT_UCOUNTS | 0xffffffc082573d48 | **0xffffffc082190cf8** | `init_ucounts` |
| GEO_SELINUX_WRITE | selinux_state-7 | **0xffffffc0823ba411** | `-7` 由 BTF 布局复核仍成立 |
| LINK_ALLOC_TIMER | 0xffffffc08051a110 = do_timer_create+0xac | **0xffffffc0803aec40 = do_timer_create+0x94** | `bl kmem_cache_alloc`；cache=`posix_timers_cache`；唯一命中 |
| LINK_ALLOC_CRED | 0xffffffc08019c474 = prepare_creds+0x2c | **0xffffffc0802536a0 = prepare_creds+0x20** | `bl kmem_cache_alloc`；cache=`cred_jar`；唯一命中 |
| LINK_ALLOC_TASK | copy_process+0x190（实测） | **0xffffffc0801e0e48 = copy_process+0x144** | cache=`task_struct_cachep`（6.6 无 noprof 变体） |

> 6.6 内核没有 `CONFIG_MEM_ALLOC_PROFILING`，因此不存在 `*_alloc_tag` 干扰项，
> `do_timer_create`/`prepare_creds` 内各自只有一次 `bl kmem_cache_alloc`，派生结果唯一、无歧义。

### 5.2 漏洞前提静态验证（必须项）— 成立 ✅

`begin_new_exec`（`0xffffffc0801e7ccc`，706 条指令）内的调用顺序（capstone 反汇编，`EXTRACT/disasm-begin_new_exec.txt`）：

| 偏移 | 调用 | 对应 6.12.58 参照 |
|---|---|---|
| +0x3EC | `bl release_task` | BNE_RELEASE_TASK_OFF=0x410 |
| +0x4E8 | `bl exec_mm_release`（`exec_mmap()` 被内联，含 +0x4F4 `down_write_killable` / +0x508 `down_read_killable`） | BNE_DOWN_READ_OFF=0x50c |
| +0x6AC | `bl posix_cpu_timers_exit` | BNE_TIMERS_EXIT_OFF=0x87c |
| +0x6BC | `bl exit_itimers` | BNE_EXIT_ITIMERS_OFF=0x88c |

即 **`release_task → exec_mmap → posix_cpu_timers_exit → exit_itimers`** 的危险顺序在 6.6.118 上仍然存在
（与 CVE-2026-98260 移植流程第 1 步要求一致）。`alloc_posix_timer` 与 6.12 一样被内联（`do_timer_create` 内无该符号），
因此 timer alloc site 必须落在 `do_timer_create` 内——已按此取 +0x94。

### 5.3 结构体几何（BTF，`EXTRACT/btf-geometry.json`）

| 常量 | 6.12.58 | **本 6.6.118** | 备注 |
|---|---|---|---|
| `task_struct.cred` | 0x900 | **0x820** | |
| `task_struct.real_cred` | 0x8f8 | **0x818** | |
| `task_struct.comm` | 0x910 | **0x830** | |
| `sizeof(task_struct)` | ~0x1280 | **0x12C0 (4800)** | 与 slab obj 不同，见下 |
| `k_itimer.it`（=cpu_timer.node） | 0x78 | **0x78** | 相同 |
| `sizeof(k_itimer)` | 0x100 | **0x108 (264)** | 与 APK 端口 264 B 一致 |
| `sizeof(cred)` | 184 | **184** | |
| cred.uid/fsuid | 0x8 / 0x20 | **0x8 / 0x20** | 全部字段相同 |
| cred.cap_effective/bset/ambient | 0x40/0x48/0x50 | **0x40/0x48/0x50** | |
| cred.security/user/user_ns/ucounts/group_info | 0x80/0x88/0x90/0x98/0xa0 | **0x80/0x88/0x90/0x98/0xa0** | uaf_plant 里硬编码的 136/144/152/160 全部命中 ✅ |
| `selinux_state` | enforcing=0, initialized=1, size=0x80 | **同** | `GEO_SELINUX_WRITE=-7` 仍成立 |
| `GEO_TASK_OBJSIZE` | 5696（实机 slabinfo） | **未知（只能设备端读）** | 默认种子 4800，`uaf_plant` 运行期用 `/proc/slabinfo` 自动覆盖 ✅ |
| `GEOM_MEMSTART_PFN` | 0x80000 | 0x80000（沿用，需设备端 `/proc/iomem` 复核） | 错会造成 pfn 偏移 |

`CAP_FULL`：`cap_last_cap=40` → `0x1ffffffffff`（>=5.9 内核约定，与 6.12 相同；设备端可用 `cat /proc/sys/kernel/cap_last_cap` 复核）。

### 5.4 已生成的适配产物（`PATCHED/`）

| 文件 | 说明 |
|---|---|
| `pc98260_target_66118.h` | 完整 per-build 常量（§5.1/5.2/5.3），可直接 `-I` 编译 |
| `profile-66118.json` | App/工具链可读的 schema-1 profile（十六进制字符串地址，避免 JS double 丢精度） |
| `syms_66118.txt` | 225 行 `name 0x<link_addr>`，供 `ko_patch` 使用（来源：APK 的 6.6 家族 `kernelsu.ko` 的全部未定义符号；**0 个缺失**） |
| `build/exploit-android-key-ptr-66118` | 用 NDK r28c + 本 header 编译的 98260 载荷（静态产物，未上机；sha256 `2d9a3042…0fbc`） |
| `build/pc98260-su-66118` | su 客户端（与应用无关，**与官方发布资产逐字节相同**：`696240ec…6ca5`，反证编译环境可复现） |
| `boot-repack-identical.img` | 无损重打包证明（sha256 与原镜像一致，**不可刷入、也不需要刷**） |

### 5.5 KSU LKM 适配（提权之后）

项目现有流程：`ksu-template*.ko` + `syms_<profile>.txt` + 设备端 `ko_patch`
（`ko_patch <in.ko> <out.ko> <syms.txt> <slide> <kernel_release>`：把 KO 的所有 `SHN_UNDEF` 符号
改写为 `SHN_ABS = link_addr + slide`，并把 `.modinfo` 的 vermagic 换成目标 kernel release 后再 insmod）。

- **6.12 的 5 个模板不能用于本内核**：它们由 6.12 源码树构建（vermagic `6.12.76-4k …`），
  依赖 `__alloc_pages_noprof / __kmalloc_noprof / kmemdup_noprof / … / mem_alloc_profiling_key` 等
  12~14 个本内核不存在的符号（`EXTRACT/ksu-lkm-analysis.json`）。
- **可用的 6.6 家族模板**：ColorOS KMRoot APK 内的 `kernelsu.ko`（vermagic `6.6.127-4k-g46a034eca005-dirty`，
  225 个未定义符号在本 6.6.118 kallsyms 中 **全部可解析**，`__versions` 为空）。经 `ko_patch` 处理后可尝试加载；
  目标 vermagic 串：`6.6.118-android15-8-gf17133276a57-abogki518694926-4k SMP preempt mod_unload modversions aarch64`。
- 其它约束（已核对本内核 config）：`# CONFIG_MODULE_SIG_FORCE is not set`、`# CONFIG_MODULE_FORCE_LOAD is not set`、
  `CONFIG_MODVERSIONS=y`；因此 **必须走 ko_patch 的 SHN_ABS 重定位路线**（不能再让内核按名字解析符号），
  vermagic 必须逐字符匹配（patch 到上面这串）。`CONFIG_STRICT_MODULE_RWX=y` 正常，不影响该路线（6.12 同理）。
- 加载后仍需 manager/ksud 与其 LKM **同源同 uapi**（KernelSU 官方 `me.weishu.kernelsu`；APK 内即该 manager）。

### 5.6 KASLR slide

98260 链在设备上自测 slide（`t98260_plant` 的 `--slide` 参数 / `take_slide.sh`），无需 boot.img 提供；
64560 链的 `kaslr_slide_*` 需要按本内核重生成锚点：本 kallsyms 里 `worker_thread / rcu_gp_fqs_loop /
rcu_gp_kthread / folio_wait_bit_common / icc_set_bw` 都在，**但 `ufshcd_issue_dev_cmd` 不存在**，
使用 64560 路线时需替换锚点（如 `ufshcd_send_command` 或 scsi 层函数）。本任务以 98260 路线为主，不阻塞。

---

## 6. boot 重打包参数与 AVB 处理（结论：不改、不刷）

### 6.1 若要重打包（参数已备好）

- header：**保持 v4 原样**（header 页 4096 B、签名区字段、os_version=0、cmdline 空都应与原镜像一致）；
- 布局：`header(0x1000) | kernel(kernel_size) | 页对齐 pad | (v4 signature, 本镜像为空) | 16 KiB boot signature | 分区 vbmeta | 零填充 | 64 B AVB footer`；
- `PATCHED/boot-repack-identical.img` 已证明按此参数 **逐字节可复现**；
- 若换 kernel：必须同步重算/重签 **16 KiB boot signature 的两个 AVB0**、**分区 vbmeta hash**，并重写 footer 中的
  `original_image_size / vbmeta_offset / vbmeta_size`。

### 6.2 AVB 结论（关键风险）

- 本镜像 boot 分区被 **SHA256_RSA4096** AVB 保护；分区 vbmeta 公钥 sha256 `c6e46281…`，
  boot signature 公钥 `a765081a… / c6cf3af3…` —— **OEM 私钥不可得**；
- 因此 **任何修改过内容的 boot.img 都无法重签**；锁 bootloader 的设备会直接拒绝启动（软砖风险）；
- MagicRoot 6.12 方案本身**不刷 boot、不改系统分区**：只用 boot.img 离线提取 profile，提权在内存中完成
  （UAF→rootd→KSU LKM 临时加载），SELinux/cred 修改均为运行期内存写。
- 若将来确需改 boot：唯一合法路径是「已解锁 bootloader + 自持 AVB key 重签并 disable-verity/verification」，
  属于设备侧高风险操作，**不在本任务范围，也没有执行**。

---

## 7. 风险评估

| 风险 | 等级 | 说明 / 缓解 |
|---|---|---|
| 常量错 → panic | **高** | `PANIC_ON_OOPS=y`、`PANIC_TIMEOUT=-1`。本报告所有常量均双路复核（derive_profile + capstone + BTF），但仍需设备端 `--check` 灰盒验证后再跑 UAF |
| `GEO_TASK_OBJSIZE` 未知 | 中 | `uaf_plant` 运行期 `/proc/slabinfo` 自动覆盖；`GEOM_MEMSTART_PFN` 需 `/proc/iomem` 复核 |
| KASAN/KFENCE/UBSAN/CFI 全开 | 中 | 与 Honor 6.12 参照一致；6.12 链已实测可跑通，但 UAF 被 KASAN 采样命中概率存在；`panic_on_warn` 未确认（需设备端 `dmesg`/cmdline 复核） |
| 内核为 6.6.118 但 build 与 KMRoot APK 不同 | **高（若直接复用 APK 载荷）** | APK 的 `t98260_plant` 只认 `g9bc34d5b0c79`，本构建会被 `WARN=kernel-mismatch` 并可能 panic。**必须用本报告适配产物** |
| AVB/刷机 | 高 | 不改 boot、不刷机；`PATCHED/*.img` 仅作证据，刷入必失败（见 §6.2） |
| 缺 `vendor_boot`/`init_boot` | 中 | cmdline/bootconfig/SELinux 初始状态未知；设备端只读采集后再确认（`uname -r`、`cat /proc/cmdline`、`getenforce`） |
| 未上机验证 | 高 | 本任务全部产物为**静态**，未经真机。任何后续动作必须按 §8 顺序、且只读先行 |

---

## 8. 最小可行验证步骤（后续执行者用；本任务未执行）

静态（本任务已完成）：header 解析、无损重打包、kernel 版本/符号/BTF/漏洞顺序、profile 生成、NDK 可复现编译。

设备端（只读 → 灰盒 → 单次，全部需人工在场；**未在本任务中执行**）：
1. `adb shell uname -r` 必须等于 `6.6.118-android15-8-gf17133276a57-abogki518694926-4k`（不等则拒绝继续）；
2. 只读：`cat /proc/slabinfo | grep -E 'task_struct|posix_timers'`（核对 obj 大小）、`cat /proc/iomem | head`、
   `cat /proc/cmdline`、`getenforce`、`cat /proc/sys/kernel/random/boot_id`；
3. `./exploit-android-key-ptr-66118 --check --quick`（只读）判 `verdict=ok`（tracefs/trigger/event 均 1）；
4. slide 单独探测（只读）确认 2 MiB 对齐、多次一致；
5. 干净重启后一 boot 一样本跑一次 plant（出现 `[cred] installed` / `uid=0` 才算成功；出现 `miss` 只重启、
   绝不 kill 进程）——参照 6.12 实测参数：`PC98260_MAX_ATTEMPTS=12 PC98260_NO_FALLBACK=1 PC98260_BUDGET_S=180
   PC98260_WAIT_CAP_S=8 PC98260_CHURN_ROUNDS=8 PC98260_CHURN_PER_CPU=32`（本 6.6 构建需重新标定，先小 churn）；
6. KSU：`ko_patch kernelsu.ko ksu-patched.ko PATCHED/syms_66118.txt <slide>
   "6.6.118-android15-8-gf17133276a57-abogki518694926-4k"`，校验 `PATCHED=225 MISSING=0` 后
   `ksud insmod`（失败看 `dmesg | grep -iE 'kernelsu|vermagic|unknown symbol|disagrees'`）。

---

## 9. 交付物清单

| 文件 | sha256 / 说明 |
|---|---|
| `work/adapt-66118/boot/REPORT.md` | 本文件 |
| `work/adapt-66118/boot/BOOT-HEADER.md` | header/布局/AVB 全字段 |
| `work/adapt-66118/boot/EXTRACT/boot-header.json` | header 解析结果 |
| `EXTRACT/kernel.bin` | 37,128,704 B，sha256 `e8ce5dbf904ecb602b7c486ed365f0812d71d1696bddf79d188f6872906f9c79` |
| `EXTRACT/kallsyms.txt` | 4,943,619 B（110,992 行 / 107,605 唯一符号），sha256 `413d8fc5fd8a7084fa6fe036c6d383735aa5ec6f24e94585740d926930d00f48` |
| `EXTRACT/vmlinux.btf` | 6,212,735 B，sha256 `9d1dce05bb9e0b372b77489081cabbf4f4c35e36a8d10e95479661f307341fb9` |
| `EXTRACT/kernel.config` | 212,910 B，sha256 `86f19df322c2ecb83ff1eb98bb83bdbb7d672fff2ee2033d4c29e0c069885781` |
| `EXTRACT/btf-geometry.json` / `btf-dump.txt` | 结构体几何（含修正后的 bit→byte 偏移） |
| `EXTRACT/disasm-begin_new_exec.txt` / `disasm-timer-cred.txt` | 漏洞/分配点反汇编证据 |
| `EXTRACT/avb-layout.json` / `repack-evidence.txt` | AVB footer/vbmeta/boot signature + 无损重打包证明 |
| `EXTRACT/ksu-lkm-analysis.json` | 候选 LKM 与本内核符号兼容性 |
| `EXTRACT/deep-recon.json` / `kernel-recon.json` / `config-compare` 等 | 原始侦察输出（含 sha256 清单 `EXTRACT/SHA256SUMS.txt`） |
| `PATCHED/pc98260_target_66118.h` | per-build 常量头（可直接编译） |
| `PATCHED/profile-66118.json` | schema-1 profile |
| `PATCHED/syms_66118.txt` | 225 个 LKM 符号（0 缺失） |
| `PATCHED/build/exploit-android-key-ptr-66118` | 静态编译产物 sha256 `2d9a3042d24b976b3affd70837d6b405d21e161ac00cd612418b28ee92230fbc`（未上机） |
| `PATCHED/build/pc98260-su-66118` | sha256 `696240ec583616d3677e693d1e5d3783b7f590b682ace8d7ca830bc757516ca5`（与官方资产逐字节相同） |
| `PATCHED/boot-repack-identical.img` | 无损重打包证明，**不可刷入** |
| `PATCHED/PATCH-NOTES.md` | 产物使用说明与禁令 |

## 10. 限制与未完成项

1. 未提供 `init_boot.img` / `vendor_boot.img` / 分区 vbmeta 镜像 → cmdline/bootconfig/dm-verity 状态无法静态确认；
2. 本机无 avbtool，vbmeta hash 描述符尾部字段顺序未做逐字节复核（原始 body 已保存）；
3. `GEO_TASK_OBJSIZE`、`GEOM_MEMSTART_PFN` 必须设备端只读确认；
4. 编译出的 plant 二进制**未在真机运行**；`TARGET_KERNEL_SHA256` 已填 kernel Image 的 sha256，但 App 侧门禁字段
   是否以 boot.img 或 Image 的 sha256 为准，需按 App 实现核对（本项目为 `pc98260_target.h` 注释 optional）；
5. 64560 链若需要，需补 `ufshcd_issue_dev_cmd` 替代锚点并重新生成 `kaslr_slide_66118.c`。


