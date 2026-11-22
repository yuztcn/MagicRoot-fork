# MagicRoot 1.0.6：BRM、6.6、SELinux 与热重启适配

## 基线和验证边界

- 基线：`MagicRoot-1.0.5-source (2).zip`。其中没有独立 boot 镜像，因此没有新增可由该包推导的内核 profile。
- BRM 输入：`MagicRoot-6.18.21-adapt-2026-10-31.zip` 的 g186 boot/kernel/BTF/kallsyms，以及 `sganggs/CVE-2026-98260-BRM-AN00` 的适配资料。
- 6.6 输入：`MagicRoot-6.6.x-kernels-20261101.zip` 的三组 boot/kernel/BTF/kallsyms。
- SELinux 参考：`MyUse.zip`、`CGA-W00-KernelSU-复刻包 (2).zip`。保留官方 KernelSU 的规则注入和 late-load 语义，没有替换为 CGA 的精简初始化代码。
- 热重启参考：`热重启修复Zygisk和Lsp.zip` 以及 source (2) 已有的 `lsposed-hotfix.sh`。
- 当前完成的是静态推导、构建、脚本和安装包检查。BRM/6.6 真机提权、late-load 以及真实 zygote 热重启须分别在精确匹配的设备上验证；不能将静态 `MISSING=0` 当成实机成功。

## BRM-AN00 / g186

精确 release：

```text
6.18.21-android17-5-ge186062ea75f-abogki564062290-4k
```

Image SHA-256：`3f4ba772baf9e345a95c38fbdd92db154b09b6fd741761798a8a0a801dd4e554`。

官方 KernelSU 原始模板 SHA-256：`7e25d68419d08535d35e3630d9f0ff1a08e97a7026d36e878991eecb13554d9f`。

BRM 兼容模板：`main/app/assets/98260-61821-brm/ksu-template-61821-kernelsu.ko`，SHA-256：`f8dd188f3feb05998f145286c4093da2aaa944fca2cb226db561b1b784761f1e`（2026-11-03 由上游 g186 115 模块替换旧 6.12.76 兼容镜像）。

`binary-sources/61821-brm/build-ksu-brm.py` 校验原始模板哈希及目标地址，再用 `ld.lld -r` 将官方模板与 `ksu_brm_compat.S` 链接。原始模板的 225 个未定义符号中，目标内核缺少 7 项；补齐后成品有 220 个未定义符号，全部可由 `syms_61821_brm.txt` 的 263 项覆盖。

| 缺失项 | g186 处理 |
|---|---|
| `override_creds` / `revert_creds` | 按 6.18.21 的 inline 语义，用 `stlr` 替换当前任务 `cred`，返回旧指针；不额外增减 cred 引用计数 |
| `__get_task_comm` | 从 `task_struct.comm` 复制，调用 `sized_strscpy`，返回目标缓冲区 |
| `ebitmap_cmp` | 跳转到内核中等价实现 `ebitmap_equal` |
| `krealloc_noprof` | `krealloc_node_align_noprof(p,size,1,gfp,NUMA_NO_NODE)` |
| `kvrealloc_noprof` | `kvrealloc_node_align_noprof(p,size,1,gfp,NUMA_NO_NODE)` |
| `tracepoint_srcu` | 该内核 tracepoint 注销已使用 RCU；保留调用者紧随其后的 `synchronize_rcu`，去除已经不存在的 SRCU 等待 |

### BRM 关键布局与地址

| 项目 | 值 |
|---|---|
| `task_struct.real_cred` / `cred` / `comm` | `0x900` / `0x908` / `0x918` |
| `cred.size` / `uid` / `cap_effective` / `cap_bset` | `0xb8` / `0x08` / `0x40` / `0x48` |
| `cred.security` / `user_ns` | `0x80` / `0x90` |
| `k_itimer.size` / `it` / `rcu` | `0x180` / `0xe0` / `0x158` |
| `cpu_timer.node` | `it+0x00` |
| `posix_timers_cache` | 384 B object、21 objects、order-1 |
| `do_timer_create` / `LINK_ALLOC_TIMER` | `0xffffffc0803e1f18` / `0xffffffc0803e1fd0` |
| `prepare_creds` / `LINK_ALLOC_CRED` | `0xffffffc08014cd64` / `0xffffffc08014cd90` |
| `selinux_state` | `0xffffffc08299a6f0` |
| `sized_strscpy` | `0xffffffc08017d86c` |
| `ebitmap_equal` | `0xffffffc08019c4cc` |
| `krealloc_node_align_noprof` | `0xffffffc0801eaa04` |
| `kvrealloc_node_align_noprof` | `0xffffffc0802d49a8` |
| `MEMSTART_PFN` | `0x80000`，仍需实机确认 |

这些地址都是链接地址，运行时仍须使用当前 boot 的 slide。构建脚本不接受其他内核地址，也不会用 g928 或其他 flavor 的模块替代 BRM 官方兼容模块。

## 官方 KernelSU / SELinux 交接

CGA 的有效修复是恢复规则注入、缓存 SID、设置 KSU cred 并恢复 Enforcing；MyUse  additionally 证明了加载进程交接的重要性。官方 BRM 模板已经包含这些功能，因此没有把 CGA 的 `src/init.c` 覆盖进来。

构建脚本检查 `.init.text` 对以下符号的实际调用，缺一项就拒绝构建：

```text
apply_kernelsu_rules
cache_sid
setup_ksu_cred
escape_to_root_for_init
setenforce
```

`kernel_profiles.sh` 官方 flavor 固定选择 `ksu-template-61821-kernelsu.ko`。`run98260.sh` 在该 profile/flavor 下跳过管理器内通用的 6.18 模块，先把修补后的模块放入 `/data/adb/ksu/lib/`，再由官方 `ksud late-load` 在同一进程完成交接。管理器包名仍为 `me.weishu.kernelsu`，不使用 ReSuki 的包名或用户态冒充官方 KernelSU。2026-11-03 起该文件与 `98260-h1c/ksu-template-115.ko` 相同，旧 6.12.76 兼容镜像已移除。

运行日志增加：

```text
98260_SELINUX_HANDOFF=<0|1> enforcing=<state>
98260_KSU_ROOT_ID=<id output>
```

验证通过新的 KSU su provider 执行 `id`，不使用恢复 Enforcing 后可能已失效的旧 rootd socket。

## 6.6.x profiles

三份 kernel、boot、vmlinux、BTF 和 kallsyms 的 SHA-256 均与 `kernel-meta.json` 一致。g554 的两个 boot 共用同一 kernel，因而共用 profile，不按 boot 文件名或机型另建分支。

| profile | `selinux_state` | `LINK_ALLOC_TIMER` | `LINK_ALLOC_CRED` | `begin_new_exec` |
|---|---|---|---|---|
| g554 / 6.6.118-g554929766a0d | `0xffffffc0823ba418` | `0xffffffc0803afcec` | `0xffffffc080238458` | `0xffffffc0801d20bc` |
| f171 / 6.6.118-gf17133276a57 | `0xffffffc0823ba418` | `0xffffffc0803aec40` | `0xffffffc0802536a0` | `0xffffffc0801e7ccc` |
| 6658 / 6.6.58-g6484937db664 | `0xffffffc082393fa0` | `0xffffffc080390d84` | `0xffffffc08020d684` | `0xffffffc08029220c` |

三者的 BTF 布局一致：

```text
task_struct.size=0x12c0  real_cred=0x818  cred=0x820  comm=0x830  pid=0x618
cred.size=0xb8  uid=0x08  cap_effective=0x40  cap_bset=0x48
cred.security=0x80  user_ns=0x90
k_itimer.size=0x108  it=0x78  rcu=0xf8
cpu_timer.node=it+0x00
selinux_state.enforcing=+0x00
```

f171/g554 的漏洞清理调用偏移为 `0x3ec`、`0x508`、`0x6ac`、`0x6bc`。6658 的对应实际调用位置已更正为：

```text
release_task          begin_new_exec+0x990
__percpu_down_read    begin_new_exec+0x9ac
posix_cpu_timers_exit begin_new_exec+0x298
exit_itimers          begin_new_exec+0x2a8
```

这些 BNE 常量目前未被 `uaf_plant_61258.c` 引用，因此修正头文件不改变现有载荷哈希。它们用于保留准确的后续适配资料，不能按地址大小推断源码执行顺序。

`run98260.sh` 已补回 `*6.6.58*g6484937db664*) PROFILE_LOCAL=6658`，不再回退到 6.12.58 的符号表。

三组 profile、五种 KSU flavor 共 15 次零 slide 静态 `ko_patch` 检查均为 `MISSING=0`，vermagic 分别与目标 release 完全一致。零 slide 仅用于离线校验，不是设备上的 KASLR 值。

## 热重启

`run.sh` 的 `soft_reboot_repair()` 和 `root_stage.sh` 的调度块均不再自动调用 `ksud soft-reboot`，旧 marker 和环境变量也不能重新开启这条自动路径。没有添加自动 `stop`、`start`、`svc power reboot` 或第二次 framework 重启。

仅在用户明确点击“软重启修复”时：

1. 用现有官方/所选 flavor 的 `ksud post-fs-data`、`ksud services` 重放模块阶段；
2. 运行 `lsposed-hotfix.sh`；
3. 通过 `setprop ctl.restart zygote` 重启 zygote，并等待 system_server 与 LSPosed bridge。

这条路径不经过 `ksud soft-reboot` 的 stop/start 模拟重启，目标是避免 Honor late-load 环境下被 watchdog 转成硬重启。真实热重启是否成功仍须用 boot_id、system_server PID、Zygisk/LSPosed 状态和日志共同确认。

2026-11-13 起策略对齐：`/data/adb/ksu/soft_reboot.lock` 改为显式 opt-in
（`MAGICROOT_SOFT_REBOOT_GUARD=1`），6.12/6.18 与 6.1/6.6 一致，默认不布防，
以便 FinaSU 等 Flavor 用自己的 `ksud soft-reboot` 跑模块 post-fs-data/services。
自动化脚本仍不得自行调用 `ksud soft-reboot`；该 stop/start 在 late-load KSU
上仍可能变成硬重启或 `page_request` panic，风险由执行管理器的用户承担。

## 复现与检查

BRM 兼容模块：

```bash
python binary-sources/61821-brm/build-ksu-brm.py \
  --kallsyms <g186>/kallsyms.txt \
  --ko-patch <host-ko-patch>
```

预期关键输出：

```text
SELINUX_HANDOFF_OK apply_rules+cache_sid+setup_cred+escape+enforce
COMPAT_OK missing_resolved=7 undefined=220 table=263
PATCHED=220 MISSING=0 VERMAGIC=6.18.21-android17-5-ge186062ea75f-abogki564062290-4k SMP preempt mod_unload modversions aarch64
```

Shell 脚本使用 `bash -n` 检查；Android 使用 `main/app/build.ps1` 构建签名 APK。最终安装包、源码包及 SHA-256 清单位于 `magicroot/`。

本次 APK 使用本机 Android Debug 测试证书签名，不是用户正式发布私钥。源码包不包含签名密钥；正式发布时应通过 `MAGICROOT_KEYSTORE` 等构建参数提供外部密钥。Gradle 9.8.2 的 `assembleRelease`、baseline 清理、zipalign、签名验证均已执行。APK 已在 BKQ-AN10（6.12.58）安装并成功冷启动。

当前设备的官方 `ksud 3.3.1 (uapi: 5)` 与 `u:r:ksu:s0` root 可用，但 `/data/adb/modules` 下没有 Zygisk/LSPosed 模块文件。因此本次不能声称真实 Zygisk/LSPosed 热重启已验证；BRM/6.6 的提权和 late-load 也仍需对应设备实测。

缺模块实测中，`ksud post-fs-data`、`ksud services` 均返回 0，随后脚本因 `/data/adb/modules/zygisksu` 不存在而退出 1；未执行 `ctl.restart zygote`。执行前后 boot_id 均为 `4ba6a1e5-2fec-4dcf-b9a4-922611b81ede`，system_server PID 3240、zygote64 PID 1906 均未变化。这只验证缺少前置模块时的安全失败，不代表模块修复成功。
