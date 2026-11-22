# Shark / onekeyjb 生命周期研究与路径重构

研究对象：

- Shark：`8c704a449fc1a41a12dcdddc6b9b51b85f920a52` 及后续修正
  `cee30d61f548604992a709e0861f527d39c24852`；
- onekeyjb：当前 `8657b40` 的 98260 执行/管理器提取/失败处理。

两项目主体均为 GPL-3.0；onekeyjb 另有 `TERMS.md` 使用条款。本轮只提炼机制，
没有把它们的源码复制进 MagicRoot。

## 对 panic / zombie 问题的处理

### Shark

- 回收失败时不 reap 仍持页的 zombie；失败 plant 转交 holder，避免
  `timerqueue_del/rb_*` 访问外来页。
- 已有 holder 时禁止同一 boot 的第二次 plant。
- 成功/失败路径都保留页持有者，文档明确要求不要 kill/reap holder。
- 通过 `panic_on_warn` 等只读预检和 profile 常量校验减少错误内核上的尝试。

### onekeyjb

- 读取 boot_id，已有可用 root 时直接复用，避免重复 plant。
- 不执行软重启；失败时把“校准失败”和“plant 失败”分开报告。
- 管理器模块/ksud 从已安装管理器提取，不使用不匹配的内置回退。
- 未验证的内核 profile 直接拒绝，避免错误 slide/task 偏移导致 panic。

MagicRoot 当前的 victim ledger、unproven boot marker、fail-closed 路由与
管理器提取已覆盖这些原则；本机 last_kmsg 进一步证明：父进程退出后 init 收尸
unproven zombie 仍会 panic，因此 unproven>0 时必须保留看护进程和现场。

## 8c704a44 路径重构及后续修正

原提交把子进程 cwd/HOME/TMPDIR 改为 filesDir，并把 runner 默认目录改为 `.`，
但后续 `cee30d6` 明确修正：Shizuku/Stellar 以 shell 身份运行，无法进入应用
filesDir，特权 helper 会 EACCES。

因此 MagicRoot 采用两者合并后的最终语义：

- Shizuku shell：`cwd=/`、`HOME=/`，不再传 `TMPDIR`；
- 原生 root/mintwait shell：`HOME=/`；
- 资产部署与 exploit 工作区仍为 `/data/local/tmp/magic`：这是 shell 可写、可执行
  且当前 SELinux 策略允许的必要目录，不能按原提交字面删除；
- 应用自己的 stage 缓存仍留在应用目录，与特权工作区分离。

修改覆盖 MainActivity、当前 98260 6.12/6.6 payload 与 rootd、H1C plant/rootd。
旧 61821/61157 参考实现未随本轮重构改动。

## 全流程合并结果

| 阶段 | Shark / onekeyjb 的可行机制 | MagicRoot 处理 |
|---|---|---|
| 预检 | 精确 profile、root 复用、Seccomp/内核状态检查 | 已有精确 profile 和 rootd/KSU 复用，保持 |
| KASLR/符号 | 每内核标定、失败即停 | 已有 slide 收敛校验与精确 syms，保持 |
| reclaim | 自有分配证明、失败不 reap | 已采用整块硬命中与扫描窗口无分配 |
| reap/holder | exec 正常退出可重试；未解决 zombie 保持 holder | 已合并 exec_entered；unproven 继续禁止第二次 plant |
| KSU/管理器 | 从已安装管理器提取 ksud/LKM | 已有，117 五 Flavor 均 MISSING=0 |
| 收尾 | 无 unresolved victim 时允许父进程退出 | **本轮合并为 `victim_finish_or_watch()`** |
| 清理 | unproven 时不 kill/reap | 已禁止自动清理工作区 |

本轮没有合并多线程 raw-trace 喷洒、holder 存在时允许同 boot 重试，或把全部工作区
移出 `/data/local/tmp`：这些会分别重写已验证回收路径、削弱 unproven 防护，或让
Shizuku shell 无法访问工作目录。

## 2026-11-12 raw-trace 与多线程喷洒试验

快路径不是简单复制 Shark：MagicRoot 使用自己的持久 worker 和事件校验。

- 4 个 worker 在第一次 reclaim 的 exec 门闩开启前创建，之后复用；每个 worker
  独占一个 socketpair，避免 pthread 栈缺页落入回收窗口。
- 主线程仍是唯一 trace 扫描者；raw 读取复用预触页的 12 MiB 静态缓冲。
- raw 模式先读取 `mm_page_alloc/free` 的事件 ID 并打开 per-cpu raw fd，失败则
  保留文本 trace 路径。
- raw alloc 仍要求 order>=1、8 KiB 对齐、覆盖 base..base+1，且 pid 属于主进程
  或登记的 spray worker；order>10 的畸形记录直接丢弃。
- `PC98260_FAST_SPRAY=0` 回退顺序喷洒；`PC98260_RAW_TRACE=0` 回退文本扫描。

真机只读校验（未运行 UAF）：mm_page_alloc/free id=330/328，raw 记录中的
pfn/order/pid 与文本 trace 一致；样本中发现一条超大 order 畸形记录，因此加入
order≤10 边界。新增回归测试后生命周期 52/52。

## 2026-11-12 02:13 快路径失败回归

该次 fake-cred 运行 12/12 reclaim miss，日志组合为 `raw_trace=0 fast_spray=1`。
当前身份读取 raw 事件 ID 为 Permission denied，因此 raw 实际未启用；四路 worker
的事件洪水使文本扫描无法及时看到命中。

修正：多线程必须同时满足 `g_raw_active`，raw 不可用或未开启时强制顺序喷洒。
日志区分 `fast_pool`（worker 已建立）与 `fast_spray`（本次真正启用），新增回归
断言。原顺序路径的预算、硬命中与 parked 规则不变。

## 2026-11-12 其他非路径提速优化

继续对照 Shark 的 `trace_start/drain_cpu`、日志策略与 onekeyjb 的启动/收尾流程，
合入三项不改变回收判据的优化：

1. raw 模式启用前清空 per-cpu raw 旧事件，避免把上一阶段的记录当成本次命中；
2. 已加载 KernelSU 且 su 可用时跳过 boot settle 等待，仍由链级复用路径做最终证明；
3. durable log 不再为 `[triple] skip cross-half` / `[churn] round=` 逐行 fsync，
   其余关键事件继续 fdatasync，兼顾 panic 取证与开销。

未合入会改变 slab 形状的 prefill/padding 策略，也不为单纯提速减少 unproven 看护。

## 2026-11-12 02:42 rootd 启动失败导致假死

当前运行的 plant/reclaim 均成功，但 fake-cred rootd 日志为
`[rootd] startup failed errno=13 (Permission denied)`。run98260.sh 原先只等 socket，
且 PROOF_WAIT 默认 720 秒，因此表现为“流程卡住”。

新增 rootd 启动失败的即时识别与 `native_fail rootd_startup_failed`；不自动切换
real-cred，不 kill plant。新增回归后生命周期 55/55。

## 2026-11-12 03:09 收尾临时文件回归

real-cred 已成功，但 rootd 清理 helper 的 here-document 报
`can't create temporary file /data/local/...tmp: Permission denied`，并多等约 10 秒。
原因是此前按 Shark 删除了 TMPDIR；Android shell 因此在 /data/local 建临时文件。
现恢复 `TMPDIR=/data/local/tmp`，保留 `cwd=/`、`HOME=/`。新增回归后 57/57。

## 2026-11-12 04:10 成功后管理器打不开

证据链（su 可用时实测）：

1. 模块已加载且可用：`/proc/modules` 有 `kernelsu`，`su -c id` 返回 uid=0；
   **官方 KernelSU 管理器 (me.weishu.kernelsu) 可正常打开并保持运行**。
2. BakaSU 管理器 (com.resukisu.resukisu, 4.2.0-rc3) 启动即崩溃：
   `FATAL EXCEPTION: DefaultDispatcher-worker / NullPointerException ... getClass() on null`。
   该崩溃在模块已加载、su 正常、官方管理器可用的前提下仍复现，属于管理器自身问题。
3. 内核侧的 `do_track_throne: open /data/system/packages.list failed: -13` 不是主因：
   经用户授权临时把 packages.list 改为 0644 后 BakaSU 仍同样崩溃，随后已恢复 0640。
4. `ksud late-load` 运行期 rc=1、手动补跑 rc=0，说明注册动作本身可用；
   失败时现在会把 `98260-ksu.log` 尾部以 `KSU_LOG_TAIL=` 打进运行日志。

结论：这条链的 root 与模块都正常；打不开的是 BakaSU 4.2.0-rc3 管理器本身。
可用的组合是官方 KernelSU 管理器（已安装），或换用可正常启动的管理器版本。

## 2026-11-12 04:16 管理器打不开的真正根因（已修复）

BakaSU 源码（HEAD 548d1dd，与安装的 4.2.0-rc3-88-g548d1dda 一致）中
`KernelRepository` 所在协程会扫描 Zygisk 实现：

```kotlin
val property = properties.getProperty("name")
Log.i("KsuCli", "Zygisk implement: " + property)
property.getClass()          // name 缺失 → NPE
```

设备上 `/data/adb/modules/zygisksu/module.prop` 在 2026-11-12 01:12 那次 panic 后
被整体清零（mtime 与 panic 时间一致），`getProperty("name")` 返回 null，BakaSU
启动即 NPE；官方 KernelSU、SukiSU、FinaSU、Next 不读这段，所以都能打开。

修复：用同目录完好的 `module.prop.orig` 恢复 `module.prop`（Zygisk Next 1.5.3），
备份损坏文件到 `/data/local/tmp/module.prop.corrupt.*`，并扫描整个
`/data/adb/modules` 未发现其他清零文件。修复后 BakaSU 管理器可正常启动。

结论：与本项目的 init_cred 补丁无关；是 panic 导致的模块元数据损坏。

## 2026-11-12 su 取证的两次 real-cred panic

用 su 从 `/data/vendor/log/reliability/dumplog` 取回的四份 last_kmsg 中，两份
real-cred 运行以内核 BUG 结束，栈不同：

### 03:44 commit_creds BUG_ON（伪 cred + setgid）

```text
kernel BUG at kernel/cred.c:403!
pc : commit_creds+0x1f4/0x200
lr : __sys_setgid+0xb8/0x150
PID: 19031  Comm: exe  UID: 2000
```

`cred.c:403` 是 `BUG_ON(task->cred != task->real_cred)`。该进程的 `task->cred`
已经被 fake-cred tile 改成页内伪 cred，但 `real_cred` 仍是原 cred；随后 mintwait
再调用 `setgid(0)` 进入 `commit_creds`，断言失败。

修复已在 `mintwait_main()` 落地：只有当 `geteuid()!=0 || getuid()!=0` 时才
`setgid/setuid/setfsgid/setfsuid(0)`；伪 cred 已使 ids 为 0 时直接跳过，
日志分别为 `[cred] takeover ids raised` / `[cred] takeover ids already zero`。

### 04:28 init 收尸 zombie

```text
rb_next
posix_cpu_timers_exit
release_task
do_wait_pid / init
```

panic 发生在 init 收尸路径，与 exploit 进程自身无关。此前 init 对
`ppid: 1 state: Z` 的 busybox/daemon/timeout 等子进程打印
`Untracked process (...) did not have an associated service entry and will not be reaped`。
这说明失败尝试留下的 zombie 只要被任何一次 `release_task` 走到，就会在
`posix_cpu_timers_exit()` 里遍历已损坏的 timer rb 树。

因此规则不变：unproven victim 存在时不 kill/reap holder 父进程、不做第二次
plant、保留工作区；`victim_watch_forever()` 是唯一安全的收尾。已撤销的只是
App 对软重启修复的硬阻断，panic 风险本身没有消失。

## 2026-11-12 04:30 fake-cred 注册失败与 su 回退

该轮 reclaim 成功（4/4 reaped，`[rootd] listening`），但 KSU 注册失败：

```text
98260_FAKE_LATELOAD_RC=1
KSU_LOG_TAIL=connect root daemon: Permission denied
98260_FAKE_LATELOAD_RC2=1
```

原因是 rootd 伪 cred 场景下 `ksud late-load` 经当前 `$SU` 连接 root daemon 被拒。
run98260.sh 新增 `run_fake_late_load()`：依次尝试 `$SU`、`/system/bin/su`、`su`、
`/data/adb/ksu/bin/su`，用第一个 `id -u` 返回 0 的提供者执行 late-load，
并记录 `98260_FAKE_LATELOAD_SU=<路径>`；全部失败才记 `none` 并返回 1。
四处 late-load 调用点统一走该函数；生命周期回归 64/64 通过。

### 关键更正：模块已 live，管理器的可用性不是这次修复带来的

复查该轮日志的前半段：

```text
98260_INIT_CRED_INSMOD_RC=0
98260_INIT_CRED_MODULE_LIVE=1
```

`kernelsu` 模块其实已经 insmod 成功并 live，SukiSU 管理器读到的就是
这个内核状态，因此**修复前管理器就能正常打开**。`98260_KSU=failed` 是
误判，失败只发生在用户态 late-load 的连接阶段：模块 live 后，
`pc98260-su` 的新 `connect()` 返回 EACCES（`connect root daemon:
Permission denied`），与 su 提供者无关的转发也就无从执行。

误判的连锁后果：

- `$D/.ksu_loaded` 没有写入，后续走 `98260_ROOTD_KEPT=1
  reason=ksu_not_loaded`；
- 管理器/特性阶段按“未加载”处理，尽管同一轮稍后 `su -c 'id -u'` 已返回 0
  （`98260_SU_PROVIDER_EARLY=su`），特性开关 rc 也全部为 0。

修正两层：

1. `run_fake_late_load()` 在模块 live 后依次尝试 `$SU`、`/system/bin/su`、
   `su`、`/data/adb/ksu/bin/su`，用第一个 uid=0 的提供者执行 late-load；
2. 注册成功判据改为 `ksu_loaded_98260`（模块 live）。用户态 late-load 的 rc
   只记 `98260_KSU_USERSLATE_RC=`，非零时追加
   `98260_KSU_USERSLATE_WARN=module_live_userspace_failed`，不再报
   `98260_KSU=failed`。

该判据的边界：只有模块真的没加载时才失败；模块 live 时管理器可用，
用户态阶段成功与否不影响注册事实。生命周期回归 65/65。

## 2026-11-12 05:20 ga812：fake 选择 + real-engine payload

6.6.118-ga812 这轮日志（`SuSFS_SWITCH=0`，CRED_MODE=fake）的失败点：

```text
[cred] answer uid=0 euid=2000 gid=0 egid=2000
[cred] takeover ids raised
[cred] starting temporary real-cred command handoff
[rootd] bind failed errno=13 (Permission denied)
[lifetime] all victims resolved; parent exit allowed
FAIL=proof exec_exited_before_terminal
```

UAF 本身完全成功：首轮 churn 命中、victim `reaped`、`unproven=0`，
real-cred 引擎已经拿到 uid/gid=0。失败只在 rootd 监听。

根因是**引擎能力与模式选择不一致**：ga812 payload 由 6658 模板合成，
`--no-real-cred` 只被解析、从未被消费，因此即使选择 fake 也运行
real-cred 引擎；而脚本按 fake 分支设置了 `PC98260_ROOTD=1`，让
real-cred 子进程去当 rootd。real cred 没有 `CAP_DAC_OVERRIDE`，
`/data/local/tmp` 是 0771（others 只有 x），于是 `bind()` 返回 EACCES。

同一轮还有两处运行器问题：

- rootd 失败检测只匹配 `rootd] startup failed`，而 6658/6689 的 rootd 打印
  `[rootd] bind failed` / `listen failed`，检查实际是死代码；
- payload 在受害页全部解决后允许父进程退出（`all victims resolved`），
  但 state 文件仍是 `ARMED`，运行器据此写 parked marker 并要求重启。
  这是既有保守策略（失败不自动重试），本次不放开。

最终修复（取代此前的 real 自动回退方案）：

- 以附件 1.0.5 旧源码为 donor，把完整 fake-cred 引擎恢复到
  `6658` / `6689` / `ga812`：fake 主分支、task->cred 页内 FULLCAP 安装、
  SELinux 零页、重叠过滤与成功保页；real-cred direct-finit 保留为独立分支。
- 删除 `98260_CRED_MODE_FALLBACK=real`，fake 选择不再被改写。
- `g554` / `f171` 的 source-locked 静态 payload 本来就含旧 fake 引擎，
  删除 `98260_fake_cred_unsupported` 门禁即可恢复，二进制不变。
- rootd 失败检测扩展为 `startup failed|bind failed|listen failed`。
- H1C 同样被旧审计发现为 real-only：按旧 H1C 自己的布局恢复 fake，
  不使用 6.12 tile；移除 H1C 的 real-cred/cap/mintwait 误路径，保留 victim
  生命周期与新版 rootd。6.1 的 fake 引擎与旧版同 hash，不改字节。

验证：12 个可重建 6.12/6.6 payload 与 H1C 均重编；9 个 6.12 二进制 hash
不变，6.6 三个与 H1C 为新 hash。源码结构回归与 H1C 脚本流程测试通过，
但新 6.6/H1C payload 均未真机验证。

## 2026-11-12 10:02 固定 117 在 H1C 启动前退出

日志在 plant 之前结束：

```text
98260_PROFILE_MATCH=1 profile=61821h1c117
98260_ENGINE=h1c only=1
run98260.sh[1147]: H1C_DYNAMIC_LOCAL: parameter not set
```

run98260.sh 先读取 `$H1C_DYNAMIC_LOCAL` 决定是否采用自适应 syms，随后才
初始化该变量；顶层 run.sh 的 `set -u` 因而让固定 117 直接退出。此失败没有
部署/启动 H1C plant，不产生 armed victim，也不是 fake-cred 引擎回归。

修复：把 `H1C_DYNAMIC_LOCAL="${MAGICROOT_98260_ADAPTIVE:-0}"` 与
`61821|61821brm|61821h1c117 -> 0` 的覆盖移到第一次读取之前，避免固定
profile 继承旧自适应常量。新增变量顺序回归；生命周期 69/69、H1C 11/11。

## 2026-11-12 17:00 H1C 四项修复

依据 11:38/12:02/15:36/16:29 四轮真机日志：

1. **fake tile 写形状**：旧 H1C 把 rb_node 与 cred 同址，`cred[0]=self,
   cred[2]=task+cred`；按 `__rb_erase_augmented` 的 Case 2 推演，写入落在
   本页内，`task->cred` 不变。改为 6.12 的
   `{pc=task+task_cred-8, rb_right=cred_kva, rb_left=0}`，cred 体在
   `node+0x20`，`installed` 后由子进程 uid/euid 取证。
2. **task 泄漏**：raw trace 先排空再 fork；`task_struct` 对象大小读
   `/sys/kernel/slab/task_struct/object_size`（读不到才回退 5248）；收集
   最多 8 个候选，按 attempt 轮换，只有子进程回报 uid==0 才接受；泄漏后
   立即做一次通道自检，静默时打印 wchan/syscall。
3. **回收硬命中**：命中要求 base 与 base+1 两个半页都由本进程在本次尝试中
   分配（`trace_alloc_covers_self`），单半页不再算命中；每次尝试前
   `trace_clear()`；喷洒在 4 组 socket 间轮转。
4. **runner 等待**：软上限 300s 之外增加 900s 硬上限；plant 日志中的
   attempt/hit 计数推进时延长等待，只有无进展超过 120s 或到达硬上限才
   判超时；超时时区分 `plant still running` 与 parked 两种提示。

验证：源码门禁 ALL CHECKS PASSED，生命周期 72/72，H1C 流程 11/11。
新 H1C payload（48,600 B，`2c03009e…a4b7`）尚未真机验证。


## 2026-11-15 v2.4（gitee 镜像）研究：zero-resident / page chase / SELinux re-arm

上游 GitHub 已 404，镜像 `gitee.com/puci1/Shark` 的 v2.4 为最新可用版本
（62e1a09 等提交）。与 MagicRoot 直接相关的内容：

1. **P4 page chase**：miss 后 zombie 不收尸，按轮等 free（1.5 s/轮）、
   每轮释放一批喷洒、只用"自己的分配拿到该页"的严格证明；总预算 12 s /
   6 轮，轮间 drain 有界。已移植为 `victim_chase()`（见 进度.md）。
2. **zero-resident plant**：成功且无 held zombie 直接退出（释放 scratch、
   恢复 trace buffer）；持 zombie 时 exec 最小 shell holder；未武装即失败
   则直接退出允许同 boot 重试。MagicRoot 未移植最小 holder（comm 变更会
   破坏 rootd_stop/清理匹配），但失败零残留原则已由
   `victim_finish_or_watch` 覆盖。
3. **gate SELinux re-arm**：厂商在模块 live 后重新 Enforcing，父进程补写
   selinux_state 让 child 干净退出。与本项目 H1C/gate 路径语义一致，暂不
   需要移植。
4. runner 侧：`wait_su` 50→150 次、gate 路由跳过 su 安装重试 —— MagicRoot
   已用"单次非阻塞探测 + fire-and-forget 管理器启动"替代，不阻塞成功路径。
