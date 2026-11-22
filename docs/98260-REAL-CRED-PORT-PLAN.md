# 98260 real-cred 路线切换与全内核适配方案

日期：2026-11-09　分支：test/98260-real-cred-route

## 1. 结论先行

- MagicRoot 当前 HEAD 的 `binary-sources/98260-6.12/uaf_plant_61258.c` 走的是 **fake cred**：
  tile 把 `task->cred` 劫持到回收页里手写的伪造 cred（全开 cap、手写 SELinux blob），
  因此 **必须常驻 rootd**（伪造后 `cred != real_cred`，execve 会 panic，KSU 移交/ksud 加载只能由 rootd 做）。
- 上游与酷安 feed/74888861 推荐的 **real-cred（原位修改真实 cred）**：
  只把真实 cred 的 `uid/gid` 原地清零，`cred == real_cred` 保持，SELinux blob 由
  `security_prepare_creds()` 正常分配，得到**标准 root 进程**，可正常 fork/exec、可直接杀，
  **不需要常驻 rootd**，不干扰 Zygisk Next。
- 本机内核 `CONFIG_STATIC_USERMODEHELPER=y` 且 path 为空 → modprobe/core_pattern/request_key
  全部 usermodehelper 被强制 exec 空路径，**UMH 提权路线整体不可用**，只能走 cred 写。

## 2. 上游 real-cred 三大写原语（已破解，cve98260.c）

tile 布局：`{pc@0, rb_right=0@8, rb_left=target@16}`，全部走 rb_erase 的 Case-2 单子节点路径。

| 原语 | pc | 效果 | 安全性 |
|---|---|---|---|
| PLANT_ZERO | 0 | `[target]=0` | parent=NULL → 无 augment propagate；rb_next 返回 NULL → drain 终止 |
| PLANT_SELINUX | 0 | `[selinux_state+slide-7]=0` | 同上 |
| PLANT_PTR | A（=stale node 自身 kva，RB_EMPTY 自父） | `[target]=A` | RB_EMPTY 使 rb_next 立即返回 NULL；propagate 因 rb_parent(A)=A 自父、expires 相等而首轮 break |

**写非零值拿 CAP_SYS_MODULE 的关键**：`run_plant(cred+0x40, PLANT_PTR)` 把 cap_effective 写成
stale node 地址 A，并**特意挑选 bit16=1 的 victim**（`cand_a = timer_kva+0x78`，要求 `&0x10000`，
pass0 再排除 bit21=SYS_ADMIN / bit33=MAC_ADMIN）。于是 CapEff=A 天然含 SYS_MODULE(bit16)，
合法 cred 直接 `finit_module(allow_shell=1)` 装 KSU —— 这就是 real-cred 不写常量也能提 cap 的方法。

**危险禁区**：任何 pc 指向真实 parent（非 0/1/自父 A）的 tile，drain 时 `rb_next` 会沿 rb_left
链把 cred 字段当 rb_node 解引用 → `rb_next+0x3c / timerqueue_del / posix_cpu_timers_exit`
→ `AP_S_PANIC page_request`。本次三次真机重启均为自造 fake-cred value-tile 所致。

## 3. 真机验证记录（MLY-AN00, 6.12.58）

- HEAD fake-cred：一次命中 → uid=0 + CapEff 全 1 + rootd 驻留，不 panic（但属 fake cred，需驻留）。
- 上游 `src/uid0.c`（本机 clang 编译）：cred leak 成功（target=cred+8），但 3 次 plant 全部
  "victim not captured"（reclaim 未抢到释放页）→ PARKED，**不 panic**。
  → 证明上游 real-cred 机制在本机安全，但其 spray 命中率低。
- 结论：**应采用上游 real-cred 写最终态 + 我方更强的 reclaim/victim-ledger**，而非直接用上游 spray。

## 4. 全内核适配映射（上游 profile ↔ 我方 target 头文件）

上游 `src/kernel_profile.h` 的 `struct cve98260_profile` 字段与我方 `pc98260_target_*.h` 一一对应，
6.12.58 八项常量逐项相等（已核对）：

| 上游 profile 字段 | 我方 target 宏 |
|---|---|
| timer_site / timer_low21 | LINK_ALLOC_TIMER（低 21 位） |
| task_site / task_low21 | LINK_ALLOC_TASK（低 21 位） |
| cred_low21 | LINK_ALLOC_CRED 低 21 位 |
| selinux_state | LINK_SELINUX_STATE |
| root_user | LINK_ROOT_USER |
| init_user_ns | LINK_INIT_USER_NS |
| init_groups | LINK_INIT_GROUPS |
| init_ucounts | LINK_INIT_UCOUNTS |
| trace_*（0=运行时探测） | 运行时探测，无需硬编码 |

全内核适配 = 为每个已支持内核把上述常量填入 real-cred profile 表；`GEO_CRED_UID=0x8`、
`GEO_CRED_CAP_EFF=0x40`、`CRED_OFF` 等结构偏移各内核一致（cred_jar bytes_req=0xb8）。

## 5. 实施步骤

1. 6.12 把 fake-cred tile 换成 real-cred 三原语，cred 改用 child exec mint + kmem leak
   （callsite 0x19c474，bytes_req 0xb8），交付改为 uid0 shell（setuid(0)+exec），去掉 rootd 驻留依赖。
2. 加 KSU 链路：PLANT_PTR 写 cap_effective（bit16 victim）→ 合法 cred finit_module。
   保留我方 victim ledger/repair/sweep 处理 miss→held zombie（上游只有 park_forever，更弱）。
3. 全内核：把各 target 常量映射进 real-cred profile；逐内核静态审计 + 有可真机者复验。
4. 集成 App assets/部署脚本/run 链路，更新 SHA256SUMS / BINARY-SOURCES / package-source，跑 tools/check.sh。

## 6. 风险与取舍

- real-cred KSU 需多次命中（uid/gid + cap bit16 + selinux），bit16 victim 约占一半，
  在本机 reclaim 命中率偏低的情况下 KSU 成功率可能低于 fake-cred 的一次命中。需真机实测。
- 任何 tile 改动先在真机小步验证；改前 `git checkout HEAD` 保住 fake-cred 可用基线。
- 不把未真机验证的内核路径描述为"已完整验证"。

## 7. 实施进展（2026-11-09）

**6.12 real-cred 已实现**（`binary-sources/98260-6.12/uaf_plant_61258.c`，fake-cred → real-cred）：
- reclaim_stream tile 换成 PLANT_ZERO：`TILE_CRED` 写 `[真实cred+GEO_CRED_UID]=0`（uid/gid），
  `TILE_SELINUX` 写 `[selinux_state-7]=0`；第三个 tile 置 NONE。删掉了 fake-cred 的
  184 字节伪造 cred 填充、blob、usage=0x100000。
- 新增 `collect_site_pid()`（按 pid 过滤 trace record）、`leak_real_cred()`：
  child fork 后 exec 到 `mintwait` 铸私有真实 cred，parent 等 ack 后按 child pid 泄漏 cred kva。
- 新增 `mintwait_main()` 交付：收到 'k' 后 `setgid(0)/setuid(0)` → 标准 root 进程，可 exec，
  **不调用 rootd**（去掉了 fake-cred 的常驻 rootd 依赖）。
- main 流程删掉 fake-cred 的 uid-repair、real_cred 第二跳、fake 安装；`one_uaf` 里
  `g_cred_kva = victim+...` 的 fake 覆盖已删。
- rooted 判定修正为 `uid==0`（euid 由交付时 setuid(0) 补齐，不能要求 euid==0 才 rooted）。

**真机验证（6.12.58）**：
- 不 panic（PLANT_ZERO pc=0 安全），真实 cred 按 pid 泄漏准确（`real cred=0xffffff...`），
  tile 目标 `cred+8` 正确。
- 一次 reclaim 命中后 `ask_child` 报 `uid=0 gid=0`（原位写成功），euid 待 setuid(0) 补齐。
- reclaim 命中率受设备上累积的测试驻留进程/zombie 影响而偏低，需干净 boot 做最终 rooted 复验。

**6.12 家族全适配（编译层）**：real-cred 源码对 61258/61258B/61258C/6138/6138Y/6123/APH112/G142/G856
共 9 个 target 全部 `-D` 编译通过（各 target 的 LINK_ALLOC_CRED/SELINUX/INIT_* 常量齐备且已核对）。
real-cred diff 存于 `/sdcard/cccodroid/real-cred-61258.patch`，但该文件保存早于最终 bit16 预选，
仅作历史参考；同步应以当前源码/git diff 为准。6658/6689 已套用，61821 因引擎与行尾差异
已单独手工转换，不能再描述为与 6.12 同构。

**待办**：在合法 root 交付进程中接入 `finit_module` 并验证真实 KSU/管理器闭环；
runner-equivalent 复验；real-cred 改动继续同步到其余 6.18/6.1 独立引擎；集成 App assets/部署链路。

**6.12 real-cred uid0 已 rooted 交付验证（03:28 真机）**：
- 日志 `real-cred rooted, child=...` + `asked child to take over`；交付进程为 **root 身份的 `sh`**。
- 交付进程 `/proc` 实测：`Uid:0 0 0 0 / Gid:0 0 0 0`、`CapBnd=0x8000c0`（bounding set），
  不 panic、无 rootd 驻留 —— 正是 real-cred 的"标准 root 进程"形态。
- 确认 real-cred uid0 只给 bounding cap，**无 CAP_SYS_MODULE**，装 KSU 必须再写 cap_effective。

**KSU 原语方案**：用 PLANT_PTR 把 `cap_effective`(cred+0x40) 写成某 armed victim 的 stale node 地址 A
（pc=A 自父 → RB_EMPTY，drain 安全）。A 的 bit16 是否=1 决定 CapEff 是否含 CAP_SYS_MODULE；
不预选 victim，写后读 CapEff 验证 bit16，未置位则重试（上游 cap plant 6 次尝试同款思路）。

**✅ real-cred CAP_SYS_MODULE 原语已真机验证（干净 boot，03:49）**：
- `pick_triple` 在 cap 模式预选 bit16=1 的 slab（`slab & 0x10000`），使命中即落 SYS_MODULE。
- 实测日志：`[ksu] cap plant 4/8 CapEff=0xffffff8a631f8b78 bit16=1` → `[ksu] cap_effective has CAP_SYS_MODULE` → `[cred] real-cred rooted`。
- 即：合法 root cred 拿到 CAP_SYS_MODULE，**不 panic、无 rootd 驻留**。
- 验证边界：这只证明 cap 写原语与合法 root cred；当时 `mintwait` 尚未调用
  `finit_module`。本轮随后已实现 runner direct-finit，但真实 KSU 模块加载/管理器闭环
  仍需在新 APK 上复验，不能把协议测试当成真实加载。

**全内核适配进展**：
- 6.12 家族：9 个 target（61258/61258B/61258C/6138/6138Y/6123/APH112/G142/G856）全部 `-D` 编译通过。
- 6.6 家族：6658/6689 已套用 real-cred 补丁（13 块中 12 块自动应用，main 交付段手动同步），编译通过。
- 6.18 家族（61821）：已完成独立 real-cred 转换并编译通过。保留其
  `calibrate_slide_from_timers()` + `perf_leak_task()` 引擎；同一次 fork 由 perf 泄漏 task，
  随后的 exec 铸私有真实 cred，parent 等 `M` ack 后按 pid 泄漏 cred。g928 kmem 双布局均支持
  （旧布局 `bytes_req+16`，g928 `name+16 / bytes_req+24`）。tile、cap bit16 预选、
  `mintwait` 交付及 main 均已 real-cred 化，fake 页覆盖、uid repair、real_cred 第二跳
  已移除。**仅静态/编译验证，无 6.18 真机，未做端到端验证。**
- H1C（实际 6.18 运行引擎）与 legacy 61821-brm 均完成单-victim real-cred 化并编译通过。
  H1C 保留 victim ledger/repair；cap 使用 PLANT_PTR 后读 CapEff，不为预选地址提前收尸。
- 最终 direct-finit 版本已替换有完整源码的同名 APK assets：6.12 九 target、6658、6689、
  GA812、61821、61821-brm、H1C。f171/g554 缺完整可复现源码，6.1 当前资产靠确定性
  ELF rebase，均未替换；`REAL_CRED_NATIVE` 对旧 payload 保留旧协议。
- 6.1 家族（61157）：参考源码仍是 fake-cred，且布局不同（uid 0x04、CapEff 0x38、
  size 0xb0）；在补齐逐 profile 可复现构建前不能声称已 port 到 shipped assets。

**KSU cap 代码与验证状态**：
- `TILE_CRED2` + `g_cap_mode`；`reclaim_stream` 里 CRED2 走 PLANT_PTR（pc=A 自父，写 cred+0x40）。
- `pick_triple` 在 cap 模式只布 CRED2；`child_capeff()` 读子进程 CapEff。
- main 在 rooted 后、`PC98260_KSU=1` 时跑 cap plant 阶段（至多 8 次，验证 bit16），再交付。
- 干净 boot 已完成上述 cap 真机验证（见上）；早期 tracefs 并发占用问题已通过清理实例并重启排除。
- **runner direct-finit 已实现**：rootd 协议新增 `__PC98260_FINIT__` /
  `__PC98260_FINIT_EXIT__`，在 real-cred listener 内直接执行 `finit_module`，不经过
  fork/exec（本机 CapBnd 不含 SYS_MODULE）。KSU 成功后 listener 自动退出；另有认证后的
  `__PC98260_SHUTDOWN__`。
- 独立 socket + 测试桩验证：不存在模块返回 `FINIT_RC=-1 ERRNO=2`；模拟成功返回
  `FINIT_RC=0` 且 listener 退出。未在测试中触发 UAF 或加载真实模块。
- **真实 `finit_module`、KSU 模块出现及管理器闭环尚未在新 APK 上真机验证。**

## 8. 构建与静态验证（2026-11-09）

- 本机离线 `assembleRelease` 成功；使用工作区既有发布 keystore，V3 证书 SHA-256 与旧 APK
  一致（`ef572a91…c8296`）。因 SDK 的 zipalign 为 x86_64，使用 `build-test/zipalign_apk.py`
  做兼容对齐并逐项检查 local-header 数据偏移；apksigner V3 验证通过。
- APK：`/sdcard/cccodroid/MagicRoot-real-cred.apk`，61,148,145 B，SHA-256
  `ed84382d4285f57149dc2169c875eff3a9368b44acc24a7b14e88a1dda606117`。
  （04:52 干净 boot 上的 runner 验证见 §10：uid0 再次成功，随后在
  `victim_sweep()` 处理未收尸 victim 时 panic；direct-finit 未被执行到。）
- `tools/check.sh` 已通过 shell/LF、327 资产注册和 APK 逐字节对账、Java/KASLR、Flavor、
  6.1 静态审计；但整个脚本仍非全绿：工作区既有新版生命周期断言与 native 源码不匹配，
  剩余 6 failures + 1 error（native_state、trace_tail、preflight 返回值等）。本次只更新
  `leak_task()`→`leak_real_cred()` 两个相关断言，没有削弱其他断言。
- `test_h1c_flow.py` 11 项全过；finalize、cleanup、Termux su 回归全过；`verify_apk.py`
  与 `verify_98260_assets.py` 通过（后者仍仅有工作区外 port 清单警告）。
- 静态/协议验证不等于真机 root/KSU；下一步只在当前 6.12.58 设备做一次 runner-equivalent
  验证，失败不自动重试，不做 soft-reboot。

## 9. 04:39 runner 重启与防重入修复

- 从签名 APK 生成并部署 `ASSET_PLAN count=75`，设备随后于 04:41 重启，
  `sys.resettype=abnormal:AP_S_PANIC`。重启后 enforcing 下 dumplog 对 shell 拒绝访问，
  本次没有取得内核栈，不能声称已经确认具体崩溃指令。
- 本次不能作为干净的 real-cred runner 结果：03:49 的 `/data/local/tmp/rc4.log` 明确留下
  `unproven=1`，其 direct 测试进程名为 `plant_rc4`。启动前只检查了
  `exploit-android-key-ptr/cve98260_plant`，漏掉了旧 watcher。当前 boot 的
  `.magicroot-unproven` 在新 runner preflight 完成前即被刷新，说明旧测试状态混入。
- 因 native 日志在重启后缺失，不能证明 direct-finit 已执行，也不能把重启归因于新 tile。
  该次验证标记为无效/不安全，不自动重试。
- `run98260.sh` 新增 boot-scoped unproven guard：当前 boot 且计数 >0 时，在任何新 plant
  前 `FAIL=98260_unproven_victims_reboot_required`，不再依赖进程名。已有 rootd/KSU
  复用仍在 guard 之前。新增回归通过；重启后未再运行 98260，也未执行 soft-reboot。
- 该 guard 与 direct-finit 已确认包含在最终签名 APK 的
  `assets/98260/run98260.sh`（SHA-256 `2f26a7a0…5500b`）中。重启后 SELinux 恢复
  enforcing，直接 `pm install /sdcard/...` 被 `system_server` 读取 fuse 拒绝；改为
  先复制到 `/data/local/tmp` 再安装成功。安装后的 base.apk SHA-256 与交付文件一致。

## 10. 04:52 干净 boot 上的完整验证（失败，第二次 AP_S_PANIC）

- 环境：boot `cb5bcaeb…`，无残留 plant、无 KSU，unproven 标记属于上一 boot；
  部署与运行均来自最终签名 APK 的资产（`exploit=c1c399…`、`run98260.sh=2f26a7a0…`）。
  这是首次在干净环境执行 App runner 路径。
- 进程：第 1/2/3/5/6 次 reclaim miss，第 7 次命中；`[tile] CRED` 与
  `[tile] SELINUX` 下发了真实 cred 地址；随后 `[cred] answer uid=0 euid=2000 gid=0`
  —— **real-cred 原位 uid/gid 写已真机成功**。
- 紧接着整机重启，`sys.resettype=abnormal:AP_S_PANIC`。日志最后一行就是上面的
  应答；`victim_summary()` 在 `victim_sweep()` 之后无条件打印，但日志中不存在
  `[victim] summary`。因此崩溃发生在 `victim_sweep()` 处理 5 个未收尸 victim
  （23399/23588/23783/23828/23859）时，**没有进入 cap 阶段，也没有执行
  direct-finit**。
- 归因修正：本次 panic 不能归因于 direct-finit 或 PLANT_PTR cap 写；它与
  “多次 miss 后 sweep 未证明 victim”的既有收尸炸弹一致。runner 本次实际使用
  `PC98260_WAIT_CAP_S=8`（手工 rc4 成功时为 60000 ms；App UI 默认 25/40s），
  7 次尝试中 5 次 miss，显著放大了该风险。
- 结论：real-cred uid0 写入原语再次得到真机确认；但 App runner 的短等待上限 +
  连续重试会累积未证明 victim，`victim_sweep()` 在此状态下不安全。direct-finit
  仍未经真实执行验证。未自动重试，未做 soft-reboot；后续测试应使用更长的
  reclaim 等待并限制 miss 次数，或先修复 sweep 的保护条件。

## 11. 05:02 低 miss 配置验证：走到 cap，被 listener bind 挡住

- 干净 boot `6e40d0d5…`，`WAIT_CAP=60s`、`MAX_ATTEMPTS=4`、`BUDGET=900s`、
  `KSU=1`。前三次尝试即完成 uid0 与 cap，**全程没有 panic**；
  第 8 次 cap plant：`CapEff=0xffffff8a20a9aa78 bit16=1` →
  `cap_effective has CAP_SYS_MODULE` → `real-cred rooted`。
- 随后 `start_child_ksu()` 进入 `mintwait-rootd`：
  `[rootd] startup failed errno=13 (Permission denied)`，socket 从未出现，
  runner 正常 `98260_CHAIN_END=FAIL code=80` 退出。**direct-finit 未被调用。**
- 现场：SELinux 仍为 Permissive，logcat 无 `avc: denied`，`/data/local/tmp`
  为 `root:shell 0771`；真实 cred 进程以 euid 0 运行但其 fsuid/厂商 LSM 是否
  允许在 shell_data_file 目录创建 root 所有的 socket 尚未确认。fake-cred 时代的
  rootd 能绑定，是因为其 cred security blob 被伪造为内核 SID，路径不可直接复用。
- 结果：real-cred uid0 与 CAP_SYS_MODULE 在同一 boot 内真机同时成立；剩余阻塞
  点是“real-cred 进程创建文件系统 socket”。**未验证 finit_module 与 KSU 管理器闭环。**
- 本次运行留下 6 个 OPEN/UNPROVEN victim（`/data/local/tmp/.magicroot-unproven`
  为当前 boot `6e40d0d5… 6`），exploit 父进程 17651（PPID=1）仍在驻留。按既有
  规则：**本 boot 不得再启动 UAF，也不得 kill 该父进程；必须重启**。
- 修复已实施：改为上游式的**无 socket 进程内 finit_module**（见 §12）。

## 12. 无 socket 进程内 finit_module（2026-11-09 实施）

动机：real-cred 进程在此 ROM 上无法创建文件系统 socket（bind EACCES），
fake-cred 时代由伪造 cred 的 security blob 绕过，real-cred 不可复用。

实现：

- `binary-sources/98260-6.12/uaf_plant_61258.c`、`6658/`、`6689/`、`61821/`、
  `61821-brm/` 的 `mintwait` 交付分支新增：读取 `PC98260_FINIT_READY`
  （patched KO 就绪标记）、`PC98260_FINIT_KO`、`PC98260_FINIT_PARAMS_FILE`，
  在 setuid(0)/setfsuid(0) 后**直接** `finit_module(fd, params, 0)`，打印
  `[ksu] in-process finit_module rc=... errno=...`；`PC98260_FINIT_EXIT=1` 时
  成功后退出，不再经过 exec（exec 会按 CapBnd 丢失 CAP_SYS_MODULE），也不再
  需要 rootd socket。
- `run98260.sh`：real-cred 且 KSU 开启时，启动前写 `finit.params`、删除旧
  patched KO/ready 标记并传入 FINIT 环境；跳过 socket 等待与 socket 证明；
  `ko_patch` 完成且 vermagic 匹配后才创建 `ksu-patched.ready`（避免子进程加载
  半成品）；随后轮询 `/proc/modules` 的 `kernelsu`，再探测 KSU su 的 uid 0，
  最后复用既有 `finish_ksu_loaded`。KSU 关闭时不再下发 `PC98260_KSU`，仍可
  单独验证 uid0。
- `REAL_CRED_ENV` 不再请求 `PC98260_ROOTD`；临时 listener 仅保留给旧资产/兼容
  路径。SuSFS 预载在 real-cred 模式下跳过（原先依赖 socket）。
- 新增回归 `test_real_cred_inproc_finit_path`；`test_98260_uaf_lifecycle.py` 全量
  仍有 6 failures + 1 error，均为本次之前既存的断言错位。

验证边界：仅编译与静态/流程测试。新 APK 尚未安装/运行；`/data/local/tmp/magic`
里正在执行的旧 payload 无法覆盖（ETXTBSY），必须重启后重新部署。新 APK 位于
`/sdcard/cccodroid/MagicRoot-inproc.apk`，61,156,337 B，SHA-256
`f8c5864bfdeb343c663fce254f409bc856d2139a1066a07ef700186fd59b6771`，V3 证书
与发布证书一致。

## 13. 05:31 严格收尸 + 进程内 finit 真机运行（无 panic，root 未命中）

- 使用 §12 的 in-process runner 与严格收尸前的 payload（`efd20938…`）。
  4 次尝试：第 1 次 trace 报 hit 但 uid 仍为 2000（假命中：只有 buddy half
  被我们的分配覆盖，节点 half 未覆盖，tile 未生效）；第 2–4 次 miss。
- `victim_sweep()` 在 3 个未证明 victim 下**没有 panic**，打印
  `unproven_reap_refused` ×3 与 `summary total=4 reaped=1 unproven=3`，随后
  `[uaf] missed page; holding zombie` 按设计驻留。严格收尸修复验证通过。
- 因 rooted=0，cap 与进程内 finit 均未执行；runner 等满 PROOF_WAIT=720s 后
  `FAIL code=80`。plant 父进程 17220 已 reparent 到 init，marker 记录本 boot 3 个
  unproven victim；本 boot 不得再跑 UAF。
- 两项后续修复：
  1. hit 判定从 order-1 `base` 改为节点所在 4K 半页 `node_pfn`，消除上述假命中；
  2. runner 在等待 kernelsu 时检测 `missed page; holding zombie`，立即
     `FAIL=root_not_achieved` 并退出，不再空等。
- 仍待验证：在真实命中且 cap 成功时，mintwait 的进程内 `finit_module` 能否
  加载 patched KO（本轮没有走到）。下一轮建议 `ATTEMPTS=12`、`WAIT_CAP=60`、
  `BUDGET=1800`。
- rc4 已重编 6.12 九 target 与 6658/6689/GA812，并重建签名 APK：
  `/sdcard/cccodroid/MagicRoot-rc4.apk`，61,152,242 B，SHA-256
  `9a640d0ab0945a586710b4cf21170a1ef01e89d081bbab3692910824539b71ad`，
  V3 证书与发布证书一致。`tools/check.sh` 的资产/语法/Java/Flavor/6.1 全过；
  生命周期套件在把“未释放也收尸”的旧断言改为新契约后，剩余 5 failures + 1 error
  均为本次之前既有的引擎/测试错位。

## 14. 05:47 真机：首次真正命中 + cap 成功，暴露 envp 丢失

- rc4（节点半页判定 + fail-fast）首次运行即**真正命中**：第 1 次尝试
  `[stream] hit` 后 `uid=0`，没有假命中；`victim summary total=1 reaped=1
  unproven=0`。第 2 次 UAF 做 cap，`[ksu] cap plant 1/8
  CapEff=0xffffff889e81aa78 bit16=1`，`CAP_SYS_MODULE` 成立。
- 但始终没有 `[ksu] in-process finit_module`，也没有 `kernelsu`。现场
  `/proc/17571/status` 显示子进程已成 **uid=0 的 sh zombie**：它走了
  “setuid → exec sh” 分支。
- 根因：`cred_child()` exec `/proc/self/exe` 时使用**固定 envp**
  （只有 PATH/HOME），`PC98260_FINIT_*` 全部丢失，mintwait 因而跳过 finit。
  修复：改用 `environ` 继承完整环境（五个 payload 源同步）。
- 新增回归 `test_mintwait_exec_inherits_environment`，通过。
- 本次设备再次需要重启（驻留父进程 17561，child 已退出）；rc5 已重编
  6.12 九 target + 6658/6689/GA812 + 61821/BRM，并重建签名 APK：
  `/sdcard/cccodroid/MagicRoot-rc5.apk`，61,152,241 B，SHA-256
  `c97f1345fbf197f934ab6133ef164534de85eef79500a77398c75e7d801414b4`，
  V3 证书一致。静态门禁资产/语法/Java/Flavor/6.1 全过，生命周期剩余 5+1 为既有错位。

## 15. ✅ 06:00 rc5 真机完整成功：进程内 finit + KSU 闭环

干净 boot `9f3c58cb…`，`ATTEMPTS=12 / WAIT_CAP=60 / BUDGET=1800`：

```text
[cred] answer uid=0 euid=2000 gid=0 egid=2000
[ksu] cap plant 4/8 CapEff=0xffffff8a3c754b78 bit16=1
[ksu] cap_effective has CAP_SYS_MODULE
[cred] real-cred rooted, child=16676
[ksu] in-process finit_module rc=0 errno=0 uid=0 euid=0
98260_REAL_CRED_INPROC_OK=1 waited=107s
98260_REAL_CRED_SU_PROOF=ok provider=su
98260_KSU=loaded method=real-cred-inproc flavor=resukisu
98260_SUCCESS=1
98260_CHAIN_END=OK
```

独立核验：

```text
/proc/modules: kernelsu 270336 0 - Live 0x0 (O)
su -c id:      uid=0(root) gid=0(root) context=u:r:ksu:s0
/proc/self/status: Uid 0 0 0 0 / Gid 0 0 0 0 / CapEff 000001ffffffffff
```

即：real-cred 原位 uid0 → PLANT_PTR cap → **不经 exec 的 finit_module** → KSU
模块 Live → KSU su 返回 uid 0。全程无 panic，runner `DONE`。

验证边界与残留：
- uid0 阶段 2 个 miss 被严格收尸规则标为 `unproven_reap_refused`；cap 阶段
  又产生若干 miss。最终 marker 为当前 boot 计数 5，exploit 父进程 16642 仍按
  设计驻留（PPID=1）。**本 boot 不得再跑 UAF、不得 kill 父进程；下次测试前重启。**
- 未做 soft-reboot、未重启 zygote；未验证管理器 UI（ReSukiSU）内的模块状态页；
  `ksud install` 预装仍为 RC=1（加载前无 su），但 KSU 内核 su 已可用。
- 6.6 / 6.18 / 6.1 仍无对应真机；本轮成功只覆盖 6.12.58。



## 16. 管理器显示“未安装”：与旧源码对比与修复

现场：KSU su 正常，但管理器 UI 显示「未安装 / 点击安装」。`dmesg` 同时出现
`do_track_throne: open /data/system/packages.list failed: -13`，且
`/sys/module/kernelsu` 被 BakaSU 用 `kobject_del` 主动隐藏。

与旧源码（`MagicRoot-1.0.5-source-rc.zip`）对比：

- 旧 late-load 路径执行 `ksud late-load --kmi … --package-name <MGR>`，把管理器
  包名交给内核；旧 `root_stage.sh` 还有完整注册：`kernel dynamic-manager set-apk`、
  顶层 `dynamic-manager set`、`manager add`、`.dynamic_manager` JSON 记录、
  **chmod/rename `/data/system/packages.list` 触发 throne 重读**、`debug set-manager`、
  `ksud install`。
- 我们的进程内 finit 直接 `finit_module`，**绕过了 `--package-name` 和整套注册**；
  加上 late-load 后内核读 packages.list 被拒（-13），管理器无法被识别。
- 另外本轮 flavor 选错：设备管理器是 **SukiSU Ultra**（`com.sukisu.ultra`，
  v4.3.0-r2/41150），却加载了 BakaSU 模板（内核 35253，内置包名
  `com.resukisu.resukisu`）。SukiSU 模板 (`ksu-template-sukisu.ko`) 内含
  `com.sukisu.ultra`，与管理器匹配。

修复：

- `run98260.sh` 新增 `register_manager_98260()`，在 su 证明成功后执行旧 root_stage
  的注册序列：`dynamic-manager set-apk`、`.dynamic_manager` JSON、packages.list
  crown 触发、`debug set-manager`、`ksud install`；并输出
  `98260_MANAGER_DEFAULT_PACKAGE` / `98260_MANAGER_MISMATCH=1` 以便发现包名选错。
- 下一轮需用 `MAGICROOT_KSU_FLAVOR=sukisu`、`MAGICROOT_KSU_PKG=com.sukisu.ultra`，
  KSUD 从 SukiSU 的 `libtqqfthevwb.so` 提取（ksud 4.3.0-r2）。

- rc6 APK 已构建：`/sdcard/cccodroid/MagicRoot-rc6.apk`，61,152,235 B，SHA-256
  `bad2d7d58beeb53ddbbbc658b631605aab35767b1b4f558d232067f2e9dbcd07`，
  V3 证书与发布证书一致。`run98260.sh` SHA-256
  `e0d86399f668b5daa1f6192f79f10f9ef0a748aa2c94516a17cd73af61241355`。


## 17. SukiSU 配置真机成功 + 管理器授权闭环（2026-11-09 06:17）

配置：`MAGICROOT_KSU_FLAVOR=sukisu`、`MAGICROOT_KSU_PKG=com.sukisu.ultra`、
KSUD 取自 SukiSU 的 `libtqqfthevwb.so`（ksud 4.3.0-r2）、KO 为
`ksu-template-sukisu.ko`。

结果：

```text
98260_KSU_PATCH_RC=0 missing=0 flavor=sukisu template=ksu-template-sukisu.ko
[ksu] in-process finit_module rc=0 errno=0 uid=0 euid=0
98260_REAL_CRED_INPROC_OK=1 waited=237s
98260_REAL_CRED_SU_PROOF=ok provider=su
98260_MANAGER_REGISTER_BEGIN pkg=com.sukisu.ultra
98260_MANAGER_DEFAULT_PACKAGE=com.sukisu.ultra
98260_MANAGER_KSUD_INSTALL=ok
98260_MANAGER_DYNAMIC_FILE=ok size=860
98260_MANAGER_REGISTER=done pkg=com.sukisu.ultra
98260_CHAIN_END=OK / DONE
```

内核 `41150`，`ksud debug package` 为 `com.sukisu.ultra`，su 为
`uid=0 u:r:ksu:s0`、CapEff 全 1。**但管理器仍显示“未安装”**——SukiSU 的
ksud 不支持 `kernel dynamic-manager`，只写 `.dynamic_manager` 文件无效。

补上 SukiSU 的 `ksud manager add <pkg> <size> <hash>` + `manager set-enabled true`
后：

```text
enabled: true
com.sukisu.ultra  860  947ae944…93eef  10395
```

管理器 UI 变为：**越狱模式 工作中、版本 41150-6、5 个超级用户、3 个模块**。
该路径已写入 `register_manager_98260()`（capability probe `ksud manager --help`），
并新增 `98260_MANAGER_ADD_RC` / `98260_MANAGER_LIST` 日志与回归断言。

## 18. 多管理器 Flavor 选择核对

静态：

- `kernel_profiles.sh ksu_flavor_pkg()` 与 App `ksuPkgOf()` 五套映射一致：
  kernelsu→me.weishu.kernelsu、resukisu→com.resukisu.resukisu、
  sukisu→com.sukisu.ultra、next→com.rifsxd.ksunext、fina→me.yuki.fina。
- 61258 profile 下 `ksu_select_ko` 对五种 flavor 分别选中
  `ksu-template.ko` / `-bakasu` / `-sukisu` / `-next` / `-fina`，并匹配各自的
  `syms_61258*.txt`，`FLAVOR_SYMS_MISSING=0`。
- `tools/audit_kernel_flavors.sh` 覆盖全部 profile×flavor 模板/符号表矩阵并通过。
- App 侧：`UiState` 循环五种 flavor 并持久化，`MainActivity` 写 `ksu_flavor`、
  传 `MAGICROOT_KSU_FLAVOR`、按 flavor 提取 ksud/LKM；`extractManagerLkm`
  会用管理器内嵌 LKM（SukiSU 的 carved 结果与内置模板同字节）。

真机（sukisu）：模板、ksud、内核版本、默认管理器包名、`ksud manager list`
与管理器 UI 全部一致，说明该 flavor 的端到端选择正确。其余 flavor 未逐一切换
真机验证（每次切换需重启），仅静态矩阵与 App 路径审计通过。

残留：本 boot marker=6、父进程 17296(PPID=1) 驻留，需重启后再做其他 flavor
的真机切换测试；未执行 soft-reboot。

- rc7 APK（含 `ksud manager add` 注册路径）：`/sdcard/cccodroid/MagicRoot-rc7.apk`，
  61,156,337 B，SHA-256
  `d98762ca44b5213c43f26e7c3514e5b6a10ec89e01cf02f2ec7566c81f9f1ff0`，
  V3 证书与发布证书一致。`run98260.sh` SHA-256
  `5dc25488fb5a51750569ed6014ce61fdc21aa8a8bf2f1a75cc8b0f4053798679`。


## 19. SuSFS 加载路径与“保留 su”默认关（2026-11-09）

SuSFS：

- 旧逻辑在 `MAGICROOT_SUSFS_PROTECT=1`（UI 默认）且未预载时直接跳过，理由是
  “protect mode 需要 rootd 预载”。real-cred 没有 rootd，因此永远不加载。
- 现在 `run.sh susfs_load()` 在该分支先探测可用的 KSU su：若 `su -c id -u` 为 0，
  则记录 `SuSFS_LKM_PROTECT=post_load reason=real_cred_su` 并继续加载；只有无 su
  时才维持原来的跳过。加载顺序改为 KSU 之后，由 KSU 的全能力 su 执行
  `ksud insmod`，失败回退 `susfs_insmod`。
- `susfs_insmod` 回退路径补上 `expose_proc=1`，与 `ksud insmod` 参数一致。
- 真机验证受阻：本轮 boot 在打开 SukiSU 管理器后 `su` 入口消失（管理器首次启动
  重装 userspace / 撤掉 late-load su 覆盖层），无法再执行 insmod。需重启后用
  `MAGICROOT_SUSFS=1 MAGICROOT_SUSFS_PROTECT=1` 的完整 runner 复验。

“保留 su”默认关：

- `UiState.suEntry` 初始值由 true 改为 false；`resetRunDefaults()` 也改为 false。
- `restoreSuDefaults()` 是用户显式“恢复 su”动作，仍保持 true。
- `run98260.sh` 的 `SU_ENTRY_98260` 环境缺省由 1 改为 0；App 仍会显式传入 UI 值。
- `su_compat` 默认保持开启，未改动。

rc8 APK（含以上修改 + `ksud manager add`）：
`/sdcard/cccodroid/MagicRoot-rc8.apk`，61,156,336 B，SHA-256
`ec29b09b5e8d7962aee55045d309bbf5ac9531f72819e3912e2220e73ad730e2`，
V3 证书一致；`run.sh=d3b29dda…235c`、`98260/run98260.sh=e7576a06…fd23`。


## 20. 16:32 FinaSU 运行的卡点：cap 全 miss → finit EPERM

截图停在“修补 KernelSU 模块 36%”，但该标签已过时；日志明确显示
`98260_KSU_PATCH_RC=0 missing=0`、KO_READY 与 INPROC_FINIT_READY，KO 修补已完成。

实际 native 过程：

- uid0 前 11 次尝试均未写成，第 12 次才命中；`victim summary total=12
  reaped=4 unproven=8`。
- 随后的 8 次 cap 尝试全部在 reclaim 阶段返回非零，**没有任何一条
  `[ksu] cap plant ...` 成功记录**，所以 CapEff 没有 CAP_SYS_MODULE。
- `[ksu] cap_effective plant did not land bit16` 后仍然交付，
  `[ksu] in-process finit_module rc=-1 errno=1`（EPERM），KSU 未加载。
- runner 仍按旧的 720s PROOF_WAIT 等待；界面停在 36% 是因为 RunProgress 不识别
  real-cred 的新标记。设备未因此 panic；marker 为当前 boot 计数 11，父进程
  23250 驻留，本 boot 不再重试。

修复：

1. 六个 real-cred 引擎在 `cap_ok=0` 时打印
   `FAIL=cap_sys_module_not_achieved; finit blocked` 并进入原有驻留/观察路径，
   不再做必然 EPERM 的 finit。
2. runner 检测到 cap 失败或 `in-process finit_module rc=-` 时立即以明确的
   `FAIL=98260_cap_sys_module_not_achieved` / `FAIL=98260_finit_module_error`
   退出，不再空等。
3. RunProgress 新增 INPROC、KO_READY、FINIT_READY、INPROC_OK、SU_PROOF 与
   MANAGER_REGISTER 标记，分别显示 UAF、等待提权、加载 KSU、su、管理器注册；
   新增回归测试通过。

rc9 重编全部有源码目标并重建 APK；本轮只修错误处理与显示，未再次运行 UAF。


## 21. 失败日志完整分析与命中率优化（重启前）

完整日志已保存到 `/sdcard/cccodroid/failure-1632-native.log`（314 行）、
`failure-1632-run.log`、`failure-1632-ksu.log`。统计：

- uid0：12 次尝试，4 次 trace `hit`，只有最后一次 `uid=0`；其中两次 hit 后
  uid 仍为 2000，另一次 reap 状态 0（不是 SIGKILL），都说明“命中”证据不足。
- cap：日志只有 3 个 victim/CRED2 块，没有一次 cap verify 成功；其余尝试在
  fork 或 trace 初始化前即返回，旧代码没有诊断。
- 资源：父进程 FD=13、VmRSS≈1.9MB，不是 fd/内存耗尽；但有 72 个 zombie/helper，
  且 uid 成功后的 sweep 与 cap 共用 socket spray，cap 第一次出现 `writes=0`。
- 多次 `page_freed=0` 是 slab 仍停在 CPU partial，churn 不足；多次 4K half miss
  说明只喷节点半页时竞争也很强。trace 目前仍是从头扫描、共享预算，可能漏掉
  最新事件；不能把 trace 命中当成 tile 已执行的证明。

已实施的优化（rc10，未真机）：

1. **单次 reclaim 合并三次写入**：原引擎三个 clock tree 本来就对应三个独立
   rb_erase；现在 KSU 模式下 tile0=CRED(uid/gid)、tile1=SELINUX、tile2=CRED2
   （PLANT_PTR cap_effective）。同一个 8K slab 预选 bit16=1，命中即同时拥有
   uid0、permissive 与 CAP_SYS_MODULE，不再另开 cap UAF。这样既消除第二轮
   spray 的 miss，也避开 sweep/cap 共用 socket 的问题。
2. 命中后先读 CapEff，bit16 已成立则直接使用；未成立才进入旧 cap 回退。
3. 新增 `[alloc-hit]` 原始 trace 行、victim fork errno、`cap attempt ... reclaim
   failed before verify`，下次能区分静默失败和真实命中。
4. 所有改动仅组合已验证的 PLANT_ZERO/PLANT_PTR，不引入新 tile 形状；编译与新增
   回归通过。没有在本 boot 运行验证。


## 22. rc10 合并写入真机成功；FinaSU 动态管理器授权修复（2026-11-09）

17:05 的干净 boot 真机日志（`/sdcard/Download/MagicRoot/magicroot-success-1794215160269.log`）
确认 rc10 的合并写入路线成立：

- 第 2 次尝试命中节点半页，同一次 reclaim 同时得到 uid0、SELinux permissive 和
  `CapEff=0xffffff88993b0578 bit16=1`；没有进入第二轮 cap UAF。
- `[ksu] in-process finit_module rc=0`，FinaSU LKM 加载、KSU su uid0 均成功。
- `SuSFS_LKM_LOAD_RC=0`、`SuSFS_LKM_VERIFIED=module_or_proc rc=0`，此前未验证的
  real-cred post-load SuSFS 路径本轮也已成功。
- 两次 attempt 留下 `unproven=1`，严格收尸没有 panic；仍需保留 UAF 父进程到重启，
  未执行 soft-reboot。

本轮管理器未授权与提权/模块加载无关。实际 flavor 是 `fina`，管理器包名
`me.yuki.fina`、签名 size/hash 均读取正确，但旧 real-cred 注册函数只支持
`kernel dynamic-manager`、`manager add` 和旧 JSON 文件，不支持 FinaSU 1.5.0 的
`ksud dynamic` 接口。真机只读 help/get 确认其流程为：

1. `ksud dynamic set-apk [--version-code N] <APK>` 登记签名；
2. `ksud dynamic grant <appid>` 授权已安装应用的 UID；
3. `ksud dynamic list` 同时显示签名与 `authorized appids`。

在当前已 root 状态执行完整 set-apk（versionCode=33174）+ grant（appid=10397）
均返回 0，持久化 `.dynamic_manager` 为 `signs[] + uids[]`。但这只证明 CLI 配置写入，
不代表管理器 UI 已闭环；随后 rc11 真机首页仍显示“未安装”，详见 §23。
没有为重跑该命令触发新的 UAF。

代码修复同时覆盖 `98260/run98260.sh` 与 `root_stage.sh`：增加 Fina `dynamic`
能力探测、版本代码、UID 查询、grant 和结果日志；Fina 新接口成功后不再用旧的
单签名 JSON 覆盖新格式。保留 SukiSU `manager add`、ReSukiSU/旧版 dynamic-manager
和官方 debug 路径。脚本语法与新增管理器回归通过；其余 flavor 的真机状态不被此次
Fina 结果替代。

rc11 APK：`/sdcard/cccodroid/MagicRoot-rc11.apk`，61,160,432 B，SHA-256
`5c82d32717ef9fc0d322035193c1a0e82b4f917897f4323c4f263b16c4bdfda2`，V3 发布证书不变，
已以 `pm install -r` 安装并确认 versionCode 12 / 1.0.5。rc11 仅补齐 CLI 登记/授权，
其自动注册时序和 UI 状态当时均未闭环。

## 23. Fina 首页未安装根因与可恢复扫描窗口（2026-11-09）

对照 FinaSU v1.5.0（commit `fbf8e003d902c43213d435632a22e4fb1a219aeb`）源码和当前
设备状态后，首页判据不是动态 JSON 是否存在，而是 native `GET_INFO` 的 manager flag；
管理器进程还必须持有 `anon_inode:[ksu_driver]` fd。rc10 的 direct-finit 调用进程
`CapEff=0xffffff88993b0578` 有 bit16（CAP_SYS_MODULE）但没有 bit1
（CAP_DAC_OVERRIDE）。Fina 初始化以 `prepare_creds()` 保存该调用者的 `ksu_cred`，
throne tracker 随后以它打开真实的 0640 `/data/system/packages.list`，因此持续
`open ... failed: -13`，APK 扫描在签名匹配前就中止。

在当前 root 会话中做了不重跑 UAF 的运行时验证：保存原 mode 640，仅在扫描期间临时
改为 0644，再执行签名/UID 登记并立即恢复 640。完整扫描随后出现
`Crowning manager: me.yuki.fina(uid=10397)`。该官方证书命中固定可信槽位，所以
`dynamic set-uid` 末尾只查动态 app 表的 `verify_appid_trusted()` 即使 crown 成功也可能
误报 E0005；自动流程继续使用 `set-apk + grant`，不依据该误报回滚固定管理器身份。

旧 Fina 进程在 crown 前已经启动，没有驱动 fd；注册后 force-stop 并重新启动，新的
PID 6108 实测持有 fd 5（`anon_inode:[ksu_driver]`），内核同时记录
`ksu fd installed: 5 for pid 6108`。`packages.list` 已恢复并只读复核为
`640 system:package_info`，SELinux 为 Enforcing。未 kill PPID=1 的 UAF 父进程，
未执行 soft-reboot，未再次触发 98260。

脚本修复把上述顺序固化到 `run98260.sh` 与 `root_stage.sh`：root 下读取并保存 mode，
扫描前临时 0644，成功/失败路径均恢复原 mode；Fina 使用同步 dynamic rescan，不再做
额外 packages.list 改名；注册后重启管理器并轮询真实 ksu_driver fd。旧 runner 的低权限
`[ -f /data/system/packages.list ]` guard 也已移入 root 命令，避免跳过 chmod。
运行时内核/fd 证据已确认；自动脚本的完整开机链路仍需后续干净 boot 复验，UI 最终
显示以用户观察为准。

修复版 rc12 APK：`/sdcard/cccodroid/MagicRoot-rc12.apk`，61,160,433 B，SHA-256
`7c468b097b4db6cbd07b4767a6591c68f17276f3a569e9ddb021b1435e854db3`。V3 发布证书
SHA-256 保持 `ef572a91ebf470dc6606af3639e8aa8d28b4bd0768d31b5efbbb2933d92c8296`；
已通过流式 `pm install -r` 安装，versionCode 12 / versionName 1.0.5 不变。
`tools/check.sh` 的 65 个 shell、327 个资产逐字节对账、profile/Flavor/6.1 等门禁通过；
生命周期 37 项仍有既存 5 failures + 1 error，新增管理器注册与权限恢复测试通过。
安装只更新 APK，没有运行 root 链路。

## 24. post-load 提前退出导致 SELinux feature 未下发（2026-11-09）

用户提供的 Duck Detector 报告（18:28）不是“仍在 Permissive”：报告和现场
`getenforce` 均为 Enforcing。与旧报告的差别是 KSU/LSPosed context 已进入 live
policy，且 Fina 的 `selinux_hide` 现场读回为 Disabled。模块自身策略没有被本次修复
删除或重写。

rc10 成功日志只有 `98260_KSU=loaded method=real-cred-inproc`，随后直接到
`98260_CLEANUP=ok` 和最终 success；没有 `98260_KSU_SU_WAIT` 或任何
`98260_FEATURE_*`。代码定位为 `finish_ksu_loaded()` 在初次加载和复用入口末尾直接
`exit 0`，使公共尾部的 su 验证、feature 下发和最终 Enforcing 检查全部不可达。
这与 UI 默认请求 `selinux_hide=1` 形成实际配置回归。

修复后 `finish_ksu_loaded()` 只记录模块加载与 victim 台账并返回；rootd 清理延后到
真实 KSU su 验证成功之后，su 未就绪时保留回退。公共尾部继续执行既有
`kernel_umount`、`selinux_hide`、`adb_root`、`su_compat` 设置和 Enforcing 检查，
最终 success 的 reused 值来自实际入口，不再固定为 0。没有新增策略规则或新的隐藏
实现。

新增静态回归验证 loaded → su wait → cleanup → selinux feature → Enforcing → success
的顺序，并要求 finish 函数不再包含 `exit 0` 或提前 success。当前 boot 仅补执行既有
feature 下发，读回为 `selinux_hide Value: 1 / Status: enabled`，同时
`MODE=Enforcing`；未重跑 UAF、未重启 zygote、未执行 soft-reboot。新 APK 的完整
初次加载链路仍需下一次允许测试时复验。

修复版 rc13 APK：`/sdcard/cccodroid/MagicRoot-rc13.apk`，61,160,427 B，SHA-256
`9f3c632ed219e3e3b2c90ac4be449b2a2b5af6bf46c5d0b5f2a7f47583af4431`，V3 发布证书不变，
已流式安装并确认 versionCode 12 / versionName 1.0.5。`tools/check.sh` 的 65 个 shell、
327 个资产逐字节对账、profile/Flavor/6.1 等门禁通过；生命周期增至 38 项，新增 post-load
测试通过，既存 5 failures + 1 error 保持不变。安装未启动或重跑 root 链路；目标应用的
实际启动结果待用户重试确认。

## 25. real-cred 早期漏采诊断与有界重试（2026-11-09）

19:06 的运行在 UAF 之前中止：`[cred] no real cred for pid=18065 (site recs=0)`
与 `[cred] real cred leak failed`。native 已退出，但 runner 只识别
`missed page`/cap/finit 三类失败，仍等待 `PROOF_WAIT=720` 秒。

源码新增只读 `--diag-cred`：arm 同一 kmem trace，创建/删除一个 timer，fork/exec
一个 mintwait 子进程，然后先读非破坏性 text trace，再读 raw 流。它不发送 `k`
命令、不写 cred、不进入 UAF。在本机（同 boot，Enforcing）实测：

```text
[cred-diag] slide=0x1269600000 expected_cred_site=0xffffffd2e979c474
[cred-diag] text=... call_site=prepare_creds+0x2c/0x1bc ptr=... bytes_req=184 ...
[cred-diag] raw_bytes=81920 cred_recs=2 timer_recs=640 expected_hits=2 pid_hits=1
[cred-diag] cred_site=0xffffffd2e979c474 count=2 implied_slide=0x1269600000 aligned=1
[cred-diag] timer_site=0xffffffd2e9b1a110 count=1 implied_slide=0x1269600000 aligned=1
```

结论：slide 与 call site 常量正确；同一 boot 可正常捕获，19:06 属瞬时漏采。
timer 直方图中其他同尺寸记录的隐含 slide 均不对齐，现有对齐检查可靠。

改进：

- `leak_real_cred()` 改为最多 3 次有界重试；miss 通过 EOF 释放 mintwait 子进程，
  再重新 arm trace。整个阶段在 UAF 之前，重试不写内核内存。
- 捕获前校验 `events/kmem/kmem_cache_alloc/enable` 实际为 1，防止 trigger 写入
  返回 EEXIST 但事件未启用；失败时 disable/重新 enable 后复查。
- 最终失败输出 raw bytes、cred/timer 尺寸 call site、隐含 slide 与 pid 命中数。
- runner 识别 `real cred leak failed` 立即 FAIL（`FAIL=98260_real_cred_capture`），
  并在 native 进程消失时 fail closed（未知退出会 parked_mark）。

九个 6.12 payload 已用本机 clang 21.1.8 重建并更新 hash（见 BINARY-SOURCES）。
只读诊断与重试路径已真机验证；完整 UAF→KSU 链路未在重建后重新运行。

修复版 rc14 APK：`/sdcard/cccodroid/MagicRoot-rc14.apk`，61,213,770 B，SHA-256
`2021050d801dddc01310d9dca8dd5ec22ffdd3b24fb1b8ed4ed54e7c984b6314`，V3 发布证书不变，
已流式安装并确认 versionCode 12 / versionName 1.0.5。`tools/check.sh` 的 65 shell、
327 资产逐字节对账、profile/Flavor/6.1 门禁通过；生命周期 40 项中新增 capture/diag
测试通过，既存 5 failures + 1 error 不变。安装未启动或重跑 root 链路。

## 26. arm 校验改为 trigger 文件（2026-11-09）

rc14 的 `cred_event_enabled()` 读取 `events/kmem/kmem_cache_alloc/enable`
作为 arm 校验。19:45 的两次运行全部在 UAF 之前失败：

```text
[cred] kmem event not enabled after trigger; re-arming
[cred] kmem event unavailable; capture skipped
[cred] capture diagnostics raw=0 cred_recs=0 ...
FAIL=98260_real_cred_capture
```

实测（uid 2000，SELinux enforcing）：该 `enable` 文件 `stat/cat` 均返回
`EACCES`，而 `events/kmem/rss_stat/trigger` 可读可写，写入后显示
`enable_event:kmem:kmem_cache_alloc:unlimited`。即校验本身不可能通过，
不是事件没启用。

修复：

- `cred_trigger_armed()` 读 `rss_stat/trigger` 并查找
  `enable_event:kmem:kmem_cache_alloc`；缺失时移除后重新 arm、重新 kick
  并复查，仍缺失才关闭 tracing 并跳过捕获。
- `--diag-cred` 输出 `trigger_armed=`，只读复验该判定。
- 同一 boot 真机结果：`trigger_armed=1`，slide `0x1390200000`，
  `raw_bytes=86016 cred_recs=2 expected_hits=2 pid_hits=1`。
- 九个 6.12 payload 重建并更新全部 hash；rc15 APK 已构建安装。

完整 UAF→KSU 链路未在 rc15 后重新运行。

## 27. 22:27 低命中/慢失败复核与 trace 尾部扫描回归（2026-11-09）

rc15 实际已在 20:04 的 boot `8749fb18` 完成 real-cred、进程内 finit、KSU/su
闭环；首次 cred 漏采由第 2 次有界重试恢复。重启后的 22:27 新运行则是另一种
失败：12 次尝试、169 秒、最终 `FAIL=chain_98260 rc=80`。其中 4 次
`page_freed=0` 都在完整 timer churn 后继续等待 25 秒，合计约 100 秒；其余
`page_freed=1` 尝试中多次 `writes=480 hit=0`。

根因之一是 real-cred 移植时把 2026-11-07 已实现的 per-CPU 尾部扫描弄丢了：
旧代码从 cpu0 开始正向扫描，并让所有 CPU 共享 4 MiB 文本预算；高负载时前面
CPU 的旧事件耗尽预算，free CPU 上的新 alloc 事件不可达。本次重新移植
`trace_tail_open/next`，free 每 CPU 使用 1 MiB 尾部预算，alloc 每 CPU 使用
4 MiB 且优先 free CPU；保留 real-cred 后期加强的 `node_pfn` 半页校验与
`trace_task_is_self`，没有退回只检查 8 KiB base 的假命中行为。

速度修复不改变 UI 上限：完整 churn 已失败时，被动尾部等待默认最多 1000 ms
（`PC98260_POST_CHURN_WAIT_MS` 可调），不再机械等待 UI 的 25 秒；若 churn
已找到 free，则完全不进入该等待。新增 `cover8k/cover` 诊断以区分未分配与
task 不匹配。

SELinux Hide 链路同时复核：Compose 默认值 → `MainActivity` 的
`MAGICROOT_SELINUX_HIDE` → `run.sh` 规范化/export → `run98260.sh` →
`ksud feature set selinux_hide` 均一致。已成功运行导出的
`98260_FEATURE_selinux_hide=1 rc=0` 证明它确实应用；22:27 失败运行在 root 前
退出，不执行 post-load feature 是预期行为。为避免失败日志无法显示请求值，
`98260_OPTIONS` 现在显式包含 `selinux_hide`（以及 kernel_umount/adb_root）。

6.12/6.6 的 12 个共享源 payload 已重编并更新 hash，三份 C 源逐字节一致。
除本轮 trace/post-churn/SELinux 回归外，还补齐了同源的 ARMED/NO_ROOT 原子状态、
状态失败拒绝 arm、waitid/waitpid 失败保持 UNPROVEN 与 preflight 真实退出码；
生命周期套件 43/43 全部通过。当前 6.12 boot 已 parked，未自动重试；修复后的
真机命中率与总耗时必须在重启后单独验证，6.6 仅有静态适配验证。

rc16 APK（已否决并改名）：`/sdcard/cccodroid/MagicRoot-rc16-REJECTED-PANIC.apk`，61,197,297 B，SHA-256
`7bffc4a00b43190886c464819d14ed24af1b6e31f48f3ba741c5e4af79de4e82`；
V3 发布证书不变。`verify_apk.py` 通过，APK 内 6.12.58 payload 为
`f829548b…88b237c`，runner 为 `3bcbd119…d3c5d`。最终
`bash tools/check.sh` 输出 `ALL CHECKS PASSED`：65 shell、35 profile hash、
327 资产/APK 对账、41 dedup、43 生命周期、11 H1C 及其余 Java/Flavor/6.1/
finalize/cleanup/su 回归全部通过。

## 28. rc16 真机 AP_S_PANIC：否决合并与 fake-cred 布局收缩

rc16 设备执行后直接重启，`sys.resettype=abnormal:AP_S_PANIC`。该候选即使本地
全绿也不得合入。崩溃 boot 没有导出 native 日志，当前 Enforcing 又拒绝 shell
读取 dumplog/faultdetect，因此不能声称已经取得具体 panic 栈，更不能把责任
确定归给某个新函数。

按用户要求，rc17 改为对照本机 6.12 fake-cred 正确路径，而不是继续挪用其他
内核版本：

1. 撤销 6.6 整文件同步和本轮 6.6 payload 替换；源文件恢复修改前快照，资产
   从 rc15 原样恢复。测试只核对共享 preflight 函数契约，不再强迫不同内核
   整个 C 文件一致。
2. real-cred 的 uid/SELinux pass 恢复 fake-cred 的 `CRED + SELINUX + NONE`
   三槽布局，删除 `g_want_cap` 和 `cap plant combined`。CAP_SYS_MODULE 使用
   独立 PLANT_PTR pass，并在 finit 前验证 bit16；这对应早期已成功的分离 cap
   路线，不再把 self-parent 合并 tile 当成无风险优化。
3. 保留只读 trace 尾部扫描与有界尾等待；它们不引入新内核写目标。通用
   ARMED/NO_ROOT、waitid/waitpid 失败保持 UNPROVEN 的门禁也保留。
4. 新回归 `test_uid_phase_uses_fake_cred_layout_without_cap_tile` 锁定上述
   分离时序。rc17 只重建九份 6.12 payload，未合入、未做真机复验。

panic 的确切根因仍待可读 dumplog 证明；本次收缩是撤销未证明安全的假设，
不是声称已经定位到唯一根因。

rc17 候选 APK：`/sdcard/cccodroid/MagicRoot-rc17.apk`，61,189,104 B，
SHA-256 `7e60b19d18cffc9821e30a390750d271209a061a5cac18f26712589108e7d500`。
V3 发布证书与版本号不变，未自动安装或运行。最终 `tools/check.sh` 输出
`ALL CHECKS PASSED`（43 生命周期、11 H1C、327 资产及其余完整本地门禁）。
