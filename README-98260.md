# MagicRoot 1.0.5-98260-dual — CVE-2026-98260 实验链路（6.12.58 / 6.12.38 双内核）

> **状态：实验性、默认关闭。** 本目录是 `MagicRoot-Enhanced-1.0.3` 的副本，
> 新增 CVE-2026-98260 作为**第二条可构建/可验证链路**（按设备内核选择对应适配版本）；
> CVE-2026-64560 默认链路行为不变。全程未连接设备、未 adb、未安装 APK、未刷机。
>
> 本文档记录 1.0.5 基线的链路细节；1.0.6 的支持矩阵与发布说明见
> [`README-1.0.6-release.md`](README-1.0.6-release.md)。

## 1. 版本与产物

| 项 | 值 |
|---|---|
| package | `com.aoki.magicroot` |
| versionCode / versionName | **10** / **1.0.5-98260-dual**（legacy manifest 同步） |
| 主交付 | compose APK：`MagicRoot-1.0.5-98260-dual.apk`（仓库根目录，4,076,170 B，SHA256 `e4603d5e…fdb98b56`；完整证据见 `INTEGRATION-EVIDENCE.md`） |
| 构建 | `main/app/build.ps1`（Gradle 9.3.1 + AGP 9.1.0 + JDK25 + SDK37；仅本机构建，二次构建哈希一致） |
| 目标内核 A | `6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k`（用户提供的 mly-fw / Magic8Pro(BKQ-AN90) boot 镜像） |
| 目标内核 B | `6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k`（用户本次指定的 `Downloads/boot.img`） |

## 2. 双内核资产布局

设备侧共用一台阶段机 `main/app/assets/98260/run98260.sh`；它按精确 `uname -r` 选择二进制目录：

| 内核构建 | 设备端目录 | 本地 assets | 适配常量 |
|---|---|---|---|
| 6.12.58-…541502914-4k | `$D/98260/` | `assets/98260/` | `LINK_SELINUX_STATE=0xffffffc0827e7a60`、`LINK_GETPID=0xffffffc0804770d4` |
| 6.12.38-…481467632-4k | `$D/98260-6138/` | `assets/98260-6138/` | `LINK_SELINUX_STATE=0xffffffc0826663c8`、`LINK_GETPID=0xffffffc080d65124` |

每个目录包含 4 个适配二进制 + `target.sh` + `SHA256SUMS.txt`；6.12.58 目录另含共享阶段机
`run98260.sh`。两个内核的二进制均由 Lead 用 NDK r28c（28.2.13676358）从上游源码重建，
相对早期参考实现均为 3 类改动：2 个 LINK 常量 + 定时器分配探针替换
（`alloc_posix_timer` 被 LTO 内联 → `do_timer_create+0xac timer=%x0:x64`，两个内核该偏移恰好相同）。

| 内核 | perf / chain / key-ptr / su (SHA256 前缀) |
|---|---|
| 6.12.58 | `bd52314d…` / `1cca5772…` / `61bcb479…` / `374bac50…`（大小 66232/66904/80480/8584） |
| 6.12.38 | `7a95e545…` / `7ce538cb…` / `d055e3fd…` / `374bac50…`（大小相同） |

## 3. 默认门控（安全关键）

- 默认 `MAGICROOT_CHAIN=64560`、`MAGICROOT_ENABLE_98260=0`；64560 流程完全不变。
- UI「链路选择」默认 64560；切到 98260 需**二次确认弹窗**；未确认时「开始提权」会被拒绝。
- `run.sh`/`run98260.sh` 按 `uname -r` 精确匹配两个目标内核之一；不匹配 `FAIL=kernel_unsupported`
  （fail-closed）。上游参考的 6.12.69 不是可运行目标。
- 设备型号只做告警（允许 MLY-AN00 / BKQ-AN90；以内核构建串为硬门控）。
- 98260 链**不使用 KernelSU 后端**：不 ko_patch / 不 finit_module / 不 root_stage / 不写 `/data/adb`；
  KASLR 由 98260 二进制自行通过 tracefs kprobe + perf 观测，不使用 64560 的 `kaslr_slide_*`。
- 98260 成功**不自动清理**（rootd 必须存活）；「清理临时文件」会结束 rootd，需用户显式操作。

## 4. 运行方式（真机前置条件，全部待实测）

1. Honor Magic8 Pro（BKQ-AN90 或 MLY-AN00）运行上面两个目标内核构建之一；
2. 开发者选项/USB 调试可用，已安装并运行 **Stellar**（优先）或 **Shizuku**；
3. 安装本 APK → 授权 Shell → 链路选择切到 98260 并确认；
4. **建议先勾选「预检模式」跑一次**：只读检查内核/boot_id/对应资产哈希/tracefs kprobe 可写/
   `exploit-android-perf --preflight`（32/32 owned slab + RCU 回调）/
   `--aio-probe` / `--pcp-probe` / `--cred-dump`（fullcap `cred+0x48` gate）/ `@memstart_addr` kprobe/
   `posix_timers_cache` slabinfo；
5. 预检通过后再取消预检、点「开始提权」。失败后按失败码处理（见 §5）。

## 5. 失败码 / fail-stop

| 输出 | 含义 | 处理 |
|---|---|---|
| `FAIL=chain_98260_not_enabled` | 未显式启用（缺 `MAGICROOT_ENABLE_98260=1`） | 在 UI 确认链路后重试 |
| `FAIL=kernel_unsupported` | `uname -r` 不是两个目标内核构建之一 | 不要运行；该链只绑定 6.12.58-…541502914-4k / 6.12.38-…481467632-4k |
| `FAIL=asset_hash` | 对应内核目录的资产被篡改/损坏（与 `SHA256SUMS.txt` 不符） | 重新部署；勿绕过 |
| `FAIL=tracefs_kprobe_unwritable` | tracefs/kprobe_events 不可写 | 只能设备侧排查（SELinux/权限）；不要强行运行 |
| `FAIL=selinux`（exit 78） | 等待 12 分钟后仍非 Permissive，或进程退出仍为 Enforcing | 重启手机后再试 |
| `FAIL=parked` | 出现 `[PARKED]`/`retain mappings`；危险状态被保留 | **不要 kill、不要重试**；重启手机；标记会阻止同 boot 重跑 |
| `FAIL=parked_retained` | 同一次开机内已有 PARKED 记录（跨 clean 保留于 `$D/.98260-parked` 及 `/data/local/tmp/.magicroot-98260-parked`） | 重启手机（或确认后手动删标记） |
| `FAIL=proof`（exit 80） | cred/fullcap 未在 12 分钟内产出 `uid=0 + CapEff/CapPrm/CapBnd=000001ffffffffff + Permissive` | 进程/rootd 保留不 kill；重启手机后再试 |
| `FAIL=deploy` | 部署失败（磁盘/权限/覆盖校验） | 查看日志；必要时手动清理后重试 |

成功判据（脚本内独立查询，不接受“SELinux 已 permissive”代理指标）：
`PC98260_SOCK=/data/local/tmp/pc98260-root.sock .../pc98260-su -c 'id; grep -E "Cap(Eff|Prm|Bnd)" /proc/self/status; getenforce'`
必须同时给出 `uid=0(root)`、`CapEff/CapPrm/CapBnd = 000001ffffffffff`、`Permissive`，脚本输出 `98260_SUCCESS=1`。

## 6. 与 64560 的隔离

- 资产：`assets/98260/` 与 `assets/98260-6138/`（64560 资产零改动）
- 设备目录：`$D/98260/`、`$D/98260-6138/`；64560 使用 `$D/` 顶层
- 部署：3 个 exploit 二进制会复制到 `/data/local/tmp/`（perf-chain 源码硬编码 exec
  `/data/local/tmp/exploit-android-key-ptr`）；clean 按两个 manifest 的哈希只删本工具文件
- 进程：`exploit-android-*` / `pc98260-*`，clean 按名/哈希清理
- KSU：98260 分支不加载任何 LKM、不写 `/data/adb`
- 日志：`/data/local/tmp/magic/98260.log` + `$D/98260*/*.log` + stage.log
- 默认：64560 路径的 env/行为不变（见 `INTEGRATION-EVIDENCE.md` 的 diff 证据）

## 7. 未验证项（诚实边界）

- 真机执行：**本版本未在设备上运行过**；上游参考版也只在 ADB shell（uid 2000）验证成功，
  Stellar/Shizuku shell 域下的 tracefs/perf_event_open/AIO/keyring 可达性未知。
- 两个内核各自的 `MEMSTART_PFN=0x80000` 均需设备侧 `/proc/iomem` / `@memstart_addr` kprobe 预检确认；
  失配只影响 pcp-drain 门控并 fail-stop，不会误写。
- `SLAB_OBJECTS=32` / `posix_timers` 的 order/objs_per_slab 需 `--preflight` 或 `/sys/kernel/slab` 确认。
- 6.12.58 目标 bootargs 含 `page_poison=on`；6.12.38 目标 bootargs（Downloads/vendor_boot）**无** page_poison，
  两者页重用时序可能不同，均未实测。
- `[PARKED]` 的清理语义：脚本有意不回收危险状态，需重启手机。
- 成功率：上游明确为概率成功、非 100%，且仅当前开机周期有效。

## 8. 其它

- 构建与校验脚本：`tools/verify_98260_assets.py`（单内核旧工具）、`tools/verify_98260_dual.py`（双内核+集成校验）、
  `tools/verify_apk.py`（APK 资产/marker 校验）。
- 证据：`INTEGRATION-EVIDENCE.md`（APK 哈希、双内核资产核对、shell 语法检查、改动清单、64560 不变证据）。
- 安全边界：本项目不提供自动部署；本版本未 adb、未安装、未推送。
