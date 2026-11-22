# OnekeyJB 精确命中逻辑复核与 6.12 应用

日期：2026-11-10。状态：本地候选，未合入，未真机复验。
2026-11-11 更新：fake-cred 再次 panic 后定位到第二个根因（跨半页 triple），
同半页修复已应用；见第 6 节，仍未真机复验。

> 注意：第 6 节是 2026-11-11 的补充。它推翻了“上一节修复即可消除 panic”的
> 预期 —— 那套修复解决的是 miss 后盲写，不是本次跨半页 reap。

## 1. 本次异常重启的证据边界

新版运行后设备为 `abnormal:AP_S_PANIC`。崩溃 boot 的 run.log 只保留到
`CHAIN_98260_PRE`，没有生成可读取的 `98260.log`，因此不能声称已经拿到具体
panic 指令或把原因归给某个 tile。

此前 `magicroot-live.log` 在非 debuggable 应用的内部目录，授权 shell 不能读取。
本候选把它迁到 `getExternalFilesDir()`（实际为
`/sdcard/Android/data/com.aoki.magicroot/files/magicroot-live.log`），首次启动迁移
旧的内部日志。后续异常重启后可用授权 shell 直接取证。

## 2. 深入核对的 OnekeyJB 实现

### 可执行源码

`merged-app/app/src/main/cpp/ghostkey/uaf_plant.c` 包含真实的 stream、pipe、AIO
回收实现，不是 `native/executor` 的占位 plant：

- `reclaim_stream()` 先查 free，再以 8 KiB AF_UNIX 写回收；
- `reclaim_and_plant()` 把每个 CPU 的 filemap 事件行号与 `g_cpu_ctx[cpu][index]`
  对应，只有行数与 ring 数一致时才取对应 ring，随后还校验 magic；
- 这是“事件行号 → 具体 AIO ring”的精确归属证明，比单纯 PFN+task 更强，
  但它属于 AIO 回收器。当前 MagicRoot 主路径是 stream，不能在不切换回收器时
  假装拥有同样的 ring 证明。

### 实测成功规格

`analysis/SUCCESS-SPEC.md` 与 `analysis/device/PROGRESS.md` 记录 OnePlus 16 的
真实成功日志：

- `RECLAIM_FREED=1 cpu=5` 先于写入；
- `RECLAIM_WRITES=4096 HIT=1`，一次 tile 命中约 558 ms；
- 随后真实 cred/late-load/su 验收。

`knowledge/13-踩坑与修复记录.md` 另明确禁止在 `RECLAIM_FREED=0/HIT=0` 时继续
盲写和无限重试。这些是可应用的时序/预算约束，不是可照抄的内核地址。

## 3. 当前实现的原问题

- free 等待耗尽后仍继续执行 6×80=480 次 8 KiB 写入，属于无 free 证据盲写；
- free 已证明时也只有 480 次预算，随后再进入 4 KiB half 重试；
- 现有命中仍严格要求 `mm_page_alloc` + 当前进程 task + stale-node 所在 4 KiB
  半页，不能为了套用参考实现而放宽。

## 4. 已应用的最小改进

1. **无 free，零写入**：直接走原 miss/victim 处理，不再喷无关页面。
2. **有 free，才有界写**：`PC98260_STREAM_WRITE_BUDGET` 默认 4096，允许
   80..16384；每 80 次检测一次，命中立即停止，仍有原 8 秒时间上限。
3. **保留现有安全判据**：self-task、node_pfn、victim ledger、unproven 不 reap、
   fake/real 分支隔离和 cap 失败禁止 finit 均不变。
4. **不移植 AIO 映射**：不把另一回收器的命中证明硬套进 stream，也不默认开启
   历史上检测较弱的 pipe/AIO fallback。

预期效果是减少无意义 spray 和由低预算造成的额外 miss；实际命中率、耗时和
panic 是否消失必须真机验证，不能由静态测试推断。

## 5. 本地验证

- 新增 `test_stream_writes_require_free_and_use_bounded_4096_budget`，锁定
  free→write 顺序、4096 有界预算、命中即停与 node_pfn 检查；
- 当前生命周期 48/48 通过；LiveLogStoreTest 继续通过；
- 九份 6.12 payload 重建，6.6 保持此前恢复资产；
- real/fake 两包均重新签名、对账；最终 `tools/check.sh` 已输出
  `ALL CHECKS PASSED`（48 生命周期、11 H1C、LiveLogStoreTest 及全套既有测试）。

候选包：

- `/sdcard/cccodroid/MagicRoot-real-cred.apk`，61,209,585 B，SHA-256
  `97d983dfcb30729431d5ecee2ebfaba6769e863fc6267e129572dff6e266748b`
- `/sdcard/cccodroid/MagicRoot-fake-cred.apk`，61,209,585 B，SHA-256
  `8c7a19d601e3c687d6a5114544f127a915be44a54a419b180794b0db340860d8`

两包均保持 versionCode 12 / versionName 1.0.5 和原 V3 证书；未合入、未自动安装，
真实命中率和 panic 是否消除仍需下一次明确授权的真机测试。

参考仓库与许可证仍按 `docs/ONEKEYJB-REFERENCE.md`：onekeyjb GPL-3.0，固定提交
`8657b405a0da25894f331994d8220c3edd234a08`。

## 6. 2026-11-11 fake-cred 再次 panic：跨半页 triple 根因

22:08:32 的运行确认为 fake-cred（`cred 分支: fake-cred`，
`98260_MANAGER_PAIR=strict mode=fake`），22:09:08 触发
`reason [page_request]` 的 `abnormal:AP_S_PANIC`。部署的 g142 payload 已包含
上一节的 free→write 顺序与有界 4096 预算（资产内可见
`skip writes: no proven page free` / `write_budget=` / `unproven_reap_refused`），
因此不是旧资产回退。崩溃同样没有留下 `98260.log`。

代码复核定位到**独立的第二个根因**：`pick_triple()` 只要求三个 armed timer
节点同在一个 8 KiB slab，未要求同在一个 4 KiB 半页；而回收命中判据
`find_page_alloc(node_pfn)` 只证明 base 0（victim）所在半页已被我方 8 KiB 页
写入。fake/uid 模式的 base 2 是 `TILE_NONE`（只 arm、不植 tile），real cap 模式
的 base 0/1 也是 `TILE_NONE`；这些节点的半页若不在证明范围内，reap 时
`posix_cpu_timers_exit → timerqueue_del → rb_erase/rb_next` 读到的是释放后 slab
的残留内容，与 2026-11-07 的 page_request 栈同型。历史运行日志中确实出现过
跨半页 triple 被选中并立即 reap 的组合（三节点分属两个半页，而 ledger 的
`need` 只有 1 位）。

修复（`binary-sources/98260-6.12`、`6658`、`6689` 三份同源 C）：

- `pick_triple()` 增加同半页约束：三个 `g_tile_off` 与 base 0 的 bit12 必须
  一致，不符则跳过该 slab，并记录 `[triple] skip cross-half`；
- `victim_reg()` 的 `need` 掩码改为包含全部三个 tile 半页加上 victim 节点半页
  （原先只算非 `TILE_NONE` 的已植 tile）。同半页约束下运行时 `need` 仍是 1 位，
  该改动是防回归的第二道证明：即使将来再次选到跨半页组合，也会因未覆盖而
  refusal-to-reap，而不是 panic；
- 回归 `test_armed_triple_stays_in_one_4k_half` 锁定以上两条。

未改动 H1C（单 tile、单 timer，本就只依赖 victim 半页）与 61821/61821-brm
（旧实现）。g554/f171 的 6.6 二进制没有对应源码，仍带旧 triple 逻辑，未重编。

同半页约束使可用 slab 变少，可能降低单次命中率；miss 会按原有 fail-stop
停在 parked 状态，不会自动重试。panic 是否消除仍需下一次明确授权的真机测试。

候选包（默认 fake，同一版本/证书）：

- `/sdcard/cccodroid/MagicRoot-fake-cred.apk`（同时覆盖
  `main/app/MagicRoot.apk`），61,217,777 B，SHA-256
  `37675d332e8ce7de15e3aae7e72a7a7c0c901b806735b62c57e2ba1d44fd3663`
- `/sdcard/cccodroid/MagicRoot-real-cred.apk`，61,217,777 B，SHA-256
  `16282091b1616955a6a5bc5107afeed73a9c61e4cebe487d89a84c76f419b140`

12 份 payload 的新 hash 与重编命令见 `BINARY-SOURCES.md` 2026-11-11 末节。


## 7. 2026-11-11 深夜 二次修复：命中的是扫描器自己的匿名页

22:50 的 real-cred 日志：cap 第 7 次尝试 `[stream] hit` + `[uaf] reaped status=9`，
但 `/proc/16150/status` 至今仍是 `CapEff: 0`。该次 `[alloc-hit]` 是
`order=0 … GFP_USER|__GFP_COMP|__GFP_ZERO|__GFP_ACCOUNT`；当天三次成功运行的命中
全部是 `order=1`。

根因是「命中」判据只证明本进程分配了该 pfn，不证明 tile 落到了节点所在半页：

- `find_page_alloc()` 接受任何本进程的 mm_page_alloc；
- 喷洒循环每 80 次写调用一次扫描，`trace_tail_open()` 每次 malloc 1 MiB 并 fread，
  这些堆页在窗口内缺页，会抢到刚释放的 8K 半页并满足命中；
- 未被 fread 写过的零页 → `rb_erase` 安全分支，静默不写（CapEff=0）；
  已写入 trace 文本的页 → `rb_next`/`rb_erase` 拿文本当地址 → 野指针 panic。

修复：硬命中（order>=1 且覆盖 base..base+1）、扫描缓冲启动时预分配预触页、
`--exec-ok`/mintwait 跳过预触页、`cover_self` 同判据、payload 日志 O_SYNC 镜像 +
App 启动导出。

新 APK：`main/app/MagicRoot.apk`，61,225,968 B，SHA-256
`a0512996e01139e6687c55d9ca490aa44a1505a4ebdf5dfa7520d73d2d2741cb`
（内含 g142 payload `5b43bebf…3e2d41`）。`tools/check.sh` ALL CHECKS PASSED。
未在真机执行 UAF。
