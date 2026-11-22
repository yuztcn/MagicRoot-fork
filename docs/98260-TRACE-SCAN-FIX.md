# 98260 trace-scan reclaim 修复（2026-11-07，6.12.58 g142 FAIL=80 根因）

## 1. 背景与失败签名

参考包 `MagicRoot-1.0.4-v17-117r1.apk` 的两份 prev-run 日志中，
`prev-run-1794059690090.txt` 在内核
`6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k`
（g142ddad31e60 构建）上 12/12 次尝试全部失败：

```text
[stream] writes=480 hit=0 cover8k=… cover=…   ← 修复前无 cover 字段
[half] miss …
…
FAIL code=80
```

特征：`page_freed=1` 能检测到（free 事件被看见），但 reclaim 写入后
`find_page_alloc` 永远 miss。

## 2. 根因

`binary-sources/98260-6.12/uaf_plant_61258.c`（`binary-sources/6658/`、
`binary-sources/6689/` 下为 md5 相同副本）：

- `TRACE_SCAN_BUDGET (4U << 20)` 是**所有** `per_cpu/cpuN/trace` 文件
  **共享的单一预算**。
- 扫描顺序为 cpu0 → cpuN **正向**，且每个 dump 内部按 **oldest → newest**
  （ftrace per-cpu buffer 是时间序）。
- 失败运行负载 load≈23–27，cpu0 的 trace dump 文本超过 4 MiB，预算在
  cpu0 内部耗尽 → cpu≥1 的 dump **从未被扫描**。
- `find_page_free` 在 churn 早期 dump 尚小时命中（`page_freed=1`）；
  但 `mm_page_alloc` 事件全部落在 cpu2/cpu3（日志 `free_cpu=2,2,3`），
  alloc 检测不可达 → 12 次全部 miss。

该缺陷是**负载敏感**的检测 bug，不是 g142 专属：此前 61258（g3a7ac）
能通过只是当时 dump 未超预算。同一签名此前已在 MLY-AN00 上出现过
（`pfn_event_covers` 注释有记录）。

## 3. 修复内容

对三个相同源文件同步修改：

1. **新增 `struct trace_tail`**：`trace_tail_open` 把整个 per-cpu trace
   文件读入 malloc 缓冲（上限 128 MiB），`trace_tail_next` 从**最新一行
   向最旧**迭代。目标事件（我们的 alloc/free）永远是 dump 末尾的最新事件，
   tail 扫描既快又不会被旧事件挤出预算。
2. **`find_page_free`**：每 cpu 独立 `TRACE_FREE_TAIL_BUDGET`（1 MiB），
   churn 热路径保持有界。
3. **`find_page_alloc(uint64_t pfn, int prefer_cpu)`**：`prefer_cpu`
   （写入绑定的 free_cpu）先扫，其余 cpu 随后；每 cpu 独立
   `TRACE_SCAN_BUDGET`（4 MiB）。命中条件不变：`mm_page_alloc:` +
   `pfn_event_covers` + `trace_task_is_self`。
4. **诊断字段 `g_alloc_cover`**：在 task 过滤**之前**统计覆盖该 PFN 的
   `mm_page_alloc` 行数。miss 时：
   - `cover=0` → 我方写入从未分配该页（reclaim 未落地）；
   - `cover>0` → 页被分配但非我方 task（task 字段不匹配）。
   `[half] miss` 现在打印 `cover=%lu`；`[stream] writes=…` 打印
   `cover8k=%lu cover=%lu`。
5. 调用点更新：`find_page_alloc(free_pfn, free_cpu)`（`reclaim_stream_half`）、
   `find_page_alloc(base, free_cpu)`（`reclaim_stream`）。

## 4. Runner 开关（默认关闭，仅现场调试用）

`main/app/assets/98260/run98260.sh`：

- `CHAIN_98260_ENABLE_FALLBACK=1` 或 `MAGICROOT_98260_FALLBACK=1`
  → `PC98260_ENABLE_FALLBACK=1`。启用 pipe/AIO 回退 reclaim。
  **不默认开**：`reclaim_pipe` 的检测缺 `task_is_self`，误命中会
  `rb_erase` 外来内容（参见 2026-11-02 21:00 `page_request` panic 记录）；
  `reclaim_and_plant` 对所有 AIO ring 无条件种假 node。
- `MAGICROOT_98260_STREAM_BUF_KB=<n>` → `PC98260_STREAM_BUF_KB=<n>`。

## 5. 重建与哈希

全部 12 个可重建 payload 用 Termux clang 21.1.8 重编（动态 bionic PIE，
与 ledger 构建同一配方；改动前已验证该工具链可逐字节复现旧资产）。
每个二进制现为 **75,696 B**：

| 资产 | SHA-256 |
|---|---|
| `98260/exploit-android-key-ptr` (6.12.58 g3a7ac) | `26e0092e122a6df4d992517dc0b0109078f2abcacb56f12cb91bbb09bc84a122` |
| `98260-6123/…` | `524abae3c9f4b19168a8ca1ae9612b02abe2daa1f9052cfe384e43a179d54d0c` |
| `98260-61258b/…` | `675fcbb4538a2ee06ca97dd45dcd5159535bcfa3f32b692328e18d7f17886576` |
| `98260-61258c/…` | `f8a04887171a669e45dc1256baa4e7c481a7d684204103f69747f3fe8333f77b` |
| `98260-6138/…` | `b9ee1909d5d5dc7261c7f7532dc32f4c0065173a5a77eca1b7b9e8b2838d0171` |
| `98260-6138y/…` | `46c89e51cb21ccdd71297a69d6b960af2ae860fb9efac0943125eb756ba13652` |
| `98260-g856/…` | `87335a0f86f81ccd0cd87bd463d167115fe123bf4f37eeb78e9542de871da7fc` |
| `98260-g142/…` | `63a408f61a17de995fd6676665b530fb64153d299e99a657e1879718fd5e06e7` |
| `98260-6658/…` | `4677adf3903f72f3549cfc53ccd20e4e903e1a7997fef6f1e67d9591e818af88` |
| `98260-6689/…` | `dc33f8d5991855cc409f494c3a274751c1123c5260403deff24d530275da6872` |
| `98260-ga812/…` | `b956e43fe48ab2e621eba96ee311988e1f41301eacd4bb55c4ca8005729c79c8` |

`exploit-61258b` 与 `exploit-aph112` 仍逐字节相同；`98260-aph112/exploit-android-key-ptr`
已加入 `tools/asset_dedup_map.json` 与 `KernelLogHelper.DEDUP_ASSET_MAP`
（canonical = `98260-61258b/exploit-android-key-ptr`）。

同步更新：6 个 `98260*/SHA256SUMS.txt`、`build-98260-6.12.ps1` `$expect`、
`tools/verify_apk.py`、`tools/verify_98260_assets.py`、`BINARY-SOURCES.md`、
`SOURCE-MANIFEST.txt`、`tools/test_98260_uaf_lifecycle.py`。

## 6. 验证状态（如实说明）

- **静态**：根因由代码审查 + 失败日志签名证实；修复后
  `tools/check.sh` 全部门禁通过（含新增的
  `test_trace_scan_is_per_cpu_newest_first` 断言）；payload 重建与
  Termux clang 配方逐字节一致。
- **未验证**：修复后**没有任何真机 98260 运行**。g142 reclaim 是否成功
  需真机确认；下一次设备日志应出现 `cover=`/`cover8k=` 字段，可直接区分
  「写入未分配」与「已分配但 task 不匹配」两种 miss。
- 6.1.x（~2.3 MB）与 6.18（~450 KB）payload 是不同二进制，本次未动。

## 7. 2026-11-09 real-cred 移植后的回归与恢复

real-cred 6.12 源在后续移植中回到了旧的共享预算正向扫描，22:27 的高负载
运行再次出现同类 miss。此次从 6.6 同源实现重新移植尾部扫描，但保留
real-cred 后续加入的两项更严格条件：`find_page_alloc(node_pfn, free_cpu)`
检查 stale-node 所在的 4 KiB 半页（不是旧文档中的 8 KiB base），并继续要求
`trace_task_is_self`。因此 §5 的 base 调用点说明已被当前实现取代。

同一轮修复还新增 `PC98260_POST_CHURN_WAIT_MS=1000` 默认值：timer churn 已
完整跑完仍未观察到 free 时，只保留 1 秒尾部等待，而不是继续耗尽 UI 的 25 秒
上限。该值只影响 miss 的耗时，不改变 reclaim 或收尸判据。rc16 曾一度同步
6.6 并重建 12 份资产，但真机 AP_S_PANIC 后该候选被否决；rc17 已撤销 6.6
同步/资产替换，只保留九份 6.12 候选重建，并恢复 fake-cred 的分离 cap 时序。
当前 43 项静态回归通过；rc17 尚未真机运行。
