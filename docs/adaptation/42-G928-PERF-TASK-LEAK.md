# g928 task_struct perf 泄漏实现

日期：2026-10-30

## 背景

g928 `copy_process+0x13c` 调用：

```text
bl kmem_cache_alloc_node_noprof
```

但内核只导出 `__tracepoint_kmem_cache_alloc`，没有
`kmem_cache_alloc_node` tracepoint；`kprobe_events` 对 shell 返回 EACCES。
所以 BRM 风格的 `leak_task()` 看不到 task_struct，稳定失败：

```text
[task] leak failed
```

## 实现顺序

```text
1. 98260 UAF 零写 selinux_state-7
2. SELinux 变 Permissive
3. perf_event_open(sched_process_fork)
4. sample_type = TID | TIME | RAW | REGS_INTR
5. sample_regs_intr = X0 | X1
6. fork cred_child
7. 从 x1（child）取 task_struct，失败回退 x0
8. 用该 task 做 fake cred UAF
```

关键原因：perf_event_open 在 Enforcing 下返回 EACCES，必须先做 SELinux 零写；
该零写不需要 task 指针。

## 日志

成功路径应看到：

```text
[selinux] pre-perf attempt 1/4 target=...
[selinux] permissive before perf
[task-perf] sample id=... abi=... x0=0x... x1=0x...
[task-perf] child task=0x... pid=...
[cred] plant attempt ...
```

失败分类：

```text
[task-perf] fork tracepoint id unavailable
[task-perf] perf_event_open errno=13 id=...
[task-perf] no child task pointer
[task] leak failed
```

## 边界

- 未在 g928 真机验证；当前 ADB 设备是 6.12.58。
- `sched_process_fork` 的 tracepoint id 在内核中读取；若 Permissive 后仍被 DAC 拒绝，需要从 root 提供 id。
- `PERF_SAMPLE_REGS_INTR` 是否能稳定捕获 tracepoint 参数需真机日志确认。
- 不在 Enforcing 下直接调用 perf。

## 版本

```text
MagicRoot-1.0.5.apk
sha256 FEB3A09CAC3020D1774D10917FF7F25E48AD2D13F2AFE8A98F6D01F8DB7F56AE
```
