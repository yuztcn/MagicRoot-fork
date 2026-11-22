# 48 — 6.12.58 回收页匹配、全屏日志返回与收尾卡顿修复（2026-11-05）

真机：HONOR MLY-AN00，`6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k`，
FinaSU，Shizuku uid=2000。

三份现场日志（`/sdcard/Download/MagicRoot/`）：

- `fail_log_1793824139885.txt`：04:24 运行，`FAIL=proof no_rootd_socket_after_240s`。
- `magicroot-log-1793891702756.txt` / 运行日志截图：23:09 运行成功到 `DONE`。
- 23:09 运行的 `98260_FINALIZE_BEGIN` 到 `DONE` 之间约 64 s 没有新日志。

## 1. 6.12.58 UAF 回收经常 miss

### 1.1 现象

失败运行里多轮出现：

```text
[churn] round=3 total=1024
[stream] waiting page_freed pfn=0x92e98a (cap 25000 ms)
[stream] wait cap 25000 ms hit at iter 268, treating as miss
[stream] page_freed=0 pfn=0 order=0 cpu=0 (25030 ms, 268 iter)
[stream] writes=480 hit=0
[uaf] page miss, retry (stream-only)
```

8 次 attempt 里只有 2 次 `page_freed=1`，且在 180 s plant 预算内耗尽，
rootd socket 从未出现，run98260 在 240 s 后判失败。成功运行同样有大量
`page_freed=0`，只是第 5/9 次碰巧命中。

### 1.2 根因

`find_page_free()` 只接受 `pfn == base`（order=1）或 `pfn == node_pfn`
（order=0）的事件，`find_page_alloc()` 只做 head PFN 精确比较。

6.12 的 `skb_page_frag_refill()` 分配 order-2/3 的 page_frag；buddy 合并
会把刚释放的 order-1 `k_itimer` slab 折进这种复合页。`mm_page_free` /
`mm_page_alloc` 记录的是**复合页头 PFN + order=N**：

- 头部不等于 base 时，连第一个 pfn 比较都过不了；
- 头部恰好等于 base 时，`order > 1` 也被显式跳过。

于是 slab 已经释放、或写已经落在目标页，插件仍然报 `page_freed=0` /
`hit=0`，白等满 wait cap 后丢弃这次结果。6.18.21 H1C 插件已经修过同一
缺陷（`docs/98260-H1C-ENGINE.md`），6.12 的 `uaf_plant_61258.c` 没有同步。

### 1.3 修复

`binary-sources/98260-6.12/uaf_plant_61258.c`

- 新增 `pfn_event_covers()`：解析 `pfn=0x…` 与 `order=N`，按
  `[head, head + 2^order)` 判断目标页是否落在事件范围内。
- `pfn_in_line()` 改为范围匹配（`trace_seen` 间接使用）。
- `find_page_free()` 用 `pfn_event_covers(line, want_half, …)`；order>=2
  的复合页释放会被接受，`out->pfn` 记录复合页头、`out->order` 记录真实
  order，后续 8 KiB/4 KiB 喷射逻辑不变。
- `find_page_alloc()` 同样改为范围匹配：socket 写若分配了覆盖 base 的
  order-2/3 page_frag，也算命中。

重建产物（见下一节）：

```text
788f53546a9b00527b9993792d5a43f64ad74881f1a4cf080c94f1b3ec580ee0
main/app/assets/98260/exploit-android-key-ptr  (58,552 B)
```

### 1.4 构建方式与限制

本机 Termux clang 21.1.8 **没有静态 bionic libc**
（`libc.a` / `crtbegin_static.o` 不存在，`pkg ndk-sysroot` 也只带动态桩），
无法复现原来的 `-static` 产物，因此本次用：

```bash
clang -std=gnu11 -O2 -w -pthread -I binary-sources/98260-6.12 \
  -o exploit-android-key-ptr \
  uaf_plant_61258.c stubs.c rootd.c
```

生成**动态链接 bionic PIE**（`interpreter /system/bin/linker64`）。UAF 竞态
在内核侧（`execve("/proc/self/exe")` 后 `tgkill`），与用户态加载器无关；
`exec-ok` 子进程仍在 `execve` 后立刻 `_exit(0)`。

`build-98260-6.12.ps1` 里 61258 的期望 hash 仍是旧的 `fe67a61d…`，用
NDK 静态重建时需要先更新该门禁值。其余 6.12 profile（61258b/61258c/6138
等）的 payload 未改动。

### 1.5 验证

- `pfn_event_covers` 的独立单测：order=0/1/2/3、head 命中/不命中、无
  order 字段共 12 例全部通过。
- 新二进制在本机可执行 `--check`（uid 限制下 tracefs 不可读，输出
  `verdict:"blocked"`，与部署前动态构建一致，无崩溃）。
- **真机未验证**：需要一次同一 boot 的 98260 完整运行确认日志出现
  `page_freed=1 … order>=2` 或更早命中，并且 `DONE` 前无 240 s 失败。
  按既有安全规则，一次开机只跑一次、失败即重启。

## 2. 全屏日志返回后退出最后一步、进度消失

### 2.1 根因

`MiuixHost.kt` 根组合在 `state.showFullLog` 为真时直接渲染 `FullLogPage`
并 `return`，`HomePage` 整体离开组合。`HomePage` 内的

```kotlin
var step by remember { mutableIntStateOf(0) }
var showLog by remember { mutableStateOf(false) }
```

随之销毁；返回时 step 重置为 0，页面回到“授权”卡片，提权进度面板自然
不可见。切换底部页签也会离开 `HomePage`，同样会重置。

### 2.2 修复

- `UiState` 新增 `homeStep` / `homeShowLog`（Compose `mutableIntStateOf` /
  `mutableStateOf`），生命周期与 Activity 一致。
- `HomePage` 改为读写 `state.homeStep` / `state.homeShowLog`；
  `goStep()` 与一键提权入口同步更新。

返回全屏日志后停留在“提权”步骤，展开的日志面板与进度条保持原状。

## 3. 收尾阶段 98% 卡住约 1 分钟

### 3.1 根因

`cleanup_98260_rootd_listener()` 的 root helper 用

```sh
for p in /proc/[0-9]*; do
  for fd in "$p"/fd/*; do
    link=$(readlink "$fd")   # 每个 fd 一次 fork+exec
```

遍历**全机所有进程的所有 fd** 找 socket inode。开机 3.5 小时后进程和 fd
数量很大，这一步实测约 1 分钟；而调用侧是

```sh
_rout=$(timeout -k 5 15 "$_ksu_su" -c "sh '$_helper'")
```

`timeout` 只能杀 `su`，杀不掉它 fork 出来的 root 侧 `sh`；后者继续持有
管道，命令替换要等到它退出才返回 —— 于是 `timeout 15` 形同虚设。日志上
表现为 `SOFT_REBOOT_REPAIR=disabled` 之后约 60 s 空白，进度停在 98%。

另外备份路径比较的是 20 字符的 `exploit-android-key-ptr`，而内核 comm
最多 15 字符（实际是 `exploit-android`），该分支永远匹配不到。

### 3.2 修复

- helper 优先用 `/proc/<parent>/task/<tid>/children` 直接取已停放
  exploit 父进程的子进程，只对这几个 pid 做 fd 检查；父进程查找全部用
  shell 内建 `read` 读 `/proc/<pid>/comm`、`/proc/<pid>/status`，不再
  每进程 fork 一次。
- comm 匹配改为 15 字符的 `exploit-android`。
- 旧的“全机 fd 扫描”只在拿不到 children 且 socket inode 仍存在时兜底。
- 调用侧把 helper 输出重定向到文件后再 `cat`，不再用管道命令替换；
  `timeout` 因此能真正放弃等待。新增
  `98260_ROOTD_CLEANUP_MS=<耗时> rc=<timeout 返回码>` 便于后续观察。
- su 探测同样改为写临时文件，避免同类“孙进程持有管道”阻塞。

### 3.3 预期日志

```text
98260_ROOTD_CLEANUP=root_helper ROOTD_PID=… PPID=… COMM=exploit-android
ROOTD_KILL_RC=0
98260_ROOTD_CLEANUP=ok reason=listener_child_zombie_via_root
98260_ROOTD_CLEANUP_MS=<远小于 15000> rc=0
```

## 4. 静态验证

```text
bash tools/check.sh                              ALL CHECKS PASSED
python3 -I tools/test_98260_finalize.py          PASS
bash -n /system/bin/sh -n run.sh                 通过
Kotlin/Java assembleRelease                      BUILD SUCCESSFUL
```

APK：`main/app/MagicRoot.apk`，`62,313,943` 字节，
SHA-256 `8eb3fd9ed924e6559f48dfe66eccc81d73c6caff35042f39a2ce21e0f7bd08c0`，
versionCode 12 / versionName 1.0.5 未变。

## 5. 未验证项

- 6.12.58 的 UAF 回收命中率改善需要下一次真机运行确认；复合页假设来自
  同机型 6.18.21 的既有分析和本日志的 `page_freed=0`/`hit=0` 特征。
- 收尾耗时改善需要真机日志出现 `98260_ROOTD_CLEANUP_MS` 才能量化。
- 动态链接 payload 的 exec 竞态行为与静态版等价属推断，仍需一次完整
  98260 运行确认最终 root/KSU 闭环。

## 6. 2026-11-07 真机成功后的 129 秒收尾

用户日志确认 root/KSU 已成功，但收尾仍出现：

```text
ROOTD_KILL_RC=0
98260_ROOTD_CLEANUP_MS=128730 rc=137
```

listener 已被杀死，说明卡点不是 kill 本身，而是同步 `su` 会话没有退出。
仅把输出重定向到文件不足以脱离该会话。修复改为：

- 用 `setsid` 后台启动 root helper，stdin/stdout/stderr 全部脱离；
- `su` 只负责启动，外层最多轮询结果文件 5 秒；
- 新增 `ROOTD_CLEAN_LAUNCH_RC` / `ROOTD_CLEAN_WAIT_MS`，区分启动和 helper 等待；
- 保留只杀 listener 子进程、保留 PPID=1 exploit 父进程的安全边界。

同一份日志还出现：

```text
can't open /proc/24776/comm: No such file or directory
```

这是 children/fd 扫描后候选进程已退出的 TOCTOU 竞态。helper 现在将读取失败
视为消失进程并安静跳过，不再输出误导性错误。

离线 harness 直接执行生产 `cleanup_98260_rootd_listener()`，只把危险 root
helper 替换为 stub；结果为 `ROOTD_CLEAN_WAIT_MS=100`、总耗时约 285ms。
这验证了调用和等待机制，修复后的真机耗时仍需下一次运行确认。
