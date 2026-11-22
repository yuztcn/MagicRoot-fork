# 6.1.x CGA 的 su：Termux 找不到入口的根因与修复

日期：2026-11-04

## 1. 现象

用户提供的 HONOR GT（`6.1.157-android14-11-g2646292297b1`）截图：

```text
KernelSU v3.3.1 (32680-5) · 工作中 [越狱模式]
设置 → 传统 SU 命令支持：置灰
提示：禁用直到下次重启 / 内核不支持此特性
```

Termux 里执行 `su`：

```text
No su program found on this device.
```

提权链路本身是成功的：CGA 模块已加载，管理器显示“工作中”。问题只在
**普通 App 如何找到 su**，不是 UAF、rootd 或模块加载失败。

## 2. 根因

### 2.1 CGA 模块按设计裁掉了 sucompat

6.1.x 的 CGA 复刻模块是 late-load/越狱模式，init 末尾明确跳过：

```c
pr_info("L6a: syscall hooks SKIPPED\n");
pr_info("L6a: setuid/sucompat SKIPPED\n");
```

它不调用 `ksu_ksud_init()`，没有 exec/stat/faccessat 的 sucompat 钩子。
管理器查询 feature 时得到“不支持”，所以“传统 SU 命令支持”置灰。这是
**预期行为**，`ksud feature set su_compat 1` 和 `force_feature=su_compat:1`
都无法打开；本轮也没有实现 kprobe 版 sucompat（见
`docs/6157-G264-CGA.md` §12，风险高）。

### 2.2 6.1 CGA 的 su 实际是 `su_lkm`

成功分支执行：

```text
setup_su_app.sh
  → 复制 su_lkm 到 /data/adb/ksu/bin/su 和 /data/local/tmp/route/m6/su_forward
  → su_optional.sh enable
      → 把 su_forward 放进 tmpfs upper，overlay 到 /system_ext/bin
      → /system_ext/bin/su 就是 su_lkm
```

`su_lkm` 不走内核 sucompat，而是：

```c
prctl(KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2, 0, &fd, 0);
ioctl(fd, KSU_IOCTL_GRANT_ROOT, 0);
```

只对 KernelSU allowlist 里的 uid 生效。管理器里必须给 Termux 打开超级用户。

### 2.3 Termux 不搜索 `/system_ext/bin`

Termux 的 `su` 是 termux-tools 提供的脚本，按**固定绝对路径列表**探测，
不搜索 `PATH`。上游 `scripts/su.in`：

```sh
for p in /debug_ramdisk/su /sbin/su /system/sbin/su /system/bin/su \
         /system/xbin/su /su/bin/su /magisk/.core/bin/su
do
    if [ -x "$p" ]; then
        exec "$p" "$@"
    fi
done
echo "No su program found on this device. Termux"
```

`/system_ext/bin/su` 不在列表里，所以即使 overlay 挂载完全成功，Termux
仍然会打印 “No su program found”。

`su_entry.sh` 本来会修补这个列表，但 g264 分支明确跳过它：

```text
98260_SU_ENTRY=skipped reason=g264_overlay_su
```

于是 6.1 CGA 路径上没有任何人修补 Termux。

### 2.4 已在运行的 Termux 看不到后来的挂载

overlay 是 setns 进 pid 1 与 zygote 的 mount namespace 后挂的。Android 的
app 进程在 fork 时会拿到自己的 mount namespace 副本，**已经在运行的
Termux 不会继承之后挂进 zygote 的 overlay**。即使搜索列表补好了，旧进程
仍然看不到 `/system_ext/bin/su`。

## 3. 修复

### 3.1 补 Termux 搜索列表

`main/app/assets/su-g264/su_optional.sh`（以及同步的
`main/app/assets/61157/su-g264/su_optional.sh`）新增 `termux_su_patch()`：

- 只处理标准 termux-tools `su` 脚本（存在 `^for p in ` 行）；其他形态输出
  `SU_OPTIONAL_TERMUX=unsupported`，不改文件。
- 把实际挂载目标放在列表最前，随后是 `/system_ext/bin/su`、
  `/data/adb/ksu/bin/su`、`/data/local/tmp/magic/su`，再保留原有条目并去重。
- 首次修改前备份为 `<su>.magicroot.bak`；用 `cat > 原文件` 写回同一个
  inode，避免 `mv` 把属主改成 `root:root` 导致 Termux 无法执行。
- 幂等：列表已经包含目标时输出 `SU_OPTIONAL_TERMUX=already`。
- 成功路径、fallback 目标（`/system/xbin`、`/vendor/bin`）以及
  `no_mountable_target` 失败路径都会调用，失败时让 Termux 至少能尝试
  `/data/adb/ksu/bin/su`，报错比 “No su program found” 更有诊断价值。

### 3.2 覆盖正在运行的 Termux

`all_pids()` 增加：

```sh
pidof com.termux
pidof com.termux:terminal
```

`enable_one()` 会为这些 pid 也 setns 并挂 overlay，旧 Termux 进程立即
可见。同时把 zygote 判定拆开：Termux 自己的挂载成功不再被误当成
“zygote 已挂载”，避免掩盖 zygote mount 失败。

### 3.3 日志

新增：

```text
SU_OPTIONAL_TERMUX=patched target=/system_ext/bin
SU_OPTIONAL_TERMUX_LINE=for p in /system_ext/bin/su /data/adb/ksu/bin/su ...
```

其他状态：

```text
SU_OPTIONAL_TERMUX=already
SU_OPTIONAL_TERMUX=absent
SU_OPTIONAL_TERMUX=unsupported reason=no_search_list
SU_OPTIONAL_TERMUX=failed reason=rewrite|write
```

### 3.4 UI 说明

98260 运行参数页在检测到 `6.1.x` 内核时增加一行说明：

> 6.1.x CGA 模块没有内核 su_compat，管理器的“传统 SU 命令支持”会显示
> 不支持。su 由 su_lkm 用户态入口提供，MagicRoot 会自动修补 Termux 的
> su 搜索列表。

避免用户把管理器置灰误判为提权失败。

## 4. 验证

已执行：

```bash
python3 -I tools/test_termux_su_entry.py
bash -n main/app/assets/su-g264/su_optional.sh
bash -n main/app/assets/61157/su-g264/su_optional.sh
/system/bin/sh -n main/app/assets/su-g264/su_optional.sh
```

`tools/test_termux_su_entry.py` 覆盖：

- 两份 `su_optional.sh` 字节一致；
- `all_pids` 覆盖 `com.termux`，zygote 判定独立；
- 成功/失败路径都调用 `termux_su_patch`；
- 用上游 `su.in` 做临时文件，验证重写后的 `for p in` 行、备份、
  幂等、自定义目标、属主/权限不变；
- 非标准 wrapper 与 Termux 未安装分别输出 `unsupported` / `absent`。

APK 构建与包内一致性校验见 `进度.md` 第 38 节。

本轮**没有**安装 APK、没有部署资产、没有执行 UAF/rootd/LKM/重启；
6.1.157 g264 的 Termux 实测仍需下一次真机运行确认。

## 5. 真机验收

成功日志应出现：

```text
98260_SU_SETUP_BEGIN ksud=...
SU_OPTIONAL_MODE=overlay-system-ext-bin-tmpfs
SU_OPTIONAL_TERMUX=patched target=/system_ext/bin
SU_OPTIONAL_OK
98260_SU_SETUP_RC=0
```

然后在 Termux（已在运行也可以，脚本会对它的 namespace 补挂）：

```sh
su -c id
# uid=0(root) ... context=u:r:su:s0
```

失败判读：

| 现象 | 含义 |
|---|---|
| `SU_OPTIONAL_TERMUX=absent` | 没装 Termux 或不是标准 termux-tools |
| `SU_OPTIONAL_TERMUX=failed` | root 写不进 Termux 数据目录（SELinux/权限） |
| Termux 仍报 No su program found | 列表没补上，或 Termux 进程在挂载前创建且 setns 失败；重启 Termux 再试 |
| `su: grant failed` | Termux 不在 KernelSU 超级用户 allowlist |
| 管理器仍显示“内核不支持此特性” | 正常，CGA 模块没有 sucompat，不是故障 |

## 6. 边界

- 不实现、不伪造内核 su_compat；管理器置灰保持原样。
- 不修改 `/system`、`/vendor` 分区；不创建 `/system/bin/su`。
- 只改 Termux 自己的 `su` 脚本，并保留 `.magicroot.bak`。
- overlay 与 `.bak` 都是本次开机的临时状态，重启后由下次运行重建。
- 仍是一次性临时 root；不持久化、不碰 `/data/adb` 管理器数据。

## 7. 2026-11-11 恢复版范围

本文记录的是恢复前的精简 CGA 行为。当前仅 **g264/gaaa** 已生成包含
`su_compat`、`kernel_umount`、`selinux_hide` 的恢复版模块；其他 profile 仍按
本文的 `su_lkm` 路径工作。恢复版的 dispatcher 失败回退、hash 和静态验证见
`docs/6157-CGA-FEATURE-RESTORE.md`，未真机加载前不把“管理器支持”视为已完成
端到端验证。
