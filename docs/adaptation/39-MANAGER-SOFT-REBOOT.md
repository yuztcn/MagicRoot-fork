# 管理器软重启变冷重启：源码分析与 FinaSU 解锁

日期：2026-10-29  
管理器：FinaSU `me.yuki.fina`（KernelSU 分支）  
内核：6.12.58 late-load KSU

## 1. 源码结论

管理器源码：

```text
manager/.../rebootlistpopup/RebootListPopup.kt
manager/.../ui/util/KsuCli.kt
userspace/ksud/src/soft_reboot.rs
```

软重启入口：

```kotlin
if (reason == "soft_reboot") {
    execKsud("soft-reboot", true, true)
    return
}
```

`ksud soft-reboot` 不是 `svc power reboot userspace`，而是：

```text
reset sys.boot_completed=0
→ emulated-soft-reboot stage
→ waitsys 跟踪服务
→ stop
→ 等待服务停止
→ startup_epoch +1
→ post-fs-data / start
→ services / boot-completed
```

也就是 **stop/start 模拟 userspace reboot**，用于让 Zygisk 等模块重新走 post-fs-data/services。

## 2. 为什么之前无法软重启

上一版把：

```text
/data/adb/ksu/soft_reboot.lock
```

做成了目录，用来阻止危险 soft reboot。

`ksud soft-reboot` 在 `stop` 前会先对同一路径执行：

```text
flock(LOCK_EX|LOCK_NB)
```

目录导致 `open(O_RDWR)` 直接失败，所以 FinaSU 的软重启在进入 stop/start 前就退出了。  
表现就是：

```text
管理器点软重启无效果 / 报错
Zygisk 模块不重新加载
```

这不是 FinaSU 的 bug，是上一版防护把路径堵死了。

## 3. 当前行为

`MAGICROOT_SOFT_REBOOT_GUARD` 现在默认：

```text
0
```

即 **默认不阻断**，FinaSU 可以正常调用 `ksud soft-reboot`。

如果检测到旧的目录锁，链收尾会清理：

```text
SOFT_REBOOT_GUARD=disabled cleaned_old_lock_dir
```

启用防护（仅调试）：

```text
MAGICROOT_SOFT_REBOOT_GUARD=1
```

不再默认创建目录锁。

## 4. 手动解除旧锁

如果当前 boot 已经有旧目录锁：

```bash
su -c 'rm -rf /data/adb/ksu/soft_reboot.lock'
```

然后重新在 FinaSU 里点软重启。

如果连 `su` 都不可用，说明 KSU su provider 已失效，需要先用当前 APK 重新跑一次 98260 链。

## 5. Zygisk 加载验证

软重启后检查：

```bash
su -c 'id'
/data/adb/ksud zygisk status
getprop | grep -i zygisk
```

FinaSU 侧还可看：

```text
模块 → 启用状态
日志 → post-fs-data / service
```

如果模块仍未加载，抓：

```bash
logcat -b all -d | grep -Ei 'ksud|zygisk|soft.?reboot|startup_epoch|waitsys'
```

重点看：

```text
Another soft reboot is already in progress
waitsys ... timed out
userspace stop was not confirmed
FolkZygisk could not prepare
```

## 6. 仍存在的风险

FinaSU 的 soft reboot 仍是 stop/start 仿真；在 late-load KSU + Honor watchdog 上仍可能偶发冷启动。

如果再次出现冷启动：

1. 先确认没有旧目录锁；
2. 抓 `logcat`/`pstore`；
3. 必要时重新启用 `MAGICROOT_SOFT_REBOOT_GUARD=1`，改用完整重启。

更彻底的上游修复仍然是：late-load 模式下隐藏管理器的 soft reboot 入口，或把 ksud 的 stop/start 改成受支持的 userspace reboot。
