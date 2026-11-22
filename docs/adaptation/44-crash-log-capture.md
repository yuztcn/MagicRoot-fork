# 黑屏 / 重启日志抓取

适用于 Honor 6.12 / 6.6 / 6.18 的 98260 调试。设备上锁或黑屏时不要先清理
`/data/local/tmp/magic`，也不要 kill parked exploit。

## 1. 测试前先开持久日志

```powershell
adb shell "mkdir -p /data/local/tmp/magic"
adb shell "nohup logcat -b all -v threadtime -f /data/local/tmp/magic/logcat.txt -r 4096 -n 4 >/dev/null 2>&1 &"
```

有 root 时再开内核日志：

```powershell
adb shell su -c "nohup dmesg -w > /data/local/tmp/magic/dmesg-live.txt 2>&1 &"
```

如果 toybox `dmesg` 不支持 `-w`：

```powershell
adb shell su -c "nohup sh -c 'while true; do dmesg; sleep 5; done' > /data/local/tmp/magic/dmesg-live.txt 2>&1 &"
```

## 2. 黑屏但 adb 还活着

先抓现场，不要重启：

```powershell
adb devices
adb exec-out "logcat -b all -v threadtime -d" | Out-File -Encoding utf8 logcat-live.txt
adb exec-out "su -c 'dmesg'" | Out-File -Encoding utf8 dmesg-live.txt
adb exec-out "su -c 'cat /proc/last_kmsg'" | Out-File -Encoding utf8 last_kmsg.txt
```

如果只是 SurfaceFlinger/SystemUI 黑屏，`logcat` 里通常还有：

```text
FATAL EXCEPTION
ANR in
SurfaceFlinger
system_server
Watchdog
```

## 3. 已经重启：先抓 pstore

这是内核 panic/重启最重要的一手证据。

```powershell
adb wait-for-device
adb shell su -c "ls -l /sys/fs/pstore"
```

抓取：

```powershell
adb shell su -c "mkdir -p /data/local/tmp/magic/crash/pstore"
adb shell su -c "cp /sys/fs/pstore/* /data/local/tmp/magic/crash/pstore/ 2>/dev/null"
adb pull /data/local/tmp/magic/crash/pstore .
```

常见文件：

```text
/sys/fs/pstore/console-ramoops-0
/sys/fs/pstore/dmesg-ramoops-0
/sys/fs/pstore/pmsg-ramoops-0
```

没有 pstore 时：

```powershell
adb exec-out "su -c 'cat /proc/last_kmsg'" | Out-File -Encoding utf8 last_kmsg.txt
```

## 4. 框架崩溃 / watchdog

```powershell
adb shell su -c "mkdir -p /data/local/tmp/magic/crash"
adb shell su -c "cp -r /data/system/dropbox /data/anr /data/tombstones /data/local/tmp/magic/crash/ 2>/dev/null"
adb pull /data/local/tmp/magic/crash .
adb exec-out "logcat -b crash -d" | Out-File -Encoding utf8 crash.txt
adb bugreport
```

重点看：

```text
/data/system/dropbox/system_server_watchdog
/data/system/dropbox/SYSTEM_TOMBSTONE
/data/system/dropbox/system_server_crash
/data/tombstones/tombstone_*
/data/anr/anr_*
```

## 5. Honor / Qualcomm 额外路径

```powershell
adb shell su -c "ls -l /data/log /data/hiview /data/vendor/hiview /data/vendor/ramdump /data/ramdump 2>/dev/null"
```

可能相关：

```text
/data/log/
/data/log/reliability/
/data/hiview/
/data/vendor/hiview/
/data/vendor/ramdump/
/data/ramdump/
```

Qualcomm ramdump 通常很大，先只列目录，确认有 `*.elf` / `*.bin` 再决定是否 pull。

## 6. 分析关键词

pstore / last_kmsg：

```text
Kernel panic
Unable to handle kernel paging request
BUG:
watchdog
soft lockup
thermal
Call trace
pc :
lr :
posix_cpu_timers_exit
rb_erase
rb_next
selinux_state
kmem_cache_alloc
```

框架日志：

```text
Watchdog
FATAL EXCEPTION
ANR in
system_server
SurfaceFlinger
```

## 7. 设备完全进不去系统

- TWRP/Recovery 挂载 `/data` 后 pull：
  ```text
  /sys/fs/pstore
  /data/system/dropbox
  /data/tombstones
  /data/anr
  /data/vendor/ramdump
  ```
- 如果 pstore 为空，再考虑 Qualcomm ramdump / 售后日志。

## 8. 注意

- 黑屏后不要先清 `/data/local/tmp/magic`。
- 不要 kill parked exploit。
- 不要连续第二次 plant。
- 先确认是内核 panic、watchdog、SurfaceFlinger 还是 thermal，再决定是否重启。
