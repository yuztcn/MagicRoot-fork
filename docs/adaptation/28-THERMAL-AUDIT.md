# 设备异常发热排查（MLY-AN00）

采集时间：2026-10-28 23:28  
设备：MLY-AN00  
内核：`6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k`  
开机时长：约 57 分钟

## 关键数据

### 负载 / CPU

```text
loadavg: 15.31 17.74 18.24
tasks: 1038 total, 2 zombie
threads: ~12249
CPU: 800% total
     17% user, 34% sys, 741% idle, 7% irq
```

没有单个进程跑满 CPU；`dumpsys cpuinfo` 前几名：

```text
9.9%  system_server
6.6%  com.tencent.mobileqq
6.3%  surfaceflinger
5.0%  flar2.devcheck
3.4%  vendor.qti.hardware.display.composer-service
2.5%  com.android.settings
2.4%  launcher
2.3%  com.tencent.mm:appbrand0
```

高负载更像**内存压力/大量缺页/大量进程**，而不是某个进程持续占满 CPU。

### 内存

```text
Mem: 15011M total, 14807M used, 203M free
Swap: 16383M total, 8248M used
```

内存几乎耗尽，swap 已使用 8.2GB。主要 major fault：

```text
com.tencent.mobileqq        114640 major
com.tencent.mm:appbrand0     59215 major
flar2.devcheck                3911 major
system_server                 1350 major
```

### 温度

```text
battery: 40.0°C
skin:    40.8°C
CPU 当前(HAL): 约 42.8~44.6°C
thermal status: 2
```

缓存中 CPU4 曾出现 `89.9°C` 峰值，但 HAL 当前值已回落到约 44°C；屏幕亮度已被热控限制到约 39%，说明系统正在做热缓解。

### Wake lock

```text
flar2.devcheck
  PARTIAL_WAKE_LOCK
  JobInfoSchedulerService
  已持有 3 分钟以上

com.tencent.mobileqq
  MSF:WakeLock:MsgPush
```

### 电源

```text
AC powered: true
level: 100%
charging state: 0
battery temperature: 40°C
```

满电仍处于充电/供电状态，也会叠加发热。

## 是否有 MagicRoot / 链条残留

检查进程列表：

```text
无 rootd / exploit / t64560 / t98260 / pc98260 / ksud / lspd 进程
仅系统 zygote/system_server/surfaceflinger，以及正常应用
```

所以本次发热**没有证据指向 MagicRoot 提权链残留进程或 SuSFS LKM 异常占用**；SuSFS 模块也没有用户态进程在跑。

## 结论

当前发热的主要组合因素是：

1. **内存几乎耗尽 + 8GB swap + 大量 major fault**，导致系统负载长期 15+；
2. **QQ、微信、支付宝、Chrome、CoolApk、MT、Termux 等大量后台应用同时驻留**；
3. **flar2.devcheck 持有长 partial wake lock**，并持续做检查/IO；
4. 设备满电状态下仍接着电源；
5. 系统已进入 thermal status 2，亮度被限制，属于热缓解状态。

不是单一进程死循环，也没有发现 MagicRoot 链残留或 SuSFS LKM 自身异常占 CPU 的证据。

## 建议

1. 关闭/强制停止 `flar2.devcheck`，以及暂时不用的 QQ、微信、支付宝、Chrome、CoolApk、MT、Termux。
2. 重启设备，释放 1038 个进程和 8.2GB swap 占用；重启后再观察 idle 负载。
3. 不需要长期插着 100% 电源测试；满电后可拔掉供电。
4. 复测：
   ```bash
   dumpsys battery
   dumpsys thermalservice
   dumpsys cpuinfo
   top -b -n 1
   ```
5. 如果重启后 idle 仍高负载/高温，再抓 `dmesg`、`logcat -b all` 和 `dumpsys thermalservice`，重点看内核 wakelock、zram/swap 和异常驱动。
