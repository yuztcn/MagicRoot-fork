# STP Root 状态清除：平行空间 Root 拦截的真正修复点

## 结论

平行空间 Root 拦截的最终来源不是 HUKS ASSET、不是 `persist.sys.root.status`，而是 **STP（hisecd）判决**：

```text
HwSecurityDiagnoseManager.getRootStatusSync()
  -> IHwSecurityDiagnosePlugin.getRootStatusSync()
  -> com.hihonor.server.security.securitydiagnose.HwSecurityDiagnosePlugin
  -> AppLayerStpProxy.getRootStatusSync()
  -> HwStpHidlAdapter.stpGetStatusByCategory(8,...)
  -> vendor.honor.hardware.hwstp.IHwStp/default
  -> hisecd (/vendor/bin/hisecd)
```

`hisecd` 读取 `/vendor/etc/hisecd/stp.conf`，检查：

- `check-su`：`/sbin /system/bin /vendor/bin /odm/bin /system/vendor/bin` 下的 su
- `sysrw`：根目录/系统分区是否 RW
- `root-prop`：`ro.secure` / `ro.debuggable` / `ro.build.tags`
- `verifyboot` / `verity-enable` / `verified-state`
- `oeminfo_root_info`、`/proc/kernel_stp`
- 状态会持久化（日志：`status loaded from storage` / `status stored into storage`）

m6 只 kill hisecd + 软重启 framework + 复位 property，不会清除 STP 已持久化/kernel 的判决，所以弹窗依旧。

## 修复 API

反编译 `/vendor/lib64/libstp.so` 发现：

```text
StpClearStatus()          // 无参数，清除 STP 状态
StpCleanKshieldStatus()   // 无参数
StpGetStatus/GetStatusByCategory/GetStatusById
StpStaticCheck/TriggerKshieldCheck
```

实测：

```text
StpClearStatus=0
StpCleanKshieldStatus=-32
```

## 实测结果

使用 rootd full-cap（uid0 / CapEff full / `u:r:system_server:s0`）调用 `StpClearStatus()` 后：

```text
persist.sys.root.status=0
平行空间 Root 弹窗消失
正常进入创建引导
UserInfo{100:平行空间} running
ParallelSpaceLauncherActivity 正常
```

再次 30s 后调用 clear + force-stop/start，仍正常进入 Launcher：

```text
FOCUS=ParallelSpaceLauncherActivity
USERS=UserInfo{100:平行空间} running
ROOTSTATUS=0
```

随后恢复：

```text
SELinux=Enforcing
KSU=0
/system/bin/su 不存在
rootd 仍存活
```

## Helper

源码：

```text
work/stpclear.c
```

实现：

```c
dlopen("/vendor/lib64/libstp.so", RTLD_NOW|RTLD_GLOBAL);
dlsym(h, "StpClearStatus");
dlsym(h, "StpCleanKshieldStatus");
```

编译：

```text
work/toolchain/ndk/android-ndk-r28c/.../aarch64-linux-android35-clang.cmd
  -fPIE -pie -O2 -o stpclear stpclear.c -ldl
```

运行：

```text
rootd-exec.sh /data/local/tmp/stpclear
```

## 生产集成建议

1. 把 `stpclear` 源码/二进制加入 MagicRoot 的 98260 assets。
2. rootd 成功、socket 可用后执行：
   ```text
   pc98260-su -c "!/data/local/tmp/magic/stpclear"
   ```
3. 再执行：
   ```text
   setprop persist.sys.root.status 0
   ```
4. 再启动/创建平行空间。
5. m6 v7.9 的四步应改成：
   ```text
   kill kmsg_dumper
   kill hisecd
   soft restart system_server
   StpClearStatus()      <-- 新增关键步骤
   120s 守望复位 property
   ```

## 限制

- 当前已验证的是 **rootd-only（KSU=0，无 su）**。
- KSU root 会在 `/system/bin/su` 留痕，STP static check 可能再次判 root；需要 root-hide 或每次创建前 clear。
- `StpCleanKshieldStatus` 返回 -32，但 `StpClearStatus` 已足够。
- 全程未修改 `/system`、`/vendor`，未 remount，未改 AVB。
