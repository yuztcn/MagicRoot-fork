# MagicRoot Root 检测与修复完整报告（中文）

日期：2026-10-28  
设备：Honor MLY-AN00 / MagicOS 10 / Android 16 / kernel 6.12.58  
版本：MagicRoot 1.0.5（versionCode 12）  
范围：只读分析 + /data 运行时手段；未修改 `/system`、`/vendor`，未破坏 AVB。

---

## 一、结论摘要

1. Honor 的 Root 判定主源是 **hisecd / STP**，不是 HUKS，也不是 `persist.sys.root.status`。
2. `securityserver` 的真实 provider 位于 **system_server**（services-magic.jar），不是 `com.hihonor.securityserver` APK。
3. 平行空间读取 STP 实时结果；系统服务不可用时是 **fail-closed**，杀 hisecd/system_server 仍会拦截。
4. m6 的“杀 hisecd + 软重启 + 复位 property”在 MagicOS 10/MLY 上不够，因为 STP 状态持久化在:
   - `oeminfo_root_info`
   - `/proc/kernel_stp`
   - hisecd storage
5. 已验证有效的运行时修复是调用 **libstp.so 的 `StpClearStatus()`**。
6. `StpClearStatus()` 需要真正的 root/full-cap 执行环境；rootd full-cap（real_cred + direct exec + system_server context）验证通过。
7. 清除后平行空间 Root 弹窗消失，User100 创建成功并可进入 Launcher。
8. HUKS debug 文件、`persist.sys.root.status=0`、只杀 `com.hihonor.securityserver` 均不能解决平行空间。
9. LSPosed/Zygisk 等模块加载可通过可选 `ksud soft-reboot` 修复；模块加载与管理器 grant 两个意图共享一次重启，默认关闭。
10. Widevine lazy HAL 本身没有 Root 检测；其进程由 Honor ID 的 MediaDrm 请求拉起。

---

## 二、Root 检测分层架构

```text
应用 native 检测层
  libhisec.so / libhonordetect.so
  DetectUtil / RootDetect / RiskDetect
        │  结果用于风控、H5 cookie、DRM、游戏、AI
        ▼
系统服务层
  hisecd (STP engine)
        │ HIDL
  vendor.honor.hardware.hwstp.IHwStp/default
        │ libstp.so
  system_server
  HwSecurityService -> HwSecurityDiagnosePlugin -> AppLayerStpProxy
        │
        ├─ HUKS/ASSET key policy
        ├─ persist.sys.root.status 上报/MDM
        └─ 应用 getRootStatusSync()

应用消费层
  Parallel Space / Game Manager / Honor ID / YOYO / 安全服务
```

---

## 三、hisecd / STP 检测原理

### 3.1 hisecd

- 路径：`/vendor/bin/hisecd`
- init：`/vendor/etc/init/hisecd.rc`
- 配置：`/vendor/etc/hisecd/stp.conf`
- HIDL：`vendor.honor.hardware.hwstp.IHwStp/default`
- hisecd 负责 STP 静态检查、状态持久化、风险上报。

### 3.2 stp.conf 检查项

| 检查 | ID | 内容 |
|---|---:|---|
| firstrun | 0x400 | 首次运行、初始化状态 |
| fblock | 0x206 | 文件/块设备检查 |
| userlock | 0x207 | 用户锁状态 |
| check-su | 0x208 | `/sbin`、`/system/bin`、`/vendor/bin`、`/odm/bin`、`/system/vendor/bin` 下 su |
| sysrw | 0x305 | `/`、`/system`、`/vendor`、`/odm`、`/cust`、`/hw_product`、`/version`、`/patch_hn`、`/preload` 是否 RW mount |
| root-prop | 0x300 | `ro.secure=0`、`ro.debuggable=1`、`ro.build.tags=test-keys` |
| verifyboot | 0x200 | verified boot 状态 |
| verity-enable | 0x201 | dm-verity 状态 |
| verified-state | 0x203 | verified state |
| key-files | 0x202 | key/系统文件校验 |
| image-valid | 0x211 | 镜像有效性 |
| mrcinfo | 0x285 | 其他安全信息 |

`credible` 含义：

```text
0 = STP_REFERENCE
1 = STP_CREDIBLE
2 = STP_CREDIBLE_EX_FB
```

### 3.3 状态持久化

hisecd 关键日志：

```text
status loaded from storage
status stored into storage
su found at %s
root-prop
dm-verity disabled at %s
rw mount at %s
persist.vendor.hisecd.firstrun
ro.vendor.hisecd.refreshed
oeminfo_root_info
/proc/kernel_stp
```

因此：

- 杀 hisecd 后 init 可以重启；
- 重启后状态可能从 storage/OEMINFO/kernel_stp 恢复；
- 单纯复位 `persist.sys.root.status` 不改变 STP 状态。

### 3.4 HIDL 查询链

```text
HwSecurityDiagnoseManager.getRootStatusSync()
  -> HwSecurityServiceProxy.queryInterface(2)
  -> HwSecurityDiagnosePlugin.getRootStatusSync()
  -> AppLayerStpProxy.getRootStatusSync()
  -> HwStpHidlAdapter.stpGetStatusByCategory(8)
  -> vendor.honor.hardware.hwstp.IHwStp/default
  -> libstp.so StpGetStatusByCategory()
  -> hisecd Unix socket cmd 2002, key 8
```

`STP_ROOT_THREAT = 8`。

返回：

```text
0    = 非 Root
非0  = Root/风险
-1000/-1001/-1002/-2000 = 服务不可用，仍然 fail-closed
```

---

## 四、system_server 中的真实 securityserver

真实服务不是 `HnSecurityServer.apk`。

```text
system_server
com.android.server.security.HwSecurityService
  -> HwSecurityServiceProxy.onStart()
     ServiceManagerEx.addService("securityserver", wrapper)
     registerCorePlugins() -> resident plugin id 2
  -> HwSecurityDiagnosePlugin
```

`HnSecurityServer.apk` 注册的是 `security_server`（带下划线），与框架使用的 `securityserver` 不是同一个 binder。

这也解释了：

- 停用/杀掉 `com.hihonor.securityserver` 对 STP 判定无效；
- 真正的判定驻留在 system_server，重启后重新注册。

---

## 五、HUKS 的角色

HUKS 是 STP 判决的消费者：

```text
HwKeystoreServiceImpl.isRoot()
  -> HwSecurityDiagnoseManager.getRootStatusSync()
```

`libhwkeystore_jni.so` 包含：

```text
CheckRootStatus
get isRoot method not found
strictRoot
the device has been rooted!
```

HUKS 本地旁路文件：

```text
/data/user/0/com.hihonor.securityserver/asset_debug_info.txt
```

内容必须精确为：

```text
msc.asset.debug=true
```

该文件只放宽 HUKS/ASSET 自身判定，不影响 STP，也不影响平行空间。

---

## 六、平行空间 Root 拦截原理

`ParallelSpace InitActivity.onCreate` 调用：

```text
parallel.g1.e()
```

语义：**1 = 拦截，0 = 允许**。

```text
manager == null -> 1（拦截）
status = getRootStatusSync()
debug  = getProperty(msc.parallelspace.debug_mode)
if status == 0      -> 0（允许）
if debug == 1       -> 0（允许）
if g1.c() == 0      -> 0（OEM demo 例外）
否则                -> 1（拦截）
```

`g1.c()` 只在 OEM demo 条件成立时放行；当前 `msc.sys.vendor=all`、`msc.sys.country=cn`，不会放行。

对话框资源：

```text
0x7f100025 alert_message_enter_when_root
```

---

## 七、应用层 native 检测

### 7.1 libhisec.so

JNI 注册在：

```text
com.hihonor.secure.android.common.detect.S
```

注册项：

```text
idj  -> 反调试
iej  -> 模拟器检查
irpj -> APK 签名 SHA-256 allow-list
irtj -> Root 检查
```

`irtj` 检查：

```text
ro.secure
ro.build.tags == test-keys
21 个前缀 + /su
21 个前缀 + /magisk
/system/usr/we-need-root
init.svc.su_kpbs_daemon
```

`idj` 检查：

```text
TracerPid
/proc/net/tcp 0x5D8A
android_server / android_server64 cmdline
```

### 7.2 libhonordetect.so

导出：

```text
NativeLib.isRT()
NativeLib.isSMT()
NativeLib.isDG()
```

`isRT` 特征：

- 29 个前缀下的 `/su`、`/magisk`
- `/cache/.disable_magisk`
- `ro.secure`
- `ro.build.tags`
- `/proc/self/maps` 中 Frida/Xposed/libmemtrack
- 19 个 LSPosed/Riru/EdXposed 路径

返回值是位掩码：

```text
bit0  = root 文件/路径命中
bit8  = 不安全构建
bit16 = hook 框架命中
```

### 7.3 应用侧检测结果去向

- magicvoice：`rootStatus` 写入 H5 cookie、JS bridge、AISO fallback；
- 游戏管家：使用同一 Hihonor Secure SDK；
- Honor ID：`Kit_Data_Collector` 调用 `RiskDetect`，并读取 Widevine `deviceUniqueId`；
- HnDockBar（AI侧边栏）：无本地 root detector，但缓存 Root 状态/推荐结果；清 app 数据可恢复显示。

---

## 八、失败实验与原因

### 8.1 只杀 hisecd

失败原因：

- init 会重启 hisecd；
- 状态持久化；
- 服务不可用返回非0，仍 block。

### 8.2 杀 `com.hihonor.securityserver`

失败原因：

- 它不是 `securityserver`；
- 真正的服务在 system_server。

### 8.3 软重启 system_server

失败原因：

- 服务重新注册；
- STP 状态仍在；
- 旧 binder 死亡返回 -2000。

### 8.4 `persist.sys.root.status=0`

失败原因：

- 只是 report/MDM 属性；
- `getRootStatusSync()` 不读取它。

### 8.5 HUKS debug 文件

失败原因：

- 只影响 HUKS/ASSET；
- 不影响 STP；
- 平行空间仍拦截。

### 8.6 m6 四步

m6：

```text
kill kmsg_dumper
kill hisecd
soft restart system_server
120s watchdog reset property
```

在 MLY/MagicOS 10 上缺少：

```text
StpClearStatus()
```

所以仍被拦截。

---

## 九、修复方式

### 9.1 核心修复：StpClearStatus

`/vendor/lib64/libstp.so` 导出：

```text
StpClearStatus()
StpCleanKshieldStatus()
StpGetStatusByCategory()
```

已验证：

```text
StpClearStatus=0
StpCleanKshieldStatus=-32
```

最小 helper：

```c
dlopen("/vendor/lib64/libstp.so", RTLD_NOW|RTLD_GLOBAL);
clear = dlsym(h, "StpClearStatus");
clear();
```

设备执行：

```text
su -c /data/local/tmp/magic/98260/stpclear
```

成功日志：

```text
StpClearStatus=0
```

效果：

```text
平行空间 Root 弹窗消失
进入正常创建引导
UserInfo{100:平行空间} running
ParallelSpaceLauncherActivity 正常
```

### 9.2 rootd full-cap 执行环境

KSU su 或普通 shell 不足以执行部分操作，rootd 需要：

1. real_cred 写入：`[real_cred] task->real_cred installed (uid: 0)`
2. `!argv` 直接 exec，绕过 `/system/bin/sh` 降权；
3. setcon 到 `u:r:system_server:s0`。

验证：

```text
uid=0
CapEff=000001ffffffffff
context=u:r:system_server:s0
cmd -l 正常
setprop 正常
```

### 9.3 资产部署

APK 必须部署：

```text
/data/local/tmp/magic/98260/stpclear
```

部署清单 `ASSETS_98260` 已加入 `"98260/stpclear"`。

run.sh：

```text
98260 成功
  -> stp_clear_fix
  -> soft_reboot_repair
```

### 9.4 软重启修复

用于 LSPosed/Zygisk 等模块加载和管理器 grant：

```text
模块加载软重启
管理器 grant 软重启
```

两者共享一次：

```text
/data/adb/ksud soft-reboot
失败回退：
setprop ctl.restart zygote
```

通过 `/system/bin/su -c` 执行。

默认关闭；旧聚合开关不自动迁移为开启。

### 9.5 其他可选项

- hook `AppLayerStpProxy.getRootStatusSync()` 返回0；
- hook `HwSecurityDiagnosePlugin.getRootStatusSync()`；
- hook HIDL `stpGetStatusByCategory`；
- hook 应用 `parallel.g1.e()`；
- root-hide：
  - `/system/bin/su`
  - `/sbin/.magisk`、LSPosed/Riru 路径
  - `ro.secure`、`ro.debuggable`、`ro.build.tags`
- HnDockBar 显示异常：清 `com.hihonor.hndockbar` 数据；
- magicvoice：hook `DetectUtil.isRooted()` / `SecurityDetectUtils.isRoot()`。

---

## 十、风险与限制

1. `StpClearStatus()` 会影响全局安全状态，不只是平行空间。
2. 如果 `/system/bin/su`、RW mount、LSPosed 路径再次可见，STP 可能重新判定 Root。
3. KSU 模式与 rootd-only 行为不同；已验证的是 rootd-only 路径。
4. rootd UAF 存在页回收 miss，表现为 `[uaf] page miss` / `holding zombie`；此时需要重启重试。
5. 软重启会重启 framework，ADB 可能短暂断开。
6. 不要修改 `/system`、`/vendor`；否则可能破坏 AVB 导致无法开机。
7. 服务端独立 HUKS/设备认证不在客户端修复范围内。

---

## 十一、验证命令

```bash
# Root 状态
su -c "getprop persist.sys.root.status"
su -c "/data/local/tmp/magic/98260/stpclear"

# STP 日志
grep -E "StpClearStatus|HISEC|cmd 2002" /data/local/tmp/magic/run.log

# 平行空间
su -c "am start -n com.hihonor.parallelspace/.launcher.InitActivity"
pm list users

# 软重启
/data/adb/ksud soft-reboot
cat /data/local/tmp/magic/soft_reboot.log
```

---

## 十二、交付与源码

完整源码已合并：

```text
docs/adaptation/00-ROOT-DETECTION-FIX-REPORT-CN.md
docs/adaptation/01-STP-clear-fix.md
docs/adaptation/02-rootd-context-and-ai-sidebar.md
docs/adaptation/03-honor-id-analysis.md
docs/adaptation/04-securityserver-huks-analysis.md
docs/adaptation/05-native-analysis.md
docs/adaptation/06-ai-sidebar-magicvoice.md
docs/adaptation/07-root-targets-and-widevine.md
docs/ADAPT-ROOTD-STP-REPRO.md

binary-sources/98260-6.12/verified/
  exploit-direct3-61258
  pc98260-su-61258
  stpclear

main/app/assets/98260/stpclear
binary-sources/98260-6.12/stpclear.c
```

不提供独立 toolkit zip / source-extras 层级。

---

## 十三、最终判断

- **m6 + hisecd 清理**：不足；
- **HUKS debug / property 复位**：不足；
- **STP clear**：已验证有效；
- **rootd full-cap**：已验证可执行；
- **KSU 模式自动 stpclear**：仍需在最新包上再跑一次 98260 做最终实机确认；
- **建议最终顺序**：

```text
重启 → 最新包部署资产 → 98260 rootd/full-cap
→ StpClearStatus()=0
→ setprop persist.sys.root.status 0
→ 打开平行空间创建
```

如需要模块加载/管理器 grant，再按需开启两个软重启开关。
