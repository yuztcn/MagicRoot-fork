# Duck Detector 报告分析（MLY-AN00 / 2026-10-29 22:09）

报告：`duck_detector_report_MLY-AN00_20261029_140936.txt`  
设备：HONOR MLY-AN00，Android 17 / API 37  
内核：6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k  
扫描时状态：KernelSU 已 late-load，SuSFS 开关关闭

## 1. 总结

```text
Overall: DANGER
Danger : 4  (LSPosed / SELinux / SU / TEE)
Warning: 5  (ADB / Dangerous Apps / Native Root / Network / Root Managers)
Ready  : 20
```

真正暴露 Root 的主因是**用户态**：

1. LSPosed 活跃；
2. `/product/bin/su` 可见；
3. 5 个 Root 管理器包可枚举；
4. SuSFS 本次没有加载，文件隐藏链未生效。

KernelSU 内核侧反而比较干净：

- supercall 被 seccomp 阻止，无法完成探针；
- supercall timing ratio 1.69，低于 3.0 阈值；
- prctl 探针 Clean；
- self process `[ksu_driver]` FD = 0；
- isolated mount drift Clean；
- kernelTraces Clean；
- propertyResidue Clean；
- 仅 `ksuManagerFingerprint` 2/3 traits，属于弱信号。

## 2. 四项 DANGER

### 2.1 LSPosed（最优先）

报告命中：

```text
LSPosed Manager: org.lsposed.manager
Modules:
  me.teble.xposed.autodaily
  com.owo233.tcqt
  com.spacegate.unlock
Runtime:
  2 file descriptors
  2 native maps
```

含义：

- 不只是“安装了管理器”，而是 **LSPosed 运行时映射/FD 活跃**；
- SpaceGate 也在模块列表中，这是之前为平行空间安装的；
- 游戏/反作弊若检查 LSPosed 包、模块元数据、maps/FD，会直接命中。

### 2.2 SU

报告命中：

```text
SU binaries: 1 (/product/bin/su)
Daemons: None
Processes: 0
```

注意：

- 命中的是 **`/product/bin/su`**，不是当前 SuSFS 规则里的 `/system/bin/su`；
- 当前 `run.sh` 只对 `/system/bin/su` 做 open redirect；
- 本次 `SuSFS_LKM_LOAD=disabled reason=switch_off`，所以连 `/system/bin/su` 的隐藏也没有生效。

### 2.3 Root Managers

报告枚举到 5 个：

```text
me.weishu.kernelsu      KernelSU
me.yuki.fina            FinaSU
com.rifsxd.ksunext      KernelSU-Next
com.sukisu.ultra        SukiSU
com.resukisu.resukisu   BakaSU / ReSukiSU
```

这属于 PackageManager 可见性，不需要 Root 权限就能看到。

### 2.4 SELinux

报告写的是：

```text
Enforcing (paradox)
```

但细节是：

- KSU 专用 context `u:r:ksu:s0`、`u:object_r:ksu_file:s0` 都被 live policy 拒绝（errno 22）；
- dirty sepolicy 规则全部 Denied：
  - system_server execmem
  - shell -> su
  - adbd -> adbroot
  - untrusted_app -> magisk/ksu_file/lsposed_file
- 没有 permissive domain。

结论：这是检测器读不到 enforce 文件产生的“paradox”，**不是实际 permissive，也不是 Root 证据**。不要为了这个去改 SELinux。

### 2.5 TEE

报告：

```text
Verdict: TAMPERED
Tier: StrongBox
Trust: Google
Score: 28
Boot: Verified / locked
Boot consistency: Matched
Signals: 1 policy hard, 0 policy review, 0 local
```

关键点：

- 证书链本地验证通过；
- Google root 匹配；
- verified boot = Verified；
- deviceLocked = true；
- attested verifiedBootHash 与 `ro.boot.vbmeta.digest` 一致；
- 没有 local chain mismatch。

所以这不是“Bootloader 解锁/系统分区被改”的典型 Root 证据。  
`1 policy hard` 更像 Duck 自身对 KeyMint/Keystore 行为策略的判定，报告没有给出可操作的单项修正。不要为了这个改 AVB/TEE。

## 3. 五项 WARNING

### 3.1 Native Root

唯一命中：

```text
KernelSU manager weak fingerprint
package=me.weishu.kernelsu
traits=2/3
```

其他全 Clean：

```text
ksuReadonlySupercall: Blocked by seccomp
__NR_supercall: ratio 1.69 (<3.0)
prctlProbe: Clean
susfsSideChannel: Normal
selfProcessIoc: Normal, driver FDs=0
isolatedMountDrift: Clean
kernelTraces: Clean
propertyResidue: Clean
tempRootArtifacts: Clean
```

这说明当前 KSU 的**内核隐藏**基本有效，主要漏在 manager 包名。

### 3.2 ADB Runtime

```text
USB debugging: Enabled
Wireless debugging: Enabled
init.svc.adbd: running
sys.usb.state: hisuite,mtp,mass_storage,adb
```

游戏/检测器会把 ADB 当作调试环境信号，但不等于 Root。

### 3.3 Dangerous Apps

9 个：

```text
MT Manager
AutoDaily
KernelSU
KSU Next
LSPosed Manager
ReSukiSU
Shizuku
SukiSU Ultra
Termux
```

其中 Shizuku 是 MagicRoot 部署资产所需；游戏时可以不启动。

### 3.4 Mount / System Properties

```text
Mount: Clean, coverage 75%
Shell tmp view: Clean
/proc/self/mounts: Clean
System properties: Boot/Build clean, coverage reduced
```

没有发现 overlay、bind mount、mount namespace 漂移。  
`/data/adb` 不可读是普通 app 的正常限制，不是 Root 证据。

## 4. 对“游戏锁帧”的意义

这份报告证明的是**检测面**，不是直接证明游戏锁帧。

如果游戏使用类似检测，最可能触发的是：

```text
LSPosed 运行时 / SpaceGate 模块
→ /product/bin/su
→ 5 个 Root 管理器包
```

而不是 KernelSU 内核 supercall。

同时当前设备还有：

```text
Thermal Status: 3
```

所以锁帧仍要分两条线：

1. 热控（先测）；
2. 游戏检测到 LSPosed/SU/manager（隐藏后对比）。

## 5. 建议的修复顺序

### 第一优先：LSPosed

1. LSPosed 管理器开启“隐藏管理器”；
2. 用 HMA 对游戏隐藏：
   - `org.lsposed.manager`
   - `com.spacegate.unlock`
   - `me.teble.xposed.autodaily`
   - `com.owo233.tcqt`
3. 游戏作用域里只保留必要模块；不需要时关闭 SpaceGate。

### 第二优先：SU 路径

当前只隐藏 `/system/bin/su`，但 Duck 命中的是 `/product/bin/su`。

需要在 SuSFS 加载后补：

```text
add_open_redirect /product/bin/su /dev/null 0
add_open_redirect /system/bin/su /dev/null 0
```

并确认：

```text
SuSFS_LKM_STATE=loaded
```

本次报告是 `switch_off`，所以隐藏链根本没生效。

### 第三优先：Root 管理器包

只保留一个正在使用的管理器（当前是 FinaSU），其余卸载或禁用：

```text
me.weishu.kernelsu
com.rifsxd.ksunext
com.sukisu.ultra
com.resukisu.resukisu
```

然后：

- 用管理器自身的“隐藏应用”；
- 用 HMA 对游戏隐藏 FinaSU；
- 注意隐藏后仍要保证授权/模块管理可用。

### 第四优先：环境

- 关闭 USB 调试和无线调试；
- 游戏时停止 Shizuku；
- 卸载/禁用 MT Manager、Termux 等非必要工具；
- 不要动 SELinux enforcing；
- 不要动 AVB/TEE。

## 6. 复测目标

修复后重跑 Duck，期望：

```text
SU: 不再命中 /product/bin/su
Root Managers: 只看到 1 个或 0 个
LSPosed: 包/maps/FD 不再命中
Native Root: 仍为 weak/clean
SELinux: 仍可能 paradox（可接受）
TEE: 仍可能 policy hard（不建议动）
```

只要 LSPosed/SU/manager 三项下降，游戏侧检测面就会明显缩小；热控仍需单独处理。


## 7. 对 SuSFS uid_scheme 的关键修正

当前代码：

`	ext
add_open_redirect /system/bin/su /dev/null 0
`

uid_scheme=0 只命中：

`	ext
非 app 进程（uid % 100000 < 10000）
`

所以：

- hisecd/check-su 这类非 app 进程看不到；
- Duck Detector（app UID 10373）仍然能看到 /product/bin/su；
- 游戏（也是 app UID）同样能看到。

因此仅追加一条 scheme 0 的 /product/bin/su 规则，**不能**解决 app 侧检测。

正确方向：

`	ext
对会被 umount 的 app 使用 scheme 3/4
add_open_redirect /product/bin/su /dev/null 4
add_open_redirect /system/bin/su /dev/null 4
`

或者只对指定游戏 UID 使用 scheme 3（前提是该 app 在 KSU umount 列表里）。

注意：

- scheme 3/4 会影响该 app 的 su 可见性；
- 只应对游戏/检测器 app 生效，不要全局破坏 Termux/Shizuku 的 su；
- 需要 SuSFS 已加载；本次报告是 SuSFS_LKM_LOAD=disabled reason=switch_off，规则根本没有执行。
