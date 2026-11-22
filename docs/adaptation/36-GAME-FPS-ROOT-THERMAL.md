# 游戏锁帧与 hisecd/Root 检测分析

日期：2026-10-29  
设备：MLY-AN00，6.12.58  
当前状态：root 已丢失（`persist.sys.root.status=0`），SELinux Enforcing

## 结论先行

1. **没有发现 hisecd/STP 直接修改游戏帧率的证据。**
2. hisecd/STP 的 Root 状态主要影响：
   - 系统安全判定；
   - 平行空间；
   - HUKS/ASSET/DRM 等安全能力。
3. **游戏管家/游戏 SDK 自己有 RootDetect**：
   - `libhisec` / `libhonordetect`；
   - 会扫描 `/data/local/tmp`、`/system/bin/su` 等路径；
   - 游戏 SDK 把 `rootStatus` 写入 cookie/上报给游戏/H5 服务。
4. 游戏是否因此锁帧，取决于**游戏/反作弊服务端策略**，不是 hisecd 本地的帧率 API。
5. 当前设备更直接的锁帧原因是**热控**：
   ```text
   Thermal Status: 3
   CPU 55~57°C
   GPU 52~55°C
   ```
   thermal status 3 会限制 CPU/GPU/亮度/持续性能，足以造成掉帧或锁帧。

## 1. hisecd/STP 链路

已有分析确认：

```text
hisecd / kernel STP
→ HwSecurityDiagnoseManager.getRootStatusSync()
→ 安全组件/平行空间/HUKS 消费者
```

它不提供游戏帧率接口，也不会直接调用 Game Manager 的帧率策略。

杀 hisecd 无效且更糟：

- hisecd/STP 是 fail-closed；
- 系统服务异常时返回负值，仍被当作 Root；
- 不能清持久化判决。

正确做法仍是 `StpClearStatus()`，但它只清 STP，不会隐藏文件系统中的 `/data/local/tmp/magic`。

## 2. 游戏管家/游戏 SDK 的独立检测

`com.hihonor.gameassistant` 内含：

```text
com.hihonor.secure.android.common.detect.RootDetect
libhisec.so
libhonordetect.so
RootStatus
```

`libhisec` 的 root 路径表包含：

```text
/data/local/tmp
/system/bin
/system/xbin
/vendor/bin
...
```

游戏 SDK：

```text
com.hihonor.gamecenter.gamesdk.core.net.utils.DetectUtil.isRooted()
com.hihonor.gamecenter.gamesdk.core.utils.cookie.DeviceInfo.rootStatus
```

后者会把 Root 标记放进游戏 WebView cookie，发送给游戏/H5 服务端。

因此存在这条链：

```text
游戏 SDK 本机扫描到 /data/local/tmp/magic 或 /system/bin/su
→ rootStatus=true
→ 游戏/反作弊服务端决定画质/帧率/匹配策略
```

这条链**不需要 hisecd**，STP 清零也不会让 `libhisec` 看不到文件。

## 3. 本机静态代码的负向证据

- `RootDetect.isRoot()` 在 gameassistant base APK 内没有调用者；
- 实际运行的是 `DetectUtil.isRooted()`（game SDK）；
- 没有找到 `rootStatus` 直接调用 `ifFrameLimit` / `performanceMode` 的代码；
- Game Assistant 的帧率选项是独立功能：
  ```text
  帧率增强
  解除帧率限制
  优化功耗
  ```
- `dumpsys game` 当前没有对这些游戏设置 intervention。

所以“游戏管家因为 Root 直接锁 60 帧”目前**没有被静态代码证明**。

## 4. 当前设备的热控证据

```text
Thermal Status: 3
CPU0..7: 52.5~57.6°C
GPU0..9: 51.7~55.6°C
```

另外：

```text
persist.sys.root.status=0
getenforce=Enforcing
dumpsys game: No intervention found
```

这组数据说明：

- 当前不是 Root 可见状态；
- 系统已经进入高温热缓解；
- 如果此时游戏锁帧，优先归因热控/功耗策略，而不是 hisecd。

## 5. 正确的区分实验

控制变量，按顺序做：

### A. 热控基线

1. 拔掉充电，冷却到：
   ```text
   Thermal Status 0 或 1
   CPU < 45°C
   ```
2. 关闭 QQ/微信/Chrome/MT/Termux 等后台；
3. 同一游戏、同一画质/帧率设置、同一场景 10 分钟；
4. 记录：
   ```bash
   dumpsys thermalservice
   dumpsys SurfaceFlinger --latency
   dumpsys game
   settings get system peak_refresh_rate
   ```

如果热控基线仍锁帧，先处理热控，不要继续折腾 Root。

### B. Root 可见 vs 隐藏

在热控相同的前提下比较：

```text
A: /system/bin/su 可见 + /data/local/tmp/magic 存在
B: su 隐藏 + workdir 隐藏 + STP 清零
```

观察：

```text
persist.sys.root.status
游戏内帧率
Game Assistant 帧率增强是否可用
```

### C. 游戏 SDK Root 标记

如果 B 仍锁、A 不锁，优先怀疑：

```text
DetectUtil.isRooted()
rootStatus cookie
游戏服务端反作弊
```

这时只清 STP 没用，需要同时隐藏文件系统痕迹或 hook 游戏进程的检测。

## 6. 可落地的隐藏顺序

1. **KernelSU DenyList/Shamiko**：对游戏、gameassistant、gamesdk 进程隐藏模块与 su。
2. **SuSFS open redirect**：
   ```text
   add_open_redirect /system/bin/su /dev/null 0
   ```
3. **SuSFS sus_path / hide_mounts**：
   - 默认 hide_mounts 已含 `/data/local/tmp/`；
   - 但 `/data/local/tmp/magic` 是目录，不是独立挂载，必要时加 sus_path；
   - 注意不要破坏 rootd 自身访问。
4. **STP clear**：只解决 HwSecurityDiagnose/平行空间，不解决 libhisec 文件扫描。
5. **LSPosed hook**：只有确认游戏进程调用 `DetectUtil.isRooted`/RootStatus 后再做，避免无谓 hook。

不要杀 hisecd，不要反复软重启。

## 7. 建议的下一步

需要用户补充：

- 具体游戏包名；
- 锁帧数值（60/90/120）；
- 锁帧时 `Thermal Status`；
- 是否只在 Root 可见时锁；
- Game Assistant 的“帧率增强/解除帧率限制”是否消失或报错。

有了这些，才能判断是：

```text
A. 热控
B. 游戏服务端反作弊
C. Game Assistant 本地策略
D. 显示刷新率/省电模式
```

目前证据优先级：

```text
热控 > 游戏反作弊/文件检测 > Game Assistant 本地策略 > hisecd 直接锁帧
```


## 8. 四个类的反汇编结论

### 8.1 
et.bean.DeviceInfo

`	ext
rootStatus: int
setRootStatus(int)
`

所有主要调用点都使用：

`	ext
repository.b.Y() -> int
`


epository.b.Y() 的反汇编：

`	ext
DetectUtil.isRooted()
→ true  : 返回 b.f（非零，通常 1）
→ false : 返回 0
`

也就是说这是**真正的 Root 检测值**，不是 UI 字段。

### 8.2 
et.repository.cookie.DeviceInfo

`	ext
rootStatus: String  (0 / 1)
toCookieData(): base64(JSON)
`

它把 rootStatus 写进 cookie/JSON，供游戏 H5/服务端读取。

### 8.3 
et.req.GameReservationReq

`	ext
rootStatus: int
setRootStatus(b.Y())
`

随预约请求的 
iskControl 上报。

### 8.4 
et.req.GameVersionReservationReq

同样：

`	ext
rootStatus: int
setRootStatus(b.Y())
`

随版本预约请求上报。

### 8.5 关键：GetGameFrameReq

GetGameFrameReq 含：

`	ext
riskControl: RickControlBean
`

而 RickControlBean.DeviceInfo.rootStatus 就是上面的 Root 检测值。

因此存在：

`	ext
DetectUtil.isRooted() = true
→ DeviceInfo.rootStatus = 1
→ GetGameFrameReq.riskControl
→ 服务端返回/调整帧率策略
`

这是目前唯一能从代码证明的 **Root→帧率** 路径。

注意：

- 它发生在**服务端**；
- 不是 hisecd；
- 不是本地 ifFrameLimit 直接调用；
- STP 清零不会改变 DetectUtil.isRooted()；
- 需要隐藏文件系统痕迹或 hook 游戏进程的检测。

### 8.6 当前设备

`	ext
persist.sys.root.status=0
Thermal Status=3
`

因此当前若锁帧，Root 上报不是第一嫌疑；先看热控。
