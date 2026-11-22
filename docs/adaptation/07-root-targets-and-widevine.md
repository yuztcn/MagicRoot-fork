# Root 检测目标与 Widevine 分析

## 当前侧边栏窗口

- 当前浮窗：`HnDockBarFloatWindow`
- Owner：`com.hihonor.hndockbar`（label `Multi-Window`）
- hndockbar 静态：`RootStatus` 只出现为 UI 字段 `mRootStatus`，没有 `libhisec`/`libhonordetect`/`HwSecurityDiagnose`/`isRoot` 检测路径。
- 结论：如果指的是这个浮窗，没有找到 Root 检测。
- YOYO AI 侧边栏实际是 `com.hihonor.magicvoice`，另有检测与 `rootStatus` 导出，详见 `work/ai-sidebar/REPORT.md`。

## 目标包 Root 检测结论

| 包 | Root 检测 | 依据 |
|---|---|---|
| `com.hihonor.gtxdrivers` (UGTX) | 否 | 无 secure SDK/检测类；native 中的 root 是通用图形字符串 |
| `com.hihonor.gameassistant` (Game Manager) | 是 | 含 `com.hihonor.secure...RootDetect`、`libhisec.so`、`libhonordetect.so`、`RootStatus` |
| `com.hihonor.securitypluginbase` | 否/弱 | DEX 只有通用 `isRoot` 方法名，无 bundled 检测器 |
| `com.hihonor.securityserver`（安全公共服务） | 是 | HUKS `CheckRootStatus`、`HwKeystoreServiceImpl.isRoot`、ASSET 判决 |
| `com.hihonor.hndockbar` | 否 | 无检测类/库；`mRootStatus` 是 UI 状态 |

## Widevine

- 来源：`/vendor/apex/com.google.android.widevine.lazy.apex`
- 服务：`vendor.drm-widevine-hal` → `/apex/com.google.android.widevine.lazy/bin/hw/android.hardware.drm-service-lazy.widevine`
- init 属性：`oneshot`、`disabled`、`class hal`、`user media`
- 当前未运行；只有 `android.hardware.drm-service.clearkey`。

root 状态日志（`m6-recreate-log.txt`，14:32:52）：

```text
android.hardware.drm-service-lazy.widevine: Is commercial user: 1
libbinder.AidlLazyServiceRegistrar: Registering service android.hardware.drm.IDrmFactory/widevine
Process has 1 (of 1 available) client(s) in use ... has clients: 1
WVCdm: IsSecurityLevelSupported level = L1
WVCdm: Could not load oemcrypto ... liboemcrypto.so not found
WVCdm: Falling back to L3
WVCdm: ValidateOrInstallL1KeyboxOrCert L1 not initialized. Falling back to L3
WVCdm: Keybox error: 25. Falling back to L3
WVCdm-DrmFactory: [app][com.hihonor.id] createDrmPlugin
```

结论：

- Widevine payload 未发现 `su`/`magisk`/root 检测字符串；
- 这是按需拉起的 lazy HAL，持有 client 时会常驻；
- 日志中的 L1→L3 回退是 `liboemcrypto.so` 缺失/keybox 25 导致，不是 Root 检测；
- 若观察到 CPU/内存占用异常，优先怀疑：
  1. `com.hihonor.id` 等 client 未释放 DRM session；
  2. lazy HAL 被反复拉起 / L1 keybox 初始化失败重试；
  3. KSU mount namespace 影响 APEX 挂载（需 root 下对比验证）。
- 没有修改系统分区；只读 pull/strings/logcat。
