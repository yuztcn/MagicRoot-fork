# 平行空间 / 远程协助隐藏 root 方案

样本：

```text
平行空间和远程协助隐藏root.apk.1
package: com.ksu.roothider
entry:   com.ksu.roothider.Hook
类型:    Xposed / LSPosed 模块
```

## 1. 隐藏模块做了什么

`xposed_init`：

```text
com.ksu.roothider.Hook
```

Hook 目标：

```text
HwSecurityDiagnoseManager.getRootStatusSync -> 0
HwSecurityDiagnoseManager.getRootStatus(callback) -> onResult(0)
AppLayerStpProxy.getRootStatusSync -> 0
HwSecurityDiagnosePlugin.getRootStatusSync -> 0
SystemPropertiesEx.getInt("msc.parallelspace.debug_mode", 0) -> 1
```

因此它不是“清 STP”方案，而是**在进程内强制 root=0 并伪造 debug_mode=1**。

## 2. 平行空间自身判断

反编译 `com.hihonor.parallelspace` 后，`parallel/g1.java`：

```java
return (manager.getRootStatusSync() == 0
        || SystemPropertiesEx.getInt("msc.parallelspace.debug_mode", 0) == 1
        || 演示区域)
       ? false : true;
```

即：

- `getRootStatusSync()==0`：允许；
- 或 `msc.parallelspace.debug_mode=1`：允许；
- 否则判定 root，弹出 “root 环境无法进入平行空间”。

**只清 STP 不够**：如果 `getRootStatusSync` 仍返回非 0，必须设置 debug_mode。

## 3. 远程协助

`com.hihonor.remoteassist` 也引用：

```text
HwSecurityDiagnoseManager.getRootStatusSync
```

没有 debug_mode 分支。Xposed 模块通过 Hook Manager 对远程协助同样返回 0。
没有 Xposed 时，工具只能：

1. `stpclear` 清 STP；
2. 强制停止远程协助，让新进程重新查询；
3. 若仍检测 root，需要 LSPosed + RootHider 模块。

## 4. App 内 STP 按钮已移除

App 不再提供“清除 STP”按钮。原因：

- 该操作必须配合**重启 + 重新提权**才真正生效，按钮容易让用户误以为“一键修复完成”。
- 清除 STP 属于一次性准备工作，不需要每次运行都暴露在首页。
- 隐藏链路本身仍由 KernelSU/SuSFS/STP 持久状态完成，不依赖 RootHider/Xposed。

需要时由用户/测试流程手动执行：

```text
/data/local/tmp/magic/stpclear
```

然后重启设备、重新提权，再打开平行空间/远程协助。

### 设备实测

```text
StpClearStatus=0 StpCleanKshieldStatus=-32
PARALLELSPACE_DEBUG_MODE=1
```

按钮点击后 UI 显示：

```text
平行空间修复完成
```

## 5. 限制

- `msc.parallelspace.debug_mode` 在首次设置后可能变为 **read-only property**；
  再设置会报 “Read-only property was already set”，因此只在当前值非 1 时尝试。
- 如果属性初始不存在且 KernelSU su 对该 property context 无写权限，`setprop` 会失败；
  此时需要 LSPosed + RootHider 的 `SystemPropertiesEx` Hook。
- 即使 debug_mode=1，若平行空间进程内 `getRootStatusSync` 仍为非 0，
  也仍然允许（debug 分支是 OR）；但远程协助没有 debug 分支，只能依赖 STP 清除或 Xposed。
- 不修改系统分区；force-stop 只重启用户态进程。


## 6. 最终采用方案（不安装 RootHider / Xposed）

不使用 RootHider、LSPosed 模块或任何进程内 Hook。实际链路：

1. 调用 stpclear 清 STP（一次性；状态会持久化）；
2. 重启设备，让 system_server/创建服务重新读取 STP 状态；
3. 重新运行 MagicRoot 98260 提权链，恢复 KernelSU/root；
4. SuSFS 对 /system/bin/su 做 open_redirect，隐藏 kernelsu 模块；
5. 启动平行空间。

实测：重启并重新提权后，未在本次开机再次执行 stpclear，平行空间可直接创建/进入设置页，不再出现“该设备已经 Root，创建平行空间会存在风险”。

内置的 MAGICROOT_SKIP_STP=1 / /data/local/tmp/magic/skip_stp 仅用于诊断，不属于正式隐藏链路。

系统应用检测清单见 23-SYSTEM-ROOT-CHECK-INVENTORY.md；.ko 提取修复见 24-KO-EXTRACTION-FIX.md。


## 7. 按钮是否保留

已移除。STP 清除不在 App 内提供入口；保留 root 链、SuSFS 和 STP 持久状态即可。
